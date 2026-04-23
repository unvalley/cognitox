//! GetTokensFromRefreshToken API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_GetTokensFromRefreshToken.html>

use chrono::Utc;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::{
    action::user::auth_flow::require_refresh_token_auth_flow,
    error::{AppError, Result},
    jwt::{
        generate_access_token, generate_id_token, resolve_access_token_expiry,
        resolve_id_token_expiry,
    },
    storage::Storage,
    types::ClientId,
};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Request {
    client_id: ClientId,
    refresh_token: String,
    #[serde(default)]
    client_secret: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    device_key: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    client_metadata: Option<serde_json::Map<String, Value>>,
}

pub async fn handler(storage: &Storage, body: Value) -> Result<Value> {
    let req: Request = serde_json::from_value(body)
        .map_err(|e| AppError::InvalidParameter(format!("Invalid request: {}", e)))?;

    let client = storage
        .get_user_pool_client(&req.client_id)
        .await
        .ok_or(AppError::UserPoolClientNotFound)?;
    require_refresh_token_auth_flow(&client)?;

    if let Some(expected_secret) = client.client_secret.as_ref() {
        match req.client_secret.as_deref() {
            Some(provided) if provided == expected_secret => {}
            Some(_) => {
                return Err(AppError::InvalidParameter(
                    "Invalid client secret".to_string(),
                ));
            }
            None => {
                return Err(AppError::InvalidParameter(
                    "Client secret required".to_string(),
                ));
            }
        }
    }

    let stored_token = storage
        .get_refresh_token(&req.refresh_token)
        .await
        .ok_or(AppError::InvalidRefreshToken)?;

    if stored_token.client_id != req.client_id {
        return Err(AppError::InvalidRefreshToken);
    }

    if stored_token.expires_at < Utc::now() {
        return Err(AppError::InvalidRefreshToken);
    }

    let user = storage
        .get_user(&stored_token.user_id)
        .await
        .ok_or(AppError::UserNotFound)?;

    if !user.enabled {
        return Err(AppError::UserDisabled);
    }

    let groups = storage.get_groups_for_user(&user.id).await;

    let access_expiry = resolve_access_token_expiry(&client);
    let id_expiry = resolve_id_token_expiry(&client);

    let access_token = generate_access_token(
        &user,
        req.client_id.as_str(),
        &client.user_pool_id,
        &groups,
        &client.allowed_oauth_scopes,
        access_expiry,
    )
    .map_err(AppError::Internal)?;
    let id_token = generate_id_token(
        &user,
        req.client_id.as_str(),
        &client.user_pool_id,
        &groups,
        id_expiry,
    )
    .map_err(AppError::Internal)?;

    Ok(json!({
        "AuthenticationResult": {
            "AccessToken": access_token,
            "IdToken": id_token,
            "ExpiresIn": access_expiry.num_seconds(),
            "TokenType": "Bearer"
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::user::{initiate_auth, sign_up};
    use crate::action::user_pool::{create_user_pool, create_user_pool_client};

    async fn setup_and_get_refresh_token(storage: &Storage) -> (String, String) {
        let pool = create_user_pool::handler(storage, json!({"PoolName": "test"}))
            .await
            .unwrap();
        let pool_id = pool["UserPool"]["Id"].as_str().unwrap();

        let client = create_user_pool_client::handler(
            storage,
            json!({
                "UserPoolId": pool_id,
                "ClientName": "test-client"
            }),
        )
        .await
        .unwrap();
        let client_id = client["UserPoolClient"]["ClientId"]
            .as_str()
            .unwrap()
            .to_string();

        let sign_up_result = sign_up::handler(
            storage,
            json!({
                "ClientId": client_id,
                "Username": "testuser",
                "Password": "Password123!"
            }),
        )
        .await
        .unwrap();

        let user_sub = sign_up_result["UserSub"].as_str().unwrap();
        let user_id = uuid::Uuid::parse_str(user_sub).unwrap();
        storage.confirm_user(&user_id).await;

        let auth = initiate_auth::handler(
            storage,
            json!({
                "ClientId": client_id,
                "AuthFlow": "USER_PASSWORD_AUTH",
                "AuthParameters": {
                    "USERNAME": "testuser",
                    "PASSWORD": "Password123!"
                }
            }),
        )
        .await
        .unwrap();

        let refresh_token = auth["AuthenticationResult"]["RefreshToken"]
            .as_str()
            .unwrap()
            .to_string();

        (client_id, refresh_token)
    }

    #[tokio::test]
    async fn test_get_tokens_from_refresh_token_success() {
        let storage = Storage::new();
        let (client_id, refresh_token) = setup_and_get_refresh_token(&storage).await;

        let result = handler(
            &storage,
            json!({
                "ClientId": client_id,
                "RefreshToken": refresh_token
            }),
        )
        .await
        .unwrap();

        assert!(
            result["AuthenticationResult"]["AccessToken"]
                .as_str()
                .is_some()
        );
        assert!(result["AuthenticationResult"]["IdToken"].as_str().is_some());
    }

    #[tokio::test]
    async fn test_get_tokens_from_refresh_token_invalid_token() {
        let storage = Storage::new();

        let pool = create_user_pool::handler(&storage, json!({"PoolName": "test"}))
            .await
            .unwrap();
        let pool_id = pool["UserPool"]["Id"].as_str().unwrap();
        let client = create_user_pool_client::handler(
            &storage,
            json!({"UserPoolId": pool_id, "ClientName": "test-client"}),
        )
        .await
        .unwrap();

        let result = handler(
            &storage,
            json!({
                "ClientId": client["UserPoolClient"]["ClientId"],
                "RefreshToken": "invalid"
            }),
        )
        .await;

        assert!(matches!(result.unwrap_err(), AppError::InvalidRefreshToken));
    }
}
