//! GetTokensFromRefreshToken API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_GetTokensFromRefreshToken.html>

use chrono::{Duration, Utc};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::{
    action::user::auth_flow::{
        RefreshSecret, authenticate_with_refresh_token, authentication_result, new_session_token,
        require_refresh_token_auth_flow,
    },
    error::{AppError, Result},
    jwt::TokenSession,
    storage::Storage,
    types::{ClientId, RefreshToken, RefreshTokenRotationFeature},
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
    let req: Request = crate::action::io::parse_request(body)?;

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

    let (user, stored_token) = authenticate_with_refresh_token(
        storage,
        &client,
        &req.refresh_token,
        RefreshSecret::Verified,
    )
    .await?;

    // With refresh token rotation, every exchange hands out a new refresh
    // token and the presented one stops working once the grace period ends.
    let rotation = client
        .refresh_token_rotation
        .as_ref()
        .filter(|rotation| rotation.feature == Some(RefreshTokenRotationFeature::Enabled));
    let rotated = match rotation {
        Some(rotation) => {
            let grace =
                Duration::seconds(i64::from(rotation.retry_grace_period_seconds.unwrap_or(0)));
            let replacement = new_session_token();
            storage
                .save_refresh_token(RefreshToken {
                    token: replacement.clone(),
                    ..stored_token.clone()
                })
                .await;
            let retired_at = Utc::now() + grace;
            if retired_at < stored_token.expires_at {
                storage
                    .save_refresh_token(RefreshToken {
                        expires_at: retired_at,
                        ..stored_token.clone()
                    })
                    .await;
            }
            Some(replacement)
        }
        None => None,
    };

    let session = TokenSession::resumed(stored_token.origin_jti.clone(), stored_token.auth_time);
    let authentication_result =
        authentication_result(storage, &client, &user, &session, rotated).await?;

    Ok(json!({
        "AuthenticationResult": authentication_result,
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
                "ExplicitAuthFlows": ["ALLOW_USER_PASSWORD_AUTH", "ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_USER_SRP_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
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
            json!({"UserPoolId": pool_id, "ClientName": "test-client", "ExplicitAuthFlows": ["ALLOW_USER_PASSWORD_AUTH", "ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_USER_SRP_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"]}),
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
