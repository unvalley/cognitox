//! RevokeToken API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_RevokeToken.html>

use serde::Deserialize;
use serde_json::{Value, json};

use crate::{
    error::{AppError, Result},
    storage::Storage,
    types::ClientId,
};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Request {
    token: String,
    client_id: ClientId,
    #[serde(default)]
    client_secret: Option<String>,
}

pub async fn handler(storage: &Storage, body: Value) -> Result<Value> {
    let req: Request = serde_json::from_value(body)
        .map_err(|e| AppError::InvalidParameter(format!("Invalid request: {}", e)))?;

    // Verify the client exists
    let client = storage
        .get_user_pool_client(&req.client_id)
        .await
        .ok_or(AppError::UserPoolClientNotFound)?;

    // If client has a secret, verify it
    if let Some(ref client_secret) = client.client_secret {
        match &req.client_secret {
            Some(provided_secret) if provided_secret == client_secret => {}
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

    // Get and validate the refresh token
    let refresh_token = storage
        .get_refresh_token(&req.token)
        .await
        .ok_or(AppError::InvalidRefreshToken)?;

    // Verify the token belongs to this client
    if refresh_token.client_id != req.client_id {
        return Err(AppError::InvalidRefreshToken);
    }

    // Delete the refresh token
    storage.delete_refresh_token(&req.token).await;
    storage
        .invalidate_access_tokens_for_user(&refresh_token.user_id)
        .await;

    Ok(json!({}))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    use crate::action::user::{initiate_auth, sign_up};
    use crate::action::user_pool::{create_user_pool, create_user_pool_client};

    async fn setup_pool_and_client(storage: &Storage) -> (String, String) {
        let pool = create_user_pool::handler(storage, json!({"PoolName": "test"}))
            .await
            .unwrap();
        let pool_id = pool["UserPool"]["Id"].as_str().unwrap().to_string();

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

        (pool_id, client_id)
    }

    async fn create_confirmed_user_and_get_tokens(
        storage: &Storage,
        client_id: &str,
        username: &str,
        password: &str,
    ) -> (String, String) {
        let sign_up_result = sign_up::handler(
            storage,
            json!({
                "ClientId": client_id,
                "Username": username,
                "Password": password
            }),
        )
        .await
        .unwrap();

        let user_sub = sign_up_result["UserSub"].as_str().unwrap();
        let user_id = uuid::Uuid::parse_str(user_sub).unwrap();
        storage.confirm_user(&user_id).await;

        let auth_result = initiate_auth::handler(
            storage,
            json!({
                "ClientId": client_id,
                "AuthFlow": "USER_PASSWORD_AUTH",
                "AuthParameters": {
                    "USERNAME": username,
                    "PASSWORD": password
                }
            }),
        )
        .await
        .unwrap();

        let access_token = auth_result["AuthenticationResult"]["AccessToken"]
            .as_str()
            .unwrap()
            .to_string();
        let refresh_token = auth_result["AuthenticationResult"]["RefreshToken"]
            .as_str()
            .unwrap()
            .to_string();

        (access_token, refresh_token)
    }

    #[tokio::test]
    async fn test_revoke_token_success() {
        let storage = Storage::new();
        let (_pool_id, client_id) = setup_pool_and_client(&storage).await;

        let (_access_token, refresh_token) =
            create_confirmed_user_and_get_tokens(&storage, &client_id, "testuser", "Password123!")
                .await;

        // Verify refresh token exists
        assert!(storage.get_refresh_token(&refresh_token).await.is_some());

        let result = handler(
            &storage,
            json!({
                "Token": refresh_token,
                "ClientId": client_id
            }),
        )
        .await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), json!({}));

        // Verify refresh token was deleted
        assert!(storage.get_refresh_token(&refresh_token).await.is_none());
    }

    #[tokio::test]
    async fn test_revoke_token_invalid_token() {
        let storage = Storage::new();
        let (_pool_id, client_id) = setup_pool_and_client(&storage).await;

        let result = handler(
            &storage,
            json!({
                "Token": "invalid-refresh-token",
                "ClientId": client_id
            }),
        )
        .await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AppError::InvalidRefreshToken));
    }

    #[tokio::test]
    async fn test_revoke_token_client_not_found() {
        let storage = Storage::new();

        let result = handler(
            &storage,
            json!({
                "Token": "some-token",
                "ClientId": "nonexistent-client-id"
            }),
        )
        .await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            AppError::UserPoolClientNotFound
        ));
    }
}
