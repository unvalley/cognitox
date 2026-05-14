//! DeleteUser API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_DeleteUser.html>

use serde::Deserialize;
use serde_json::{Value, json};

use crate::{
    error::{AppError, Result},
    storage::Storage,
};

use super::helpers::verify_and_extract_active_user_id;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Request {
    access_token: String,
}

pub async fn handler(storage: &Storage, body: Value) -> Result<Value> {
    let req: Request = serde_json::from_value(body)
        .map_err(|e| AppError::InvalidParameter(format!("Invalid request: {}", e)))?;

    let user_id = verify_and_extract_active_user_id(storage, &req.access_token)
        .await
        .map_err(|_| AppError::InvalidAccessToken)?;

    storage
        .delete_user(&user_id)
        .await
        .ok_or(AppError::UserNotFound)?;
    storage.delete_refresh_tokens_for_user(&user_id).await;

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

    async fn create_confirmed_user_and_get_token(
        storage: &Storage,
        client_id: &str,
        username: &str,
        password: &str,
    ) -> (String, uuid::Uuid) {
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

        (access_token, user_id)
    }

    #[tokio::test]
    async fn test_delete_user_success() {
        let storage = Storage::new();
        let (_pool_id, client_id) = setup_pool_and_client(&storage).await;

        let (access_token, user_id) =
            create_confirmed_user_and_get_token(&storage, &client_id, "testuser", "Password123!")
                .await;

        // Verify user exists
        assert!(storage.get_user(&user_id).await.is_some());

        let result = handler(
            &storage,
            json!({
                "AccessToken": access_token
            }),
        )
        .await;

        assert!(result.is_ok());

        // Verify user was deleted
        assert!(storage.get_user(&user_id).await.is_none());
    }

    #[tokio::test]
    async fn test_delete_user_invalid_token() {
        let storage = Storage::new();

        let result = handler(
            &storage,
            json!({
                "AccessToken": "invalid-token"
            }),
        )
        .await;

        assert!(result.is_err());
    }
}
