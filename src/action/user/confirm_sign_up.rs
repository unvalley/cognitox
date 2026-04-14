//! ConfirmSignUp API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_ConfirmSignUp.html>

use chrono::Utc;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::{
    error::{AppError, Result},
    storage::Storage,
    types::{ClientId, UserStatus},
};

use super::helpers::normalize_confirmation_code;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Request {
    client_id: ClientId,
    username: String,
    confirmation_code: String,
    #[serde(default)]
    analytics_metadata: Option<Value>,
    #[serde(default)]
    client_metadata: Option<std::collections::HashMap<String, String>>,
    #[serde(default)]
    force_alias_creation: Option<bool>,
    #[serde(default)]
    secret_hash: Option<String>,
    #[serde(default)]
    session: Option<String>,
    #[serde(default)]
    user_context_data: Option<Value>,
}

pub async fn handler(storage: &Storage, body: Value) -> Result<Value> {
    let req: Request = serde_json::from_value(body)
        .map_err(|e| AppError::InvalidParameter(format!("Invalid request: {}", e)))?;
    let _ = (
        &req.analytics_metadata,
        &req.client_metadata,
        &req.force_alias_creation,
        &req.secret_hash,
        &req.user_context_data,
    );

    let client = storage
        .get_user_pool_client(&req.client_id)
        .await
        .ok_or(AppError::UserPoolClientNotFound)?;

    let mut user = storage
        .get_user_by_username(&client.user_pool_id, &req.username)
        .await
        .ok_or(AppError::UserNotFound)?;

    let confirmation = storage
        .get_confirmation_code(&user.id)
        .await
        .ok_or(AppError::InvalidConfirmationCode)?;

    // Normalize codes for comparison (removes dashes, converts to uppercase)
    if normalize_confirmation_code(&confirmation.code)
        != normalize_confirmation_code(&req.confirmation_code)
    {
        return Err(AppError::InvalidConfirmationCode);
    }

    if confirmation.expires_at < Utc::now() {
        return Err(AppError::InvalidConfirmationCode);
    }

    user.user_status = UserStatus::Confirmed;
    user.last_modified_date = Utc::now();
    storage.update_user(user).await;
    storage
        .delete_confirmation_code(&confirmation.user_id)
        .await;

    Ok(json!({
        "Session": req.session
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    use crate::action::user::sign_up;
    use crate::action::user_pool::{create_user_pool, create_user_pool_client};
    use crate::types::UserPoolId;

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

    #[tokio::test]
    async fn test_confirm_sign_up_success() {
        let storage = Storage::new();
        let (pool_id, client_id) = setup_pool_and_client(&storage).await;

        // Sign up a user first
        let sign_up_result = sign_up::handler(
            &storage,
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

        // Get the confirmation code from storage
        let confirmation = storage.get_confirmation_code(&user_id).await.unwrap();

        let result = handler(
            &storage,
            json!({
                "ClientId": client_id,
                "Username": "testuser",
                "ConfirmationCode": confirmation.code
            }),
        )
        .await;

        assert!(result.is_ok());

        // Verify user is confirmed
        let pool_id_typed: UserPoolId = pool_id.parse().unwrap();
        let user = storage
            .get_user_by_username(&pool_id_typed, "testuser")
            .await
            .unwrap();
        assert_eq!(user.user_status, UserStatus::Confirmed);
    }

    #[tokio::test]
    async fn test_confirm_sign_up_invalid_code() {
        let storage = Storage::new();
        let (_pool_id, client_id) = setup_pool_and_client(&storage).await;

        // Sign up a user first
        sign_up::handler(
            &storage,
            json!({
                "ClientId": client_id,
                "Username": "testuser",
                "Password": "Password123!"
            }),
        )
        .await
        .unwrap();

        let result = handler(
            &storage,
            json!({
                "ClientId": client_id,
                "Username": "testuser",
                "ConfirmationCode": "WRONG-CODE-HERE"
            }),
        )
        .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_confirm_sign_up_user_not_found() {
        let storage = Storage::new();
        let (_pool_id, client_id) = setup_pool_and_client(&storage).await;

        let result = handler(
            &storage,
            json!({
                "ClientId": client_id,
                "Username": "nonexistent",
                "ConfirmationCode": "123456"
            }),
        )
        .await;

        assert!(result.is_err());
    }
}
