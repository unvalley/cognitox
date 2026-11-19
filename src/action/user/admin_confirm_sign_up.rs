//! AdminConfirmSignUp API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AdminConfirmSignUp.html>

use std::collections::HashMap;

use chrono::Utc;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::{
    error::{AppError, Result},
    storage::Storage,
    types::{UserPoolId, UserStatus},
};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Request {
    user_pool_id: UserPoolId,
    username: String,
    client_metadata: Option<HashMap<String, String>>,
}

pub async fn handler(storage: &Storage, body: Value) -> Result<Value> {
    let req: Request = crate::action::io::parse_request(body)?;
    let _ = &req.client_metadata;

    storage
        .get_user_pool(&req.user_pool_id)
        .await
        .ok_or(AppError::UserPoolNotFound)?;

    let mut user = storage
        .get_user_by_username(&req.user_pool_id, &req.username)
        .await
        .ok_or(AppError::UserNotFound)?;

    // Only a self-registered user who has not confirmed yet can be
    // confirmed.
    if user.user_status != UserStatus::Unconfirmed {
        let status = json!(user.user_status);
        return Err(AppError::NotAuthorized(format!(
            "User cannot be confirmed. Current status is {}",
            status.as_str().unwrap_or_default()
        )));
    }

    let user_id = user.id;
    user.user_status = UserStatus::Confirmed;
    user.last_modified_date = Utc::now();

    storage.update_user(user).await;
    storage.delete_confirmation_code(&user_id).await;

    Ok(json!({}))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::user::admin_create_user;
    use crate::action::user_pool::create_user_pool;
    use serde_json::json;

    #[tokio::test]
    async fn test_admin_confirm_sign_up_success() {
        let storage = Storage::new();

        let pool = create_user_pool::handler(&storage, json!({"PoolName": "test"}))
            .await
            .unwrap();
        let pool_id = pool["UserPool"]["Id"].as_str().unwrap();

        // A user who registered themselves and has not confirmed yet.
        let client = crate::action::user_pool::create_user_pool_client::handler(
            &storage,
            json!({"UserPoolId": pool_id, "ClientName": "test-client"}),
        )
        .await
        .unwrap();
        crate::action::user::sign_up::handler(
            &storage,
            json!({
                "ClientId": client["UserPoolClient"]["ClientId"],
                "Username": "testuser",
                "Password": "Password123!"
            }),
        )
        .await
        .unwrap();

        // Confirm the user
        let result = handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "Username": "testuser"
            }),
        )
        .await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), json!({}));

        // Verify user status is confirmed
        let pool_id_typed: UserPoolId = pool_id.parse().unwrap();
        let user = storage
            .get_user_by_username(&pool_id_typed, "testuser")
            .await
            .unwrap();
        assert_eq!(user.user_status, UserStatus::Confirmed);

        // Confirming twice is refused.
        let result = handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "Username": "testuser"
            }),
        )
        .await;
        assert!(matches!(
            result,
            Err(AppError::NotAuthorized(message))
                if message == "User cannot be confirmed. Current status is CONFIRMED"
        ));
    }

    #[tokio::test]
    async fn test_admin_confirm_sign_up_does_not_skip_a_temporary_password() {
        let storage = Storage::new();

        let pool = create_user_pool::handler(&storage, json!({"PoolName": "test"}))
            .await
            .unwrap();
        let pool_id = pool["UserPool"]["Id"].as_str().unwrap();
        admin_create_user::handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "Username": "invited"
            }),
        )
        .await
        .unwrap();

        let result = handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "Username": "invited"
            }),
        )
        .await;
        assert!(matches!(
            result,
            Err(AppError::NotAuthorized(message))
                if message == "User cannot be confirmed. Current status is FORCE_CHANGE_PASSWORD"
        ));
    }

    #[tokio::test]
    async fn test_admin_confirm_sign_up_user_not_found() {
        let storage = Storage::new();

        let pool = create_user_pool::handler(&storage, json!({"PoolName": "test"}))
            .await
            .unwrap();
        let pool_id = pool["UserPool"]["Id"].as_str().unwrap();

        let result = handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "Username": "nonexistent"
            }),
        )
        .await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AppError::UserNotFound));
    }

    #[tokio::test]
    async fn test_admin_confirm_sign_up_pool_not_found() {
        let storage = Storage::new();

        let result = handler(
            &storage,
            json!({
                "UserPoolId": "local_nonexistent",
                "Username": "testuser"
            }),
        )
        .await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AppError::UserPoolNotFound));
    }
}
