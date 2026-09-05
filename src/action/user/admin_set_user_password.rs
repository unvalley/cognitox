//! AdminSetUserPassword API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AdminSetUserPassword.html>

use chrono::Utc;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::{
    error::{AppError, Result},
    storage::Storage,
    types::{UserPoolId, UserStatus},
    validation::validate_password,
};

use super::helpers::hash_password;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Request {
    user_pool_id: UserPoolId,
    username: String,
    password: String,
    #[serde(default)]
    permanent: bool,
}

pub async fn handler(storage: &Storage, body: Value) -> Result<Value> {
    let req: Request = serde_json::from_value(body)
        .map_err(|e| AppError::InvalidParameter(format!("Invalid request: {}", e)))?;

    // Validate input
    validate_password(&req.password)?;

    storage
        .get_user_pool(&req.user_pool_id)
        .await
        .ok_or(AppError::UserPoolNotFound)?;

    let mut user = storage
        .get_user_by_username(&req.user_pool_id, &req.username)
        .await
        .ok_or(AppError::UserNotFound)?;

    user.password_hash = hash_password(&req.password).map_err(AppError::Internal)?;
    user.last_modified_date = Utc::now();

    // A permanent password confirms the user whatever their prior status
    // (UNCONFIRMED, RESET_REQUIRED, FORCE_CHANGE_PASSWORD), as in Cognito.
    if req.permanent {
        user.user_status = UserStatus::Confirmed;
    } else {
        user.user_status = UserStatus::ForceChangePassword;
    }
    let user_id = user.id;

    storage.update_user(user).await;
    storage.delete_password_reset_code(&user_id).await;

    Ok(json!({}))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::user::admin_create_user;
    use crate::action::user_pool::create_user_pool;
    use serde_json::json;

    #[tokio::test]
    async fn test_admin_set_user_password_permanent() {
        let storage = Storage::new();

        let pool = create_user_pool::handler(&storage, json!({"PoolName": "test"}))
            .await
            .unwrap();
        let pool_id = pool["UserPool"]["Id"].as_str().unwrap();

        // Create a user first (will have FORCE_CHANGE_PASSWORD status)
        admin_create_user::handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "Username": "testuser"
            }),
        )
        .await
        .unwrap();

        // Set password permanently
        let result = handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "Username": "testuser",
                "Password": "NewPassword123!",
                "Permanent": true
            }),
        )
        .await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), json!({}));

        // Verify user status changed to Confirmed
        let pool_id_typed: UserPoolId = pool_id.parse().unwrap();
        let user = storage
            .get_user_by_username(&pool_id_typed, "testuser")
            .await
            .unwrap();
        assert_eq!(user.user_status, UserStatus::Confirmed);
    }

    #[tokio::test]
    async fn test_admin_set_user_password_temporary() {
        let storage = Storage::new();

        let pool = create_user_pool::handler(&storage, json!({"PoolName": "test"}))
            .await
            .unwrap();
        let pool_id = pool["UserPool"]["Id"].as_str().unwrap();

        // Create a user first
        admin_create_user::handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "Username": "testuser"
            }),
        )
        .await
        .unwrap();

        // Set password temporarily (Permanent: false or not specified)
        let result = handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "Username": "testuser",
                "Password": "NewPassword123!"
            }),
        )
        .await;

        assert!(result.is_ok());

        // Verify user status is still FORCE_CHANGE_PASSWORD
        let pool_id_typed: UserPoolId = pool_id.parse().unwrap();
        let user = storage
            .get_user_by_username(&pool_id_typed, "testuser")
            .await
            .unwrap();
        assert_eq!(user.user_status, UserStatus::ForceChangePassword);
    }

    #[tokio::test]
    async fn test_admin_set_user_password_user_not_found() {
        let storage = Storage::new();

        let pool = create_user_pool::handler(&storage, json!({"PoolName": "test"}))
            .await
            .unwrap();
        let pool_id = pool["UserPool"]["Id"].as_str().unwrap();

        let result = handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "Username": "nonexistent",
                "Password": "NewPassword123!"
            }),
        )
        .await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AppError::UserNotFound));
    }

    #[tokio::test]
    async fn test_admin_set_user_password_permanent_confirms_any_status() {
        use crate::action::user::{admin_reset_user_password, sign_up};
        use crate::action::user_pool::create_user_pool_client;

        let storage = Storage::new();
        let pool = create_user_pool::handler(&storage, json!({"PoolName": "test"}))
            .await
            .unwrap();
        let pool_id = pool["UserPool"]["Id"].as_str().unwrap();
        let client = create_user_pool_client::handler(
            &storage,
            json!({ "UserPoolId": pool_id, "ClientName": "c" }),
        )
        .await
        .unwrap();
        let client_id = client["UserPoolClient"]["ClientId"].as_str().unwrap();

        // UNCONFIRMED via SignUp.
        sign_up::handler(
            &storage,
            json!({
                "ClientId": client_id,
                "Username": "pending",
                "Password": "Password123!",
                "UserAttributes": [{"Name": "email", "Value": "p@example.com"}]
            }),
        )
        .await
        .unwrap();
        handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "Username": "pending",
                "Password": "Another123!",
                "Permanent": true
            }),
        )
        .await
        .unwrap();
        let pool_id_typed: UserPoolId = pool_id.parse().unwrap();
        let user = storage
            .get_user_by_username(&pool_id_typed, "pending")
            .await
            .unwrap();
        assert_eq!(user.user_status, UserStatus::Confirmed);

        // RESET_REQUIRED via AdminResetUserPassword; the pending reset code
        // is dropped along with the status.
        admin_reset_user_password::handler(
            &storage,
            json!({ "UserPoolId": pool_id, "Username": "pending" }),
        )
        .await
        .unwrap();
        assert!(storage.get_password_reset_code(&user.id).await.is_some());
        handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "Username": "pending",
                "Password": "Third1234!",
                "Permanent": true
            }),
        )
        .await
        .unwrap();
        let user = storage.get_user(&user.id).await.unwrap();
        assert_eq!(user.user_status, UserStatus::Confirmed);
        assert!(storage.get_password_reset_code(&user.id).await.is_none());
    }
}
