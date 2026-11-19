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
    validation::validate_password_against_policy,
};

use super::helpers::set_user_password;

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
    let req: Request = crate::action::io::parse_request(body)?;

    let pool = storage
        .get_user_pool(&req.user_pool_id)
        .await
        .ok_or(AppError::UserPoolNotFound)?;
    validate_password_against_policy(&pool, &req.password)?;

    let mut user = storage
        .get_user_by_username(&req.user_pool_id, &req.username)
        .await
        .ok_or(AppError::UserNotFound)?;

    set_user_password(&mut user, &req.password)?;
    user.last_modified_date = Utc::now();

    // A permanent password leaves the user ready to sign in, whatever state
    // the account was in; a temporary one has to be replaced at sign-in.
    user.user_status = if req.permanent {
        UserStatus::Confirmed
    } else {
        UserStatus::ForceChangePassword
    };

    storage.update_user(user).await;

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
}
