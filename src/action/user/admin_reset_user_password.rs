//! AdminResetUserPassword API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AdminResetUserPassword.html>

use std::collections::HashMap;

use chrono::{Duration, Utc};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::{
    action::io::parse_request,
    error::{AppError, Result},
    storage::Storage,
    types::{PasswordResetCode, UserPoolId, UserStatus},
    validation::validate_username,
};

use super::helpers::{generate_confirmation_code, recovery_delivery};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Request {
    user_pool_id: UserPoolId,
    username: String,
    client_metadata: Option<HashMap<String, String>>,
}

pub async fn handler(storage: &Storage, body: Value) -> Result<Value> {
    let req: Request = parse_request(body)?;
    let _ = &req.client_metadata;
    validate_username(&req.username)?;

    let pool = storage
        .get_user_pool(&req.user_pool_id)
        .await
        .ok_or(AppError::UserPoolNotFound)?;

    let mut user = storage
        .get_user_by_username(&req.user_pool_id, &req.username)
        .await
        .ok_or(AppError::UserNotFound)?;

    // A temporary password is replaced by resending the invitation, not by
    // a reset.
    if user.user_status == UserStatus::ForceChangePassword {
        return Err(AppError::NotAuthorized(
            "User password cannot be reset in the current state.".to_string(),
        ));
    }

    // The code needs a verified phone number or email address to go to.
    let mfa_factors = storage.list_user_auth_factors(&user.id).await;
    recovery_delivery(&pool, &user, &mfa_factors, false)?;

    let code = generate_confirmation_code();
    let reset_code = PasswordResetCode {
        user_id: user.id,
        code: code.clone(),
        expires_at: Utc::now() + Duration::hours(1),
    };

    storage.save_password_reset_code(reset_code).await;
    tracing::debug!("AdminResetUserPassword code for {}: {}", req.username, code);

    // The current password stops working: sign-in answers
    // PasswordResetRequiredException until ConfirmForgotPassword.
    user.user_status = UserStatus::ResetRequired;
    user.last_modified_date = Utc::now();
    storage.update_user(user.clone()).await;

    Ok(json!({}))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::user::admin_create_user;
    use crate::action::user_pool::create_user_pool;
    use serde_json::json;

    #[tokio::test]
    async fn test_admin_reset_user_password_success() {
        let storage = Storage::new();

        let pool = create_user_pool::handler(&storage, json!({"PoolName": "test"}))
            .await
            .unwrap();
        let pool_id = pool["UserPool"]["Id"].as_str().unwrap();

        admin_create_user::handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "Username": "testuser",
                "TemporaryPassword": "TempPass123!",
                "UserAttributes": [
                    {"Name": "email", "Value": "test@example.com"},
                    {"Name": "email_verified", "Value": "true"}
                ]
            }),
        )
        .await
        .unwrap();

        // A temporary password cannot be reset; the invitation is resent.
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
                if message == "User password cannot be reset in the current state."
        ));

        crate::action::user::admin_set_user_password::handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "Username": "testuser",
                "Password": "Password123!",
                "Permanent": true
            }),
        )
        .await
        .unwrap();

        let result = handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "Username": "testuser"
            }),
        )
        .await;

        assert!(result.is_ok());
        // The response is empty; the code goes to the verified address.
        assert_eq!(result.unwrap(), json!({}));

        // Verify user status changed to RESET_REQUIRED
        let pool_id_typed: UserPoolId = pool_id.parse().unwrap();
        let user = storage
            .get_user_by_username(&pool_id_typed, "testuser")
            .await
            .unwrap();
        assert_eq!(user.user_status, UserStatus::ResetRequired);

        // Verify password reset code was saved
        let reset_code = storage.get_password_reset_code(&user.id).await;
        assert!(reset_code.is_some());
    }

    #[tokio::test]
    async fn test_admin_reset_user_password_user_not_found() {
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
    async fn test_admin_reset_user_password_pool_not_found() {
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

    #[tokio::test]
    async fn test_admin_reset_user_password_needs_a_verified_contact() {
        let storage = Storage::new();

        let pool = create_user_pool::handler(&storage, json!({"PoolName": "test"}))
            .await
            .unwrap();
        let pool_id = pool["UserPool"]["Id"].as_str().unwrap();

        admin_create_user::handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "Username": "testuser",
                "UserAttributes": [
                    {"Name": "email", "Value": "test@example.com"}
                ]
            }),
        )
        .await
        .unwrap();
        crate::action::user::admin_set_user_password::handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "Username": "testuser",
                "Password": "Password123!",
                "Permanent": true
            }),
        )
        .await
        .unwrap();

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
            Err(AppError::InvalidParameter(message))
                if message == "Cannot reset password for the user as there is no registered/verified email or phone_number"
        ));
    }
}
