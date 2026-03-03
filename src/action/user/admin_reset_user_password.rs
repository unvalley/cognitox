//! AdminResetUserPassword API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AdminResetUserPassword.html>

use chrono::{Duration, Utc};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::HashMap;

use crate::{
    error::{AppError, Result},
    storage::Storage,
    types::{PasswordResetCode, UserPoolId, UserStatus},
};

use super::helpers::{generate_confirmation_code, mask_email};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Request {
    user_pool_id: UserPoolId,
    username: String,
    #[allow(dead_code)]
    client_metadata: Option<HashMap<String, String>>,
}

pub async fn handler(storage: &Storage, body: Value) -> Result<Value> {
    let req: Request = serde_json::from_value(body)
        .map_err(|e| AppError::InvalidParameter(format!("Invalid request: {}", e)))?;

    storage
        .get_user_pool(&req.user_pool_id)
        .await
        .ok_or(AppError::UserPoolNotFound)?;

    let mut user = storage
        .get_user_by_username(&req.user_pool_id, &req.username)
        .await
        .ok_or(AppError::UserNotFound)?;

    // Generate password reset code
    let code = generate_confirmation_code();
    let reset_code = PasswordResetCode {
        user_id: user.id,
        code: code.clone(),
        expires_at: Utc::now() + Duration::hours(1),
    };

    storage.save_password_reset_code(reset_code).await;

    // Update user status to RESET_REQUIRED
    user.user_status = UserStatus::ResetRequired;
    user.last_modified_date = Utc::now();
    storage.update_user(user.clone()).await;

    // Return code delivery details (in real implementation, would send email/SMS)
    let destination = user.email.as_deref().map(mask_email);
    let delivery_medium = if user.email.is_some() { "EMAIL" } else { "SMS" };

    Ok(json!({
        "CodeDeliveryDetails": {
            "AttributeName": "email",
            "DeliveryMedium": delivery_medium,
            "Destination": destination
        }
    }))
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
                "UserAttributes": [
                    {"Name": "email", "Value": "test@example.com"}
                ]
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
        let body = result.unwrap();
        assert_eq!(body["CodeDeliveryDetails"]["DeliveryMedium"], "EMAIL");

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
}
