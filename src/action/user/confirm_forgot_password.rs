//! ConfirmForgotPassword API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_ConfirmForgotPassword.html>

use chrono::Utc;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::{
    error::{AppError, Result},
    storage::Storage,
    types::ClientId,
    validation::validate_password,
};

use super::helpers::{hash_password, normalize_confirmation_code};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Request {
    client_id: ClientId,
    username: String,
    confirmation_code: String,
    password: String,
    #[serde(default)]
    analytics_metadata: Option<Value>,
    #[serde(default)]
    client_metadata: Option<std::collections::HashMap<String, String>>,
    #[serde(default)]
    secret_hash: Option<String>,
    #[serde(default)]
    user_context_data: Option<Value>,
}

pub async fn handler(storage: &Storage, body: Value) -> Result<Value> {
    let req: Request = serde_json::from_value(body)
        .map_err(|e| AppError::InvalidParameter(format!("Invalid request: {}", e)))?;
    let _ = (
        &req.analytics_metadata,
        &req.client_metadata,
        &req.secret_hash,
        &req.user_context_data,
    );

    // Validate new password
    validate_password(&req.password)?;

    let client = storage
        .get_user_pool_client(&req.client_id)
        .await
        .ok_or(AppError::UserPoolClientNotFound)?;

    let mut user = storage
        .get_user_by_username(&client.user_pool_id, &req.username)
        .await
        .ok_or(AppError::UserNotFound)?;

    let reset_code = storage
        .get_password_reset_code(&user.id)
        .await
        .ok_or(AppError::InvalidConfirmationCode)?;

    // Normalize codes for comparison (removes dashes, converts to uppercase)
    if normalize_confirmation_code(&reset_code.code)
        != normalize_confirmation_code(&req.confirmation_code)
    {
        return Err(AppError::InvalidConfirmationCode);
    }

    if reset_code.expires_at < Utc::now() {
        storage.delete_password_reset_code(&user.id).await;
        return Err(AppError::ExpiredCode);
    }

    user.password_hash = hash_password(&req.password).map_err(AppError::Internal)?;
    user.last_modified_date = Utc::now();

    storage.update_user(user.clone()).await;
    storage.delete_password_reset_code(&user.id).await;

    Ok(json!({}))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    use crate::action::user::{forgot_password, initiate_auth, sign_up};
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

    #[tokio::test]
    async fn test_confirm_forgot_password_success() {
        let storage = Storage::new();
        let (_pool_id, client_id) = setup_pool_and_client(&storage).await;

        // Sign up and confirm a user
        let sign_up_result = sign_up::handler(
            &storage,
            json!({
                "ClientId": client_id,
                "Username": "testuser",
                "Password": "Password123!",
                "UserAttributes": [
                    {"Name": "email", "Value": "test@example.com"}
                ]
            }),
        )
        .await
        .unwrap();

        let user_sub = sign_up_result["UserSub"].as_str().unwrap();
        let user_id = uuid::Uuid::parse_str(user_sub).unwrap();
        storage.confirm_user(&user_id).await;

        // Request password reset
        forgot_password::handler(
            &storage,
            json!({
                "ClientId": client_id,
                "Username": "testuser"
            }),
        )
        .await
        .unwrap();

        // Get the reset code
        let reset_code = storage.get_password_reset_code(&user_id).await.unwrap();

        // Confirm password reset
        let result = handler(
            &storage,
            json!({
                "ClientId": client_id,
                "Username": "testuser",
                "ConfirmationCode": reset_code.code,
                "Password": "NewPassword456!"
            }),
        )
        .await;

        assert!(result.is_ok());

        // Verify new password works
        let auth_result = initiate_auth::handler(
            &storage,
            json!({
                "ClientId": client_id,
                "AuthFlow": "USER_PASSWORD_AUTH",
                "AuthParameters": {
                    "USERNAME": "testuser",
                    "PASSWORD": "NewPassword456!"
                }
            }),
        )
        .await;

        assert!(auth_result.is_ok());
    }

    #[tokio::test]
    async fn test_confirm_forgot_password_invalid_code() {
        let storage = Storage::new();
        let (_pool_id, client_id) = setup_pool_and_client(&storage).await;

        // Sign up and confirm a user
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
        storage.confirm_user(&user_id).await;

        // Request password reset
        forgot_password::handler(
            &storage,
            json!({
                "ClientId": client_id,
                "Username": "testuser"
            }),
        )
        .await
        .unwrap();

        // Try to confirm with wrong code
        let result = handler(
            &storage,
            json!({
                "ClientId": client_id,
                "Username": "testuser",
                "ConfirmationCode": "WRONG-CODE",
                "Password": "NewPassword456!"
            }),
        )
        .await;

        assert!(result.is_err());
    }
}
