//! ResendConfirmationCode API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_ResendConfirmationCode.html>

use chrono::{Duration, Utc};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::{
    action::io::parse_request,
    error::{AppError, Result},
    storage::Storage,
    types::{ClientId, ConfirmationCode, UserStatus},
    validation::validate_username,
};

use super::helpers::{
    generate_confirmation_code, require_code_delivery_details, verify_secret_hash,
};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Request {
    client_id: ClientId,
    username: String,
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
    let req: Request = parse_request(body)?;
    let _ = (
        &req.analytics_metadata,
        &req.client_metadata,
        &req.secret_hash,
        &req.user_context_data,
    );

    validate_username(&req.username)?;

    let client = storage
        .get_user_pool_client(&req.client_id)
        .await
        .ok_or(AppError::UserPoolClientNotFound)?;
    verify_secret_hash(&client, &req.username, req.secret_hash.as_deref())?;

    let user = storage
        .get_user_by_username(&client.user_pool_id, &req.username)
        .await
        .ok_or(AppError::UserNotFound)?;

    if user.user_status == UserStatus::Confirmed {
        return Err(AppError::NotAuthorized(
            "User cannot be resent a confirmation code. Current status is CONFIRMED".to_string(),
        ));
    }

    let code_delivery_details = require_code_delivery_details(&user)?;

    let code = generate_confirmation_code();
    let confirmation = ConfirmationCode {
        user_id: user.id,
        code: code.clone(),
        expires_at: Utc::now() + Duration::hours(24),
    };
    storage.save_confirmation_code(confirmation).await;

    tracing::info!("Resend confirmation code for {}: {}", req.username, code);

    Ok(json!({
        "CodeDeliveryDetails": code_delivery_details
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    use crate::action::user::sign_up;
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
    async fn test_resend_confirmation_code_success() {
        let storage = Storage::new();
        let (_pool_id, client_id) = setup_pool_and_client(&storage).await;

        // Sign up a user
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

        // Get original confirmation code
        let original_code = storage.get_confirmation_code(&user_id).await.unwrap();

        // Resend confirmation code
        let result = handler(
            &storage,
            json!({
                "ClientId": client_id,
                "Username": "testuser"
            }),
        )
        .await;

        assert!(result.is_ok());
        let body = result.unwrap();
        assert!(
            body["CodeDeliveryDetails"]["Destination"]
                .as_str()
                .unwrap()
                .contains("***")
        );

        // Verify new confirmation code was generated
        let new_code = storage.get_confirmation_code(&user_id).await.unwrap();
        assert_ne!(original_code.code, new_code.code);
    }

    #[tokio::test]
    async fn test_resend_confirmation_code_user_not_found() {
        let storage = Storage::new();
        let (_pool_id, client_id) = setup_pool_and_client(&storage).await;

        let result = handler(
            &storage,
            json!({
                "ClientId": client_id,
                "Username": "nonexistent"
            }),
        )
        .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_resend_confirmation_code_invalid_client() {
        let storage = Storage::new();

        let result = handler(
            &storage,
            json!({
                "ClientId": "invalid-client-id",
                "Username": "testuser"
            }),
        )
        .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_resend_confirmation_code_rejects_confirmed_user() {
        let storage = Storage::new();
        let (_pool_id, client_id) = setup_pool_and_client(&storage).await;

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

        let result = handler(
            &storage,
            json!({
                "ClientId": client_id,
                "Username": "testuser"
            }),
        )
        .await;

        assert!(matches!(result, Err(AppError::NotAuthorized(_))));
    }

    #[tokio::test]
    async fn test_resend_confirmation_code_uses_sms_when_phone_number_is_only_delivery_target() {
        let storage = Storage::new();
        let (_pool_id, client_id) = setup_pool_and_client(&storage).await;

        sign_up::handler(
            &storage,
            json!({
                "ClientId": client_id,
                "Username": "smsuser",
                "Password": "Password123!",
                "UserAttributes": [
                    {"Name": "phone_number", "Value": "+15555550100"}
                ]
            }),
        )
        .await
        .unwrap();

        let result = handler(
            &storage,
            json!({
                "ClientId": client_id,
                "Username": "smsuser"
            }),
        )
        .await
        .unwrap();

        assert_eq!(
            result["CodeDeliveryDetails"]["AttributeName"],
            "phone_number"
        );
        assert_eq!(result["CodeDeliveryDetails"]["DeliveryMedium"], "SMS");
    }
}
