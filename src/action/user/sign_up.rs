//! SignUp API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_SignUp.html>

use std::collections::HashMap;

use chrono::{Duration, Utc};
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::{
    error::{AppError, Result},
    storage::Storage,
    types::{ClientId, ConfirmationCode, User, UserAttribute, UserStatus},
    validation::{validate_email, validate_password, validate_phone_number, validate_username},
};

use super::helpers::{
    build_code_delivery_details, find_user_attribute_value, generate_confirmation_code,
    hash_password,
};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct AnalyticsMetadata {
    analytics_endpoint_id: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct UserContextData {
    encoded_data: Option<String>,
    ip_address: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Request {
    client_id: ClientId,
    username: String,
    password: String,
    user_attributes: Option<Vec<UserAttribute>>,
    validation_data: Option<Vec<UserAttribute>>,
    secret_hash: Option<String>,
    user_context_data: Option<UserContextData>,
    analytics_metadata: Option<AnalyticsMetadata>,
    client_metadata: Option<HashMap<String, String>>,
}

pub async fn handler(storage: &Storage, body: Value) -> Result<Value> {
    let req: Request = serde_json::from_value(body)
        .map_err(|e| AppError::InvalidParameter(format!("Invalid request: {}", e)))?;
    let _ = (
        &req.validation_data,
        &req.secret_hash,
        &req.client_metadata,
        req.user_context_data
            .as_ref()
            .map(|ctx| (&ctx.encoded_data, &ctx.ip_address)),
        req.analytics_metadata
            .as_ref()
            .map(|meta| &meta.analytics_endpoint_id),
    );

    // Validate input
    validate_username(&req.username)?;
    validate_password(&req.password)?;

    if let Some(email) = req
        .user_attributes
        .as_ref()
        .and_then(|attrs| find_user_attribute_value(attrs, "email"))
    {
        validate_email(&email)?;
    }
    if let Some(phone_number) = req
        .user_attributes
        .as_ref()
        .and_then(|attrs| find_user_attribute_value(attrs, "phone_number"))
    {
        validate_phone_number(&phone_number)?;
    }

    let client = storage
        .get_user_pool_client(&req.client_id)
        .await
        .ok_or(AppError::UserPoolClientNotFound)?;

    if storage
        .get_user_by_username(&client.user_pool_id, &req.username)
        .await
        .is_some()
    {
        return Err(AppError::UserAlreadyExists);
    }

    let now = Utc::now();
    let user_id = Uuid::new_v4();

    let email = req
        .user_attributes
        .as_ref()
        .and_then(|attrs| find_user_attribute_value(attrs, "email"));
    let phone_number = req
        .user_attributes
        .as_ref()
        .and_then(|attrs| find_user_attribute_value(attrs, "phone_number"));

    let user = User {
        id: user_id,
        user_pool_id: client.user_pool_id.clone(),
        username: req.username.clone(),
        email: email.clone(),
        phone_number: phone_number.clone(),
        password_hash: hash_password(&req.password).map_err(AppError::Internal)?,
        enabled: true,
        user_status: UserStatus::Unconfirmed,
        attributes: req.user_attributes.unwrap_or_default(),
        creation_date: now,
        last_modified_date: now,
    };

    storage.create_user(user).await;

    let code = generate_confirmation_code();
    let confirmation = ConfirmationCode {
        user_id,
        code: code.clone(),
        expires_at: now + Duration::hours(24),
    };
    storage.save_confirmation_code(confirmation).await;

    tracing::info!("SignUp confirmation code for {}: {}", req.username, code);

    let code_delivery_details =
        build_code_delivery_details(email.as_deref(), phone_number.as_deref()).unwrap_or_else(
            || {
                json!({
                    "Destination": "",
                    "DeliveryMedium": "EMAIL",
                    "AttributeName": "email"
                })
            },
        );

    Ok(json!({
        "UserConfirmed": false,
        "UserSub": user_id.to_string(),
        "Session": null,
        "CodeDeliveryDetails": code_delivery_details
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

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
    async fn test_sign_up_success() {
        let storage = Storage::new();
        let (pool_id, client_id) = setup_pool_and_client(&storage).await;

        let result = handler(
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
        .await;

        assert!(result.is_ok());
        let body = result.unwrap();
        assert_eq!(body["UserConfirmed"], false);
        assert!(body["UserSub"].as_str().is_some());
        assert!(
            body["CodeDeliveryDetails"]["Destination"]
                .as_str()
                .unwrap()
                .contains("***")
        );

        let pool_id = UserPoolId::new(pool_id).unwrap();
        let user = storage
            .get_user_by_username(&pool_id, "testuser")
            .await
            .unwrap();
        assert_eq!(user.email.as_deref(), Some("test@example.com"));
    }

    #[tokio::test]
    async fn test_sign_up_persists_phone_number() {
        let storage = Storage::new();
        let (pool_id, client_id) = setup_pool_and_client(&storage).await;

        let result = handler(
            &storage,
            json!({
                "ClientId": client_id,
                "Username": "phoneuser",
                "Password": "Password123!",
                "UserAttributes": [
                    {"Name": "phone_number", "Value": "+15555550100"}
                ]
            }),
        )
        .await
        .unwrap();

        assert_eq!(
            result["CodeDeliveryDetails"]["AttributeName"],
            "phone_number"
        );
        assert_eq!(result["CodeDeliveryDetails"]["DeliveryMedium"], "SMS");

        let pool_id = UserPoolId::new(pool_id).unwrap();
        let user = storage
            .get_user_by_username(&pool_id, "phoneuser")
            .await
            .unwrap();
        assert_eq!(user.phone_number.as_deref(), Some("+15555550100"));
    }

    #[tokio::test]
    async fn test_sign_up_user_already_exists() {
        let storage = Storage::new();
        let (_pool_id, client_id) = setup_pool_and_client(&storage).await;

        // First sign up
        handler(
            &storage,
            json!({
                "ClientId": client_id,
                "Username": "testuser",
                "Password": "Password123!"
            }),
        )
        .await
        .unwrap();

        // Second sign up with same username
        let result = handler(
            &storage,
            json!({
                "ClientId": client_id,
                "Username": "testuser",
                "Password": "Password456!"
            }),
        )
        .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_sign_up_invalid_client() {
        let storage = Storage::new();

        let result = handler(
            &storage,
            json!({
                "ClientId": "invalid-client-id",
                "Username": "testuser",
                "Password": "Password123!"
            }),
        )
        .await;

        assert!(result.is_err());
    }
}
