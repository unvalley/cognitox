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
    hash_password, sync_user_profile_attributes, verify_secret_hash,
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
    verify_secret_hash(&client, &req.username, req.secret_hash.as_deref())?;

    let admin_only = storage
        .with_user_pool(&client.user_pool_id, |pool| {
            pool.admin_create_user_config
                .as_ref()
                .and_then(|config| config.allow_admin_create_user_only)
                .unwrap_or(false)
        })
        .await
        .ok_or(AppError::UserPoolNotFound)?;
    if admin_only {
        return Err(AppError::NotAuthorized(
            "SignUp is not permitted for this user pool".to_string(),
        ));
    }

    if storage
        .get_user_by_username(&client.user_pool_id, &req.username)
        .await
        .is_some()
    {
        return Err(AppError::UserAlreadyExists);
    }

    let now = Utc::now();
    let user_id = Uuid::new_v4();

    let mut user = User {
        id: user_id,
        user_pool_id: client.user_pool_id.clone(),
        username: req.username.clone(),
        email: None,
        phone_number: None,
        password_hash: hash_password(&req.password).map_err(AppError::Internal)?,
        enabled: true,
        user_status: UserStatus::Unconfirmed,
        attributes: req.user_attributes.unwrap_or_default(),
        creation_date: now,
        last_modified_date: now,
    };
    sync_user_profile_attributes(&mut user);

    let email = user.email.clone();
    let phone_number = user.phone_number.clone();

    storage
        .try_create_user(user)
        .await
        .ok_or(AppError::UserAlreadyExists)?;

    let code = generate_confirmation_code();
    let confirmation = ConfirmationCode {
        user_id,
        attribute_name: None,
        code: code.clone(),
        expires_at: now + Duration::hours(24),
    };
    storage.save_confirmation_code(confirmation).await;

    tracing::debug!("SignUp confirmation code for {}: {}", req.username, code);

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

    use crate::action::user::helpers::calculate_secret_hash;
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
    async fn test_concurrent_sign_up_allows_only_one_user() {
        let storage = Storage::new();
        let (pool_id, client_id) = setup_pool_and_client(&storage).await;
        let request = |client_id: String| {
            handler(
                &storage,
                json!({
                    "ClientId": client_id,
                    "Username": "concurrent-user",
                    "Password": "Password123!",
                    "UserAttributes": [
                        {"Name": "email", "Value": "concurrent@example.com"}
                    ]
                }),
            )
        };

        let (first, second) = tokio::join!(request(client_id.clone()), request(client_id));
        assert_eq!(first.is_ok() as u8 + second.is_ok() as u8, 1);

        let pool_id = UserPoolId::new(pool_id).unwrap();
        assert_eq!(storage.count_users(&pool_id).await, 1);
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
    async fn test_sign_up_requires_secret_hash_for_secret_client() {
        let storage = Storage::new();

        let pool = create_user_pool::handler(&storage, json!({"PoolName": "test"}))
            .await
            .unwrap();
        let pool_id = pool["UserPool"]["Id"].as_str().unwrap();

        let client = create_user_pool_client::handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "ClientName": "secret-client",
                "GenerateSecret": true
            }),
        )
        .await
        .unwrap();
        let client_id = client["UserPoolClient"]["ClientId"].as_str().unwrap();
        let client_secret = client["UserPoolClient"]["ClientSecret"].as_str().unwrap();

        let result = handler(
            &storage,
            json!({
                "ClientId": client_id,
                "Username": "secretuser",
                "Password": "Password123!"
            }),
        )
        .await;
        assert!(matches!(result, Err(AppError::NotAuthorized(_))));

        let secret_hash = calculate_secret_hash(client_id, client_secret, "secretuser").unwrap();
        let result = handler(
            &storage,
            json!({
                "ClientId": client_id,
                "Username": "secretuser",
                "Password": "Password123!",
                "SecretHash": secret_hash
            }),
        )
        .await;
        assert!(result.is_ok());
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

    #[tokio::test]
    async fn test_sign_up_rejected_when_pool_is_admin_create_only() {
        let storage = Storage::new();
        let pool = create_user_pool::handler(
            &storage,
            json!({
                "PoolName": "admin-only",
                "AdminCreateUserConfig": { "AllowAdminCreateUserOnly": true }
            }),
        )
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

        let result = handler(
            &storage,
            json!({
                "ClientId": client_id,
                "Username": "testuser",
                "Password": "Password123!"
            }),
        )
        .await;
        assert!(matches!(result, Err(AppError::NotAuthorized(_))));
    }
}
