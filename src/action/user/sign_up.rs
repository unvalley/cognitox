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
    validation::{
        validate_email, validate_password_against_policy, validate_phone_number, validate_username,
    },
};

use super::helpers::{
    confirmation_delivery, find_user_attribute_value, generate_confirmation_code,
    remove_user_attribute, set_user_password, sync_user_profile_attributes, upsert_user_attribute,
    verify_secret_hash,
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
    let req: Request = crate::action::io::parse_request(body)?;
    let _ = (
        &req.validation_data,
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
    let pool = storage
        .get_user_pool(&client.user_pool_id)
        .await
        .ok_or(AppError::UserPoolNotFound)?;

    if pool
        .admin_create_user_config
        .as_ref()
        .and_then(|config| config.allow_admin_create_user_only)
        == Some(true)
    {
        return Err(AppError::NotAuthorized(
            "SignUp is not permitted for this user pool".to_string(),
        ));
    }
    validate_password_against_policy(&pool, &req.password)?;

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
        password_hash: String::new(),
        enabled: true,
        user_status: UserStatus::Unconfirmed,
        attributes: req.user_attributes.unwrap_or_default(),
        creation_date: now,
        last_modified_date: now,
        srp_salt: None,
        srp_verifier: None,
        password_set_at: None,
    };
    set_user_password(&mut user, &req.password)?;
    sync_user_profile_attributes(&mut user);

    // A self-registered address or number starts out unverified, whatever
    // the request claims.
    for (present, verified_attribute) in [
        (user.email.is_some(), "email_verified"),
        (user.phone_number.is_some(), "phone_number_verified"),
    ] {
        if present {
            upsert_user_attribute(
                &mut user.attributes,
                verified_attribute,
                Some("false".to_string()),
            );
        } else {
            remove_user_attribute(&mut user.attributes, verified_attribute);
        }
    }

    let code_delivery_details = confirmation_delivery(&pool, &user);

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

    let mut response = json!({
        "UserConfirmed": false,
        "UserSub": user_id.to_string()
    });
    if let Some(code_delivery_details) = code_delivery_details {
        response["CodeDeliveryDetails"] = code_delivery_details;
    }
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    use crate::action::user::helpers::calculate_secret_hash;
    use crate::action::user_pool::{create_user_pool, create_user_pool_client};
    use crate::types::UserPoolId;

    async fn setup_pool_and_client(storage: &Storage) -> (String, String) {
        let pool = create_user_pool::handler(
            storage,
            json!({
                "PoolName": "test",
                "AutoVerifiedAttributes": ["email", "phone_number"]
            }),
        )
        .await
        .unwrap();
        let pool_id = pool["UserPool"]["Id"].as_str().unwrap().to_string();

        let client = create_user_pool_client::handler(
            storage,
            json!({
                "UserPoolId": pool_id,
                "ExplicitAuthFlows": ["ALLOW_USER_PASSWORD_AUTH", "ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_USER_SRP_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
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
        assert_eq!(
            body["CodeDeliveryDetails"],
            json!({
                "Destination": "t***@e***",
                "DeliveryMedium": "EMAIL",
                "AttributeName": "email"
            })
        );
        assert!(body.get("Session").is_none());

        let pool_id = UserPoolId::new(pool_id).unwrap();
        let user = storage
            .get_user_by_username(&pool_id, "testuser")
            .await
            .unwrap();
        assert_eq!(user.email.as_deref(), Some("test@example.com"));
        // The address is unverified until the code comes back.
        assert!(
            user.attributes
                .iter()
                .any(|attribute| attribute.name == "email_verified"
                    && attribute.value.as_deref() == Some("false"))
        );
        // Cognito sends six-digit codes.
        let code = storage.get_confirmation_code(&user.id).await.unwrap().code;
        assert_eq!(code.len(), 6);
        assert!(code.chars().all(|ch| ch.is_ascii_digit()));
    }

    #[tokio::test]
    async fn test_sign_up_without_auto_verification_delivers_no_code() {
        let storage = Storage::new();
        let pool = create_user_pool::handler(&storage, json!({"PoolName": "test"}))
            .await
            .unwrap();
        let client = create_user_pool_client::handler(
            &storage,
            json!({"UserPoolId": pool["UserPool"]["Id"], "ClientName": "test-client"}),
        )
        .await
        .unwrap();

        let body = handler(
            &storage,
            json!({
                "ClientId": client["UserPoolClient"]["ClientId"],
                "Username": "testuser",
                "Password": "Password123!",
                "UserAttributes": [
                    {"Name": "email", "Value": "test@example.com"}
                ]
            }),
        )
        .await
        .unwrap();

        assert_eq!(body["UserConfirmed"], false);
        assert!(body.get("CodeDeliveryDetails").is_none());
    }

    #[tokio::test]
    async fn test_sign_up_enforces_the_password_policy() {
        let storage = Storage::new();
        let (_pool_id, client_id) = setup_pool_and_client(&storage).await;

        let result = handler(
            &storage,
            json!({
                "ClientId": client_id,
                "Username": "testuser",
                "Password": "password"
            }),
        )
        .await;

        assert!(matches!(
            result,
            Err(AppError::InvalidPassword(message))
                if message == "Password did not conform with policy: Password must have uppercase characters"
        ));
    }

    #[tokio::test]
    async fn test_sign_up_is_refused_when_only_admins_create_users() {
        let storage = Storage::new();
        let pool = create_user_pool::handler(
            &storage,
            json!({
                "PoolName": "test",
                "AdminCreateUserConfig": {"AllowAdminCreateUserOnly": true}
            }),
        )
        .await
        .unwrap();
        let client = create_user_pool_client::handler(
            &storage,
            json!({"UserPoolId": pool["UserPool"]["Id"], "ClientName": "test-client"}),
        )
        .await
        .unwrap();

        let result = handler(
            &storage,
            json!({
                "ClientId": client["UserPoolClient"]["ClientId"],
                "Username": "testuser",
                "Password": "Password123!"
            }),
        )
        .await;

        assert!(matches!(
            result,
            Err(AppError::NotAuthorized(message))
                if message == "SignUp is not permitted for this user pool"
        ));
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
                "ExplicitAuthFlows": ["ALLOW_USER_PASSWORD_AUTH", "ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_USER_SRP_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
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
}
