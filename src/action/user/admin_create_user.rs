//! AdminCreateUser API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AdminCreateUser.html>

use std::collections::HashMap;

use chrono::Utc;
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::{
    error::{AppError, Result},
    storage::Storage,
    types::{User, UserAttribute, UserPoolId, UserStatus},
    validation::{validate_email, validate_password, validate_username},
};

use super::helpers::hash_password;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Request {
    user_pool_id: UserPoolId,
    username: String,
    temporary_password: Option<String>,
    user_attributes: Option<Vec<UserAttribute>>,
    force_alias_creation: Option<bool>,
    message_action: Option<String>,
    desired_delivery_mediums: Option<Vec<String>>,
    client_metadata: Option<HashMap<String, String>>,
    validation_data: Option<Vec<UserAttribute>>,
}

pub async fn handler(storage: &Storage, body: Value) -> Result<Value> {
    let req: Request = serde_json::from_value(body)
        .map_err(|e| AppError::InvalidParameter(format!("Invalid request: {}", e)))?;
    let _ = (
        &req.force_alias_creation,
        &req.message_action,
        &req.desired_delivery_mediums,
        &req.client_metadata,
        &req.validation_data,
    );

    // Validate input
    validate_username(&req.username)?;
    if let Some(password) = &req.temporary_password {
        validate_password(password)?;
    }

    // Validate email if provided
    if let Some(email) = req
        .user_attributes
        .as_ref()
        .and_then(|attrs| attrs.iter().find(|a| a.name == "email"))
        .and_then(|a| a.value.as_ref())
    {
        validate_email(email)?;
    }

    storage
        .get_user_pool(&req.user_pool_id)
        .await
        .ok_or(AppError::UserPoolNotFound)?;

    if storage
        .get_user_by_username(&req.user_pool_id, &req.username)
        .await
        .is_some()
    {
        return Err(AppError::UserAlreadyExists);
    }

    let now = Utc::now();
    let user_id = Uuid::new_v4();
    let password = req
        .temporary_password
        .unwrap_or_else(|| Uuid::new_v4().to_string());

    let email = req.user_attributes.as_ref().and_then(|attrs| {
        attrs
            .iter()
            .find(|a| a.name == "email")
            .and_then(|a| a.value.clone())
    });

    let user = User {
        id: user_id,
        user_pool_id: req.user_pool_id.clone(),
        username: req.username.clone(),
        email,
        phone_number: None,
        password_hash: hash_password(&password).map_err(AppError::Internal)?,
        enabled: true,
        user_status: UserStatus::ForceChangePassword,
        attributes: req.user_attributes.unwrap_or_default(),
        creation_date: now,
        last_modified_date: now,
    };

    let created = storage.create_user(user).await;

    Ok(json!({
        "User": {
            "Username": created.username,
            "Enabled": created.enabled,
            "UserStatus": created.user_status,
            "UserCreateDate": created.creation_date.timestamp(),
            "UserLastModifiedDate": created.last_modified_date.timestamp(),
            "Attributes": created.attributes.iter().map(|a| {
                json!({
                    "Name": a.name,
                    "Value": a.value
                })
            }).collect::<Vec<_>>()
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::user_pool::create_user_pool;
    use serde_json::json;

    #[tokio::test]
    async fn test_admin_create_user_success() {
        let storage = Storage::new();

        let pool = create_user_pool::handler(&storage, json!({"PoolName": "test"}))
            .await
            .unwrap();
        let pool_id = pool["UserPool"]["Id"].as_str().unwrap();

        let result = handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "Username": "testuser",
                "TemporaryPassword": "TempPass123!",
                "UserAttributes": [
                    {"Name": "email", "Value": "test@example.com"}
                ]
            }),
        )
        .await;

        assert!(result.is_ok());
        let body = result.unwrap();
        assert_eq!(body["User"]["Username"], "testuser");
        assert_eq!(body["User"]["Enabled"], true);
        assert_eq!(body["User"]["UserStatus"], "FORCE_CHANGE_PASSWORD");
    }

    #[tokio::test]
    async fn test_admin_create_user_pool_not_found() {
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
    async fn test_admin_create_user_already_exists() {
        let storage = Storage::new();

        let pool = create_user_pool::handler(&storage, json!({"PoolName": "test"}))
            .await
            .unwrap();
        let pool_id = pool["UserPool"]["Id"].as_str().unwrap();

        // Create first user
        handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "Username": "testuser"
            }),
        )
        .await
        .unwrap();

        // Try to create same user again
        let result = handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "Username": "testuser"
            }),
        )
        .await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AppError::UserAlreadyExists));
    }

    #[tokio::test]
    async fn test_admin_create_user_accepts_full_request_syntax_fields() {
        let storage = Storage::new();

        let pool = create_user_pool::handler(&storage, json!({"PoolName": "test"}))
            .await
            .unwrap();
        let pool_id = pool["UserPool"]["Id"].as_str().unwrap();

        let result = handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "Username": "fullsyntaxuser",
                "TemporaryPassword": "TempPass123!",
                "ForceAliasCreation": false,
                "MessageAction": "SUPPRESS",
                "DesiredDeliveryMediums": ["EMAIL"],
                "ClientMetadata": {
                    "trace_id": "local-test"
                },
                "UserAttributes": [
                    {"Name": "email", "Value": "full@example.com"}
                ],
                "ValidationData": [
                    {"Name": "department", "Value": "engineering"}
                ]
            }),
        )
        .await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap()["User"]["Username"], "fullsyntaxuser");
    }
}
