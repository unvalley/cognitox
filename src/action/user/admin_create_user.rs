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
    types::{AliasAttribute, User, UserAttribute, UserPoolId, UserStatus},
    validation::{validate_email, validate_password, validate_phone_number, validate_username},
};

use super::helpers::{
    build_user_attributes, find_user_attribute_value, hash_password, sync_user_profile_attributes,
    upsert_user_attribute,
};

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
        &req.desired_delivery_mediums,
        &req.client_metadata,
        &req.validation_data,
    );
    let resend = match req.message_action.as_deref() {
        None | Some("SUPPRESS") => false,
        Some("RESEND") => true,
        Some(action) => {
            return Err(AppError::InvalidParameter(format!(
                "Invalid MessageAction: {action}"
            )));
        }
    };

    // Validate input
    validate_username(&req.username)?;
    if let Some(password) = &req.temporary_password {
        validate_password(password)?;
    }

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

    let pool = storage
        .get_user_pool(&req.user_pool_id)
        .await
        .ok_or(AppError::UserPoolNotFound)?;

    let existing = storage
        .get_user_by_username(&req.user_pool_id, &req.username)
        .await;
    if resend {
        return resend_invitation(storage, existing, req.temporary_password).await;
    }
    if existing.is_some() {
        return Err(AppError::UserAlreadyExists);
    }

    let now = Utc::now();
    let user_id = Uuid::new_v4();
    let password = req
        .temporary_password
        .unwrap_or_else(|| Uuid::new_v4().to_string());

    let mut user = User {
        id: user_id,
        user_pool_id: req.user_pool_id.clone(),
        username: req.username.clone(),
        email: None,
        phone_number: None,
        password_hash: hash_password(&password).map_err(AppError::Internal)?,
        enabled: true,
        user_status: UserStatus::ForceChangePassword,
        attributes: req.user_attributes.unwrap_or_default(),
        creation_date: now,
        last_modified_date: now,
    };
    sync_user_profile_attributes(&mut user);

    // An email address or phone number created as verified becomes a sign-in
    // alias, which must be unique within the user pool.
    for (alias, name, verified_attribute) in [
        (AliasAttribute::Email, "email", "email_verified"),
        (
            AliasAttribute::PhoneNumber,
            "phone_number",
            "phone_number_verified",
        ),
    ] {
        let is_alias = pool
            .alias_attributes
            .as_ref()
            .is_some_and(|attributes| attributes.contains(&alias));
        let is_verified = find_user_attribute_value(&user.attributes, verified_attribute)
            .is_some_and(|value| value == "true");
        if !is_alias || !is_verified {
            continue;
        }
        let Some(value) = user.alias_value(alias) else {
            continue;
        };
        let Some(owner) = storage.get_user_by_alias(&req.user_pool_id, value).await else {
            continue;
        };
        if req.force_alias_creation != Some(true) {
            return Err(AppError::AliasExists(name));
        }
        // ForceAliasCreation migrates the alias: the previous owner keeps the
        // attribute but can no longer be addressed by it.
        storage
            .update_user_with(&owner.id, |owner| {
                upsert_user_attribute(
                    &mut owner.attributes,
                    verified_attribute,
                    Some("false".to_string()),
                );
            })
            .await;
    }

    let created = storage
        .try_create_user(user)
        .await
        .ok_or(AppError::UserAlreadyExists)?;

    Ok(json!({
        "User": user_view(&created)
    }))
}

/// `MessageAction: RESEND` re-sends the invitation of a user that has not
/// signed in yet. The emulator delivers no message, so the only observable
/// effect is that a given temporary password replaces the previous one.
async fn resend_invitation(
    storage: &Storage,
    existing: Option<User>,
    temporary_password: Option<String>,
) -> Result<Value> {
    let user = existing.ok_or(AppError::UserNotFound)?;
    if user.user_status != UserStatus::ForceChangePassword {
        return Err(AppError::UnsupportedUserState(format!(
            "Resend not possible. {} status is not FORCE_CHANGE_PASSWORD",
            user.id
        )));
    }
    let Some(password) = temporary_password else {
        return Ok(json!({
            "User": user_view(&user)
        }));
    };
    let password_hash = hash_password(&password).map_err(AppError::Internal)?;
    let updated = storage
        .update_user_with(&user.id, |user| {
            user.password_hash = password_hash;
            user.last_modified_date = Utc::now();
            user.clone()
        })
        .await
        .ok_or(AppError::UserNotFound)?;

    Ok(json!({
        "User": user_view(&updated)
    }))
}

fn user_view(user: &User) -> Value {
    json!({
        "Username": user.username,
        "Enabled": user.enabled,
        "UserStatus": user.user_status,
        "UserCreateDate": user.creation_date.timestamp(),
        "UserLastModifiedDate": user.last_modified_date.timestamp(),
        "Attributes": build_user_attributes(user)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::user_pool::create_user_pool;
    use crate::types::UserPoolId;
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

        let pool_id = UserPoolId::new(pool_id).unwrap();
        let user = storage
            .get_user_by_username(&pool_id, "testuser")
            .await
            .unwrap();
        assert_eq!(
            body["User"]["Attributes"]
                .as_array()
                .unwrap()
                .iter()
                .find(|attribute| attribute["Name"] == "sub")
                .and_then(|attribute| attribute["Value"].as_str()),
            Some(user.id.to_string()).as_deref()
        );
        assert_eq!(user.email.as_deref(), Some("test@example.com"));
    }

    #[tokio::test]
    async fn test_admin_create_user_persists_phone_number() {
        let storage = Storage::new();

        let pool = create_user_pool::handler(&storage, json!({"PoolName": "test"}))
            .await
            .unwrap();
        let pool_id = pool["UserPool"]["Id"].as_str().unwrap();

        handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "Username": "phoneuser",
                "TemporaryPassword": "TempPass123!",
                "UserAttributes": [
                    {"Name": "phone_number", "Value": "+15555550100"}
                ]
            }),
        )
        .await
        .unwrap();

        let pool_id = UserPoolId::new(pool_id).unwrap();
        let user = storage
            .get_user_by_username(&pool_id, "phoneuser")
            .await
            .unwrap();
        assert_eq!(user.phone_number.as_deref(), Some("+15555550100"));
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

    async fn create_email_alias_pool(storage: &Storage) -> String {
        let pool = create_user_pool::handler(
            storage,
            json!({"PoolName": "test", "AliasAttributes": ["email"]}),
        )
        .await
        .unwrap();
        pool["UserPool"]["Id"].as_str().unwrap().to_string()
    }

    fn verified_email_user(pool_id: &str, username: &str) -> Value {
        json!({
            "UserPoolId": pool_id,
            "Username": username,
            "TemporaryPassword": "TempPass123!",
            "UserAttributes": [
                {"Name": "email", "Value": "shared@example.com"},
                {"Name": "email_verified", "Value": "true"}
            ]
        })
    }

    #[tokio::test]
    async fn test_admin_create_user_rejects_existing_email_alias() {
        let storage = Storage::new();
        let pool_id = create_email_alias_pool(&storage).await;
        handler(&storage, verified_email_user(&pool_id, "first"))
            .await
            .unwrap();

        let result = handler(&storage, verified_email_user(&pool_id, "second")).await;

        assert!(matches!(result, Err(AppError::AliasExists("email"))));
    }

    #[tokio::test]
    async fn test_admin_create_user_allows_duplicate_email_without_alias() {
        let storage = Storage::new();
        let pool = create_user_pool::handler(&storage, json!({"PoolName": "test"}))
            .await
            .unwrap();
        let pool_id = pool["UserPool"]["Id"].as_str().unwrap();
        handler(&storage, verified_email_user(pool_id, "first"))
            .await
            .unwrap();

        let result = handler(&storage, verified_email_user(pool_id, "second")).await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_admin_create_user_force_alias_creation_migrates_alias() {
        let storage = Storage::new();
        let pool_id = create_email_alias_pool(&storage).await;
        handler(&storage, verified_email_user(&pool_id, "first"))
            .await
            .unwrap();

        let mut request = verified_email_user(&pool_id, "second");
        request["ForceAliasCreation"] = json!(true);
        handler(&storage, request).await.unwrap();

        let pool_id = UserPoolId::new(pool_id).unwrap();
        let owner = storage
            .get_user_by_username(&pool_id, "shared@example.com")
            .await
            .unwrap();
        assert_eq!(owner.username, "second");
    }

    #[tokio::test]
    async fn test_admin_create_user_resend_replaces_temporary_password() {
        let storage = Storage::new();
        let pool_id = create_email_alias_pool(&storage).await;
        handler(&storage, verified_email_user(&pool_id, "invited"))
            .await
            .unwrap();
        let parsed_pool_id = UserPoolId::new(pool_id.as_str()).unwrap();
        let before = storage
            .get_user_by_username(&parsed_pool_id, "invited")
            .await
            .unwrap();

        let result = handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "Username": "invited",
                "TemporaryPassword": "NewTempPass123!",
                "MessageAction": "RESEND"
            }),
        )
        .await
        .unwrap();

        assert_eq!(result["User"]["UserStatus"], "FORCE_CHANGE_PASSWORD");
        let after = storage
            .get_user_by_username(&parsed_pool_id, "invited")
            .await
            .unwrap();
        assert_ne!(before.password_hash, after.password_hash);
    }

    #[tokio::test]
    async fn test_admin_create_user_resend_requires_invited_user() {
        let storage = Storage::new();
        let pool_id = create_email_alias_pool(&storage).await;

        let missing = handler(
            &storage,
            json!({"UserPoolId": pool_id, "Username": "missing", "MessageAction": "RESEND"}),
        )
        .await;
        assert!(matches!(missing, Err(AppError::UserNotFound)));

        handler(&storage, verified_email_user(&pool_id, "confirmed"))
            .await
            .unwrap();
        let parsed_pool_id = UserPoolId::new(pool_id.as_str()).unwrap();
        let user = storage
            .get_user_by_username(&parsed_pool_id, "confirmed")
            .await
            .unwrap();
        storage
            .update_user_with(&user.id, |user| user.user_status = UserStatus::Confirmed)
            .await;

        let confirmed = handler(
            &storage,
            json!({"UserPoolId": pool_id, "Username": "confirmed", "MessageAction": "RESEND"}),
        )
        .await;
        assert!(matches!(confirmed, Err(AppError::UnsupportedUserState(_))));
    }
}
