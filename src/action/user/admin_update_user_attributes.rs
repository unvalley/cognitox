//! AdminUpdateUserAttributes API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AdminUpdateUserAttributes.html>

use chrono::Utc;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::{
    action::io::parse_request,
    error::{AppError, Result},
    storage::Storage,
    types::{UserAttribute, UserPoolId},
    validation::{validate_email, validate_phone_number},
};

use super::helpers::upsert_user_attribute;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Request {
    user_pool_id: UserPoolId,
    username: String,
    user_attributes: Vec<UserAttribute>,
    #[serde(default)]
    client_metadata: Option<std::collections::HashMap<String, String>>,
}

pub async fn handler(storage: &Storage, body: Value) -> Result<Value> {
    let req: Request = parse_request(body)?;
    let _ = &req.client_metadata;

    storage
        .get_user_pool(&req.user_pool_id)
        .await
        .ok_or(AppError::UserPoolNotFound)?;

    let mut user = storage
        .get_user_by_username(&req.user_pool_id, &req.username)
        .await
        .ok_or(AppError::UserNotFound)?;

    let mut email_updated = false;
    let mut phone_updated = false;
    let mut email_verified_explicit = false;
    let mut phone_verified_explicit = false;

    for new_attr in req.user_attributes {
        match new_attr.name.as_str() {
            "email" => {
                if let Some(value) = new_attr.value.as_deref() {
                    validate_email(value)?;
                }
                email_updated = true;
            }
            "phone_number" => {
                if let Some(value) = new_attr.value.as_deref() {
                    validate_phone_number(value)?;
                }
                phone_updated = true;
            }
            "email_verified" => email_verified_explicit = true,
            "phone_number_verified" => phone_verified_explicit = true,
            _ => {}
        }

        upsert_user_attribute(&mut user.attributes, &new_attr.name, new_attr.value);
    }

    if email_updated && !email_verified_explicit {
        upsert_user_attribute(
            &mut user.attributes,
            "email_verified",
            Some("false".to_string()),
        );
    }
    if phone_updated && !phone_verified_explicit {
        upsert_user_attribute(
            &mut user.attributes,
            "phone_number_verified",
            Some("false".to_string()),
        );
    }

    for attr in &user.attributes {
        match attr.name.as_str() {
            "email" => user.email = attr.value.clone(),
            "phone_number" => user.phone_number = attr.value.clone(),
            _ => {}
        }
    }

    user.last_modified_date = Utc::now();

    storage.update_user(user).await;

    Ok(json!({}))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::user::admin_create_user;
    use crate::action::user::admin_get_user;
    use crate::action::user_pool::create_user_pool;
    use serde_json::json;

    #[tokio::test]
    async fn test_admin_update_user_attributes_success() {
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
                "Username": "testuser",
                "UserAttributes": [
                    {"Name": "email", "Value": "old@example.com"}
                ]
            }),
        )
        .await
        .unwrap();

        // Update attributes
        let result = handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "Username": "testuser",
                "UserAttributes": [
                    {"Name": "email", "Value": "new@example.com"},
                    {"Name": "custom:role", "Value": "admin"}
                ]
            }),
        )
        .await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), json!({}));

        // Verify the update
        let user = admin_get_user::handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "Username": "testuser"
            }),
        )
        .await
        .unwrap();

        let attrs = user["UserAttributes"].as_array().unwrap();
        let email_attr = attrs.iter().find(|a| a["Name"] == "email").unwrap();
        assert_eq!(email_attr["Value"], "new@example.com");

        let custom_attr = attrs.iter().find(|a| a["Name"] == "custom:role").unwrap();
        assert_eq!(custom_attr["Value"], "admin");
    }

    #[tokio::test]
    async fn test_admin_update_user_attributes_user_not_found() {
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
                "UserAttributes": [
                    {"Name": "email", "Value": "test@example.com"}
                ]
            }),
        )
        .await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AppError::UserNotFound));
    }

    #[tokio::test]
    async fn test_admin_update_user_attributes_pool_not_found() {
        let storage = Storage::new();

        let result = handler(
            &storage,
            json!({
                "UserPoolId": "local_nonexistent",
                "Username": "testuser",
                "UserAttributes": [
                    {"Name": "email", "Value": "test@example.com"}
                ]
            }),
        )
        .await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AppError::UserPoolNotFound));
    }
}
