//! AdminCreateUser API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AdminCreateUser.html>

use chrono::Utc;
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::{
    error::{AppError, Result},
    storage::Storage,
    types::{User, UserAttribute, UserStatus},
    validation::{validate_email, validate_password, validate_username},
};

use super::helpers::hash_password;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Request {
    user_pool_id: String,
    username: String,
    temporary_password: Option<String>,
    user_attributes: Option<Vec<UserAttribute>>,
}

pub async fn handler(storage: &Storage, body: Value) -> Result<Value> {
    let req: Request = serde_json::from_value(body)
        .map_err(|e| AppError::Internal(format!("Invalid request: {}", e)))?;

    // Validate input
    validate_username(&req.username)?;
    if let Some(password) = &req.temporary_password {
        validate_password(password)?;
    }

    // Validate email if provided
    if let Some(attrs) = &req.user_attributes {
        if let Some(email_attr) = attrs.iter().find(|a| a.name == "email") {
            if let Some(email) = &email_attr.value {
                validate_email(email)?;
            }
        }
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
        password_hash: hash_password(&password),
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
