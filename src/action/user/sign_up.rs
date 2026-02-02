//! SignUp API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_SignUp.html>

use chrono::{Duration, Utc};
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::{
    error::{AppError, Result},
    storage::Storage,
    types::{ConfirmationCode, User, UserAttribute, UserStatus},
};

use super::helpers::{generate_confirmation_code, hash_password, mask_email};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Request {
    client_id: String,
    username: String,
    password: String,
    user_attributes: Option<Vec<UserAttribute>>,
}

pub async fn handler(storage: &Storage, body: Value) -> Result<Value> {
    let req: Request = serde_json::from_value(body)
        .map_err(|e| AppError::Internal(format!("Invalid request: {}", e)))?;

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

    let email = req.user_attributes.as_ref().and_then(|attrs| {
        attrs
            .iter()
            .find(|a| a.name == "email")
            .and_then(|a| a.value.clone())
    });

    let user = User {
        id: user_id,
        user_pool_id: client.user_pool_id.clone(),
        username: req.username.clone(),
        email: email.clone(),
        phone_number: None,
        password_hash: hash_password(&req.password),
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

    Ok(json!({
        "UserConfirmed": false,
        "UserSub": user_id.to_string(),
        "CodeDeliveryDetails": {
            "Destination": email.map(|e| mask_email(&e)).unwrap_or_default(),
            "DeliveryMedium": "EMAIL",
            "AttributeName": "email"
        }
    }))
}
