//! ForgotPassword API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_ForgotPassword.html>

use chrono::{Duration, Utc};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::{
    error::{AppError, Result},
    storage::Storage,
    types::PasswordResetCode,
};

use super::helpers::{generate_confirmation_code, mask_email};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Request {
    client_id: String,
    username: String,
}

pub async fn handler(storage: &Storage, body: Value) -> Result<Value> {
    let req: Request = serde_json::from_value(body)
        .map_err(|e| AppError::Internal(format!("Invalid request: {}", e)))?;

    let client = storage
        .get_user_pool_client(&req.client_id)
        .await
        .ok_or(AppError::UserPoolClientNotFound)?;

    let user = storage
        .get_user_by_username(&client.user_pool_id, &req.username)
        .await
        .ok_or(AppError::UserNotFound)?;

    let code = generate_confirmation_code();
    let reset_code = PasswordResetCode {
        user_id: user.id,
        code: code.clone(),
        expires_at: Utc::now() + Duration::hours(1),
    };

    storage.save_password_reset_code(reset_code).await;

    let destination = user.email.as_deref().map(mask_email);
    let delivery_medium = if user.email.is_some() { "EMAIL" } else { "SMS" };

    Ok(json!({
        "CodeDeliveryDetails": {
            "AttributeName": "email",
            "DeliveryMedium": delivery_medium,
            "Destination": destination
        }
    }))
}
