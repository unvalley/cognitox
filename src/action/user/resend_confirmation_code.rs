//! ResendConfirmationCode API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_ResendConfirmationCode.html>

use chrono::{Duration, Utc};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::{
    error::{AppError, Result},
    storage::Storage,
    types::{ClientId, ConfirmationCode},
};

use super::helpers::{generate_confirmation_code, mask_email};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Request {
    client_id: ClientId,
    username: String,
}

pub async fn handler(storage: &Storage, body: Value) -> Result<Value> {
    let req: Request = serde_json::from_value(body)
        .map_err(|e| AppError::InvalidParameter(format!("Invalid request: {}", e)))?;

    let client = storage
        .get_user_pool_client(&req.client_id)
        .await
        .ok_or(AppError::UserPoolClientNotFound)?;

    let user = storage
        .get_user_by_username(&client.user_pool_id, &req.username)
        .await
        .ok_or(AppError::UserNotFound)?;

    let code = generate_confirmation_code();
    let confirmation = ConfirmationCode {
        user_id: user.id,
        code: code.clone(),
        expires_at: Utc::now() + Duration::hours(24),
    };
    storage.save_confirmation_code(confirmation).await;

    tracing::info!("Resend confirmation code for {}: {}", req.username, code);

    Ok(json!({
        "CodeDeliveryDetails": {
            "Destination": user.email.map(|e| mask_email(&e)).unwrap_or_default(),
            "DeliveryMedium": "EMAIL",
            "AttributeName": "email"
        }
    }))
}
