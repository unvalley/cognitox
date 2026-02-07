//! ConfirmSignUp API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_ConfirmSignUp.html>

use chrono::Utc;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::{
    error::{AppError, Result},
    storage::Storage,
    types::UserStatus,
};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Request {
    client_id: String,
    username: String,
    confirmation_code: String,
}

pub async fn handler(storage: &Storage, body: Value) -> Result<Value> {
    let req: Request = serde_json::from_value(body)
        .map_err(|e| AppError::InvalidParameter(format!("Invalid request: {}", e)))?;

    let client = storage
        .get_user_pool_client(&req.client_id)
        .await
        .ok_or(AppError::UserPoolClientNotFound)?;

    let mut user = storage
        .get_user_by_username(&client.user_pool_id, &req.username)
        .await
        .ok_or(AppError::UserNotFound)?;

    let confirmation = storage
        .get_confirmation_code(&user.id)
        .await
        .ok_or(AppError::InvalidConfirmationCode)?;

    if confirmation.code != req.confirmation_code {
        return Err(AppError::InvalidConfirmationCode);
    }

    if confirmation.expires_at < Utc::now() {
        return Err(AppError::InvalidConfirmationCode);
    }

    user.user_status = UserStatus::Confirmed;
    user.last_modified_date = Utc::now();
    storage.update_user(user).await;
    storage
        .delete_confirmation_code(&confirmation.user_id)
        .await;

    Ok(json!({}))
}
