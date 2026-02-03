//! AdminConfirmSignUp API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AdminConfirmSignUp.html>

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
    user_pool_id: String,
    username: String,
}

pub async fn handler(storage: &Storage, body: Value) -> Result<Value> {
    let req: Request = serde_json::from_value(body)
        .map_err(|e| AppError::Internal(format!("Invalid request: {}", e)))?;

    storage
        .get_user_pool(&req.user_pool_id)
        .await
        .ok_or(AppError::UserPoolNotFound)?;

    let mut user = storage
        .get_user_by_username(&req.user_pool_id, &req.username)
        .await
        .ok_or(AppError::UserNotFound)?;

    let user_id = user.id;
    user.user_status = UserStatus::Confirmed;
    user.last_modified_date = Utc::now();

    storage.update_user(user).await;
    storage.delete_confirmation_code(&user_id).await;

    Ok(json!({}))
}
