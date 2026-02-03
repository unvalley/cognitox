//! ChangePassword API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_ChangePassword.html>

use chrono::Utc;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::{
    error::{AppError, Result},
    storage::Storage,
};

use super::helpers::{extract_user_id_from_token, hash_password};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Request {
    access_token: String,
    previous_password: String,
    proposed_password: String,
}

pub async fn handler(storage: &Storage, body: Value) -> Result<Value> {
    let req: Request = serde_json::from_value(body)
        .map_err(|e| AppError::Internal(format!("Invalid request: {}", e)))?;

    let user_id =
        extract_user_id_from_token(&req.access_token).ok_or(AppError::InvalidAccessToken)?;

    let mut user = storage
        .get_user(&user_id)
        .await
        .ok_or(AppError::UserNotFound)?;

    let previous_hash = hash_password(&req.previous_password);
    if user.password_hash != previous_hash {
        return Err(AppError::InvalidPassword);
    }

    user.password_hash = hash_password(&req.proposed_password);
    user.last_modified_date = Utc::now();

    storage.update_user(user).await;

    Ok(json!({}))
}
