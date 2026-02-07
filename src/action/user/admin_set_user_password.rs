//! AdminSetUserPassword API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AdminSetUserPassword.html>

use chrono::Utc;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::{
    error::{AppError, Result},
    storage::Storage,
    types::{UserPoolId, UserStatus},
    validation::validate_password,
};

use super::helpers::hash_password;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Request {
    user_pool_id: UserPoolId,
    username: String,
    password: String,
    #[serde(default)]
    permanent: bool,
}

pub async fn handler(storage: &Storage, body: Value) -> Result<Value> {
    let req: Request = serde_json::from_value(body)
        .map_err(|e| AppError::InvalidParameter(format!("Invalid request: {}", e)))?;

    // Validate input
    validate_password(&req.password)?;

    storage
        .get_user_pool(&req.user_pool_id)
        .await
        .ok_or(AppError::UserPoolNotFound)?;

    let mut user = storage
        .get_user_by_username(&req.user_pool_id, &req.username)
        .await
        .ok_or(AppError::UserNotFound)?;

    user.password_hash = hash_password(&req.password).map_err(AppError::Internal)?;
    user.last_modified_date = Utc::now();

    if req.permanent {
        if user.user_status == UserStatus::ForceChangePassword {
            user.user_status = UserStatus::Confirmed;
        }
    } else {
        user.user_status = UserStatus::ForceChangePassword;
    }

    storage.update_user(user).await;

    Ok(json!({}))
}
