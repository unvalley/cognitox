//! AdminGetUser API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AdminGetUser.html>

use serde::Deserialize;
use serde_json::{Value, json};

use crate::{
    error::{AppError, Result},
    storage::Storage,
    types::UserPoolId,
};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Request {
    user_pool_id: UserPoolId,
    username: String,
}

pub async fn handler(storage: &Storage, body: Value) -> Result<Value> {
    let req: Request = serde_json::from_value(body)
        .map_err(|e| AppError::InvalidParameter(format!("Invalid request: {}", e)))?;

    let user = storage
        .get_user_by_username(&req.user_pool_id, &req.username)
        .await
        .ok_or(AppError::UserNotFound)?;

    Ok(json!({
        "Username": user.username,
        "Enabled": user.enabled,
        "UserStatus": user.user_status,
        "UserCreateDate": user.creation_date.timestamp(),
        "UserLastModifiedDate": user.last_modified_date.timestamp(),
        "UserAttributes": user.attributes.iter().map(|a| {
            json!({
                "Name": a.name,
                "Value": a.value
            })
        }).collect::<Vec<_>>()
    }))
}
