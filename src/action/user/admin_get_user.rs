//! AdminGetUser API implementation

use serde::Deserialize;
use serde_json::{json, Value};

use crate::{
    error::{AppError, Result},
    storage::Storage,
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
