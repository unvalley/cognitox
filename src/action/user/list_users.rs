//! ListUsers API implementation

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
    limit: Option<u32>,
}

pub async fn handler(storage: &Storage, body: Value) -> Result<Value> {
    let req: Request = serde_json::from_value(body)
        .map_err(|e| AppError::Internal(format!("Invalid request: {}", e)))?;

    let users = storage.list_users(&req.user_pool_id).await;
    let limit = req.limit.unwrap_or(60) as usize;

    let users_json: Vec<_> = users
        .into_iter()
        .take(limit)
        .map(|u| {
            json!({
                "Username": u.username,
                "Enabled": u.enabled,
                "UserStatus": u.user_status,
                "UserCreateDate": u.creation_date.timestamp(),
                "UserLastModifiedDate": u.last_modified_date.timestamp(),
                "Attributes": u.attributes.iter().map(|a| {
                    json!({
                        "Name": a.name,
                        "Value": a.value
                    })
                }).collect::<Vec<_>>()
            })
        })
        .collect();

    Ok(json!({
        "Users": users_json
    }))
}
