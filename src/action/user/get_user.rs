//! GetUser API implementation

use serde::Deserialize;
use serde_json::{json, Value};

use crate::{
    error::{AppError, Result},
    storage::Storage,
};

use super::helpers::extract_user_id_from_token;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Request {
    access_token: String,
}

pub async fn handler(storage: &Storage, body: Value) -> Result<Value> {
    let req: Request = serde_json::from_value(body)
        .map_err(|e| AppError::Internal(format!("Invalid request: {}", e)))?;

    let user_id =
        extract_user_id_from_token(&req.access_token).ok_or(AppError::InvalidAccessToken)?;

    let user = storage
        .get_user(&user_id)
        .await
        .ok_or(AppError::UserNotFound)?;

    let user_attributes: Vec<_> = user
        .attributes
        .iter()
        .map(|a| {
            json!({
                "Name": a.name,
                "Value": a.value
            })
        })
        .collect();

    Ok(json!({
        "Username": user.username,
        "UserAttributes": user_attributes
    }))
}
