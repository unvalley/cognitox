//! GetUser API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_GetUser.html>

use serde::Deserialize;
use serde_json::{Value, json};

use crate::{
    error::{AppError, Result},
    storage::Storage,
};

use super::helpers::verify_and_extract_user_id;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Request {
    access_token: String,
}

pub async fn handler(storage: &Storage, body: Value) -> Result<Value> {
    let req: Request = serde_json::from_value(body)
        .map_err(|e| AppError::InvalidParameter(format!("Invalid request: {}", e)))?;

    let user_id =
        verify_and_extract_user_id(&req.access_token).map_err(|_| AppError::InvalidAccessToken)?;

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
