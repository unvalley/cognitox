//! ListUsersInGroup API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_ListUsersInGroup.html>

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
    group_name: String,
    #[serde(default = "default_limit")]
    limit: i32,
    #[allow(dead_code)]
    next_token: Option<String>,
}

fn default_limit() -> i32 {
    60
}

pub async fn handler(storage: &Storage, body: Value) -> Result<Value> {
    let req: Request = serde_json::from_value(body)
        .map_err(|e| AppError::InvalidParameter(format!("Invalid request: {}", e)))?;

    storage
        .get_user_pool(&req.user_pool_id)
        .await
        .ok_or(AppError::UserPoolNotFound)?;

    storage
        .get_group(&req.user_pool_id, &req.group_name)
        .await
        .ok_or(AppError::GroupNotFound)?;

    let users = storage
        .get_users_in_group(&req.user_pool_id, &req.group_name)
        .await;

    let users_json: Vec<Value> = users
        .iter()
        .take(req.limit as usize)
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
