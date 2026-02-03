//! ListGroups API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_ListGroups.html>

use serde::Deserialize;
use serde_json::{Value, json};

use crate::{
    error::{AppError, Result},
    storage::Storage,
};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Request {
    user_pool_id: String,
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
        .map_err(|e| AppError::Internal(format!("Invalid request: {}", e)))?;

    storage
        .get_user_pool(&req.user_pool_id)
        .await
        .ok_or(AppError::UserPoolNotFound)?;

    let groups = storage.list_groups(&req.user_pool_id).await;

    let groups_json: Vec<Value> = groups
        .iter()
        .take(req.limit as usize)
        .map(|g| {
            json!({
                "GroupName": g.group_name,
                "UserPoolId": g.user_pool_id,
                "Description": g.description,
                "RoleArn": g.role_arn,
                "Precedence": g.precedence,
                "CreationDate": g.creation_date.timestamp(),
                "LastModifiedDate": g.last_modified_date.timestamp()
            })
        })
        .collect();

    Ok(json!({
        "Groups": groups_json
    }))
}
