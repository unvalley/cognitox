//! AdminListGroupsForUser API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AdminListGroupsForUser.html>

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

    let user = storage
        .get_user_by_username(&req.user_pool_id, &req.username)
        .await
        .ok_or(AppError::UserNotFound)?;

    let group_names = storage.get_groups_for_user(&user.id).await;

    let mut groups_json = Vec::new();
    for group_name in group_names.iter().take(req.limit as usize) {
        if let Some(group) = storage.get_group(&req.user_pool_id, group_name).await {
            groups_json.push(json!({
                "GroupName": group.group_name,
                "UserPoolId": group.user_pool_id,
                "Description": group.description,
                "RoleArn": group.role_arn,
                "Precedence": group.precedence,
                "CreationDate": group.creation_date.timestamp(),
                "LastModifiedDate": group.last_modified_date.timestamp()
            }));
        }
    }

    Ok(json!({
        "Groups": groups_json
    }))
}
