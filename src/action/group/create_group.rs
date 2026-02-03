//! CreateGroup API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_CreateGroup.html>

use chrono::Utc;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::{
    error::{AppError, Result},
    storage::Storage,
    types::Group,
};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Request {
    user_pool_id: String,
    group_name: String,
    description: Option<String>,
    role_arn: Option<String>,
    precedence: Option<i32>,
}

pub async fn handler(storage: &Storage, body: Value) -> Result<Value> {
    let req: Request = serde_json::from_value(body)
        .map_err(|e| AppError::Internal(format!("Invalid request: {}", e)))?;

    storage
        .get_user_pool(&req.user_pool_id)
        .await
        .ok_or(AppError::UserPoolNotFound)?;

    if storage
        .get_group(&req.user_pool_id, &req.group_name)
        .await
        .is_some()
    {
        return Err(AppError::GroupAlreadyExists);
    }

    let now = Utc::now();
    let group = Group {
        group_name: req.group_name,
        user_pool_id: req.user_pool_id,
        description: req.description,
        role_arn: req.role_arn,
        precedence: req.precedence,
        creation_date: now,
        last_modified_date: now,
    };

    let created = storage.create_group(group).await;

    Ok(json!({
        "Group": {
            "GroupName": created.group_name,
            "UserPoolId": created.user_pool_id,
            "Description": created.description,
            "RoleArn": created.role_arn,
            "Precedence": created.precedence,
            "CreationDate": created.creation_date.timestamp(),
            "LastModifiedDate": created.last_modified_date.timestamp()
        }
    }))
}
