//! GetGroup API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_GetGroup.html>

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
    group_name: String,
}

pub async fn handler(storage: &Storage, body: Value) -> Result<Value> {
    let req: Request = serde_json::from_value(body)
        .map_err(|e| AppError::Internal(format!("Invalid request: {}", e)))?;

    storage
        .get_user_pool(&req.user_pool_id)
        .await
        .ok_or(AppError::UserPoolNotFound)?;

    let group = storage
        .get_group(&req.user_pool_id, &req.group_name)
        .await
        .ok_or(AppError::GroupNotFound)?;

    Ok(json!({
        "Group": {
            "GroupName": group.group_name,
            "UserPoolId": group.user_pool_id,
            "Description": group.description,
            "RoleArn": group.role_arn,
            "Precedence": group.precedence,
            "CreationDate": group.creation_date.timestamp(),
            "LastModifiedDate": group.last_modified_date.timestamp()
        }
    }))
}
