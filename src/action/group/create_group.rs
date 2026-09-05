//! CreateGroup API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_CreateGroup.html>

use chrono::Utc;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::{
    error::{AppError, Result},
    storage::Storage,
    types::{Group, UserPoolId},
    validation::validate_group_name,
};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Request {
    user_pool_id: UserPoolId,
    group_name: String,
    description: Option<String>,
    role_arn: Option<String>,
    precedence: Option<i32>,
}

pub async fn handler(storage: &Storage, body: Value) -> Result<Value> {
    let req: Request = serde_json::from_value(body)
        .map_err(|e| AppError::InvalidParameter(format!("Invalid request: {}", e)))?;

    // Validate input
    validate_group_name(&req.group_name)?;

    storage
        .get_user_pool(&req.user_pool_id)
        .await
        .ok_or(AppError::UserPoolNotFound)?;

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

    let created = storage
        .try_create_group(group)
        .await
        .ok_or(AppError::GroupAlreadyExists)?;

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::user_pool::create_user_pool;
    use serde_json::json;

    #[tokio::test]
    async fn test_create_group_success() {
        let storage = Storage::new();

        let pool = create_user_pool::handler(&storage, json!({"PoolName": "test-pool"}))
            .await
            .unwrap();
        let pool_id = pool["UserPool"]["Id"].as_str().unwrap();

        let result = handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "GroupName": "admins",
                "Description": "Admin group",
                "Precedence": 1
            }),
        )
        .await;

        assert!(result.is_ok());
        let body = result.unwrap();
        assert_eq!(body["Group"]["GroupName"], "admins");
        assert_eq!(body["Group"]["Description"], "Admin group");
        assert_eq!(body["Group"]["Precedence"], 1);
    }

    #[tokio::test]
    async fn test_create_group_duplicate() {
        let storage = Storage::new();

        let pool = create_user_pool::handler(&storage, json!({"PoolName": "test-pool"}))
            .await
            .unwrap();
        let pool_id = pool["UserPool"]["Id"].as_str().unwrap();

        handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "GroupName": "admins"
            }),
        )
        .await
        .unwrap();

        let result = handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "GroupName": "admins"
            }),
        )
        .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_create_group_pool_not_found() {
        let storage = Storage::new();

        let result = handler(
            &storage,
            json!({
                "UserPoolId": "local_nonexistent",
                "GroupName": "admins"
            }),
        )
        .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_concurrent_create_group_allows_only_one() {
        let storage = Storage::new();
        let pool = create_user_pool::handler(&storage, json!({"PoolName": "test-pool"}))
            .await
            .unwrap();
        let pool_id = pool["UserPool"]["Id"].as_str().unwrap().to_string();
        let request = || {
            handler(
                &storage,
                json!({ "UserPoolId": pool_id, "GroupName": "racers" }),
            )
        };

        let (first, second) = tokio::join!(request(), request());
        assert_eq!(first.is_ok() as u8 + second.is_ok() as u8, 1);
        let err = if first.is_err() { first } else { second };
        assert!(matches!(err, Err(AppError::GroupAlreadyExists)));
    }
}
