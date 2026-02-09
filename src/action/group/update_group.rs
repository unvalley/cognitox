//! UpdateGroup API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_UpdateGroup.html>

use chrono::Utc;
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
    description: Option<String>,
    role_arn: Option<String>,
    precedence: Option<i32>,
}

pub async fn handler(storage: &Storage, body: Value) -> Result<Value> {
    let req: Request = serde_json::from_value(body)
        .map_err(|e| AppError::InvalidParameter(format!("Invalid request: {}", e)))?;

    storage
        .get_user_pool(&req.user_pool_id)
        .await
        .ok_or(AppError::UserPoolNotFound)?;

    let mut group = storage
        .get_group(&req.user_pool_id, &req.group_name)
        .await
        .ok_or(AppError::GroupNotFound)?;

    // Update fields if provided
    if let Some(description) = req.description {
        group.description = Some(description);
    }
    if let Some(role_arn) = req.role_arn {
        group.role_arn = Some(role_arn);
    }
    if let Some(precedence) = req.precedence {
        group.precedence = Some(precedence);
    }

    group.last_modified_date = Utc::now();

    let updated = storage.update_group(group).await.unwrap();

    Ok(json!({
        "Group": {
            "GroupName": updated.group_name,
            "UserPoolId": updated.user_pool_id,
            "Description": updated.description,
            "RoleArn": updated.role_arn,
            "Precedence": updated.precedence,
            "CreationDate": updated.creation_date.timestamp(),
            "LastModifiedDate": updated.last_modified_date.timestamp()
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::group::create_group;
    use crate::action::user_pool::create_user_pool;
    use serde_json::json;

    #[tokio::test]
    async fn test_update_group_success() {
        let storage = Storage::new();

        let pool = create_user_pool::handler(&storage, json!({"PoolName": "test-pool"}))
            .await
            .unwrap();
        let pool_id = pool["UserPool"]["Id"].as_str().unwrap();

        // Create a group first
        create_group::handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "GroupName": "admins",
                "Description": "Original description",
                "Precedence": 1
            }),
        )
        .await
        .unwrap();

        // Update the group
        let result = handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "GroupName": "admins",
                "Description": "Updated description",
                "Precedence": 10
            }),
        )
        .await;

        assert!(result.is_ok());
        let body = result.unwrap();
        assert_eq!(body["Group"]["GroupName"], "admins");
        assert_eq!(body["Group"]["Description"], "Updated description");
        assert_eq!(body["Group"]["Precedence"], 10);
    }

    #[tokio::test]
    async fn test_update_group_partial() {
        let storage = Storage::new();

        let pool = create_user_pool::handler(&storage, json!({"PoolName": "test-pool"}))
            .await
            .unwrap();
        let pool_id = pool["UserPool"]["Id"].as_str().unwrap();

        create_group::handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "GroupName": "admins",
                "Description": "Original",
                "Precedence": 1
            }),
        )
        .await
        .unwrap();

        // Only update description
        let result = handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "GroupName": "admins",
                "Description": "New description"
            }),
        )
        .await;

        assert!(result.is_ok());
        let body = result.unwrap();
        assert_eq!(body["Group"]["Description"], "New description");
        assert_eq!(body["Group"]["Precedence"], 1); // Unchanged
    }

    #[tokio::test]
    async fn test_update_group_not_found() {
        let storage = Storage::new();

        let pool = create_user_pool::handler(&storage, json!({"PoolName": "test-pool"}))
            .await
            .unwrap();
        let pool_id = pool["UserPool"]["Id"].as_str().unwrap();

        let result = handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "GroupName": "nonexistent"
            }),
        )
        .await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AppError::GroupNotFound));
    }

    #[tokio::test]
    async fn test_update_group_pool_not_found() {
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
        assert!(matches!(result.unwrap_err(), AppError::UserPoolNotFound));
    }
}
