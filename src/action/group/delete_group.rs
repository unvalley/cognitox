//! DeleteGroup API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_DeleteGroup.html>

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
}

pub async fn handler(storage: &Storage, body: Value) -> Result<Value> {
    let req: Request = serde_json::from_value(body)
        .map_err(|e| AppError::InvalidParameter(format!("Invalid request: {}", e)))?;

    storage
        .get_user_pool(&req.user_pool_id)
        .await
        .ok_or(AppError::UserPoolNotFound)?;

    storage
        .delete_group(&req.user_pool_id, &req.group_name)
        .await
        .ok_or(AppError::GroupNotFound)?;

    Ok(json!({}))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::group::{
        admin_add_user_to_group, admin_list_groups_for_user, create_group, get_group,
    };
    use crate::action::user::admin_create_user;
    use crate::action::user_pool::create_user_pool;
    use serde_json::json;

    #[tokio::test]
    async fn test_delete_group_success() {
        let storage = Storage::new();

        let pool = create_user_pool::handler(&storage, json!({"PoolName": "test-pool"}))
            .await
            .unwrap();
        let pool_id = pool["UserPool"]["Id"].as_str().unwrap();

        create_group::handler(
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

        assert!(result.is_ok());

        // Verify group is deleted by trying to get it
        let get_result = get_group::handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "GroupName": "admins"
            }),
        )
        .await;
        assert!(get_result.is_err());
    }

    #[tokio::test]
    async fn test_delete_group_not_found() {
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
    }

    #[tokio::test]
    async fn test_delete_group_pool_not_found() {
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
    async fn test_delete_group_cleans_memberships() {
        let storage = Storage::new();

        let pool = create_user_pool::handler(&storage, json!({"PoolName": "test-pool"}))
            .await
            .unwrap();
        let pool_id = pool["UserPool"]["Id"].as_str().unwrap();

        create_group::handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "GroupName": "admins"
            }),
        )
        .await
        .unwrap();

        admin_create_user::handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "Username": "testuser",
                "TemporaryPassword": "TempPass123!"
            }),
        )
        .await
        .unwrap();

        admin_add_user_to_group::handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "Username": "testuser",
                "GroupName": "admins"
            }),
        )
        .await
        .unwrap();

        handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "GroupName": "admins"
            }),
        )
        .await
        .unwrap();

        let listed = admin_list_groups_for_user::handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "Username": "testuser"
            }),
        )
        .await
        .unwrap();

        assert!(listed["Groups"].as_array().unwrap().is_empty());
    }
}
