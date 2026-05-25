//! DeleteUserPool API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_DeleteUserPool.html>

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    action::io::{parse_request, to_response_value},
    error::{AppError, Result},
    storage::Storage,
    types::{DeletionProtection, UserPoolId},
};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Request {
    user_pool_id: UserPoolId,
}

#[derive(Debug, Serialize)]
struct Response {}

pub async fn handler(storage: &Storage, body: Value) -> Result<Value> {
    let req: Request = parse_request(body)?;

    let pool = storage
        .get_user_pool(&req.user_pool_id)
        .await
        .ok_or(AppError::UserPoolNotFound)?;

    if pool.deletion_protection == Some(DeletionProtection::Active) {
        return Err(AppError::InvalidParameter(
            "Cannot delete user pool while deletion protection is ACTIVE".to_string(),
        ));
    }

    storage
        .delete_user_pool(&req.user_pool_id)
        .await
        .ok_or(AppError::UserPoolNotFound)?;

    to_response_value(Response {})
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::group::create_group;
    use crate::action::user::sign_up;
    use crate::action::user_pool::{create_user_pool, create_user_pool_client};
    use serde_json::json;

    #[tokio::test]
    async fn test_delete_user_pool_success() {
        let storage = Storage::new();

        // Create a user pool first
        let pool = create_user_pool::handler(&storage, json!({"PoolName": "test-pool"}))
            .await
            .unwrap();
        let pool_id = pool["UserPool"]["Id"].as_str().unwrap();

        // Delete the user pool
        let result = handler(&storage, json!({"UserPoolId": pool_id})).await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), json!({}));

        // Verify it's deleted
        assert!(
            storage
                .get_user_pool(&pool_id.parse().unwrap())
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn test_delete_user_pool_rejects_active_deletion_protection() {
        let storage = Storage::new();

        let pool = create_user_pool::handler(
            &storage,
            json!({
                "PoolName": "protected-pool",
                "DeletionProtection": "ACTIVE"
            }),
        )
        .await
        .unwrap();
        let pool_id = pool["UserPool"]["Id"].as_str().unwrap();

        let result = handler(&storage, json!({"UserPoolId": pool_id})).await;

        assert!(matches!(result, Err(AppError::InvalidParameter(_))));
        assert!(
            storage
                .get_user_pool(&pool_id.parse().unwrap())
                .await
                .is_some()
        );
    }

    #[tokio::test]
    async fn test_delete_user_pool_cascades_related_data() {
        let storage = Storage::new();

        // Create user pool
        let pool = create_user_pool::handler(&storage, json!({"PoolName": "cascade-test"}))
            .await
            .unwrap();
        let pool_id = pool["UserPool"]["Id"].as_str().unwrap().to_string();

        // Create client
        let client = create_user_pool_client::handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "ClientName": "test-client"
            }),
        )
        .await
        .unwrap();
        let client_id = client["UserPoolClient"]["ClientId"]
            .as_str()
            .unwrap()
            .to_string();

        // Create user
        let sign_up_result = sign_up::handler(
            &storage,
            json!({
                "ClientId": client_id,
                "Username": "testuser",
                "Password": "Password123!"
            }),
        )
        .await
        .unwrap();
        let user_sub = sign_up_result["UserSub"].as_str().unwrap();
        let user_id: uuid::Uuid = user_sub.parse().unwrap();

        // Create group
        create_group::handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "GroupName": "test-group"
            }),
        )
        .await
        .unwrap();

        // Delete the user pool
        let result = handler(&storage, json!({"UserPoolId": pool_id})).await;
        assert!(result.is_ok());

        // Verify all related data is cleaned up
        assert!(
            storage
                .get_user_pool(&pool_id.parse().unwrap())
                .await
                .is_none()
        );
        assert!(
            storage
                .get_user_pool_client(&client_id.parse().unwrap())
                .await
                .is_none()
        );
        assert!(storage.get_user(&user_id).await.is_none());
        assert!(
            storage
                .get_group(&pool_id.parse().unwrap(), &"test-group".to_string())
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn test_delete_user_pool_not_found() {
        let storage = Storage::new();

        let result = handler(&storage, json!({"UserPoolId": "local_nonexistent123"})).await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_delete_user_pool_missing_id() {
        let storage = Storage::new();

        let result = handler(&storage, json!({})).await;

        assert!(result.is_err());
    }
}
