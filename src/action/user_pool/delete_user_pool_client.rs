//! DeleteUserPoolClient API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_DeleteUserPoolClient.html>

use serde::Deserialize;
use serde_json::{Value, json};

use crate::{
    error::{AppError, Result},
    storage::Storage,
    types::{ClientId, UserPoolId},
};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Request {
    user_pool_id: UserPoolId,
    client_id: ClientId,
}

pub async fn handler(storage: &Storage, body: Value) -> Result<Value> {
    let req: Request = serde_json::from_value(body)
        .map_err(|e| AppError::InvalidParameter(format!("Invalid request: {}", e)))?;

    if !storage.user_pool_exists(&req.user_pool_id).await {
        return Err(AppError::UserPoolNotFound);
    }

    let client = storage
        .get_user_pool_client(&req.client_id)
        .await
        .ok_or(AppError::UserPoolClientNotFound)?;
    if client.user_pool_id != req.user_pool_id {
        return Err(AppError::UserPoolClientNotFound);
    }

    storage
        .delete_user_pool_client(&req.client_id)
        .await
        .ok_or(AppError::UserPoolClientNotFound)?;

    Ok(json!({}))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::user_pool::{create_user_pool, create_user_pool_client};
    use serde_json::json;

    #[tokio::test]
    async fn test_delete_user_pool_client_success() {
        let storage = Storage::new();

        // Create a user pool and client first
        let pool = create_user_pool::handler(&storage, json!({"PoolName": "test-pool"}))
            .await
            .unwrap();
        let pool_id = pool["UserPool"]["Id"].as_str().unwrap();

        let client = create_user_pool_client::handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "ClientName": "test-client"
            }),
        )
        .await
        .unwrap();
        let client_id = client["UserPoolClient"]["ClientId"].as_str().unwrap();

        // Delete the client
        let result = handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "ClientId": client_id
            }),
        )
        .await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), json!({}));

        // Verify it's deleted
        assert!(
            storage
                .get_user_pool_client(&client_id.parse().unwrap())
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn test_delete_user_pool_client_not_found() {
        let storage = Storage::new();

        let result = handler(
            &storage,
            json!({
                "UserPoolId": "local_pool123",
                "ClientId": "nonexistent123456789012345"
            }),
        )
        .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_delete_user_pool_client_pool_not_found() {
        let storage = Storage::new();

        let result = handler(
            &storage,
            json!({
                "UserPoolId": "local_pool123",
                "ClientId": "nonexistent123456789012345"
            }),
        )
        .await;

        assert!(matches!(result, Err(AppError::UserPoolNotFound)));
    }

    #[tokio::test]
    async fn test_delete_user_pool_client_wrong_pool() {
        let storage = Storage::new();

        let pool1 = create_user_pool::handler(&storage, json!({"PoolName": "pool-1"}))
            .await
            .unwrap();
        let pool1_id = pool1["UserPool"]["Id"].as_str().unwrap();
        let pool2 = create_user_pool::handler(&storage, json!({"PoolName": "pool-2"}))
            .await
            .unwrap();
        let pool2_id = pool2["UserPool"]["Id"].as_str().unwrap();

        let client = create_user_pool_client::handler(
            &storage,
            json!({
                "UserPoolId": pool1_id,
                "ClientName": "test-client"
            }),
        )
        .await
        .unwrap();
        let client_id = client["UserPoolClient"]["ClientId"].as_str().unwrap();

        let result = handler(
            &storage,
            json!({
                "UserPoolId": pool2_id,
                "ClientId": client_id
            }),
        )
        .await;

        assert!(matches!(result, Err(AppError::UserPoolClientNotFound)));
        assert!(
            storage
                .get_user_pool_client(&client_id.parse().unwrap())
                .await
                .is_some()
        );
    }
}
