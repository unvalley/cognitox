//! DeleteUserPool API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_DeleteUserPool.html>

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    action::io::{parse_request, to_response_value},
    error::{AppError, Result},
    storage::Storage,
    types::UserPoolId,
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

    storage
        .delete_user_pool(&req.user_pool_id)
        .await
        .ok_or(AppError::UserPoolNotFound)?;

    to_response_value(Response {})
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::user_pool::create_user_pool;
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
