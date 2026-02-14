//! DescribeUserPool API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_DescribeUserPool.html>

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    action::io::{parse_request, to_response_value},
    error::{AppError, Result},
    storage::Storage,
    types::{UserPool, UserPoolId},
};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Request {
    user_pool_id: UserPoolId,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
struct Response {
    user_pool: UserPoolView,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
struct UserPoolView {
    id: UserPoolId,
    name: String,
    creation_date: i64,
    last_modified_date: i64,
}

impl From<UserPool> for UserPoolView {
    fn from(pool: UserPool) -> Self {
        Self {
            id: pool.id,
            name: pool.name,
            creation_date: pool.creation_date.timestamp(),
            last_modified_date: pool.last_modified_date.timestamp(),
        }
    }
}

pub async fn handler(storage: &Storage, body: Value) -> Result<Value> {
    let req: Request = parse_request(body)?;

    let pool = storage
        .get_user_pool(&req.user_pool_id)
        .await
        .ok_or(AppError::UserPoolNotFound)?;

    to_response_value(Response {
        user_pool: pool.into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::user_pool::create_user_pool;
    use serde_json::json;

    #[tokio::test]
    async fn test_describe_user_pool_success() {
        let storage = Storage::new();

        // Create a user pool first
        let pool = create_user_pool::handler(&storage, json!({"PoolName": "test-pool"}))
            .await
            .unwrap();
        let pool_id = pool["UserPool"]["Id"].as_str().unwrap();

        // Describe the user pool
        let result = handler(&storage, json!({"UserPoolId": pool_id})).await;

        assert!(result.is_ok());
        let body = result.unwrap();
        assert_eq!(body["UserPool"]["Id"], pool_id);
        assert_eq!(body["UserPool"]["Name"], "test-pool");
        assert!(body["UserPool"]["CreationDate"].is_number());
        assert!(body["UserPool"]["LastModifiedDate"].is_number());
    }

    #[tokio::test]
    async fn test_describe_user_pool_not_found() {
        let storage = Storage::new();

        let result = handler(&storage, json!({"UserPoolId": "local_nonexistent123"})).await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_describe_user_pool_missing_id() {
        let storage = Storage::new();

        let result = handler(&storage, json!({})).await;

        assert!(result.is_err());
    }
}
