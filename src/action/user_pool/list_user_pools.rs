//! ListUserPools API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_ListUserPools.html>

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    action::io::{parse_request, to_response_value},
    error::Result,
    storage::Storage,
    types::{UserPool, UserPoolId},
};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Request {
    max_results: Option<u32>,
    #[allow(dead_code)]
    next_token: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
struct Response {
    user_pools: Vec<UserPoolView>,
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

    let pools = storage.list_user_pools().await;
    let max_results = req.max_results.unwrap_or(60) as usize;

    let user_pools = pools
        .into_iter()
        .take(max_results)
        .map(UserPoolView::from)
        .collect();

    to_response_value(Response { user_pools })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::user_pool::create_user_pool;
    use serde_json::json;

    #[tokio::test]
    async fn test_list_user_pools_empty() {
        let storage = Storage::new();

        let result = handler(&storage, json!({})).await;

        assert!(result.is_ok());
        let body = result.unwrap();
        assert_eq!(body["UserPools"].as_array().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn test_list_user_pools_success() {
        let storage = Storage::new();

        // Create some user pools
        create_user_pool::handler(&storage, json!({"PoolName": "pool-1"}))
            .await
            .unwrap();
        create_user_pool::handler(&storage, json!({"PoolName": "pool-2"}))
            .await
            .unwrap();

        let result = handler(&storage, json!({})).await;

        assert!(result.is_ok());
        let body = result.unwrap();
        assert_eq!(body["UserPools"].as_array().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn test_list_user_pools_with_max_results() {
        let storage = Storage::new();

        // Create three user pools
        create_user_pool::handler(&storage, json!({"PoolName": "pool-1"}))
            .await
            .unwrap();
        create_user_pool::handler(&storage, json!({"PoolName": "pool-2"}))
            .await
            .unwrap();
        create_user_pool::handler(&storage, json!({"PoolName": "pool-3"}))
            .await
            .unwrap();

        let result = handler(&storage, json!({"MaxResults": 2})).await;

        assert!(result.is_ok());
        let body = result.unwrap();
        assert_eq!(body["UserPools"].as_array().unwrap().len(), 2);
    }
}
