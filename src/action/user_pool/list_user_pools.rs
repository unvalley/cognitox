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
    next_token: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
struct Response {
    next_token: Option<String>,
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

    let max_results = req.max_results.unwrap_or(60) as usize;
    if max_results == 0 {
        return Err(crate::error::AppError::InvalidParameter(
            "MaxResults must be greater than 0".to_string(),
        ));
    }

    let mut pools = storage.list_user_pools().await;
    pools.sort_by(|a, b| a.id.as_str().cmp(b.id.as_str()));

    let start = req
        .next_token
        .as_deref()
        .map(|token| {
            token.parse::<usize>().map_err(|_| {
                crate::error::AppError::InvalidParameter("Invalid NextToken".to_string())
            })
        })
        .transpose()?
        .unwrap_or(0);

    if start > pools.len() {
        return Err(crate::error::AppError::InvalidParameter(
            "Invalid NextToken".to_string(),
        ));
    }

    let end = (start + max_results).min(pools.len());

    let user_pools = pools[start..end]
        .iter()
        .cloned()
        .map(UserPoolView::from)
        .collect();

    to_response_value(Response {
        next_token: (end < pools.len()).then(|| end.to_string()),
        user_pools,
    })
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

    #[tokio::test]
    async fn test_list_user_pools_with_pagination() {
        let storage = Storage::new();

        for name in ["pool-1", "pool-2", "pool-3"] {
            create_user_pool::handler(&storage, json!({"PoolName": name}))
                .await
                .unwrap();
        }

        let first = handler(&storage, json!({"MaxResults": 2})).await.unwrap();
        assert_eq!(first["UserPools"].as_array().unwrap().len(), 2);
        assert_eq!(first["NextToken"], "2");

        let second = handler(&storage, json!({"MaxResults": 2, "NextToken": "2"}))
            .await
            .unwrap();
        assert_eq!(second["UserPools"].as_array().unwrap().len(), 1);
        assert!(second["NextToken"].is_null());
    }
}
