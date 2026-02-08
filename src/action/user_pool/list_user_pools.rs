//! ListUserPools API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_ListUserPools.html>

use serde::Deserialize;
use serde_json::{Value, json};

use crate::{
    error::{AppError, Result},
    storage::Storage,
};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Request {
    max_results: Option<u32>,
    #[allow(dead_code)]
    next_token: Option<String>,
}

pub async fn handler(storage: &Storage, body: Value) -> Result<Value> {
    let req: Request = serde_json::from_value(body)
        .map_err(|e| AppError::InvalidParameter(format!("Invalid request: {}", e)))?;

    let pools = storage.list_user_pools().await;
    let max_results = req.max_results.unwrap_or(60) as usize;

    let user_pools: Vec<_> = pools
        .into_iter()
        .take(max_results)
        .map(|p| {
            json!({
                "Id": p.id,
                "Name": p.name,
                "CreationDate": p.creation_date.timestamp(),
                "LastModifiedDate": p.last_modified_date.timestamp()
            })
        })
        .collect();

    Ok(json!({
        "UserPools": user_pools
    }))
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
