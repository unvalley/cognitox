//! ListUserPools API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_ListUserPools.html>

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{
    action::{
        io::{parse_request, to_response_value},
        pagination::{paginate, required_page_size},
    },
    error::Result,
    storage::Storage,
    types::{UserPool, UserPoolId},
};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Request {
    max_results: Option<i32>,
    next_token: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
struct Response {
    #[serde(skip_serializing_if = "Option::is_none")]
    next_token: Option<String>,
    user_pools: Vec<UserPoolView>,
}

/// `UserPoolDescriptionType`
#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
struct UserPoolView {
    id: UserPoolId,
    name: String,
    lambda_config: Value,
    last_modified_date: i64,
    creation_date: i64,
}

impl From<UserPool> for UserPoolView {
    fn from(pool: UserPool) -> Self {
        Self {
            id: pool.id,
            name: pool.name,
            lambda_config: pool.lambda_config.unwrap_or_else(|| json!({})),
            last_modified_date: pool.last_modified_date.timestamp(),
            creation_date: pool.creation_date.timestamp(),
        }
    }
}

pub async fn handler(storage: &Storage, body: Value) -> Result<Value> {
    let req: Request = parse_request(body)?;
    // Unlike the other list operations, ListUserPools requires MaxResults.
    let max_results = required_page_size(req.max_results, "maxResults", 1, 60)?;

    let mut pools = storage.list_user_pools().await;
    pools.sort_by(|a, b| a.id.as_str().cmp(b.id.as_str()));

    let page = paginate(pools.len(), max_results, req.next_token.as_deref())?;
    let user_pools = pools[page.start..page.end]
        .iter()
        .cloned()
        .map(UserPoolView::from)
        .collect();

    to_response_value(Response {
        next_token: page.next_token,
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

        let result = handler(&storage, json!({"MaxResults": 60})).await;

        assert!(result.is_ok());
        let body = result.unwrap();
        assert_eq!(body["UserPools"].as_array().unwrap().len(), 0);
        assert!(body.get("NextToken").is_none());
    }

    #[tokio::test]
    async fn test_list_user_pools_requires_max_results_in_range() {
        let storage = Storage::new();

        let message = |result: Result<Value>| match result {
            Err(crate::error::AppError::InvalidParameter(message)) => message,
            other => panic!("expected InvalidParameterException, got {other:?}"),
        };

        assert_eq!(
            message(handler(&storage, json!({})).await),
            "1 validation error detected: Value null at 'maxResults' failed to satisfy constraint: Member must not be null"
        );
        assert_eq!(
            message(handler(&storage, json!({"MaxResults": 61})).await),
            "1 validation error detected: Value '61' at 'maxResults' failed to satisfy constraint: Member must have value less than or equal to 60"
        );
        assert_eq!(
            message(handler(&storage, json!({"MaxResults": 0})).await),
            "1 validation error detected: Value '0' at 'maxResults' failed to satisfy constraint: Member must have value greater than or equal to 1"
        );
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

        let result = handler(&storage, json!({"MaxResults": 60})).await;

        assert!(result.is_ok());
        let body = result.unwrap();
        let pools = body["UserPools"].as_array().unwrap();
        assert_eq!(pools.len(), 2);
        // `UserPoolDescriptionType`: nothing but these members.
        let mut members: Vec<&str> = pools[0]
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        members.sort_unstable();
        assert_eq!(
            members,
            [
                "CreationDate",
                "Id",
                "LambdaConfig",
                "LastModifiedDate",
                "Name"
            ]
        );
        assert_eq!(pools[0]["LambdaConfig"], json!({}));
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
        // The last page carries no token at all.
        assert!(second.get("NextToken").is_none());
    }
}
