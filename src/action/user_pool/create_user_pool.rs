//! CreateUserPool API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_CreateUserPool.html>

use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    action::io::{parse_request, to_response_value},
    error::Result,
    storage::Storage,
    types::{UserPool, UserPoolId},
    validation::validate_pool_name,
};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Request {
    pool_name: String,
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

pub async fn handler(storage: &Storage, body: Value) -> Result<Value> {
    let req: Request = parse_request(body)?;

    // Validate input
    validate_pool_name(&req.pool_name)?;

    let now = Utc::now();
    let pool_id = UserPoolId::new_local();

    let pool = UserPool {
        id: pool_id,
        name: req.pool_name,
        creation_date: now,
        last_modified_date: now,
    };

    let created = storage.create_user_pool(pool).await;

    to_response_value(Response {
        user_pool: UserPoolView {
            id: created.id,
            name: created.name,
            creation_date: created.creation_date.timestamp(),
            last_modified_date: created.last_modified_date.timestamp(),
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[tokio::test]
    async fn test_create_user_pool_success() {
        let storage = Storage::new();

        let result = handler(&storage, json!({"PoolName": "test-pool"})).await;

        assert!(result.is_ok());
        let body = result.unwrap();
        assert!(body["UserPool"]["Id"].as_str().is_some());
        assert_eq!(body["UserPool"]["Name"], "test-pool");
    }

    #[tokio::test]
    async fn test_create_user_pool_empty_name() {
        let storage = Storage::new();

        let result = handler(&storage, json!({"PoolName": ""})).await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_create_user_pool_missing_name() {
        let storage = Storage::new();

        let result = handler(&storage, json!({})).await;

        assert!(result.is_err());
    }
}
