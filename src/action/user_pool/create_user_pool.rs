//! CreateUserPool API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_CreateUserPool.html>

use chrono::Utc;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::{
    error::{AppError, Result},
    storage::Storage,
    types::{UserPool, UserPoolId},
    validation::validate_pool_name,
};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Request {
    pool_name: String,
}

pub async fn handler(storage: &Storage, body: Value) -> Result<Value> {
    let req: Request = serde_json::from_value(body)
        .map_err(|e| AppError::InvalidParameter(format!("Invalid request: {}", e)))?;

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

    Ok(json!({
        "UserPool": {
            "Id": created.id,
            "Name": created.name,
            "CreationDate": created.creation_date.timestamp(),
            "LastModifiedDate": created.last_modified_date.timestamp()
        }
    }))
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
