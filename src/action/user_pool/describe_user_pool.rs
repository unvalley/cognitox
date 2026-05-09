//! DescribeUserPool API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_DescribeUserPool.html>

use serde::Deserialize;
use serde_json::{Value, json};

use crate::{
    action::{io::parse_request, user_pool::create_user_pool::build_user_pool_view},
    error::{AppError, Result},
    storage::Storage,
    types::UserPoolId,
};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Request {
    user_pool_id: UserPoolId,
}

pub async fn handler(storage: &Storage, body: Value) -> Result<Value> {
    let req: Request = parse_request(body)?;

    if !storage.user_pool_exists(&req.user_pool_id).await {
        return Err(AppError::UserPoolNotFound);
    }

    let estimated_number_of_users = storage.count_users(&req.user_pool_id).await;
    let user_pool = storage
        .with_user_pool(&req.user_pool_id, |pool| {
            build_user_pool_view(pool, estimated_number_of_users)
        })
        .await
        .ok_or(AppError::UserPoolNotFound)?;

    Ok(json!({
        "UserPool": user_pool
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::user_pool::create_user_pool;
    use serde_json::json;

    #[tokio::test]
    async fn test_describe_user_pool_success() {
        let storage = Storage::new();

        let pool = create_user_pool::handler(&storage, json!({"PoolName": "test-pool"}))
            .await
            .unwrap();
        let pool_id = pool["UserPool"]["Id"].as_str().unwrap();

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

    #[tokio::test]
    async fn test_describe_user_pool_returns_saved_configuration() {
        let storage = Storage::new();

        let pool = create_user_pool::handler(
            &storage,
            json!({
                "PoolName": "configured-pool",
                "AliasAttributes": ["email"],
                "MfaConfiguration": "OPTIONAL",
                "UserPoolTier": "ESSENTIALS"
            }),
        )
        .await
        .unwrap();
        let pool_id = pool["UserPool"]["Id"].as_str().unwrap();

        let body = handler(&storage, json!({"UserPoolId": pool_id}))
            .await
            .unwrap();

        assert_eq!(body["UserPool"]["AliasAttributes"], json!(["email"]));
        assert_eq!(body["UserPool"]["MfaConfiguration"], "OPTIONAL");
        assert_eq!(body["UserPool"]["UserPoolTier"], "ESSENTIALS");
    }
}
