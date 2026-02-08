//! DeleteUserPoolDomain API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_DeleteUserPoolDomain.html>

use serde::Deserialize;
use serde_json::{Value, json};

use crate::{
    error::{AppError, Result},
    storage::Storage,
    types::UserPoolId,
};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Request {
    domain: String,
    user_pool_id: UserPoolId,
}

pub async fn handler(storage: &Storage, body: Value) -> Result<Value> {
    let req: Request = serde_json::from_value(body)
        .map_err(|e| AppError::InvalidParameter(format!("Invalid request: {}", e)))?;

    // Check if domain exists
    let existing = storage.get_user_pool_domain(&req.domain).await;

    match existing {
        Some(domain) => {
            // Verify the domain belongs to the specified user pool
            if domain.user_pool_id != req.user_pool_id {
                return Err(AppError::InvalidParameter(
                    "Domain does not belong to the specified user pool".to_string(),
                ));
            }

            storage.delete_user_pool_domain(&req.domain).await;
            Ok(json!({}))
        }
        None => Err(AppError::UserPoolDomainNotFound),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::user_pool::{create_user_pool, create_user_pool_domain};
    use serde_json::json;

    #[tokio::test]
    async fn test_delete_user_pool_domain_success() {
        let storage = Storage::new();

        let pool = create_user_pool::handler(&storage, json!({"PoolName": "test-pool"}))
            .await
            .unwrap();
        let pool_id = pool["UserPool"]["Id"].as_str().unwrap();

        // Create a domain
        create_user_pool_domain::handler(
            &storage,
            json!({
                "Domain": "test-domain",
                "UserPoolId": pool_id
            }),
        )
        .await
        .unwrap();

        // Delete the domain
        let result = handler(
            &storage,
            json!({
                "Domain": "test-domain",
                "UserPoolId": pool_id
            }),
        )
        .await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), json!({}));

        // Verify it's deleted
        let domain_prefix: String = "test-domain".to_string();
        assert!(storage.get_user_pool_domain(&domain_prefix).await.is_none());
    }

    #[tokio::test]
    async fn test_delete_user_pool_domain_not_found() {
        let storage = Storage::new();

        let result = handler(
            &storage,
            json!({
                "Domain": "nonexistent-domain",
                "UserPoolId": "local_pool123"
            }),
        )
        .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_delete_user_pool_domain_wrong_pool() {
        let storage = Storage::new();

        // Create first pool and domain
        let pool1 = create_user_pool::handler(&storage, json!({"PoolName": "pool-1"}))
            .await
            .unwrap();
        let pool_id1 = pool1["UserPool"]["Id"].as_str().unwrap();

        create_user_pool_domain::handler(
            &storage,
            json!({
                "Domain": "domain-1",
                "UserPoolId": pool_id1
            }),
        )
        .await
        .unwrap();

        // Create second pool
        let pool2 = create_user_pool::handler(&storage, json!({"PoolName": "pool-2"}))
            .await
            .unwrap();
        let pool_id2 = pool2["UserPool"]["Id"].as_str().unwrap();

        // Try to delete domain-1 with pool-2's ID
        let result = handler(
            &storage,
            json!({
                "Domain": "domain-1",
                "UserPoolId": pool_id2
            }),
        )
        .await;

        assert!(result.is_err());
    }
}
