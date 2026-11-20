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
    let req: Request = crate::action::io::parse_request(body)?;

    // A domain that does not exist and a domain of another user pool get
    // the same answer.
    let no_such_domain =
        || AppError::InvalidParameter("No such domain or user pool exists.".to_string());

    let domain = storage
        .get_user_pool_domain(&req.domain)
        .await
        .ok_or_else(no_such_domain)?;
    if domain.user_pool_id != req.user_pool_id {
        return Err(no_such_domain());
    }

    storage.delete_user_pool_domain(&req.domain).await;
    Ok(json!({}))
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

        assert!(matches!(
            result,
            Err(AppError::InvalidParameter(message))
                if message == "No such domain or user pool exists."
        ));
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

        // Indistinguishable from a domain that does not exist.
        assert!(matches!(
            result,
            Err(AppError::InvalidParameter(message))
                if message == "No such domain or user pool exists."
        ));
        assert!(
            storage
                .get_user_pool_domain(&"domain-1".to_string())
                .await
                .is_some()
        );
    }
}
