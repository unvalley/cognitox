//! UpdateUserPoolDomain API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_UpdateUserPoolDomain.html>

use serde::Deserialize;
use serde_json::{Value, json};

use crate::{
    error::{AppError, Result},
    storage::Storage,
    types::{CustomDomainConfig, UserPoolId},
};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Request {
    domain: String,
    user_pool_id: UserPoolId,
    custom_domain_config: Option<CustomDomainConfigInput>,
    managed_login_version: Option<i32>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct CustomDomainConfigInput {
    certificate_arn: String,
}

pub async fn handler(storage: &Storage, body: Value) -> Result<Value> {
    let req: Request = serde_json::from_value(body)
        .map_err(|e| AppError::InvalidParameter(format!("Invalid request: {}", e)))?;

    // Get existing domain
    let existing = storage.get_user_pool_domain(&req.domain).await;

    match existing {
        Some(mut domain) => {
            // Verify the domain belongs to the specified user pool
            if domain.user_pool_id != req.user_pool_id {
                return Err(AppError::InvalidParameter(
                    "Domain does not belong to the specified user pool".to_string(),
                ));
            }

            // Update custom domain config if provided
            if let Some(config) = req.custom_domain_config {
                domain.custom_domain_config = Some(CustomDomainConfig {
                    certificate_arn: config.certificate_arn,
                });

                // If switching to custom domain, generate CloudFront distribution
                if domain.cloud_front_distribution.is_none() {
                    domain.cloud_front_distribution =
                        Some(format!("E{}", uuid::Uuid::now_v7().simple()));
                }
            }

            // Update managed login version if provided
            if let Some(mlv) = req.managed_login_version {
                domain.managed_login_version = Some(mlv);
            }

            // Increment version
            let new_version = domain
                .version
                .as_ref()
                .and_then(|v| v.parse::<i32>().ok())
                .unwrap_or(0)
                + 1;
            domain.version = Some(new_version.to_string());

            let updated = storage.update_user_pool_domain(domain).await;

            match updated {
                Some(d) => {
                    let mut response = json!({});
                    if let Some(cf_dist) = &d.cloud_front_distribution {
                        response["CloudFrontDomain"] = json!(format!("{}.cloudfront.net", cf_dist));
                    }
                    Ok(response)
                }
                None => Err(AppError::Internal("Failed to update domain".to_string())),
            }
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
    async fn test_update_user_pool_domain_success() {
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

        // Update with managed login version
        let result = handler(
            &storage,
            json!({
                "Domain": "test-domain",
                "UserPoolId": pool_id,
                "ManagedLoginVersion": 2
            }),
        )
        .await;

        assert!(result.is_ok());

        // Verify the update
        let domain_prefix: String = "test-domain".to_string();
        let domain = storage.get_user_pool_domain(&domain_prefix).await.unwrap();
        assert_eq!(domain.managed_login_version, Some(2));
        assert_eq!(domain.version, Some("2".to_string())); // Version incremented
    }

    #[tokio::test]
    async fn test_update_user_pool_domain_add_custom_config() {
        let storage = Storage::new();

        let pool = create_user_pool::handler(&storage, json!({"PoolName": "test-pool"}))
            .await
            .unwrap();
        let pool_id = pool["UserPool"]["Id"].as_str().unwrap();

        // Create a standard domain
        create_user_pool_domain::handler(
            &storage,
            json!({
                "Domain": "test-domain",
                "UserPoolId": pool_id
            }),
        )
        .await
        .unwrap();

        // Update to add custom domain config
        let result = handler(
            &storage,
            json!({
                "Domain": "test-domain",
                "UserPoolId": pool_id,
                "CustomDomainConfig": {
                    "CertificateArn": "arn:aws:acm:us-east-1:123456789:certificate/abc"
                }
            }),
        )
        .await;

        assert!(result.is_ok());
        let body = result.unwrap();
        // Should now have CloudFrontDomain
        assert!(body["CloudFrontDomain"].as_str().is_some());
    }

    #[tokio::test]
    async fn test_update_user_pool_domain_not_found() {
        let storage = Storage::new();

        let result = handler(
            &storage,
            json!({
                "Domain": "nonexistent",
                "UserPoolId": "local_pool123",
                "ManagedLoginVersion": 2
            }),
        )
        .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_update_user_pool_domain_wrong_pool() {
        let storage = Storage::new();

        // Create pool and domain
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

        // Create another pool
        let pool2 = create_user_pool::handler(&storage, json!({"PoolName": "pool-2"}))
            .await
            .unwrap();
        let pool_id2 = pool2["UserPool"]["Id"].as_str().unwrap();

        // Try to update domain-1 with pool-2's ID
        let result = handler(
            &storage,
            json!({
                "Domain": "domain-1",
                "UserPoolId": pool_id2,
                "ManagedLoginVersion": 2
            }),
        )
        .await;

        assert!(result.is_err());
    }
}
