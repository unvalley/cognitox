//! CreateUserPoolDomain API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_CreateUserPoolDomain.html>

use serde::Deserialize;
use serde_json::{Value, json};

use crate::{
    error::{AppError, Result},
    storage::{DomainConflict, Storage},
    types::{CustomDomainConfig, DomainStatus, UserPoolDomain, UserPoolId},
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

    // Validate domain format (alphanumeric and hyphens only, 1-63 chars)
    if req.domain.is_empty() || req.domain.len() > 63 {
        return Err(AppError::InvalidParameter(
            "Domain must be between 1 and 63 characters".to_string(),
        ));
    }

    if !req
        .domain
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-')
    {
        return Err(AppError::InvalidParameter(
            "Domain must contain only alphanumeric characters and hyphens".to_string(),
        ));
    }

    // Check if user pool exists
    if storage.get_user_pool(&req.user_pool_id).await.is_none() {
        return Err(AppError::UserPoolNotFound);
    }

    let custom_domain_config = req.custom_domain_config.map(|c| CustomDomainConfig {
        certificate_arn: c.certificate_arn,
    });

    let cloud_front_distribution = if custom_domain_config.is_some() {
        // For custom domains, we'd normally create a CloudFront distribution
        // For emulation, we generate a fake distribution ID
        Some(format!("E{}", uuid::Uuid::new_v4().simple()))
    } else {
        None
    };

    let domain = UserPoolDomain {
        domain: req.domain,
        user_pool_id: req.user_pool_id,
        status: DomainStatus::Active, // Skip CREATING state for emulation
        version: Some("1".to_string()),
        s3_bucket: None,
        cloud_front_distribution,
        custom_domain_config,
        managed_login_version: req.managed_login_version,
    };

    // Uniqueness of the prefix and "one domain per pool" are checked
    // atomically with the insert.
    let created = storage
        .try_create_user_pool_domain(domain)
        .await
        .map_err(|conflict| match conflict {
            DomainConflict::DomainTaken => AppError::UserPoolDomainAlreadyExists,
            DomainConflict::PoolHasDomain => {
                AppError::InvalidParameter("User pool already has a domain configured".to_string())
            }
        })?;

    // Response only includes CloudFrontDomain for custom domains
    let mut response = json!({});
    if let Some(cf_dist) = &created.cloud_front_distribution {
        response["CloudFrontDomain"] = json!(format!("{}.cloudfront.net", cf_dist));
    }

    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::user_pool::create_user_pool;
    use serde_json::json;

    #[tokio::test]
    async fn test_create_user_pool_domain_success() {
        let storage = Storage::new();

        let pool = create_user_pool::handler(&storage, json!({"PoolName": "test-pool"}))
            .await
            .unwrap();
        let pool_id = pool["UserPool"]["Id"].as_str().unwrap();

        let result = handler(
            &storage,
            json!({
                "Domain": "test-domain",
                "UserPoolId": pool_id
            }),
        )
        .await;

        assert!(result.is_ok());
        // Standard domains don't return CloudFrontDomain
        assert_eq!(result.unwrap(), json!({}));

        // Verify domain was created
        let domain_prefix: String = "test-domain".to_string();
        assert!(storage.get_user_pool_domain(&domain_prefix).await.is_some());
    }

    #[tokio::test]
    async fn test_create_user_pool_domain_with_custom_config() {
        let storage = Storage::new();

        let pool = create_user_pool::handler(&storage, json!({"PoolName": "test-pool"}))
            .await
            .unwrap();
        let pool_id = pool["UserPool"]["Id"].as_str().unwrap();

        let result = handler(
            &storage,
            json!({
                "Domain": "custom-domain",
                "UserPoolId": pool_id,
                "CustomDomainConfig": {
                    "CertificateArn": "arn:aws:acm:us-east-1:123456789:certificate/abc"
                }
            }),
        )
        .await;

        assert!(result.is_ok());
        let body = result.unwrap();
        // Custom domains return CloudFrontDomain
        assert!(body["CloudFrontDomain"].as_str().is_some());
    }

    #[tokio::test]
    async fn test_create_user_pool_domain_pool_not_found() {
        let storage = Storage::new();

        let result = handler(
            &storage,
            json!({
                "Domain": "test-domain",
                "UserPoolId": "local_nonexistent123"
            }),
        )
        .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_create_user_pool_domain_already_exists() {
        let storage = Storage::new();

        let pool = create_user_pool::handler(&storage, json!({"PoolName": "test-pool"}))
            .await
            .unwrap();
        let pool_id = pool["UserPool"]["Id"].as_str().unwrap();

        // Create first domain
        handler(
            &storage,
            json!({
                "Domain": "test-domain",
                "UserPoolId": pool_id
            }),
        )
        .await
        .unwrap();

        // Create another pool and try to use same domain
        let pool2 = create_user_pool::handler(&storage, json!({"PoolName": "test-pool-2"}))
            .await
            .unwrap();
        let pool_id2 = pool2["UserPool"]["Id"].as_str().unwrap();

        let result = handler(
            &storage,
            json!({
                "Domain": "test-domain",
                "UserPoolId": pool_id2
            }),
        )
        .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_concurrent_create_domain_allows_only_one() {
        let storage = Storage::new();
        let pool_a = create_user_pool::handler(&storage, json!({"PoolName": "a"}))
            .await
            .unwrap();
        let pool_b = create_user_pool::handler(&storage, json!({"PoolName": "b"}))
            .await
            .unwrap();
        let pool_a = pool_a["UserPool"]["Id"].as_str().unwrap().to_string();
        let pool_b = pool_b["UserPool"]["Id"].as_str().unwrap().to_string();

        let request = |pool_id: &String| {
            handler(
                &storage,
                json!({ "Domain": "shared-prefix", "UserPoolId": pool_id }),
            )
        };
        let (first, second) = tokio::join!(request(&pool_a), request(&pool_b));
        assert_eq!(first.is_ok() as u8 + second.is_ok() as u8, 1);
        let err = if first.is_err() { first } else { second };
        assert!(matches!(err, Err(AppError::UserPoolDomainAlreadyExists)));

        // Exactly one pool owns the prefix and the loser has no dangling index.
        let owner = storage
            .get_user_pool_domain(&"shared-prefix".to_string())
            .await
            .unwrap()
            .user_pool_id;
        let loser = if owner.as_str() == pool_a {
            &pool_b
        } else {
            &pool_a
        };
        assert!(
            storage
                .get_user_pool_domain_by_user_pool_id(&loser.parse().unwrap())
                .await
                .is_none()
        );
    }
}
