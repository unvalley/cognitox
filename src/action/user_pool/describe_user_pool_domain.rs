//! DescribeUserPoolDomain API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_DescribeUserPoolDomain.html>

use serde::Deserialize;
use serde_json::{Value, json};

use crate::{
    error::{AppError, Result},
    storage::Storage,
    types::DomainStatus,
};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Request {
    domain: String,
}

pub async fn handler(storage: &Storage, body: Value) -> Result<Value> {
    let req: Request = serde_json::from_value(body)
        .map_err(|e| AppError::InvalidParameter(format!("Invalid request: {}", e)))?;

    let domain = storage.get_user_pool_domain(&req.domain).await;

    match domain {
        Some(d) => {
            let status = match d.status {
                DomainStatus::Creating => "CREATING",
                DomainStatus::Active => "ACTIVE",
                DomainStatus::Deleting => "DELETING",
                DomainStatus::Updating => "UPDATING",
                DomainStatus::Failed => "FAILED",
            };

            let mut domain_description = json!({
                "Domain": d.domain,
                "UserPoolId": d.user_pool_id,
                "Status": status,
            });

            if let Some(version) = &d.version {
                domain_description["Version"] = json!(version);
            }

            if let Some(s3_bucket) = &d.s3_bucket {
                domain_description["S3Bucket"] = json!(s3_bucket);
            }

            if let Some(cf_dist) = &d.cloud_front_distribution {
                domain_description["CloudFrontDistribution"] = json!(cf_dist);
            }

            if let Some(config) = &d.custom_domain_config {
                domain_description["CustomDomainConfig"] = json!({
                    "CertificateArn": config.certificate_arn
                });
            }

            if let Some(mlv) = d.managed_login_version {
                domain_description["ManagedLoginVersion"] = json!(mlv);
            }

            Ok(json!({
                "DomainDescription": domain_description
            }))
        }
        None => {
            // AWS returns an empty DomainDescription when domain doesn't exist
            Ok(json!({
                "DomainDescription": {}
            }))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::user_pool::{create_user_pool, create_user_pool_domain};
    use serde_json::json;

    #[tokio::test]
    async fn test_describe_user_pool_domain_success() {
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

        // Describe the domain
        let result = handler(&storage, json!({"Domain": "test-domain"})).await;

        assert!(result.is_ok());
        let body = result.unwrap();
        assert_eq!(body["DomainDescription"]["Domain"], "test-domain");
        assert_eq!(body["DomainDescription"]["UserPoolId"], pool_id);
        assert_eq!(body["DomainDescription"]["Status"], "ACTIVE");
    }

    #[tokio::test]
    async fn test_describe_user_pool_domain_not_found() {
        let storage = Storage::new();

        // AWS returns empty DomainDescription for non-existent domains
        let result = handler(&storage, json!({"Domain": "nonexistent"})).await;

        assert!(result.is_ok());
        let body = result.unwrap();
        assert_eq!(body["DomainDescription"], json!({}));
    }

    #[tokio::test]
    async fn test_describe_user_pool_domain_with_custom_config() {
        let storage = Storage::new();

        let pool = create_user_pool::handler(&storage, json!({"PoolName": "test-pool"}))
            .await
            .unwrap();
        let pool_id = pool["UserPool"]["Id"].as_str().unwrap();

        // Create a domain with custom config
        create_user_pool_domain::handler(
            &storage,
            json!({
                "Domain": "custom-domain",
                "UserPoolId": pool_id,
                "CustomDomainConfig": {
                    "CertificateArn": "arn:aws:acm:us-east-1:123456789:certificate/abc"
                }
            }),
        )
        .await
        .unwrap();

        let result = handler(&storage, json!({"Domain": "custom-domain"})).await;

        assert!(result.is_ok());
        let body = result.unwrap();
        assert!(
            body["DomainDescription"]["CloudFrontDistribution"]
                .as_str()
                .is_some()
        );
        assert!(
            body["DomainDescription"]["CustomDomainConfig"]["CertificateArn"]
                .as_str()
                .is_some()
        );
    }
}
