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
