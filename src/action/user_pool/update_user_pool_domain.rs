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
                        Some(format!("E{}", uuid::Uuid::new_v4().simple()));
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
