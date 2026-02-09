//! TagResource API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_TagResource.html>

use std::collections::HashMap;

use serde::Deserialize;
use serde_json::{Value, json};

use crate::{
    error::{AppError, Result},
    storage::Storage,
};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Request {
    resource_arn: String,
    #[allow(dead_code)]
    tags: HashMap<String, String>,
}

pub async fn handler(storage: &Storage, body: Value) -> Result<Value> {
    let req: Request = serde_json::from_value(body)
        .map_err(|e| AppError::InvalidParameter(format!("Invalid request: {}", e)))?;

    // Extract user pool ID from ARN
    let pool_id = extract_pool_id_from_arn(&req.resource_arn)?;

    // Verify user pool exists
    let pool_id_parsed = pool_id
        .parse()
        .map_err(|e| AppError::InvalidParameter(format!("Invalid user pool ID in ARN: {}", e)))?;

    storage
        .get_user_pool(&pool_id_parsed)
        .await
        .ok_or(AppError::UserPoolNotFound)?;

    // Note: In a full implementation, we would store the tags.
    // For the emulator, we accept the request but don't persist tags.

    Ok(json!({}))
}

fn extract_pool_id_from_arn(arn: &str) -> Result<String> {
    if arn.starts_with("arn:") {
        let parts: Vec<&str> = arn.split('/').collect();
        if parts.len() >= 2 {
            Ok(parts[1].to_string())
        } else {
            Err(AppError::InvalidParameter(format!(
                "Invalid resource ARN format: {}",
                arn
            )))
        }
    } else {
        Ok(arn.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::user_pool::create_user_pool;
    use serde_json::json;

    #[tokio::test]
    async fn test_tag_resource_success() {
        let storage = Storage::new();

        let pool = create_user_pool::handler(&storage, json!({"PoolName": "test"}))
            .await
            .unwrap();
        let pool_id = pool["UserPool"]["Id"].as_str().unwrap();

        let arn = format!(
            "arn:aws:cognito-idp:us-east-1:123456789:userpool/{}",
            pool_id
        );

        let result = handler(
            &storage,
            json!({
                "ResourceArn": arn,
                "Tags": {
                    "Environment": "test",
                    "Team": "backend"
                }
            }),
        )
        .await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), json!({}));
    }

    #[tokio::test]
    async fn test_tag_resource_pool_not_found() {
        let storage = Storage::new();

        let result = handler(
            &storage,
            json!({
                "ResourceArn": "arn:aws:cognito-idp:us-east-1:123456789:userpool/local_nonexistent",
                "Tags": {
                    "Key": "Value"
                }
            }),
        )
        .await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AppError::UserPoolNotFound));
    }
}
