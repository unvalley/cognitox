//! DeleteUserPoolDomain API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_DeleteUserPoolDomain.html>

use serde::Deserialize;
use serde_json::{Value, json};

use crate::{
    error::{AppError, Result},
    storage::Storage,
};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Request {
    domain: String,
    user_pool_id: String,
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
