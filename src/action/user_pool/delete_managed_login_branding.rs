//! DeleteManagedLoginBranding API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_DeleteManagedLoginBranding.html>

use serde::Deserialize;
use serde_json::{Value, json};

use crate::{
    error::{AppError, Result},
    storage::Storage,
};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Request {
    managed_login_branding_id: String,
    user_pool_id: String,
}

pub async fn handler(storage: &Storage, body: Value) -> Result<Value> {
    let req: Request = serde_json::from_value(body)
        .map_err(|e| AppError::InvalidParameter(format!("Invalid request: {}", e)))?;

    // Validate user pool exists
    if storage.get_user_pool(&req.user_pool_id).await.is_none() {
        return Err(AppError::UserPoolNotFound);
    }

    // Get and validate branding
    let branding = storage
        .get_managed_login_branding(&req.managed_login_branding_id)
        .await
        .ok_or_else(|| {
            AppError::InvalidParameter("Managed login branding not found".to_string())
        })?;

    // Verify it belongs to the specified user pool
    if branding.user_pool_id != req.user_pool_id {
        return Err(AppError::InvalidParameter(
            "Branding does not belong to the specified user pool".to_string(),
        ));
    }

    storage
        .delete_managed_login_branding(&req.managed_login_branding_id)
        .await;

    Ok(json!({}))
}
