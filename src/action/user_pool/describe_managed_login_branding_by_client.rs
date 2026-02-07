//! DescribeManagedLoginBrandingByClient API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_DescribeManagedLoginBrandingByClient.html>

use serde::Deserialize;
use serde_json::{Value, json};

use super::create_managed_login_branding::build_branding_response;
use crate::{
    error::{AppError, Result},
    storage::Storage,
    types::{ClientId, UserPoolId},
};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Request {
    client_id: ClientId,
    user_pool_id: UserPoolId,
}

pub async fn handler(storage: &Storage, body: Value) -> Result<Value> {
    let req: Request = serde_json::from_value(body)
        .map_err(|e| AppError::InvalidParameter(format!("Invalid request: {}", e)))?;

    // Validate user pool exists
    if storage.get_user_pool(&req.user_pool_id).await.is_none() {
        return Err(AppError::UserPoolNotFound);
    }

    // Validate client exists and belongs to user pool
    let client = storage
        .get_user_pool_client(&req.client_id)
        .await
        .ok_or(AppError::UserPoolClientNotFound)?;

    if client.user_pool_id != req.user_pool_id {
        return Err(AppError::UserPoolClientNotFound);
    }

    // Try to get client-specific branding first
    let branding = storage
        .get_managed_login_branding_by_client(&req.client_id)
        .await
        // Fall back to user pool default branding
        .or(storage
            .get_managed_login_branding_by_user_pool(&req.user_pool_id)
            .await)
        .ok_or_else(|| AppError::InvalidParameter("No managed login branding found".to_string()))?;

    Ok(json!({
        "ManagedLoginBranding": build_branding_response(&branding)
    }))
}
