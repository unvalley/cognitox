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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::user_pool::{
        create_managed_login_branding, create_user_pool, create_user_pool_client,
    };
    use serde_json::json;

    #[tokio::test]
    async fn test_describe_managed_login_branding_by_client_fallback_to_pool() {
        let storage = Storage::new();

        let pool = create_user_pool::handler(&storage, json!({"PoolName": "test"}))
            .await
            .unwrap();
        let pool_id = pool["UserPool"]["Id"].as_str().unwrap();

        let client = create_user_pool_client::handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "ClientName": "test"
            }),
        )
        .await
        .unwrap();
        let client_id = client["UserPoolClient"]["ClientId"].as_str().unwrap();

        // Create branding without client_id (pool default)
        create_managed_login_branding::handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "Settings": {
                    "PageTitle": "Pool Default"
                }
            }),
        )
        .await
        .unwrap();

        // Query by client should fall back to pool branding
        let result = handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "ClientId": client_id
            }),
        )
        .await
        .unwrap();

        assert_eq!(
            result["ManagedLoginBranding"]["Settings"]["PageTitle"],
            "Pool Default"
        );
    }

    #[tokio::test]
    async fn test_describe_managed_login_branding_by_client_not_found() {
        let storage = Storage::new();

        let pool = create_user_pool::handler(&storage, json!({"PoolName": "test"}))
            .await
            .unwrap();
        let pool_id = pool["UserPool"]["Id"].as_str().unwrap();

        let client = create_user_pool_client::handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "ClientName": "test"
            }),
        )
        .await
        .unwrap();
        let client_id = client["UserPoolClient"]["ClientId"].as_str().unwrap();

        // No branding exists
        let result = handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "ClientId": client_id
            }),
        )
        .await;

        assert!(matches!(result, Err(AppError::InvalidParameter(_))));
    }

    #[tokio::test]
    async fn test_describe_managed_login_branding_by_client_wrong_pool() {
        let storage = Storage::new();

        let pool1 = create_user_pool::handler(&storage, json!({"PoolName": "test1"}))
            .await
            .unwrap();
        let pool1_id = pool1["UserPool"]["Id"].as_str().unwrap();

        let pool2 = create_user_pool::handler(&storage, json!({"PoolName": "test2"}))
            .await
            .unwrap();
        let pool2_id = pool2["UserPool"]["Id"].as_str().unwrap();

        let client = create_user_pool_client::handler(
            &storage,
            json!({
                "UserPoolId": pool1_id,
                "ClientName": "test"
            }),
        )
        .await
        .unwrap();
        let client_id = client["UserPoolClient"]["ClientId"].as_str().unwrap();

        // Try to use client from pool1 with pool2
        let result = handler(
            &storage,
            json!({
                "UserPoolId": pool2_id,
                "ClientId": client_id
            }),
        )
        .await;

        assert!(matches!(result, Err(AppError::UserPoolClientNotFound)));
    }
}
