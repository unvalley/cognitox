//! DeleteManagedLoginBranding API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_DeleteManagedLoginBranding.html>

use serde::Deserialize;
use serde_json::{Value, json};

use crate::{
    error::{AppError, Result},
    storage::Storage,
    types::UserPoolId,
};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Request {
    managed_login_branding_id: String,
    user_pool_id: UserPoolId,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::user_pool::{create_managed_login_branding, create_user_pool};
    use serde_json::json;

    #[tokio::test]
    async fn test_delete_managed_login_branding_success() {
        let storage = Storage::new();

        let pool = create_user_pool::handler(&storage, json!({"PoolName": "test"}))
            .await
            .unwrap();
        let pool_id = pool["UserPool"]["Id"].as_str().unwrap();

        let branding = create_managed_login_branding::handler(
            &storage,
            json!({
                "UserPoolId": pool_id
            }),
        )
        .await
        .unwrap();
        let branding_id = branding["ManagedLoginBranding"]["ManagedLoginBrandingId"]
            .as_str()
            .unwrap();

        let result = handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "ManagedLoginBrandingId": branding_id
            }),
        )
        .await
        .unwrap();

        assert_eq!(result, json!({}));

        // Verify branding is deleted
        assert!(
            storage
                .get_managed_login_branding(&branding_id.to_string())
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn test_delete_managed_login_branding_not_found() {
        let storage = Storage::new();

        let pool = create_user_pool::handler(&storage, json!({"PoolName": "test"}))
            .await
            .unwrap();
        let pool_id = pool["UserPool"]["Id"].as_str().unwrap();

        let result = handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "ManagedLoginBrandingId": "nonexistent-branding-id"
            }),
        )
        .await;

        assert!(matches!(result, Err(AppError::InvalidParameter(_))));
    }

    #[tokio::test]
    async fn test_delete_managed_login_branding_user_pool_not_found() {
        let storage = Storage::new();

        let result = handler(
            &storage,
            json!({
                "UserPoolId": "us-east-1_nonexistent",
                "ManagedLoginBrandingId": "some-branding-id"
            }),
        )
        .await;

        assert!(matches!(result, Err(AppError::UserPoolNotFound)));
    }
}
