//! DeleteIdentityProvider API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_DeleteIdentityProvider.html>

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
    user_pool_id: UserPoolId,
    provider_name: String,
}

pub async fn handler(storage: &Storage, body: Value) -> Result<Value> {
    let req: Request = serde_json::from_value(body)
        .map_err(|e| AppError::InvalidParameter(format!("Invalid request: {}", e)))?;

    storage
        .get_user_pool(&req.user_pool_id)
        .await
        .ok_or(AppError::UserPoolNotFound)?;

    storage
        .delete_identity_provider(&req.user_pool_id, &req.provider_name)
        .await
        .ok_or(AppError::IdentityProviderNotFound)?;

    Ok(json!({}))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::user_pool::{create_identity_provider, create_user_pool};
    use serde_json::json;

    #[tokio::test]
    async fn test_delete_identity_provider_success() {
        let storage = Storage::new();

        let pool = create_user_pool::handler(&storage, json!({"PoolName": "test-pool"}))
            .await
            .unwrap();
        let user_pool_id = pool["UserPool"]["Id"].as_str().unwrap();

        create_identity_provider::handler(
            &storage,
            json!({
                "UserPoolId": user_pool_id,
                "ProviderName": "MyProvider"
            }),
        )
        .await
        .unwrap();

        let result = handler(
            &storage,
            json!({
                "UserPoolId": user_pool_id,
                "ProviderName": "MyProvider"
            }),
        )
        .await
        .unwrap();

        assert_eq!(result, json!({}));
    }

    #[tokio::test]
    async fn test_delete_identity_provider_not_found() {
        let storage = Storage::new();

        let pool = create_user_pool::handler(&storage, json!({"PoolName": "test-pool"}))
            .await
            .unwrap();
        let user_pool_id = pool["UserPool"]["Id"].as_str().unwrap();

        let result = handler(
            &storage,
            json!({
                "UserPoolId": user_pool_id,
                "ProviderName": "MissingProvider"
            }),
        )
        .await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            AppError::IdentityProviderNotFound
        ));
    }
}
