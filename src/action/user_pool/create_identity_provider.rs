//! CreateIdentityProvider API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_CreateIdentityProvider.html>

use chrono::Utc;
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::HashMap;

use crate::{
    error::{AppError, Result},
    storage::Storage,
    types::{IdentityProvider, UserPoolId},
};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Request {
    user_pool_id: UserPoolId,
    provider_name: String,
    #[serde(default)]
    provider_type: Option<String>,
    #[serde(default)]
    provider_details: HashMap<String, String>,
    #[serde(default)]
    attribute_mapping: HashMap<String, String>,
    #[serde(default)]
    idp_identifiers: Vec<String>,
}

pub async fn handler(storage: &Storage, body: Value) -> Result<Value> {
    let req: Request = serde_json::from_value(body)
        .map_err(|e| AppError::InvalidParameter(format!("Invalid request: {}", e)))?;

    if req.provider_name.trim().is_empty() {
        return Err(AppError::InvalidParameter(
            "ProviderName must not be empty".to_string(),
        ));
    }

    storage
        .get_user_pool(&req.user_pool_id)
        .await
        .ok_or(AppError::UserPoolNotFound)?;

    if storage
        .get_identity_provider(&req.user_pool_id, &req.provider_name)
        .await
        .is_some()
    {
        return Err(AppError::IdentityProviderAlreadyExists);
    }

    let now = Utc::now();
    let provider = IdentityProvider {
        user_pool_id: req.user_pool_id,
        provider_name: req.provider_name,
        provider_type: req.provider_type.unwrap_or_else(|| "OIDC".to_string()),
        provider_details: req.provider_details,
        attribute_mapping: req.attribute_mapping,
        idp_identifiers: req.idp_identifiers,
        creation_date: now,
        last_modified_date: now,
    };
    let created = storage.create_identity_provider(provider).await;

    Ok(json!({
        "IdentityProvider": build_identity_provider_response(&created)
    }))
}

pub(crate) fn build_identity_provider_response(provider: &IdentityProvider) -> Value {
    json!({
        "UserPoolId": provider.user_pool_id,
        "ProviderName": provider.provider_name,
        "ProviderType": provider.provider_type,
        "ProviderDetails": provider.provider_details,
        "AttributeMapping": provider.attribute_mapping,
        "IdpIdentifiers": provider.idp_identifiers,
        "CreationDate": provider.creation_date.timestamp(),
        "LastModifiedDate": provider.last_modified_date.timestamp()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::user_pool::create_user_pool;
    use serde_json::json;

    #[tokio::test]
    async fn test_create_identity_provider_success() {
        let storage = Storage::new();

        let pool = create_user_pool::handler(&storage, json!({"PoolName": "test-pool"}))
            .await
            .unwrap();
        let user_pool_id = pool["UserPool"]["Id"].as_str().unwrap();

        let result = handler(
            &storage,
            json!({
                "UserPoolId": user_pool_id,
                "ProviderName": "MyProvider",
                "ProviderType": "OIDC"
            }),
        )
        .await
        .unwrap();

        assert_eq!(result["IdentityProvider"]["ProviderName"], "MyProvider");
        assert_eq!(result["IdentityProvider"]["ProviderType"], "OIDC");
    }

    #[tokio::test]
    async fn test_create_identity_provider_duplicate() {
        let storage = Storage::new();

        let pool = create_user_pool::handler(&storage, json!({"PoolName": "test-pool"}))
            .await
            .unwrap();
        let user_pool_id = pool["UserPool"]["Id"].as_str().unwrap();

        handler(
            &storage,
            json!({
                "UserPoolId": user_pool_id,
                "ProviderName": "MyProvider",
                "ProviderType": "OIDC"
            }),
        )
        .await
        .unwrap();

        let result = handler(
            &storage,
            json!({
                "UserPoolId": user_pool_id,
                "ProviderName": "MyProvider",
                "ProviderType": "OIDC"
            }),
        )
        .await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            AppError::IdentityProviderAlreadyExists
        ));
    }
}
