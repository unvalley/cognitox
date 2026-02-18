//! UpdateIdentityProvider API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_UpdateIdentityProvider.html>

use chrono::Utc;
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::HashMap;

use crate::{
    action::user_pool::create_identity_provider::build_identity_provider_response,
    error::{AppError, Result},
    storage::Storage,
    types::UserPoolId,
};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Request {
    user_pool_id: UserPoolId,
    provider_name: String,
    #[serde(default)]
    provider_type: Option<String>,
    #[serde(default)]
    provider_details: Option<HashMap<String, String>>,
    #[serde(default)]
    attribute_mapping: Option<HashMap<String, String>>,
    #[serde(default)]
    idp_identifiers: Option<Vec<String>>,
}

pub async fn handler(storage: &Storage, body: Value) -> Result<Value> {
    let req: Request = serde_json::from_value(body)
        .map_err(|e| AppError::InvalidParameter(format!("Invalid request: {}", e)))?;

    storage
        .get_user_pool(&req.user_pool_id)
        .await
        .ok_or(AppError::UserPoolNotFound)?;

    let mut provider = storage
        .get_identity_provider(&req.user_pool_id, &req.provider_name)
        .await
        .ok_or(AppError::IdentityProviderNotFound)?;

    if let Some(provider_type) = req.provider_type {
        provider.provider_type = provider_type;
    }
    if let Some(provider_details) = req.provider_details {
        provider.provider_details = provider_details;
    }
    if let Some(attribute_mapping) = req.attribute_mapping {
        provider.attribute_mapping = attribute_mapping;
    }
    if let Some(idp_identifiers) = req.idp_identifiers {
        provider.idp_identifiers = idp_identifiers;
    }
    provider.last_modified_date = Utc::now();

    let updated = storage
        .update_identity_provider(provider)
        .await
        .ok_or(AppError::IdentityProviderNotFound)?;

    Ok(json!({
        "IdentityProvider": build_identity_provider_response(&updated)
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::user_pool::{create_identity_provider, create_user_pool};
    use serde_json::json;

    #[tokio::test]
    async fn test_update_identity_provider_success() {
        let storage = Storage::new();

        let pool = create_user_pool::handler(&storage, json!({"PoolName": "test-pool"}))
            .await
            .unwrap();
        let user_pool_id = pool["UserPool"]["Id"].as_str().unwrap();

        create_identity_provider::handler(
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
                "ProviderType": "SAML"
            }),
        )
        .await
        .unwrap();

        assert_eq!(result["IdentityProvider"]["ProviderName"], "MyProvider");
        assert_eq!(result["IdentityProvider"]["ProviderType"], "SAML");
    }
}
