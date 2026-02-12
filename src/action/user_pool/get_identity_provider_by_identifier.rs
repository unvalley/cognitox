//! GetIdentityProviderByIdentifier API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_GetIdentityProviderByIdentifier.html>

use serde::Deserialize;
use serde_json::{Value, json};

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
    identifier: String,
}

pub async fn handler(storage: &Storage, body: Value) -> Result<Value> {
    let req: Request = serde_json::from_value(body)
        .map_err(|e| AppError::InvalidParameter(format!("Invalid request: {}", e)))?;

    storage
        .get_user_pool(&req.user_pool_id)
        .await
        .ok_or(AppError::UserPoolNotFound)?;

    let provider = storage
        .get_identity_provider_by_identifier(&req.user_pool_id, &req.identifier)
        .await
        .ok_or(AppError::IdentityProviderNotFound)?;

    Ok(json!({
        "IdentityProvider": build_identity_provider_response(&provider)
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::user_pool::{create_identity_provider, create_user_pool};
    use serde_json::json;

    #[tokio::test]
    async fn test_get_identity_provider_by_identifier_success() {
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
                "ProviderType": "OIDC",
                "IdpIdentifiers": ["my-provider-id"]
            }),
        )
        .await
        .unwrap();

        let result = handler(
            &storage,
            json!({
                "UserPoolId": user_pool_id,
                "Identifier": "my-provider-id"
            }),
        )
        .await
        .unwrap();

        assert_eq!(result["IdentityProvider"]["ProviderName"], "MyProvider");
    }
}
