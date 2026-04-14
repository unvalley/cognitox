//! ListIdentityProviders API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_ListIdentityProviders.html>

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
    max_results: Option<u32>,
    next_token: Option<String>,
}

pub async fn handler(storage: &Storage, body: Value) -> Result<Value> {
    let req: Request = serde_json::from_value(body)
        .map_err(|e| AppError::InvalidParameter(format!("Invalid request: {}", e)))?;

    storage
        .get_user_pool(&req.user_pool_id)
        .await
        .ok_or(AppError::UserPoolNotFound)?;

    let mut providers = storage.list_identity_providers(&req.user_pool_id).await;
    providers.sort_by(|a, b| a.provider_name.cmp(&b.provider_name));

    let max_results = req.max_results.unwrap_or(60) as usize;
    if max_results == 0 {
        return Err(AppError::InvalidParameter(
            "MaxResults must be greater than 0".to_string(),
        ));
    }

    let start = req
        .next_token
        .as_deref()
        .map(|token| {
            token
                .parse::<usize>()
                .map_err(|_| AppError::InvalidParameter("Invalid NextToken".to_string()))
        })
        .transpose()?
        .unwrap_or(0);

    if start > providers.len() {
        return Err(AppError::InvalidParameter("Invalid NextToken".to_string()));
    }

    let end = (start + max_results).min(providers.len());
    let list: Vec<Value> = providers[start..end]
        .iter()
        .map(build_identity_provider_response)
        .collect();

    Ok(json!({
        "Providers": list,
        "NextToken": if end < providers.len() {
            Value::String(end.to_string())
        } else {
            Value::Null
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::user_pool::{create_identity_provider, create_user_pool};
    use serde_json::json;

    #[tokio::test]
    async fn test_list_identity_providers_success() {
        let storage = Storage::new();

        let pool = create_user_pool::handler(&storage, json!({"PoolName": "test-pool"}))
            .await
            .unwrap();
        let user_pool_id = pool["UserPool"]["Id"].as_str().unwrap();

        create_identity_provider::handler(
            &storage,
            json!({
                "UserPoolId": user_pool_id,
                "ProviderName": "ProviderA",
                "ProviderType": "OIDC"
            }),
        )
        .await
        .unwrap();
        create_identity_provider::handler(
            &storage,
            json!({
                "UserPoolId": user_pool_id,
                "ProviderName": "ProviderB",
                "ProviderType": "SAML"
            }),
        )
        .await
        .unwrap();

        let result = handler(
            &storage,
            json!({
                "UserPoolId": user_pool_id
            }),
        )
        .await
        .unwrap();

        assert_eq!(result["Providers"].as_array().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn test_list_identity_providers_with_pagination() {
        let storage = Storage::new();

        let pool = create_user_pool::handler(&storage, json!({"PoolName": "test-pool"}))
            .await
            .unwrap();
        let user_pool_id = pool["UserPool"]["Id"].as_str().unwrap();

        for i in 1..=3 {
            create_identity_provider::handler(
                &storage,
                json!({
                    "UserPoolId": user_pool_id,
                    "ProviderName": format!("Provider{}", i)
                }),
            )
            .await
            .unwrap();
        }

        let first = handler(
            &storage,
            json!({
                "UserPoolId": user_pool_id,
                "MaxResults": 2
            }),
        )
        .await
        .unwrap();

        assert_eq!(first["Providers"].as_array().unwrap().len(), 2);
        assert!(first["NextToken"].as_str().is_some());
    }
}
