//! ListIdentityProviders API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_ListIdentityProviders.html>

use serde::Deserialize;
use serde_json::{Value, json};

use crate::{
    action::pagination::{page_size, paginate},
    error::{AppError, Result},
    storage::Storage,
    types::UserPoolId,
};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Request {
    user_pool_id: UserPoolId,
    max_results: Option<i32>,
    next_token: Option<String>,
}

pub async fn handler(storage: &Storage, body: Value) -> Result<Value> {
    let req: Request = crate::action::io::parse_request(body)?;
    let max_results = page_size(req.max_results, "maxResults", 0, 60)?;

    storage
        .get_user_pool(&req.user_pool_id)
        .await
        .ok_or(AppError::UserPoolNotFound)?;

    let mut providers = storage.list_identity_providers(&req.user_pool_id).await;
    providers.sort_by(|a, b| a.provider_name.cmp(&b.provider_name));

    let page = paginate(providers.len(), max_results, req.next_token.as_deref())?;
    // `ProviderDescription`: the listing leaves out the provider's details.
    let list: Vec<Value> = providers[page.start..page.end]
        .iter()
        .map(|provider| {
            json!({
                "ProviderName": provider.provider_name,
                "ProviderType": provider.provider_type,
                "LastModifiedDate": provider.last_modified_date.timestamp(),
                "CreationDate": provider.creation_date.timestamp()
            })
        })
        .collect();

    let mut response = json!({
        "Providers": list
    });
    if let Some(next_token) = page.next_token {
        response["NextToken"] = json!(next_token);
    }

    Ok(response)
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

        let providers = result["Providers"].as_array().unwrap();
        assert_eq!(providers.len(), 2);
        assert!(result.get("NextToken").is_none());

        // `ProviderDescription`: name, type, and dates, without the details
        // DescribeIdentityProvider returns.
        let mut members: Vec<&str> = providers[0]
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        members.sort_unstable();
        assert_eq!(
            members,
            [
                "CreationDate",
                "LastModifiedDate",
                "ProviderName",
                "ProviderType"
            ]
        );
        assert_eq!(providers[0]["ProviderName"], "ProviderA");
        assert_eq!(providers[0]["ProviderType"], "OIDC");
    }

    #[tokio::test]
    async fn test_list_identity_providers_max_results_is_bounded() {
        let storage = Storage::new();

        let pool = create_user_pool::handler(&storage, json!({"PoolName": "test-pool"}))
            .await
            .unwrap();
        let user_pool_id = pool["UserPool"]["Id"].as_str().unwrap();

        let result = handler(
            &storage,
            json!({"UserPoolId": user_pool_id, "MaxResults": 61}),
        )
        .await;
        assert!(matches!(
            result,
            Err(AppError::InvalidParameter(message))
                if message == "1 validation error detected: Value '61' at 'maxResults' failed to satisfy constraint: Member must have value less than or equal to 60"
        ));
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

        let second = handler(
            &storage,
            json!({
                "UserPoolId": user_pool_id,
                "MaxResults": 2,
                "NextToken": first["NextToken"]
            }),
        )
        .await
        .unwrap();
        assert_eq!(second["Providers"].as_array().unwrap().len(), 1);
        assert!(second.get("NextToken").is_none());
    }
}
