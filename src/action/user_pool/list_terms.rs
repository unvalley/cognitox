//! ListTerms API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_ListTerms.html>

use serde::Deserialize;
use serde_json::{Value, json};

use crate::{
    error::{AppError, Result},
    storage::Storage,
    types::{TermsDocument, UserPoolId},
};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Request {
    user_pool_id: UserPoolId,
    max_results: Option<u32>,
    next_token: Option<String>,
}

fn terms_to_json(terms: &TermsDocument) -> Value {
    json!({
        "TermsId": terms.terms_id,
        "TermsName": terms.terms_name,
        "ClientId": terms.client_id,
        "UserPoolId": terms.user_pool_id,
        "TermsSource": terms.terms_source,
        "Enforcement": terms.enforcement,
        "Links": terms.links,
        "CreationDate": terms.creation_date.timestamp(),
        "LastModifiedDate": terms.last_modified_date.timestamp()
    })
}

pub async fn handler(storage: &Storage, body: Value) -> Result<Value> {
    let req: Request = serde_json::from_value(body)
        .map_err(|e| AppError::InvalidParameter(format!("Invalid request: {}", e)))?;

    storage
        .get_user_pool(&req.user_pool_id)
        .await
        .ok_or(AppError::UserPoolNotFound)?;

    let max = req.max_results.unwrap_or(60) as usize;
    if max == 0 {
        return Err(AppError::InvalidParameter(
            "MaxResults must be greater than 0".to_string(),
        ));
    }

    let mut all_terms = storage.list_terms(&req.user_pool_id).await;
    all_terms.sort_by(|a, b| a.terms_name.cmp(&b.terms_name));

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

    if start > all_terms.len() {
        return Err(AppError::InvalidParameter("Invalid NextToken".to_string()));
    }

    let end = (start + max).min(all_terms.len());
    let terms = all_terms[start..end]
        .iter()
        .map(terms_to_json)
        .collect::<Vec<_>>();

    let mut response = json!({
        "Terms": terms
    });
    if end < all_terms.len() {
        response["NextToken"] = json!(end.to_string());
    }

    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::user_pool::{create_terms, create_user_pool, create_user_pool_client};

    #[tokio::test]
    async fn test_list_terms_success() {
        let storage = Storage::new();
        let pool = create_user_pool::handler(&storage, json!({"PoolName": "pool"}))
            .await
            .unwrap();
        let pool_id = pool["UserPool"]["Id"].as_str().unwrap();
        let client = create_user_pool_client::handler(
            &storage,
            json!({"UserPoolId": pool_id, "ClientName": "client"}),
        )
        .await
        .unwrap();
        let client_id = client["UserPoolClient"]["ClientId"].as_str().unwrap();

        create_terms::handler(
            &storage,
            json!({
                "TermsName": "terms-v1",
                "ClientId": client_id,
                "UserPoolId": pool_id,
                "TermsSource": "https://example.com/terms"
            }),
        )
        .await
        .unwrap();

        let result = handler(&storage, json!({"UserPoolId": pool_id}))
            .await
            .unwrap();

        assert_eq!(result["Terms"].as_array().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn test_list_terms_with_pagination() {
        let storage = Storage::new();
        let pool = create_user_pool::handler(&storage, json!({"PoolName": "pool"}))
            .await
            .unwrap();
        let pool_id = pool["UserPool"]["Id"].as_str().unwrap();
        let client = create_user_pool_client::handler(
            &storage,
            json!({"UserPoolId": pool_id, "ClientName": "client"}),
        )
        .await
        .unwrap();
        let client_id = client["UserPoolClient"]["ClientId"].as_str().unwrap();

        for terms_name in ["terms-a", "terms-b", "terms-c"] {
            create_terms::handler(
                &storage,
                json!({
                    "TermsName": terms_name,
                    "ClientId": client_id,
                    "UserPoolId": pool_id,
                    "TermsSource": "https://example.com/terms"
                }),
            )
            .await
            .unwrap();
        }

        let first = handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "MaxResults": 2
            }),
        )
        .await
        .unwrap();

        assert_eq!(first["Terms"].as_array().unwrap().len(), 2);
        assert_eq!(first["NextToken"], "2");

        let second = handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "MaxResults": 2,
                "NextToken": "2"
            }),
        )
        .await
        .unwrap();

        assert_eq!(second["Terms"].as_array().unwrap().len(), 1);
        assert!(second.get("NextToken").is_none());
    }
}
