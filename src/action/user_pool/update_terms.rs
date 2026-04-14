//! UpdateTerms API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_UpdateTerms.html>

use chrono::Utc;
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::HashMap;

use crate::{
    error::{AppError, Result},
    storage::Storage,
    types::{TermsDocument, UserPoolId},
};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Request {
    user_pool_id: UserPoolId,
    terms_id: String,
    #[serde(default)]
    terms_name: Option<String>,
    #[serde(default)]
    terms_source: Option<String>,
    #[serde(default)]
    enforcement: Option<String>,
    #[serde(default)]
    links: Option<HashMap<String, String>>,
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

    let mut terms = storage
        .get_terms_by_id(&req.terms_id)
        .await
        .ok_or(AppError::TermsNotFound)?;

    if terms.user_pool_id != req.user_pool_id {
        return Err(AppError::TermsNotFound);
    }

    if let Some(terms_name) = req.terms_name {
        if let Some(existing) = storage
            .get_terms_by_name(&req.user_pool_id, &terms.client_id, &terms_name)
            .await
            && existing.terms_id != terms.terms_id
        {
            return Err(AppError::InvalidParameter(
                "Terms with same name already exists for this client".to_string(),
            ));
        }
        terms.terms_name = terms_name;
    }
    if let Some(source) = req.terms_source {
        terms.terms_source = source;
    }
    if let Some(enforcement) = req.enforcement {
        terms.enforcement = Some(enforcement);
    }
    if let Some(links) = req.links {
        terms.links = links;
    }
    terms.last_modified_date = Utc::now();

    let updated = storage
        .update_terms(terms)
        .await
        .ok_or(AppError::TermsNotFound)?;

    Ok(json!({
        "Terms": terms_to_json(&updated)
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::user_pool::{create_terms, create_user_pool, create_user_pool_client};

    #[tokio::test]
    async fn test_update_terms_success() {
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

        let created = create_terms::handler(
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
        let terms_id = created["Terms"]["TermsId"].as_str().unwrap();

        let result = handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "TermsId": terms_id,
                "TermsSource": "https://example.com/new-terms"
            }),
        )
        .await
        .unwrap();

        assert_eq!(
            result["Terms"]["TermsSource"],
            "https://example.com/new-terms"
        );
    }

    #[tokio::test]
    async fn test_update_terms_renames_terms() {
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

        let created = create_terms::handler(
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
        let terms_id = created["Terms"]["TermsId"].as_str().unwrap();

        let result = handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "TermsId": terms_id,
                "TermsName": "terms-v2"
            }),
        )
        .await
        .unwrap();

        assert_eq!(result["Terms"]["TermsName"], "terms-v2");
        assert!(
            storage
                .get_terms_by_name(
                    &pool_id.parse().unwrap(),
                    &client_id.parse().unwrap(),
                    "terms-v2"
                )
                .await
                .is_some()
        );
        assert!(
            storage
                .get_terms_by_name(
                    &pool_id.parse().unwrap(),
                    &client_id.parse().unwrap(),
                    "terms-v1"
                )
                .await
                .is_none()
        );
    }
}
