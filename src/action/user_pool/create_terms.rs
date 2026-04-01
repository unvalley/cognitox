//! CreateTerms API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_CreateTerms.html>

use std::collections::HashMap;

use chrono::Utc;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::{
    error::{AppError, Result},
    storage::Storage,
    types::{ClientId, TermsDocument, UserPoolId},
};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Request {
    terms_name: String,
    client_id: ClientId,
    user_pool_id: UserPoolId,
    terms_source: String,
    #[serde(default)]
    enforcement: Option<String>,
    #[serde(default)]
    links: HashMap<String, String>,
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

    storage
        .get_user_pool_client(&req.client_id)
        .await
        .ok_or(AppError::UserPoolClientNotFound)?;

    if storage
        .get_terms_by_name(&req.user_pool_id, &req.client_id, &req.terms_name)
        .await
        .is_some()
    {
        return Err(AppError::InvalidParameter(
            "Terms with same name already exists for this client".to_string(),
        ));
    }

    let now = Utc::now();
    let terms = TermsDocument {
        terms_id: uuid::Uuid::now_v7().to_string(),
        user_pool_id: req.user_pool_id,
        client_id: req.client_id,
        terms_name: req.terms_name,
        terms_source: req.terms_source,
        enforcement: req.enforcement,
        links: req.links,
        creation_date: now,
        last_modified_date: now,
    };

    let created = storage.create_terms(terms).await;

    Ok(json!({"Terms": terms_to_json(&created)}))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::user_pool::{create_user_pool, create_user_pool_client};

    #[tokio::test]
    async fn test_create_terms_success() {
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

        let result = handler(
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

        assert_eq!(result["Terms"]["TermsName"], "terms-v1");
    }
}
