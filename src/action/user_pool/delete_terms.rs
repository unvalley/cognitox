//! DeleteTerms API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_DeleteTerms.html>

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
    terms_id: String,
}

pub async fn handler(storage: &Storage, body: Value) -> Result<Value> {
    let req: Request = serde_json::from_value(body)
        .map_err(|e| AppError::InvalidParameter(format!("Invalid request: {}", e)))?;

    storage
        .get_user_pool(&req.user_pool_id)
        .await
        .ok_or(AppError::UserPoolNotFound)?;

    storage
        .delete_terms(&req.user_pool_id, &req.terms_id)
        .await
        .ok_or(AppError::TermsNotFound)?;

    Ok(json!({}))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::user_pool::{create_terms, create_user_pool, create_user_pool_client};

    #[tokio::test]
    async fn test_delete_terms_success() {
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
            json!({"UserPoolId": pool_id, "TermsId": terms_id}),
        )
        .await
        .unwrap();

        assert_eq!(result, json!({}));
    }
}
