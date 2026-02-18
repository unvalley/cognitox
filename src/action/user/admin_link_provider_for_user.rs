//! AdminLinkProviderForUser API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AdminLinkProviderForUser.html>

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
    #[allow(dead_code)]
    destination_user: Value,
    #[allow(dead_code)]
    source_user: Value,
}

pub async fn handler(storage: &Storage, body: Value) -> Result<Value> {
    let req: Request = serde_json::from_value(body)
        .map_err(|e| AppError::InvalidParameter(format!("Invalid request: {}", e)))?;

    storage
        .get_user_pool(&req.user_pool_id)
        .await
        .ok_or(AppError::UserPoolNotFound)?;

    Ok(json!({}))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::user_pool::create_user_pool;

    #[tokio::test]
    async fn test_admin_link_provider_for_user_success() {
        let storage = Storage::new();
        let pool = create_user_pool::handler(&storage, json!({"PoolName": "test"}))
            .await
            .unwrap();
        let pool_id = pool["UserPool"]["Id"].as_str().unwrap();

        let result = handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "DestinationUser": {
                    "ProviderName": "Cognito",
                    "ProviderAttributeValue": "local-user"
                },
                "SourceUser": {
                    "ProviderName": "Google",
                    "ProviderAttributeName": "Cognito_Subject",
                    "ProviderAttributeValue": "google-user"
                }
            }),
        )
        .await
        .unwrap();

        assert_eq!(result, json!({}));
    }
}
