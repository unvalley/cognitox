//! RespondToAuthChallenge API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_RespondToAuthChallenge.html>

use std::collections::HashMap;

use serde::Deserialize;
use serde_json::Value;

use crate::error::{AppError, Result};
use crate::storage::Storage;
use crate::types::ClientId;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct AnalyticsMetadata {
    analytics_endpoint_id: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct UserContextData {
    encoded_data: Option<String>,
    ip_address: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Request {
    client_id: ClientId,
    challenge_name: String,
    challenge_responses: Option<HashMap<String, String>>,
    analytics_metadata: Option<AnalyticsMetadata>,
    client_metadata: Option<HashMap<String, String>>,
    session: Option<String>,
    user_context_data: Option<UserContextData>,
}

pub async fn handler(_storage: &Storage, body: Value) -> Result<Value> {
    let req: Request = serde_json::from_value(body)
        .map_err(|e| AppError::InvalidParameter(format!("Invalid request: {}", e)))?;
    let _ = (
        &req.client_id,
        &req.challenge_responses,
        &req.client_metadata,
        &req.session,
        req.analytics_metadata
            .as_ref()
            .map(|meta| &meta.analytics_endpoint_id),
        req.user_context_data
            .as_ref()
            .map(|ctx| (&ctx.encoded_data, &ctx.ip_address)),
    );

    Err(AppError::NotImplemented(format!(
        "Challenge: {}",
        req.challenge_name
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    use crate::action::user_pool::{create_user_pool, create_user_pool_client};

    async fn setup_pool_and_client(storage: &Storage) -> (String, String) {
        let pool = create_user_pool::handler(storage, json!({"PoolName": "test"}))
            .await
            .unwrap();
        let pool_id = pool["UserPool"]["Id"].as_str().unwrap().to_string();

        let client = create_user_pool_client::handler(
            storage,
            json!({
                "UserPoolId": pool_id,
                "ClientName": "test-client"
            }),
        )
        .await
        .unwrap();
        let client_id = client["UserPoolClient"]["ClientId"]
            .as_str()
            .unwrap()
            .to_string();

        (pool_id, client_id)
    }

    #[tokio::test]
    async fn test_respond_to_auth_challenge_not_implemented() {
        let storage = Storage::new();
        let (_pool_id, client_id) = setup_pool_and_client(&storage).await;

        let result = handler(
            &storage,
            json!({
                "ClientId": client_id,
                "ChallengeName": "NEW_PASSWORD_REQUIRED",
                "ChallengeResponses": {
                    "USERNAME": "testuser",
                    "NEW_PASSWORD": "NewPassword123!"
                }
            }),
        )
        .await;

        // Should return NotImplemented error
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_respond_to_auth_challenge_missing_challenge_name() {
        let storage = Storage::new();
        let (_pool_id, client_id) = setup_pool_and_client(&storage).await;

        let result = handler(
            &storage,
            json!({
                "ClientId": client_id,
                "ChallengeResponses": {}
            }),
        )
        .await;

        // Should return InvalidParameter error for missing ChallengeName
        assert!(result.is_err());
    }
}
