//! RespondToAuthChallenge API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_RespondToAuthChallenge.html>

use std::collections::HashMap;

use chrono::Utc;
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::{
    error::{AppError, Result},
    jwt::{
        generate_access_token, generate_id_token, resolve_access_token_expiry,
        resolve_id_token_expiry, resolve_refresh_token_expiry,
    },
    storage::Storage,
    types::{ClientId, RefreshToken, UserStatus},
    validation::validate_password,
};

use super::helpers::hash_password;

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

fn build_auth_response(authentication_result: Value) -> Value {
    json!({
        "AuthenticationResult": authentication_result,
        "ChallengeName": null,
        "ChallengeParameters": {},
        "Session": null
    })
}

pub async fn handler(storage: &Storage, body: Value) -> Result<Value> {
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

    let client = storage
        .get_user_pool_client(&req.client_id)
        .await
        .ok_or(AppError::UserPoolClientNotFound)?;

    match req.challenge_name.as_str() {
        "NEW_PASSWORD_REQUIRED" => {
            let session = req
                .session
                .as_deref()
                .ok_or_else(|| AppError::InvalidParameter("Session required".to_string()))?;
            let challenge = storage
                .get_auth_challenge_session(session)
                .await
                .ok_or_else(|| AppError::InvalidParameter("Invalid session".to_string()))?;

            if challenge.challenge_name != "NEW_PASSWORD_REQUIRED"
                || challenge.client_id != req.client_id
                || challenge.user_pool_id != client.user_pool_id
            {
                return Err(AppError::InvalidParameter("Invalid session".to_string()));
            }
            if challenge.expires_at < Utc::now() {
                storage.delete_auth_challenge_session(session).await;
                return Err(AppError::InvalidParameter("Session expired".to_string()));
            }

            let responses = req.challenge_responses.ok_or_else(|| {
                AppError::InvalidParameter("ChallengeResponses required".to_string())
            })?;
            let new_password = responses
                .get("NEW_PASSWORD")
                .ok_or_else(|| AppError::InvalidParameter("NEW_PASSWORD required".to_string()))?;
            validate_password(new_password)?;

            let mut user = storage
                .get_user(&challenge.user_id)
                .await
                .ok_or(AppError::UserNotFound)?;
            if !user.enabled {
                return Err(AppError::UserDisabled);
            }
            if user.user_status != UserStatus::ForceChangePassword {
                return Err(AppError::InvalidParameter(
                    "User is not in FORCE_CHANGE_PASSWORD status".to_string(),
                ));
            }

            if let Some(username) = responses.get("USERNAME")
                && *username != user.username
            {
                return Err(AppError::InvalidParameter("USERNAME mismatch".to_string()));
            }

            user.password_hash = hash_password(new_password).map_err(AppError::Internal)?;
            user.user_status = UserStatus::Confirmed;
            user.last_modified_date = Utc::now();
            storage
                .update_user(user.clone())
                .await
                .ok_or(AppError::UserNotFound)?;
            storage.delete_auth_challenge_session(session).await;

            let groups = storage.get_groups_for_user(&user.id).await;
            let access_expiry = resolve_access_token_expiry(&client);
            let id_expiry = resolve_id_token_expiry(&client);
            let refresh_expiry = resolve_refresh_token_expiry(&client);

            let access_token = generate_access_token(
                &user,
                req.client_id.as_str(),
                &client.user_pool_id,
                &groups,
                &client.allowed_oauth_scopes,
                access_expiry,
            )
            .map_err(AppError::Internal)?;
            let id_token = generate_id_token(
                &user,
                req.client_id.as_str(),
                &client.user_pool_id,
                &groups,
                id_expiry,
            )
            .map_err(AppError::Internal)?;

            let refresh_token = Uuid::new_v4().to_string();
            storage
                .save_refresh_token(RefreshToken {
                    token: refresh_token.clone(),
                    user_id: user.id,
                    client_id: req.client_id.clone(),
                    expires_at: Utc::now() + refresh_expiry,
                })
                .await;

            Ok(build_auth_response(json!({
                "AccessToken": access_token,
                "IdToken": id_token,
                "RefreshToken": refresh_token,
                "ExpiresIn": access_expiry.num_seconds(),
                "TokenType": "Bearer"
            })))
        }
        _ => Err(AppError::NotImplemented(format!(
            "Challenge: {}",
            req.challenge_name
        ))),
    }
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
