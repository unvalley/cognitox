//! AdminRespondToAuthChallenge API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AdminRespondToAuthChallenge.html>

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
    types::{ClientId, RefreshToken, UserPoolId, UserStatus},
    validation::validate_password,
};

use super::helpers::{hash_password, verify_secret_hash};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct AnalyticsMetadata {
    analytics_endpoint_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct HttpHeader {
    #[serde(rename = "headerName")]
    header_name: Option<String>,
    #[serde(rename = "headerValue")]
    header_value: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ContextData {
    ip_address: Option<String>,
    server_name: Option<String>,
    server_path: Option<String>,
    http_headers: Option<Vec<HttpHeader>>,
    encoded_data: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Request {
    user_pool_id: UserPoolId,
    client_id: ClientId,
    challenge_name: String,
    challenge_responses: Option<HashMap<String, String>>,
    analytics_metadata: Option<AnalyticsMetadata>,
    client_metadata: Option<HashMap<String, String>>,
    context_data: Option<ContextData>,
    session: Option<String>,
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
        &req.session,
        &req.client_metadata,
        req.analytics_metadata
            .as_ref()
            .map(|meta| &meta.analytics_endpoint_id),
        req.context_data.as_ref().map(|ctx| {
            (
                &ctx.ip_address,
                &ctx.server_name,
                &ctx.server_path,
                &ctx.encoded_data,
                ctx.http_headers.as_ref().map(|headers| {
                    headers
                        .iter()
                        .map(|header| (&header.header_name, &header.header_value))
                        .collect::<Vec<_>>()
                }),
            )
        }),
    );

    storage
        .get_user_pool(&req.user_pool_id)
        .await
        .ok_or(AppError::UserPoolNotFound)?;

    let client = storage
        .get_user_pool_client(&req.client_id)
        .await
        .ok_or(AppError::UserPoolClientNotFound)?;

    // Verify client belongs to the user pool
    if client.user_pool_id != req.user_pool_id {
        return Err(AppError::UserPoolClientNotFound);
    }

    match req.challenge_name.as_str() {
        "NEW_PASSWORD_REQUIRED" => {
            let responses = req.challenge_responses.ok_or_else(|| {
                AppError::InvalidParameter("ChallengeResponses required".to_string())
            })?;

            let new_password = responses
                .get("NEW_PASSWORD")
                .ok_or_else(|| AppError::InvalidParameter("NEW_PASSWORD required".to_string()))?;
            validate_password(new_password)?;

            let mut user = if let Some(session) = req.session.as_deref() {
                let challenge = storage
                    .get_auth_challenge_session(session)
                    .await
                    .ok_or_else(|| AppError::InvalidParameter("Invalid session".to_string()))?;
                if challenge.challenge_name != "NEW_PASSWORD_REQUIRED"
                    || challenge.client_id != req.client_id
                    || challenge.user_pool_id != req.user_pool_id
                {
                    return Err(AppError::InvalidParameter("Invalid session".to_string()));
                }
                if challenge.expires_at < Utc::now() {
                    storage.delete_auth_challenge_session(session).await;
                    return Err(AppError::InvalidParameter("Session expired".to_string()));
                }

                let user = storage
                    .get_user(&challenge.user_id)
                    .await
                    .ok_or(AppError::UserNotFound)?;
                if let Some(username) = responses.get("USERNAME")
                    && *username != user.username
                {
                    return Err(AppError::InvalidParameter("USERNAME mismatch".to_string()));
                }
                if let Some(user_id_for_srp) = responses.get("USER_ID_FOR_SRP") {
                    let expected = Uuid::parse_str(user_id_for_srp).map_err(|_| {
                        AppError::InvalidParameter("Invalid USER_ID_FOR_SRP".to_string())
                    })?;
                    if expected != user.id {
                        return Err(AppError::InvalidParameter(
                            "USER_ID_FOR_SRP mismatch".to_string(),
                        ));
                    }
                }
                user
            } else if let Some(username) = responses.get("USERNAME") {
                storage
                    .get_user_by_username(&req.user_pool_id, username)
                    .await
                    .ok_or(AppError::UserNotFound)?
            } else if let Some(user_id_for_srp) = responses.get("USER_ID_FOR_SRP") {
                let user_id = Uuid::parse_str(user_id_for_srp).map_err(|_| {
                    AppError::InvalidParameter("Invalid USER_ID_FOR_SRP".to_string())
                })?;

                let user = storage
                    .get_user(&user_id)
                    .await
                    .ok_or(AppError::UserNotFound)?;
                if user.user_pool_id != req.user_pool_id {
                    return Err(AppError::UserNotFound);
                }
                user
            } else {
                return Err(AppError::InvalidParameter(
                    "USERNAME or USER_ID_FOR_SRP required".to_string(),
                ));
            };

            if !user.enabled {
                return Err(AppError::UserDisabled);
            }

            if user.user_status != UserStatus::ForceChangePassword {
                return Err(AppError::InvalidParameter(
                    "User is not in FORCE_CHANGE_PASSWORD status".to_string(),
                ));
            }
            verify_secret_hash(
                &client,
                &user.username,
                responses.get("SECRET_HASH").map(String::as_str),
            )?;

            user.password_hash = hash_password(new_password).map_err(AppError::Internal)?;
            user.user_status = UserStatus::Confirmed;
            user.last_modified_date = Utc::now();

            storage
                .update_user(user.clone())
                .await
                .ok_or(AppError::UserNotFound)?;
            if let Some(session) = req.session.as_deref() {
                storage.delete_auth_challenge_session(session).await;
            }

            let groups = storage.get_groups_for_user(&user.id).await;

            let access_expiry = resolve_access_token_expiry(&client);
            let id_expiry = resolve_id_token_expiry(&client);
            let refresh_expiry = resolve_refresh_token_expiry(&client);

            let access_token = generate_access_token(
                &user,
                req.client_id.as_str(),
                &req.user_pool_id,
                &groups,
                &client.allowed_oauth_scopes,
                access_expiry,
            )
            .map_err(AppError::Internal)?;
            let id_token = generate_id_token(
                &user,
                req.client_id.as_str(),
                &req.user_pool_id,
                &groups,
                id_expiry,
            )
            .map_err(AppError::Internal)?;

            let refresh_token = Uuid::new_v4().to_string();
            let refresh = RefreshToken {
                token: refresh_token.clone(),
                user_id: user.id,
                client_id: req.client_id.clone(),
                expires_at: Utc::now() + refresh_expiry,
            };
            storage.save_refresh_token(refresh).await;

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
    use crate::action::user::helpers::calculate_secret_hash;
    use crate::action::user::{admin_create_user, admin_initiate_auth};
    use crate::action::user_pool::{create_user_pool, create_user_pool_client};
    use serde_json::json;

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
    async fn test_admin_respond_to_auth_challenge_new_password_required_success() {
        let storage = Storage::new();
        let (pool_id, client_id) = setup_pool_and_client(&storage).await;

        admin_create_user::handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "Username": "testuser",
                "TemporaryPassword": "TempPass123!"
            }),
        )
        .await
        .unwrap();

        let result = handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "ClientId": client_id,
                "ChallengeName": "NEW_PASSWORD_REQUIRED",
                "ChallengeResponses": {
                    "USERNAME": "testuser",
                    "NEW_PASSWORD": "NewPassword123!"
                }
            }),
        )
        .await
        .unwrap();

        assert!(
            result["AuthenticationResult"]["AccessToken"]
                .as_str()
                .is_some()
        );
        assert!(result["AuthenticationResult"]["IdToken"].as_str().is_some());
        assert!(
            result["AuthenticationResult"]["RefreshToken"]
                .as_str()
                .is_some()
        );

        // Verify the new password is now usable with admin auth.
        let auth_result = admin_initiate_auth::handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "ClientId": client_id,
                "AuthFlow": "ADMIN_USER_PASSWORD_AUTH",
                "AuthParameters": {
                    "USERNAME": "testuser",
                    "PASSWORD": "NewPassword123!"
                }
            }),
        )
        .await
        .unwrap();
        assert!(
            auth_result["AuthenticationResult"]["AccessToken"]
                .as_str()
                .is_some()
        );
    }

    #[tokio::test]
    async fn test_admin_respond_to_auth_challenge_missing_new_password() {
        let storage = Storage::new();
        let (pool_id, client_id) = setup_pool_and_client(&storage).await;

        admin_create_user::handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "Username": "testuser"
            }),
        )
        .await
        .unwrap();

        let result = handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "ClientId": client_id,
                "ChallengeName": "NEW_PASSWORD_REQUIRED",
                "ChallengeResponses": {
                    "USERNAME": "testuser"
                }
            }),
        )
        .await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AppError::InvalidParameter(_)));
    }

    #[tokio::test]
    async fn test_admin_respond_to_auth_challenge_not_force_change_password() {
        let storage = Storage::new();
        let (pool_id, client_id) = setup_pool_and_client(&storage).await;

        admin_create_user::handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "Username": "testuser",
                "TemporaryPassword": "TempPass123!"
            }),
        )
        .await
        .unwrap();

        // First successful response moves user to CONFIRMED status.
        handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "ClientId": client_id,
                "ChallengeName": "NEW_PASSWORD_REQUIRED",
                "ChallengeResponses": {
                    "USERNAME": "testuser",
                    "NEW_PASSWORD": "NewPassword123!"
                }
            }),
        )
        .await
        .unwrap();

        // A second response should fail because the user is no longer in FORCE_CHANGE_PASSWORD.
        let second_result = handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "ClientId": client_id,
                "ChallengeName": "NEW_PASSWORD_REQUIRED",
                "ChallengeResponses": {
                    "USERNAME": "testuser",
                    "NEW_PASSWORD": "AnotherPass123!"
                }
            }),
        )
        .await;

        assert!(second_result.is_err());
        assert!(matches!(
            second_result.unwrap_err(),
            AppError::InvalidParameter(_)
        ));
    }

    #[tokio::test]
    async fn test_admin_respond_to_auth_challenge_not_implemented_challenge() {
        let storage = Storage::new();
        let (pool_id, client_id) = setup_pool_and_client(&storage).await;

        let result = handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "ClientId": client_id,
                "ChallengeName": "SMS_MFA",
                "ChallengeResponses": {}
            }),
        )
        .await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AppError::NotImplemented(_)));
    }

    #[tokio::test]
    async fn test_admin_respond_to_auth_challenge_requires_secret_hash_for_secret_client() {
        let storage = Storage::new();

        let pool = create_user_pool::handler(&storage, json!({"PoolName": "test"}))
            .await
            .unwrap();
        let pool_id = pool["UserPool"]["Id"].as_str().unwrap().to_string();

        let client = create_user_pool_client::handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "ClientName": "secret-client",
                "GenerateSecret": true
            }),
        )
        .await
        .unwrap();
        let client_id = client["UserPoolClient"]["ClientId"].as_str().unwrap();
        let client_secret = client["UserPoolClient"]["ClientSecret"].as_str().unwrap();

        admin_create_user::handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "Username": "testuser",
                "TemporaryPassword": "TempPass123!"
            }),
        )
        .await
        .unwrap();

        let result = handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "ClientId": client_id,
                "ChallengeName": "NEW_PASSWORD_REQUIRED",
                "ChallengeResponses": {
                    "USERNAME": "testuser",
                    "NEW_PASSWORD": "NewPassword123!"
                }
            }),
        )
        .await;
        assert!(matches!(result, Err(AppError::NotAuthorized(_))));

        let result = handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "ClientId": client_id,
                "ChallengeName": "NEW_PASSWORD_REQUIRED",
                "ChallengeResponses": {
                    "USERNAME": "testuser",
                    "NEW_PASSWORD": "NewPassword123!",
                    "SECRET_HASH": calculate_secret_hash(client_id, client_secret, "testuser").unwrap()
                }
            }),
        )
        .await;
        assert!(result.is_ok());
    }
}
