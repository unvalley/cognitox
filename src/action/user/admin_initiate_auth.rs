//! AdminInitiateAuth API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AdminInitiateAuth.html>

use std::collections::HashMap;

use chrono::{Duration, Utc};
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::{
    error::{AppError, Result},
    jwt::{generate_access_token, generate_id_token},
    storage::Storage,
    types::{AuthEvent, ClientId, RefreshToken, UserPoolId, UserStatus},
};

use super::helpers::verify_password;

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
    auth_flow: String,
    auth_parameters: Option<HashMap<String, String>>,
    analytics_metadata: Option<AnalyticsMetadata>,
    context_data: Option<ContextData>,
    session: Option<String>,
    client_metadata: Option<HashMap<String, String>>,
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

    match req.auth_flow.as_str() {
        "ADMIN_USER_PASSWORD_AUTH" | "ADMIN_NO_SRP_AUTH" => {
            let params = req
                .auth_parameters
                .ok_or_else(|| AppError::InvalidParameter("AuthParameters required".to_string()))?;

            let username = params
                .get("USERNAME")
                .ok_or_else(|| AppError::InvalidParameter("USERNAME required".to_string()))?;
            let password = params
                .get("PASSWORD")
                .ok_or_else(|| AppError::InvalidParameter("PASSWORD required".to_string()))?;

            let user = storage
                .get_user_by_username(&req.user_pool_id, username)
                .await
                .ok_or(AppError::UserNotFound)?;

            if !user.enabled {
                return Err(AppError::UserDisabled);
            }

            // For admin auth, we can authenticate users in FORCE_CHANGE_PASSWORD status
            // but return a challenge
            if user.user_status == UserStatus::ForceChangePassword {
                return Ok(json!({
                    "ChallengeName": "NEW_PASSWORD_REQUIRED",
                    "ChallengeParameters": {
                        "USER_ID_FOR_SRP": user.id.to_string(),
                        "userAttributes": "{}"
                    },
                    "Session": Uuid::now_v7().to_string()
                }));
            }

            if user.user_status != UserStatus::Confirmed {
                return Err(AppError::UserNotConfirmed);
            }

            if !verify_password(password, &user.password_hash) {
                return Err(AppError::InvalidPassword);
            }

            let groups = storage.get_groups_for_user(&user.id).await;

            let access_token = generate_access_token(
                &user,
                req.client_id.as_str(),
                &req.user_pool_id,
                &groups,
                &client.allowed_oauth_scopes,
            )
            .map_err(AppError::Internal)?;
            let id_token =
                generate_id_token(&user, req.client_id.as_str(), &req.user_pool_id, &groups)
                    .map_err(AppError::Internal)?;

            let refresh_token = Uuid::now_v7().to_string();
            let refresh = RefreshToken {
                token: refresh_token.clone(),
                user_id: user.id,
                client_id: req.client_id.clone(),
                expires_at: Utc::now() + Duration::days(30),
            };
            storage.save_refresh_token(refresh).await;

            storage
                .create_auth_event(AuthEvent {
                    event_id: Uuid::now_v7().to_string(),
                    user_id: user.id,
                    event_type: "SignIn".to_string(),
                    creation_date: Utc::now(),
                    event_response: "Pass".to_string(),
                    feedback_value: None,
                    feedback_provided_by: None,
                    feedback_date: None,
                })
                .await;

            Ok(json!({
                "AuthenticationResult": {
                    "AccessToken": access_token,
                    "IdToken": id_token,
                    "RefreshToken": refresh_token,
                    "ExpiresIn": 3600,
                    "TokenType": "Bearer"
                }
            }))
        }
        "REFRESH_TOKEN" | "REFRESH_TOKEN_AUTH" => {
            let params = req
                .auth_parameters
                .ok_or_else(|| AppError::InvalidParameter("AuthParameters required".to_string()))?;

            let refresh_token = params
                .get("REFRESH_TOKEN")
                .ok_or_else(|| AppError::InvalidParameter("REFRESH_TOKEN required".to_string()))?;

            let stored_token = storage
                .get_refresh_token(refresh_token)
                .await
                .ok_or(AppError::InvalidRefreshToken)?;

            if stored_token.client_id != req.client_id {
                return Err(AppError::InvalidRefreshToken);
            }

            if stored_token.expires_at < Utc::now() {
                return Err(AppError::InvalidRefreshToken);
            }

            let user = storage
                .get_user(&stored_token.user_id)
                .await
                .ok_or(AppError::UserNotFound)?;

            if !user.enabled {
                return Err(AppError::UserDisabled);
            }

            let groups = storage.get_groups_for_user(&user.id).await;

            let access_token = generate_access_token(
                &user,
                req.client_id.as_str(),
                &req.user_pool_id,
                &groups,
                &client.allowed_oauth_scopes,
            )
            .map_err(AppError::Internal)?;
            let id_token =
                generate_id_token(&user, req.client_id.as_str(), &req.user_pool_id, &groups)
                    .map_err(AppError::Internal)?;

            Ok(json!({
                "AuthenticationResult": {
                    "AccessToken": access_token,
                    "IdToken": id_token,
                    "ExpiresIn": 3600,
                    "TokenType": "Bearer"
                }
            }))
        }
        _ => Err(AppError::NotImplemented(format!(
            "Auth flow: {}",
            req.auth_flow
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::user::admin_create_user;
    use crate::action::user::admin_set_user_password;
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
    async fn test_admin_initiate_auth_success() {
        let storage = Storage::new();
        let (pool_id, client_id) = setup_pool_and_client(&storage).await;

        // Create user and set permanent password
        admin_create_user::handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "Username": "testuser"
            }),
        )
        .await
        .unwrap();

        admin_set_user_password::handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "Username": "testuser",
                "Password": "Password123!",
                "Permanent": true
            }),
        )
        .await
        .unwrap();

        let result = handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "ClientId": client_id,
                "AuthFlow": "ADMIN_USER_PASSWORD_AUTH",
                "AuthParameters": {
                    "USERNAME": "testuser",
                    "PASSWORD": "Password123!"
                }
            }),
        )
        .await;

        assert!(result.is_ok());
        let body = result.unwrap();
        assert!(
            body["AuthenticationResult"]["AccessToken"]
                .as_str()
                .is_some()
        );
        assert!(body["AuthenticationResult"]["IdToken"].as_str().is_some());
        assert!(
            body["AuthenticationResult"]["RefreshToken"]
                .as_str()
                .is_some()
        );
    }

    #[tokio::test]
    async fn test_admin_initiate_auth_force_change_password() {
        let storage = Storage::new();
        let (pool_id, client_id) = setup_pool_and_client(&storage).await;

        // Create user (will have FORCE_CHANGE_PASSWORD status)
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
                "AuthFlow": "ADMIN_USER_PASSWORD_AUTH",
                "AuthParameters": {
                    "USERNAME": "testuser",
                    "PASSWORD": "TempPass123!"
                }
            }),
        )
        .await;

        assert!(result.is_ok());
        let body = result.unwrap();
        assert_eq!(body["ChallengeName"], "NEW_PASSWORD_REQUIRED");
    }

    #[tokio::test]
    async fn test_admin_initiate_auth_invalid_password() {
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

        admin_set_user_password::handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "Username": "testuser",
                "Password": "Password123!",
                "Permanent": true
            }),
        )
        .await
        .unwrap();

        let result = handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "ClientId": client_id,
                "AuthFlow": "ADMIN_USER_PASSWORD_AUTH",
                "AuthParameters": {
                    "USERNAME": "testuser",
                    "PASSWORD": "WrongPassword!"
                }
            }),
        )
        .await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AppError::InvalidPassword));
    }

    #[tokio::test]
    async fn test_admin_initiate_auth_pool_not_found() {
        let storage = Storage::new();

        let result = handler(
            &storage,
            json!({
                "UserPoolId": "local_nonexistent",
                "ClientId": "someclientid",
                "AuthFlow": "ADMIN_USER_PASSWORD_AUTH",
                "AuthParameters": {
                    "USERNAME": "testuser",
                    "PASSWORD": "Password123!"
                }
            }),
        )
        .await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AppError::UserPoolNotFound));
    }

    #[tokio::test]
    async fn test_admin_initiate_auth_refresh_token_client_mismatch() {
        let storage = Storage::new();
        let (pool_id, client_id1) = setup_pool_and_client(&storage).await;

        let client2 = create_user_pool_client::handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "ClientName": "test-client-2"
            }),
        )
        .await
        .unwrap();
        let client_id2 = client2["UserPoolClient"]["ClientId"].as_str().unwrap();

        admin_create_user::handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "Username": "testuser"
            }),
        )
        .await
        .unwrap();
        admin_set_user_password::handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "Username": "testuser",
                "Password": "Password123!",
                "Permanent": true
            }),
        )
        .await
        .unwrap();

        let auth = handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "ClientId": client_id1,
                "AuthFlow": "ADMIN_USER_PASSWORD_AUTH",
                "AuthParameters": {
                    "USERNAME": "testuser",
                    "PASSWORD": "Password123!"
                }
            }),
        )
        .await
        .unwrap();
        let refresh_token = auth["AuthenticationResult"]["RefreshToken"]
            .as_str()
            .unwrap();

        let refresh_result = handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "ClientId": client_id2,
                "AuthFlow": "REFRESH_TOKEN_AUTH",
                "AuthParameters": {
                    "REFRESH_TOKEN": refresh_token
                }
            }),
        )
        .await;

        assert!(matches!(
            refresh_result.unwrap_err(),
            AppError::InvalidRefreshToken
        ));
    }
}
