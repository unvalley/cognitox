//! InitiateAuth API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_InitiateAuth.html>

use std::collections::HashMap;

use chrono::{Duration, Utc};
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::{
    error::{AppError, Result},
    jwt::{generate_access_token, generate_id_token},
    storage::Storage,
    types::{AuthEvent, ClientId, RefreshToken, UserStatus},
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
struct UserContextData {
    ip_address: Option<String>,
    server_name: Option<String>,
    server_path: Option<String>,
    http_headers: Option<Vec<HttpHeader>>,
    encoded_data: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Request {
    client_id: ClientId,
    auth_flow: String,
    auth_parameters: Option<HashMap<String, String>>,
    analytics_metadata: Option<AnalyticsMetadata>,
    user_context_data: Option<UserContextData>,
    client_metadata: Option<HashMap<String, String>>,
}

pub async fn handler(storage: &Storage, body: Value) -> Result<Value> {
    let req: Request = serde_json::from_value(body)
        .map_err(|e| AppError::InvalidParameter(format!("Invalid request: {}", e)))?;
    let _ = (
        &req.client_metadata,
        req.analytics_metadata
            .as_ref()
            .map(|meta| &meta.analytics_endpoint_id),
        req.user_context_data.as_ref().map(|ctx| {
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

    let client = storage
        .get_user_pool_client(&req.client_id)
        .await
        .ok_or(AppError::UserPoolClientNotFound)?;

    match req.auth_flow.as_str() {
        "USER_PASSWORD_AUTH" => {
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
                .get_user_by_username(&client.user_pool_id, username)
                .await
                .ok_or(AppError::UserNotFound)?;

            // Check if user is enabled
            if !user.enabled {
                return Err(AppError::UserDisabled);
            }

            if user.user_status != UserStatus::Confirmed {
                return Err(AppError::UserNotConfirmed);
            }

            if !verify_password(password, &user.password_hash) {
                return Err(AppError::InvalidPassword);
            }

            // Get user groups
            let groups = storage.get_groups_for_user(&user.id).await;

            // Generate JWT tokens
            let access_token = generate_access_token(
                &user,
                req.client_id.as_str(),
                &client.user_pool_id,
                &groups,
                &client.allowed_oauth_scopes,
            )
            .map_err(AppError::Internal)?;
            let id_token =
                generate_id_token(&user, req.client_id.as_str(), &client.user_pool_id, &groups)
                    .map_err(AppError::Internal)?;

            // Generate refresh token (UUID-based, stored in database)
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

            // Check if user is enabled (user could be disabled after getting refresh token)
            if !user.enabled {
                return Err(AppError::UserDisabled);
            }

            // Get user groups
            let groups = storage.get_groups_for_user(&user.id).await;

            // Generate new JWT tokens
            let access_token = generate_access_token(
                &user,
                req.client_id.as_str(),
                &client.user_pool_id,
                &groups,
                &client.allowed_oauth_scopes,
            )
            .map_err(AppError::Internal)?;
            let id_token =
                generate_id_token(&user, req.client_id.as_str(), &client.user_pool_id, &groups)
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
        "USER_SRP_AUTH" => Err(AppError::NotImplemented("USER_SRP_AUTH".to_string())),
        _ => Err(AppError::NotImplemented(format!(
            "Auth flow: {}",
            req.auth_flow
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    use crate::action::user::sign_up;
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

    async fn create_confirmed_user(
        storage: &Storage,
        client_id: &str,
        username: &str,
        password: &str,
    ) {
        let sign_up_result = sign_up::handler(
            storage,
            json!({
                "ClientId": client_id,
                "Username": username,
                "Password": password
            }),
        )
        .await
        .unwrap();

        let user_sub = sign_up_result["UserSub"].as_str().unwrap();
        let user_id = uuid::Uuid::parse_str(user_sub).unwrap();

        // Confirm the user directly via storage
        storage.confirm_user(&user_id).await;
    }

    #[tokio::test]
    async fn test_initiate_auth_user_password_auth_success() {
        let storage = Storage::new();
        let (_pool_id, client_id) = setup_pool_and_client(&storage).await;

        create_confirmed_user(&storage, &client_id, "testuser", "Password123!").await;

        let result = handler(
            &storage,
            json!({
                "ClientId": client_id,
                "AuthFlow": "USER_PASSWORD_AUTH",
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
        assert_eq!(body["AuthenticationResult"]["TokenType"], "Bearer");
    }

    #[tokio::test]
    async fn test_initiate_auth_invalid_password() {
        let storage = Storage::new();
        let (_pool_id, client_id) = setup_pool_and_client(&storage).await;

        create_confirmed_user(&storage, &client_id, "testuser", "Password123!").await;

        let result = handler(
            &storage,
            json!({
                "ClientId": client_id,
                "AuthFlow": "USER_PASSWORD_AUTH",
                "AuthParameters": {
                    "USERNAME": "testuser",
                    "PASSWORD": "WrongPassword!"
                }
            }),
        )
        .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_initiate_auth_user_not_confirmed() {
        let storage = Storage::new();
        let (_pool_id, client_id) = setup_pool_and_client(&storage).await;

        // Sign up but don't confirm
        sign_up::handler(
            &storage,
            json!({
                "ClientId": client_id,
                "Username": "testuser",
                "Password": "Password123!"
            }),
        )
        .await
        .unwrap();

        let result = handler(
            &storage,
            json!({
                "ClientId": client_id,
                "AuthFlow": "USER_PASSWORD_AUTH",
                "AuthParameters": {
                    "USERNAME": "testuser",
                    "PASSWORD": "Password123!"
                }
            }),
        )
        .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_initiate_auth_refresh_token_client_mismatch() {
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

        create_confirmed_user(&storage, &client_id1, "testuser", "Password123!").await;

        let auth = handler(
            &storage,
            json!({
                "ClientId": client_id1,
                "AuthFlow": "USER_PASSWORD_AUTH",
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
