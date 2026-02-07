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
    types::{RefreshToken, UserStatus},
};

use super::helpers::verify_password;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Request {
    client_id: String,
    auth_flow: String,
    auth_parameters: Option<HashMap<String, String>>,
}

pub async fn handler(storage: &Storage, body: Value) -> Result<Value> {
    let req: Request = serde_json::from_value(body)
        .map_err(|e| AppError::InvalidParameter(format!("Invalid request: {}", e)))?;

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
                &req.client_id,
                &client.user_pool_id,
                &groups,
                &client.allowed_oauth_scopes,
            );
            let id_token = generate_id_token(&user, &req.client_id, &client.user_pool_id, &groups);

            // Generate refresh token (UUID-based, stored in database)
            let refresh_token = Uuid::new_v4().to_string();

            let refresh = RefreshToken {
                token: refresh_token.clone(),
                user_id: user.id,
                client_id: req.client_id.clone(),
                expires_at: Utc::now() + Duration::days(30),
            };
            storage.save_refresh_token(refresh).await;

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
                &req.client_id,
                &client.user_pool_id,
                &groups,
                &client.allowed_oauth_scopes,
            );
            let id_token = generate_id_token(&user, &req.client_id, &client.user_pool_id, &groups);

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
