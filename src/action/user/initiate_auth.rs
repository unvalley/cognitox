//! InitiateAuth API implementation

use std::collections::HashMap;

use chrono::{Duration, Utc};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::{
    error::{AppError, Result},
    storage::Storage,
    types::{RefreshToken, UserStatus},
};

use super::helpers::{generate_tokens, hash_password};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Request {
    client_id: String,
    auth_flow: String,
    auth_parameters: Option<HashMap<String, String>>,
}

pub async fn handler(storage: &Storage, body: Value) -> Result<Value> {
    let req: Request = serde_json::from_value(body)
        .map_err(|e| AppError::Internal(format!("Invalid request: {}", e)))?;

    let client = storage
        .get_user_pool_client(&req.client_id)
        .await
        .ok_or(AppError::UserPoolClientNotFound)?;

    match req.auth_flow.as_str() {
        "USER_PASSWORD_AUTH" => {
            let params = req
                .auth_parameters
                .ok_or_else(|| AppError::Internal("AuthParameters required".to_string()))?;

            let username = params
                .get("USERNAME")
                .ok_or_else(|| AppError::Internal("USERNAME required".to_string()))?;
            let password = params
                .get("PASSWORD")
                .ok_or_else(|| AppError::Internal("PASSWORD required".to_string()))?;

            let user = storage
                .get_user_by_username(&client.user_pool_id, username)
                .await
                .ok_or(AppError::UserNotFound)?;

            if user.user_status != UserStatus::Confirmed {
                return Err(AppError::UserNotConfirmed);
            }

            if user.password_hash != hash_password(password) {
                return Err(AppError::InvalidPassword);
            }

            let (access_token, id_token, refresh_token) =
                generate_tokens(&user.id, &req.client_id);

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
                .ok_or_else(|| AppError::Internal("AuthParameters required".to_string()))?;

            let refresh_token = params
                .get("REFRESH_TOKEN")
                .ok_or_else(|| AppError::Internal("REFRESH_TOKEN required".to_string()))?;

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

            let (access_token, id_token, _) = generate_tokens(&user.id, &req.client_id);

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
