//! AssociateSoftwareToken API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AssociateSoftwareToken.html>

use chrono::Utc;
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::{
    error::{AppError, Result},
    storage::Storage,
    types::ChallengeType,
};

use super::auth_flow::new_session_token;
use super::helpers::verify_and_extract_active_user_id;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Request {
    #[serde(default)]
    access_token: Option<String>,
    #[serde(default)]
    session: Option<String>,
}

/// Key under which the secret of a token-authorized association waits for
/// `VerifySoftwareToken`, which that flow calls without a session.
pub(crate) fn pending_secret_key(user_id: &Uuid) -> String {
    format!("pending:{user_id}")
}

pub async fn handler(storage: &Storage, body: Value) -> Result<Value> {
    let req: Request = crate::action::io::parse_request(body)?;

    if let Some(access_token) = req.access_token.as_deref() {
        let user_id = verify_and_extract_active_user_id(storage, access_token).await?;
        storage
            .get_user(&user_id)
            .await
            .ok_or(AppError::UserNotFound)?;

        let secret_code = generate_secret_code();
        storage
            .save_software_token_session(
                pending_secret_key(&user_id),
                &user_id,
                secret_code.clone(),
            )
            .await;
        // A token-authorized association has no session to return.
        return Ok(secret_only(secret_code));
    }

    let Some(session) = req.session.as_deref() else {
        return Err(AppError::InvalidParameter(
            "AccessToken or Session is required".to_string(),
        ));
    };

    // The session is either an `MFA_SETUP` challenge from sign-in, or the
    // session of an earlier association the user is repeating.
    let invalid_session = || AppError::NotAuthorized("Invalid session for the user.".to_string());
    let next_session = new_session_token();
    let user_id = match storage.get_auth_challenge_session(session).await {
        Some(mut pending) => {
            if pending.challenge_name != ChallengeType::MfaSetup {
                return Err(invalid_session());
            }
            if pending.expires_at < Utc::now() {
                storage.delete_auth_challenge_session(session).await;
                return Err(AppError::NotAuthorized(
                    "Invalid session for the user, session is expired.".to_string(),
                ));
            }
            // Each step of the setup hands out a fresh session.
            storage.delete_auth_challenge_session(session).await;
            storage.delete_software_token_session(session).await;
            pending.session = next_session.clone();
            pending.mfa_setup_complete = false;
            let user_id = pending.user_id;
            storage.save_auth_challenge_session(pending).await;
            user_id
        }
        None => {
            let (user_id, _) = storage
                .get_software_token_session(session)
                .await
                .ok_or_else(invalid_session)?;
            storage.delete_software_token_session(session).await;
            user_id
        }
    };

    let secret_code = generate_secret_code();
    storage
        .save_software_token_session(next_session.clone(), &user_id, secret_code.clone())
        .await;

    Ok(json!({
        "SecretCode": secret_code,
        "Session": next_session
    }))
}

fn secret_only(secret_code: String) -> Value {
    let mut response = serde_json::Map::new();
    response.insert("SecretCode".to_string(), json!(secret_code));
    Value::Object(response)
}

fn generate_secret_code() -> String {
    use rand::Rng;
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut rng = rand::thread_rng();
    (0..32)
        .map(|_| CHARSET[rng.gen_range(0..CHARSET.len())] as char)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::user::{initiate_auth, sign_up};
    use crate::action::user_pool::{create_user_pool, create_user_pool_client};
    use serde_json::json;

    async fn setup_and_get_token(storage: &Storage) -> String {
        let pool = create_user_pool::handler(storage, json!({"PoolName": "test"}))
            .await
            .unwrap();
        let pool_id = pool["UserPool"]["Id"].as_str().unwrap();

        let client = create_user_pool_client::handler(
            storage,
            json!({
                "UserPoolId": pool_id,
                "ExplicitAuthFlows": ["ALLOW_USER_PASSWORD_AUTH", "ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_USER_SRP_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
                "ClientName": "test-client"
            }),
        )
        .await
        .unwrap();
        let client_id = client["UserPoolClient"]["ClientId"].as_str().unwrap();

        let sign_up_result = sign_up::handler(
            storage,
            json!({
                "ClientId": client_id,
                "Username": "testuser",
                "Password": "Password123!"
            }),
        )
        .await
        .unwrap();

        let user_sub = sign_up_result["UserSub"].as_str().unwrap();
        let user_id = uuid::Uuid::parse_str(user_sub).unwrap();
        storage.confirm_user(&user_id).await;

        let auth_result = initiate_auth::handler(
            storage,
            json!({
                "ClientId": client_id,
                "AuthFlow": "USER_PASSWORD_AUTH",
                "AuthParameters": {
                    "USERNAME": "testuser",
                    "PASSWORD": "Password123!"
                }
            }),
        )
        .await
        .unwrap();

        auth_result["AuthenticationResult"]["AccessToken"]
            .as_str()
            .unwrap()
            .to_string()
    }

    #[tokio::test]
    async fn test_associate_software_token_success() {
        let storage = Storage::new();
        let access_token = setup_and_get_token(&storage).await;

        let result = handler(
            &storage,
            json!({
                "AccessToken": access_token
            }),
        )
        .await;

        assert!(result.is_ok());
        let body = result.unwrap();
        assert_eq!(body["SecretCode"].as_str().unwrap().len(), 32);
        // Only a session-authorized association continues with a session.
        assert!(body.get("Session").is_none());
    }

    #[tokio::test]
    async fn test_associate_software_token_invalid_token() {
        let storage = Storage::new();

        let result = handler(
            &storage,
            json!({
                "AccessToken": "invalid-token"
            }),
        )
        .await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AppError::InvalidAccessToken));
    }

    #[tokio::test]
    async fn test_associate_software_token_missing_parameters() {
        let storage = Storage::new();

        let result = handler(&storage, json!({})).await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AppError::InvalidParameter(_)));
    }
}
