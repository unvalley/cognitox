//! VerifySoftwareToken API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_VerifySoftwareToken.html>

use chrono::Utc;
use hmac::{Hmac, Mac};
use serde::Deserialize;
use serde_json::{Value, json};
use sha1::Sha1;

use crate::{
    error::{AppError, Result},
    storage::Storage,
    types::ChallengeType,
};

use super::auth_flow::new_session_token;
use super::helpers::{SOFTWARE_TOKEN_MFA_FACTOR, verify_and_extract_active_user_id};

type HmacSha1 = Hmac<Sha1>;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Request {
    #[serde(default)]
    access_token: Option<String>,
    #[serde(default)]
    session: Option<String>,
    user_code: String,
    #[serde(default, rename = "FriendlyDeviceName")]
    friendly_device_name: Option<String>,
}

pub async fn handler(storage: &Storage, body: Value) -> Result<Value> {
    let req: Request = crate::action::io::parse_request(body)?;
    let _ = req.friendly_device_name;

    let code_mismatch = || AppError::EnableSoftwareTokenMfa("Code mismatch".to_string());
    let well_formed = req.user_code.len() == 6 && req.user_code.chars().all(|c| c.is_ascii_digit());

    if let Some(session) = req.session.as_deref() {
        let next_session = verify_with_session(storage, session, &req.user_code, false).await?;
        return Ok(json!({
            "Status": "SUCCESS",
            "Session": next_session
        }));
    }

    let Some(access_token) = req.access_token.as_deref() else {
        return Err(AppError::InvalidParameter(
            "AccessToken or Session is required".to_string(),
        ));
    };
    let user_id = verify_and_extract_active_user_id(storage, access_token).await?;
    storage
        .get_user(&user_id)
        .await
        .ok_or(AppError::UserNotFound)?;

    // The secret AssociateSoftwareToken just handed out, or the one already
    // verified when the user checks a code again.
    let pending = storage.get_pending_software_token_secret(&user_id).await;
    let secret = match &pending {
        Some(secret) => secret.clone(),
        None => storage
            .get_software_token_secret(&user_id)
            .await
            .ok_or_else(code_mismatch)?,
    };

    if !well_formed || !is_valid_totp_code(&secret, &req.user_code, Utc::now().timestamp())? {
        return Err(code_mismatch());
    }

    // The token is verified. It starts to count as an MFA factor when
    // SetUserMFAPreference enables it.
    if pending.is_some() {
        storage.clear_pending_software_token_secret(&user_id).await;
        storage.save_software_token_secret(&user_id, secret).await;
    }

    Ok(json!({
        "Status": "SUCCESS"
    }))
}

/// Verify the first code of an authenticator app registered under an
/// `MFA_SETUP` session. The factor becomes active, and the session returned
/// finishes the challenge.
///
/// The session is the one `associate_with_session` continued; it lives, and
/// tolerates wrong codes, as any challenge. `managed_login` says who is
/// asking: a session is only good where it was issued.
pub(crate) async fn verify_with_session(
    storage: &Storage,
    session: &str,
    user_code: &str,
    managed_login: bool,
) -> Result<String> {
    let code_mismatch = || AppError::EnableSoftwareTokenMfa("Code mismatch".to_string());
    let well_formed = user_code.len() == 6 && user_code.chars().all(|c| c.is_ascii_digit());
    let invalid_session = || AppError::NotAuthorized("Invalid session for the user.".to_string());

    let mut pending = storage
        .get_auth_challenge_session(session)
        .await
        .filter(|pending| {
            pending.challenge_name == ChallengeType::MfaSetup
                && pending.managed_login == managed_login
        })
        .ok_or_else(invalid_session)?;
    let (user_id, secret) = storage
        .get_software_token_session(session)
        .await
        .filter(|(user_id, _)| *user_id == pending.user_id)
        .ok_or_else(invalid_session)?;
    if pending.expires_at < Utc::now() {
        storage.delete_auth_challenge_session(session).await;
        storage.delete_software_token_session(session).await;
        return Err(AppError::NotAuthorized(
            "Invalid session for the user, session is expired.".to_string(),
        ));
    }
    storage
        .get_user(&user_id)
        .await
        .ok_or(AppError::UserNotFound)?;

    let attempts = storage
        .update_auth_challenge_session(session, |pending| {
            pending.failed_attempts += 1;
            pending.failed_attempts
        })
        .await
        .ok_or_else(invalid_session)?;
    if !well_formed || !is_valid_totp_code(&secret, user_code, Utc::now().timestamp())? {
        if attempts >= MAX_SETUP_ATTEMPTS {
            storage.delete_auth_challenge_session(session).await;
            storage.delete_software_token_session(session).await;
        }
        return Err(code_mismatch());
    }

    // The device is verified: the factor becomes active, and a new
    // session lets the client finish with RespondToAuthChallenge.
    storage.delete_software_token_session(session).await;
    storage.delete_auth_challenge_session(session).await;
    storage.save_software_token_secret(&user_id, secret).await;
    storage
        .add_user_auth_factor(&user_id, SOFTWARE_TOKEN_MFA_FACTOR)
        .await;
    pending.session = new_session_token();
    pending.mfa_setup_complete = true;
    pending.failed_attempts = 0;
    let next_session = pending.session.clone();
    storage.save_auth_challenge_session(pending).await;
    Ok(next_session)
}

/// Wrong codes an `MFA_SETUP` session tolerates before it is discarded.
const MAX_SETUP_ATTEMPTS: u32 = 3;

fn decode_base32_secret(secret: &str) -> Result<Vec<u8>> {
    let mut buffer = 0u32;
    let mut bits = 0u8;
    let mut output = Vec::new();

    for ch in secret
        .chars()
        .filter(|ch| !ch.is_whitespace() && *ch != '=')
    {
        let value = match ch.to_ascii_uppercase() {
            'A'..='Z' => ch.to_ascii_uppercase() as u8 - b'A',
            '2'..='7' => ch as u8 - b'2' + 26,
            _ => {
                return Err(AppError::InvalidParameter(
                    "Invalid software token secret".to_string(),
                ));
            }
        } as u32;
        buffer = (buffer << 5) | value;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            output.push((buffer >> bits) as u8);
            buffer &= (1 << bits) - 1;
        }
    }

    if output.is_empty() {
        return Err(AppError::InvalidParameter(
            "Invalid software token secret".to_string(),
        ));
    }

    Ok(output)
}

pub(crate) fn generate_totp_code(secret: &str, timestamp: i64) -> Result<String> {
    let key = decode_base32_secret(secret)?;
    let counter = (timestamp / 30) as u64;
    let mut mac = HmacSha1::new_from_slice(&key)
        .map_err(|_| AppError::Internal("Failed to initialize TOTP".to_string()))?;
    mac.update(&counter.to_be_bytes());
    let digest = mac.finalize().into_bytes();
    let offset = (digest[19] & 0x0f) as usize;
    let binary = (((digest[offset] & 0x7f) as u32) << 24)
        | ((digest[offset + 1] as u32) << 16)
        | ((digest[offset + 2] as u32) << 8)
        | (digest[offset + 3] as u32);
    Ok(format!("{:06}", binary % 1_000_000))
}

pub(crate) fn is_valid_totp_code(secret: &str, code: &str, timestamp: i64) -> Result<bool> {
    for step in -1..=1 {
        let candidate = generate_totp_code(secret, timestamp + step * 30)?;
        if candidate == code {
            return Ok(true);
        }
    }
    Ok(false)
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
    async fn test_verify_software_token_success() {
        let storage = Storage::new();
        let access_token = setup_and_get_token(&storage).await;

        let associated = crate::action::user::associate_software_token::handler(
            &storage,
            json!({
                "AccessToken": access_token
            }),
        )
        .await
        .unwrap();
        let secret = associated["SecretCode"].as_str().unwrap();
        let user_code = generate_totp_code(secret, Utc::now().timestamp()).unwrap();

        let result = handler(
            &storage,
            json!({
                "AccessToken": access_token,
                "UserCode": user_code
            }),
        )
        .await;

        assert!(result.is_ok());
        let body = result.unwrap();
        assert_eq!(body["Status"], "SUCCESS");

        // The verified secret keeps verifying codes.
        let result = handler(
            &storage,
            json!({
                "AccessToken": access_token,
                "UserCode": user_code
            }),
        )
        .await;
        assert_eq!(result.unwrap()["Status"], "SUCCESS");
    }

    #[tokio::test]
    async fn test_verify_software_token_wrong_code_is_enable_mfa_exception() {
        let storage = Storage::new();
        let access_token = setup_and_get_token(&storage).await;

        let associated = crate::action::user::associate_software_token::handler(
            &storage,
            json!({
                "AccessToken": access_token
            }),
        )
        .await
        .unwrap();
        let secret = associated["SecretCode"].as_str().unwrap();
        let right_code = generate_totp_code(secret, Utc::now().timestamp()).unwrap();
        let wrong_code = if right_code == "000000" {
            "000001"
        } else {
            "000000"
        };

        let result = handler(
            &storage,
            json!({
                "AccessToken": access_token,
                "UserCode": wrong_code
            }),
        )
        .await;
        assert!(matches!(
            result,
            Err(AppError::EnableSoftwareTokenMfa(message)) if message == "Code mismatch"
        ));
    }

    #[tokio::test]
    async fn test_verify_software_token_invalid_token() {
        let storage = Storage::new();

        let result = handler(
            &storage,
            json!({
                "AccessToken": "invalid-token",
                "UserCode": "123456"
            }),
        )
        .await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AppError::InvalidAccessToken));
    }

    #[tokio::test]
    async fn test_verify_software_token_empty_code() {
        let storage = Storage::new();
        let access_token = setup_and_get_token(&storage).await;

        let result = handler(
            &storage,
            json!({
                "AccessToken": access_token,
                "UserCode": ""
            }),
        )
        .await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            AppError::EnableSoftwareTokenMfa(_)
        ));
    }

    #[tokio::test]
    async fn test_verify_software_token_rejects_unknown_session() {
        let storage = Storage::new();

        let result = handler(
            &storage,
            json!({
                "Session": "not-a-session",
                "UserCode": "123456"
            }),
        )
        .await;

        assert!(matches!(result, Err(AppError::NotAuthorized(_))));
    }
}
