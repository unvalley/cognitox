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
};

use super::helpers::verify_and_extract_active_user_id;

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
    let req: Request = serde_json::from_value(body)
        .map_err(|e| AppError::InvalidParameter(format!("Invalid request: {}", e)))?;

    if req.user_code.trim().is_empty() {
        return Err(AppError::InvalidParameter(
            "UserCode must not be empty".to_string(),
        ));
    }
    if req.user_code.len() != 6 || !req.user_code.chars().all(|c| c.is_ascii_digit()) {
        return Err(AppError::InvalidParameter(
            "UserCode must be a 6-digit code".to_string(),
        ));
    }

    // `pending_session` is the AssociateSoftwareToken session whose secret is
    // being confirmed; it is consumed and promoted on success.
    let (user_id, secret, pending_session) = if let Some(session) = req.session.as_deref() {
        let (user_id, secret) = storage
            .get_software_token_session(session)
            .await
            .ok_or_else(|| AppError::InvalidParameter("Invalid session".to_string()))?;
        (user_id, secret, Some(session.to_string()))
    } else if let Some(access_token) = req.access_token.as_deref() {
        let user_id = verify_and_extract_active_user_id(storage, access_token)
            .await
            .map_err(|_| AppError::InvalidAccessToken)?;
        // The standard setup flow (Amplify `setUpTOTP` → `verifyTOTPSetup`)
        // calls Associate and Verify with the access token only and never
        // passes the Session back, so look for the pending secret first.
        match storage.find_software_token_session_for_user(&user_id).await {
            Some((session, secret)) => (user_id, secret, Some(session)),
            None => {
                let secret = storage
                    .get_software_token_secret(&user_id)
                    .await
                    .ok_or_else(|| {
                        AppError::InvalidParameter(
                            "User does not have SOFTWARE_TOKEN_MFA configured".to_string(),
                        )
                    })?;
                (user_id, secret, None)
            }
        }
    } else {
        return Err(AppError::InvalidParameter(
            "AccessToken or Session is required".to_string(),
        ));
    };

    storage
        .get_user(&user_id)
        .await
        .ok_or(AppError::UserNotFound)?;

    if !is_valid_totp_code(&secret, &req.user_code, Utc::now().timestamp())? {
        return Err(AppError::EnableSoftwareTokenMfa(
            "Code mismatch".to_string(),
        ));
    }

    if let Some(session) = pending_session.as_deref() {
        storage.delete_software_token_session(session).await;
        storage.save_software_token_secret(&user_id, secret).await;
    }
    storage
        .add_user_auth_factor(&user_id, "SOFTWARE_TOKEN_MFA")
        .await;

    let _ = req.friendly_device_name;

    Ok(json!({
        "Status": "SUCCESS",
        "Session": req.session
    }))
}

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

fn is_valid_totp_code(secret: &str, code: &str, timestamp: i64) -> Result<bool> {
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
        let session = associated["Session"].as_str().unwrap();
        let secret = associated["SecretCode"].as_str().unwrap();
        let user_code = generate_totp_code(secret, Utc::now().timestamp()).unwrap();

        let result = handler(
            &storage,
            json!({
                "Session": session,
                "UserCode": user_code
            }),
        )
        .await;

        assert!(result.is_ok());
        let body = result.unwrap();
        assert_eq!(body["Status"], "SUCCESS");
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
        assert!(matches!(result.unwrap_err(), AppError::InvalidParameter(_)));
    }

    #[tokio::test]
    async fn test_verify_software_token_with_session() {
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

        let session = associated["Session"].as_str().unwrap();
        let secret = associated["SecretCode"].as_str().unwrap();
        let user_code = generate_totp_code(secret, Utc::now().timestamp()).unwrap();
        let result = handler(
            &storage,
            json!({
                "Session": session,
                "UserCode": user_code
            }),
        )
        .await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap()["Status"], "SUCCESS");
    }

    #[tokio::test]
    async fn test_verify_software_token_with_access_token_only() {
        // Amplify's setUpTOTP → verifyTOTPSetup never sends the Session back.
        let storage = Storage::new();
        let access_token = setup_and_get_token(&storage).await;

        let associated = crate::action::user::associate_software_token::handler(
            &storage,
            json!({ "AccessToken": access_token }),
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
        .await
        .unwrap();
        assert_eq!(result["Status"], "SUCCESS");

        // The secret is promoted so it can be used for sign-in challenges.
        let user_id = crate::jwt::verify_access_token(&access_token)
            .unwrap()
            .claims
            .sub
            .parse::<uuid::Uuid>()
            .unwrap();
        assert_eq!(
            storage.get_software_token_secret(&user_id).await.as_deref(),
            Some(secret)
        );
        assert!(
            storage
                .find_software_token_session_for_user(&user_id)
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn test_verify_software_token_wrong_code_is_enable_software_token_mfa_exception() {
        let storage = Storage::new();
        let access_token = setup_and_get_token(&storage).await;

        crate::action::user::associate_software_token::handler(
            &storage,
            json!({ "AccessToken": access_token }),
        )
        .await
        .unwrap();

        let result = handler(
            &storage,
            json!({
                "AccessToken": access_token,
                "UserCode": "000000"
            }),
        )
        .await;
        assert!(matches!(result, Err(AppError::EnableSoftwareTokenMfa(_))));
    }
}
