//! VerifySoftwareToken API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_VerifySoftwareToken.html>

use serde::Deserialize;
use serde_json::{Value, json};

use crate::{
    error::{AppError, Result},
    storage::Storage,
};

use super::helpers::verify_and_extract_user_id;

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

    let user_id = if let Some(access_token) = req.access_token.as_deref() {
        verify_and_extract_user_id(access_token).map_err(|_| AppError::InvalidAccessToken)?
    } else if let Some(session) = req.session.as_deref() {
        storage
            .get_software_token_session(session)
            .await
            .map(|(user_id, _)| user_id)
            .ok_or_else(|| AppError::InvalidParameter("Invalid session".to_string()))?
    } else {
        return Err(AppError::InvalidParameter(
            "AccessToken or Session is required".to_string(),
        ));
    };

    storage
        .get_user(&user_id)
        .await
        .ok_or(AppError::UserNotFound)?;

    if let Some(session) = req.session.as_deref() {
        storage.delete_software_token_session(session).await;
    }
    storage
        .add_user_auth_factor(&user_id, "SOFTWARE_TOKEN_MFA")
        .await;

    let _ = req.friendly_device_name;

    Ok(json!({
        "Status": "SUCCESS"
    }))
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

        let result = handler(
            &storage,
            json!({
                "AccessToken": access_token,
                "UserCode": "123456"
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
        let result = handler(
            &storage,
            json!({
                "Session": session,
                "UserCode": "123456"
            }),
        )
        .await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap()["Status"], "SUCCESS");
    }
}
