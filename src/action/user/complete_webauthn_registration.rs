//! CompleteWebAuthnRegistration API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_CompleteWebAuthnRegistration.html>

use chrono::Utc;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::{
    error::{AppError, Result},
    storage::Storage,
    types::WebAuthnCredential,
};

use super::helpers::verify_and_extract_user_id;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Request {
    access_token: String,
    #[serde(default)]
    credential: Option<Value>,
    #[serde(default)]
    friendly_credential_name: Option<String>,
}

pub async fn handler(storage: &Storage, body: Value) -> Result<Value> {
    let req: Request = serde_json::from_value(body)
        .map_err(|e| AppError::InvalidParameter(format!("Invalid request: {}", e)))?;

    let user_id =
        verify_and_extract_user_id(&req.access_token).map_err(|_| AppError::InvalidAccessToken)?;
    storage
        .get_user(&user_id)
        .await
        .ok_or(AppError::UserNotFound)?;

    let challenge = storage.get_webauthn_challenge(&user_id).await;
    if challenge.is_none() {
        return Err(AppError::InvalidParameter(
            "No active WebAuthn registration challenge".to_string(),
        ));
    }
    storage.delete_webauthn_challenge(&user_id).await;

    let credential_id = req
        .credential
        .as_ref()
        .and_then(|c| c.get("id"))
        .and_then(|id| id.as_str())
        .map(|s| s.to_string())
        .unwrap_or_else(|| uuid::Uuid::now_v7().to_string());

    storage
        .add_webauthn_credential(
            &user_id,
            WebAuthnCredential {
                credential_id,
                friendly_credential_name: req.friendly_credential_name,
                relying_party_id: Some("localhost".to_string()),
                created_at: Utc::now(),
                authenticator_attachment: Some("platform".to_string()),
                authenticator_transports: vec!["internal".to_string()],
            },
        )
        .await;

    Ok(json!({"Status": "SUCCESS"}))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::user::{initiate_auth, sign_up, start_webauthn_registration};
    use crate::action::user_pool::{create_user_pool, create_user_pool_client};

    async fn setup_and_get_token(storage: &Storage) -> String {
        let pool = create_user_pool::handler(storage, json!({"PoolName": "test"}))
            .await
            .unwrap();
        let pool_id = pool["UserPool"]["Id"].as_str().unwrap();

        let client = create_user_pool_client::handler(
            storage,
            json!({"UserPoolId": pool_id, "ClientName": "test-client"}),
        )
        .await
        .unwrap();
        let client_id = client["UserPoolClient"]["ClientId"].as_str().unwrap();

        let signup = sign_up::handler(
            storage,
            json!({
                "ClientId": client_id,
                "Username": "testuser",
                "Password": "Password123!"
            }),
        )
        .await
        .unwrap();

        let user_sub = signup["UserSub"].as_str().unwrap();
        let user_id = uuid::Uuid::parse_str(user_sub).unwrap();
        storage.confirm_user(&user_id).await;

        let auth = initiate_auth::handler(
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

        auth["AuthenticationResult"]["AccessToken"]
            .as_str()
            .unwrap()
            .to_string()
    }

    #[tokio::test]
    async fn test_complete_webauthn_registration_success() {
        let storage = Storage::new();
        let access_token = setup_and_get_token(&storage).await;

        start_webauthn_registration::handler(
            &storage,
            json!({"AccessToken": access_token.clone()}),
        )
        .await
        .unwrap();

        let result = handler(
            &storage,
            json!({
                "AccessToken": access_token,
                "Credential": {
                    "id": "cred-1"
                },
                "FriendlyCredentialName": "My Passkey"
            }),
        )
        .await
        .unwrap();

        assert_eq!(result["Status"], "SUCCESS");
    }
}
