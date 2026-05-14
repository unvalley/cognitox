//! CompleteWebAuthnRegistration API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_CompleteWebAuthnRegistration.html>

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::{
    error::{AppError, Result},
    storage::Storage,
    types::WebAuthnCredential,
};

use super::helpers::verify_and_extract_active_user_id;

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

    let user_id = verify_and_extract_active_user_id(storage, &req.access_token)
        .await
        .map_err(|_| AppError::InvalidAccessToken)?;
    storage
        .get_user(&user_id)
        .await
        .ok_or(AppError::UserNotFound)?;

    let challenge = storage.get_webauthn_challenge(&user_id).await;
    let Some(challenge) = challenge else {
        return Err(AppError::InvalidParameter(
            "No active WebAuthn registration challenge".to_string(),
        ));
    };

    let credential = req
        .credential
        .as_ref()
        .ok_or_else(|| AppError::InvalidParameter("Credential is required".to_string()))?;
    if credential.get("type").and_then(Value::as_str) != Some("public-key") {
        return Err(AppError::InvalidParameter(
            "Credential type must be public-key".to_string(),
        ));
    }

    let credential_id = credential
        .get("id")
        .and_then(Value::as_str)
        .filter(|id| !id.trim().is_empty())
        .ok_or_else(|| AppError::InvalidParameter("Credential id is required".to_string()))?
        .to_string();
    let raw_id = credential
        .get("rawId")
        .and_then(Value::as_str)
        .filter(|raw_id| !raw_id.trim().is_empty())
        .ok_or_else(|| AppError::InvalidParameter("Credential rawId is required".to_string()))?;
    if raw_id != credential_id {
        return Err(AppError::InvalidParameter(
            "Credential rawId must match id".to_string(),
        ));
    }

    let response = credential
        .get("response")
        .and_then(Value::as_object)
        .ok_or_else(|| AppError::InvalidParameter("Credential response is required".to_string()))?;
    let client_data_json = response
        .get("clientDataJSON")
        .and_then(Value::as_str)
        .ok_or_else(|| AppError::InvalidParameter("clientDataJSON is required".to_string()))?;
    let attestation_object = response
        .get("attestationObject")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| AppError::InvalidParameter("attestationObject is required".to_string()))?;

    let client_data = URL_SAFE_NO_PAD
        .decode(client_data_json)
        .map_err(|_| AppError::InvalidParameter("Invalid clientDataJSON".to_string()))?;
    let client_data: Value = serde_json::from_slice(&client_data)
        .map_err(|_| AppError::InvalidParameter("Invalid clientDataJSON".to_string()))?;
    if client_data.get("type").and_then(Value::as_str) != Some("webauthn.create") {
        return Err(AppError::InvalidParameter(
            "clientDataJSON type must be webauthn.create".to_string(),
        ));
    }
    if client_data.get("challenge").and_then(Value::as_str) != Some(challenge.as_str()) {
        return Err(AppError::InvalidParameter(
            "WebAuthn challenge mismatch".to_string(),
        ));
    }
    URL_SAFE_NO_PAD
        .decode(attestation_object)
        .map_err(|_| AppError::InvalidParameter("Invalid attestationObject".to_string()))?;

    storage.delete_webauthn_challenge(&user_id).await;

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
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

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

        let started = start_webauthn_registration::handler(
            &storage,
            json!({"AccessToken": access_token.clone()}),
        )
        .await
        .unwrap();
        let challenge = started["CredentialCreationOptions"]["Challenge"]
            .as_str()
            .unwrap();
        let client_data_json = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&json!({
                "type": "webauthn.create",
                "challenge": challenge,
                "origin": "http://localhost"
            }))
            .unwrap(),
        );

        let result = handler(
            &storage,
            json!({
                "AccessToken": access_token,
                "Credential": {
                    "id": "cred-1",
                    "rawId": "cred-1",
                    "type": "public-key",
                    "response": {
                        "clientDataJSON": client_data_json,
                        "attestationObject": URL_SAFE_NO_PAD.encode([1, 2, 3])
                    }
                },
                "FriendlyCredentialName": "My Passkey"
            }),
        )
        .await
        .unwrap();

        assert_eq!(result["Status"], "SUCCESS");
    }
}
