//! ListWebAuthnCredentials API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_ListWebAuthnCredentials.html>

use serde::Deserialize;
use serde_json::{Value, json};

use crate::{
    error::{AppError, Result},
    storage::Storage,
};

use super::helpers::verify_and_extract_active_user_id;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Request {
    access_token: String,
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

    let credentials = storage.list_webauthn_credentials(&user_id).await;
    let credentials: Vec<Value> = credentials
        .into_iter()
        .map(|cred| {
            json!({
                "CredentialId": cred.credential_id,
                "FriendlyCredentialName": cred.friendly_credential_name,
                "RelyingPartyId": cred.relying_party_id,
                "AuthenticatorAttachment": cred.authenticator_attachment,
                "AuthenticatorTransports": cred.authenticator_transports,
                "CreatedAt": cred.created_at.timestamp()
            })
        })
        .collect();

    Ok(json!({"Credentials": credentials}))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::user::{
        complete_webauthn_registration, initiate_auth, sign_up, start_webauthn_registration,
    };
    use crate::action::user_pool::{create_user_pool, create_user_pool_client};
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

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
    async fn test_list_webauthn_credentials_success() {
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
        complete_webauthn_registration::handler(
            &storage,
            json!({
                "AccessToken": access_token.clone(),
                "Credential": {
                    "id": "cred-1",
                    "rawId": "cred-1",
                    "type": "public-key",
                    "response": {
                        "clientDataJSON": client_data_json,
                        "attestationObject": URL_SAFE_NO_PAD.encode([1, 2, 3])
                    }
                }
            }),
        )
        .await
        .unwrap();

        let result = handler(&storage, json!({"AccessToken": access_token}))
            .await
            .unwrap();

        assert_eq!(result["Credentials"].as_array().unwrap().len(), 1);
    }
}
