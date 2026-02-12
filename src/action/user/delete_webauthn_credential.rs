//! DeleteWebAuthnCredential API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_DeleteWebAuthnCredential.html>

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
    access_token: String,
    credential_id: String,
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

    let deleted = storage
        .delete_webauthn_credential(&user_id, &req.credential_id)
        .await;
    if !deleted {
        return Err(AppError::WebAuthnCredentialNotFound);
    }

    Ok(json!({}))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::user::{
        complete_webauthn_registration, initiate_auth, sign_up, start_webauthn_registration,
    };
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
    async fn test_delete_webauthn_credential_success() {
        let storage = Storage::new();
        let access_token = setup_and_get_token(&storage).await;

        start_webauthn_registration::handler(
            &storage,
            json!({"AccessToken": access_token.clone()}),
        )
        .await
        .unwrap();
        complete_webauthn_registration::handler(
            &storage,
            json!({
                "AccessToken": access_token.clone(),
                "Credential": {"id": "cred-1"}
            }),
        )
        .await
        .unwrap();

        let result = handler(
            &storage,
            json!({
                "AccessToken": access_token,
                "CredentialId": "cred-1"
            }),
        )
        .await
        .unwrap();

        assert_eq!(result, json!({}));
    }
}
