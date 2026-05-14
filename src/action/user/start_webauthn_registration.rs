//! StartWebAuthnRegistration API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_StartWebAuthnRegistration.html>

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
    let user = storage
        .get_user(&user_id)
        .await
        .ok_or(AppError::UserNotFound)?;

    let challenge = uuid::Uuid::new_v4().to_string();
    storage
        .save_webauthn_challenge(&user_id, challenge.clone())
        .await;

    Ok(json!({
        "CredentialCreationOptions": {
            "Challenge": challenge,
            "Rp": {
                "Name": "cognitox",
                "Id": "localhost"
            },
            "User": {
                "Id": user.id.to_string(),
                "Name": user.username,
                "DisplayName": user.username
            },
            "PubKeyCredParams": [
                {
                    "Type": "public-key",
                    "Alg": -7
                }
            ],
            "Timeout": 60000
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::user::{initiate_auth, sign_up};
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
    async fn test_start_webauthn_registration_success() {
        let storage = Storage::new();
        let access_token = setup_and_get_token(&storage).await;

        let result = handler(&storage, json!({"AccessToken": access_token}))
            .await
            .unwrap();

        assert!(
            result["CredentialCreationOptions"]["Challenge"]
                .as_str()
                .is_some()
        );
    }
}
