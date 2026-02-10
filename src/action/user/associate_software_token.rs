//! AssociateSoftwareToken API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AssociateSoftwareToken.html>

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
}

pub async fn handler(storage: &Storage, body: Value) -> Result<Value> {
    let req: Request = serde_json::from_value(body)
        .map_err(|e| AppError::InvalidParameter(format!("Invalid request: {}", e)))?;

    if let Some(access_token) = req.access_token.as_deref() {
        let user_id =
            verify_and_extract_user_id(access_token).map_err(|_| AppError::InvalidAccessToken)?;
        storage
            .get_user(&user_id)
            .await
            .ok_or(AppError::UserNotFound)?;
    } else if req.session.is_none() {
        return Err(AppError::InvalidParameter(
            "AccessToken or Session is required".to_string(),
        ));
    }

    let session = uuid::Uuid::new_v4().to_string();

    Ok(json!({
        "SecretCode": "SOFTWARE_TOKEN_SECRET",
        "Session": session
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
        assert_eq!(body["SecretCode"], "SOFTWARE_TOKEN_SECRET");
        assert!(body["Session"].as_str().is_some());
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
