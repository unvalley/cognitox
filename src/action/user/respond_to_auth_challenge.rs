//! RespondToAuthChallenge API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_RespondToAuthChallenge.html>

use std::collections::HashMap;

use serde::Deserialize;
use serde_json::Value;

use crate::{
    action::io::parse_request,
    error::{AppError, Result},
    storage::Storage,
    types::{ClientId, UserStatus},
    validation::validate_password,
};

use super::{
    auth_flow::{
        AuthChallengeName, ChallengeResponses, build_auth_response,
        complete_new_password_challenge, complete_software_token_mfa_challenge,
        issue_authentication_result, resolve_new_password_challenge,
        resolve_software_token_mfa_challenge,
    },
    helpers::verify_secret_hash,
};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct AnalyticsMetadata {
    analytics_endpoint_id: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct UserContextData {
    encoded_data: Option<String>,
    ip_address: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Request {
    client_id: ClientId,
    challenge_name: String,
    challenge_responses: Option<HashMap<String, String>>,
    analytics_metadata: Option<AnalyticsMetadata>,
    client_metadata: Option<HashMap<String, String>>,
    session: Option<String>,
    user_context_data: Option<UserContextData>,
}

pub async fn handler(storage: &Storage, body: Value) -> Result<Value> {
    let req: Request = parse_request(body)?;
    let _ = (
        &req.client_id,
        &req.challenge_responses,
        &req.client_metadata,
        &req.session,
        req.analytics_metadata
            .as_ref()
            .map(|meta| &meta.analytics_endpoint_id),
        req.user_context_data
            .as_ref()
            .map(|ctx| (&ctx.encoded_data, &ctx.ip_address)),
    );

    let client = storage
        .get_user_pool_client(&req.client_id)
        .await
        .ok_or(AppError::UserPoolClientNotFound)?;

    match AuthChallengeName::parse(&req.challenge_name)? {
        AuthChallengeName::NewPasswordRequired => {
            let session = req
                .session
                .as_deref()
                .ok_or_else(|| AppError::InvalidParameter("Session required".to_string()))?;
            let challenge = resolve_new_password_challenge(
                storage,
                session,
                &req.client_id,
                &client.user_pool_id,
            )
            .await?;

            let responses = req
                .challenge_responses
                .as_ref()
                .ok_or_else(|| {
                    AppError::InvalidParameter("ChallengeResponses required".to_string())
                })
                .map(ChallengeResponses::new)?;
            let new_password = responses.require("NEW_PASSWORD")?;
            validate_password(new_password)?;

            let user = storage
                .get_user(&challenge.user_id)
                .await
                .ok_or(AppError::UserNotFound)?;
            if !user.enabled {
                return Err(AppError::UserDisabled);
            }
            if user.user_status != UserStatus::ForceChangePassword {
                return Err(AppError::InvalidParameter(
                    "User is not in FORCE_CHANGE_PASSWORD status".to_string(),
                ));
            }

            if let Some(username) = responses.get("USERNAME")
                && username != user.username
            {
                return Err(AppError::InvalidParameter("USERNAME mismatch".to_string()));
            }
            verify_secret_hash(&client, &user.username, responses.secret_hash())?;

            let user = complete_new_password_challenge(storage, &user, new_password, Some(session))
                .await?;

            Ok(build_auth_response(
                issue_authentication_result(
                    storage,
                    &client,
                    &req.client_id,
                    &client.user_pool_id,
                    &user,
                    true,
                    false,
                )
                .await?,
            ))
        }
        AuthChallengeName::SoftwareTokenMfa => {
            let session = req
                .session
                .as_deref()
                .ok_or_else(|| AppError::InvalidParameter("Session required".to_string()))?;
            let challenge = resolve_software_token_mfa_challenge(
                storage,
                session,
                &req.client_id,
                &client.user_pool_id,
            )
            .await?;

            let responses = req
                .challenge_responses
                .as_ref()
                .ok_or_else(|| {
                    AppError::InvalidParameter("ChallengeResponses required".to_string())
                })
                .map(ChallengeResponses::new)?;
            let code = responses.require("SOFTWARE_TOKEN_MFA_CODE")?;

            let user = storage
                .get_user(&challenge.user_id)
                .await
                .ok_or(AppError::UserNotFound)?;
            if !user.enabled {
                return Err(AppError::UserDisabled);
            }
            if user.user_status != UserStatus::Confirmed {
                return Err(AppError::InvalidParameter(
                    "User is not in CONFIRMED status".to_string(),
                ));
            }
            if let Some(username) = responses.get("USERNAME")
                && username != user.username
            {
                return Err(AppError::InvalidParameter("USERNAME mismatch".to_string()));
            }
            verify_secret_hash(&client, &user.username, responses.secret_hash())?;

            let user = complete_software_token_mfa_challenge(storage, &user, code, session).await?;

            Ok(build_auth_response(
                issue_authentication_result(
                    storage,
                    &client,
                    &req.client_id,
                    &client.user_pool_id,
                    &user,
                    true,
                    false,
                )
                .await?,
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    use crate::action::user::{helpers::upsert_user_attribute, initiate_auth, sign_up};
    use crate::action::user_pool::{create_user_pool, create_user_pool_client};

    async fn setup_pool_and_client(storage: &Storage) -> (String, String) {
        let pool = create_user_pool::handler(storage, json!({"PoolName": "test"}))
            .await
            .unwrap();
        let pool_id = pool["UserPool"]["Id"].as_str().unwrap().to_string();

        let client = create_user_pool_client::handler(
            storage,
            json!({
                "UserPoolId": pool_id,
                "ClientName": "test-client"
            }),
        )
        .await
        .unwrap();
        let client_id = client["UserPoolClient"]["ClientId"]
            .as_str()
            .unwrap()
            .to_string();

        (pool_id, client_id)
    }

    async fn create_confirmed_user_with_software_mfa(
        storage: &Storage,
        client_id: &str,
        username: &str,
        password: &str,
    ) {
        let sign_up_result = sign_up::handler(
            storage,
            json!({
                "ClientId": client_id,
                "Username": username,
                "Password": password
            }),
        )
        .await
        .unwrap();

        let user_id = uuid::Uuid::parse_str(sign_up_result["UserSub"].as_str().unwrap()).unwrap();
        storage.confirm_user(&user_id).await;
        storage
            .add_user_auth_factor(&user_id, "SOFTWARE_TOKEN_MFA")
            .await;

        let mut user = storage.get_user(&user_id).await.unwrap();
        upsert_user_attribute(
            &mut user.attributes,
            "preferred_mfa_setting",
            Some("SOFTWARE_TOKEN_MFA".to_string()),
        );
        storage.update_user(user).await.unwrap();
    }

    #[tokio::test]
    async fn test_respond_to_auth_challenge_not_implemented() {
        let storage = Storage::new();
        let (_pool_id, client_id) = setup_pool_and_client(&storage).await;

        let result = handler(
            &storage,
            json!({
                "ClientId": client_id,
                "ChallengeName": "NEW_PASSWORD_REQUIRED",
                "ChallengeResponses": {
                    "USERNAME": "testuser",
                    "NEW_PASSWORD": "NewPassword123!"
                }
            }),
        )
        .await;

        // Should return NotImplemented error
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_respond_to_auth_challenge_missing_challenge_name() {
        let storage = Storage::new();
        let (_pool_id, client_id) = setup_pool_and_client(&storage).await;

        let result = handler(
            &storage,
            json!({
                "ClientId": client_id,
                "ChallengeResponses": {}
            }),
        )
        .await;

        // Should return InvalidParameter error for missing ChallengeName
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_respond_to_auth_challenge_software_token_mfa_success() {
        let storage = Storage::new();
        let (_pool_id, client_id) = setup_pool_and_client(&storage).await;

        create_confirmed_user_with_software_mfa(&storage, &client_id, "testuser", "Password123!")
            .await;

        let initiated = initiate_auth::handler(
            &storage,
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

        assert_eq!(initiated["ChallengeName"], "SOFTWARE_TOKEN_MFA");
        let session = initiated["Session"].as_str().unwrap();

        let result = handler(
            &storage,
            json!({
                "ClientId": client_id,
                "ChallengeName": "SOFTWARE_TOKEN_MFA",
                "Session": session,
                "ChallengeResponses": {
                    "USERNAME": "testuser",
                    "SOFTWARE_TOKEN_MFA_CODE": "123456"
                }
            }),
        )
        .await
        .unwrap();

        assert!(
            result["AuthenticationResult"]["AccessToken"]
                .as_str()
                .is_some()
        );
        assert!(result["AuthenticationResult"]["IdToken"].as_str().is_some());
        assert!(
            result["AuthenticationResult"]["RefreshToken"]
                .as_str()
                .is_some()
        );
    }
}
