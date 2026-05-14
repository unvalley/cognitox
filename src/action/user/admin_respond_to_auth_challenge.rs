//! AdminRespondToAuthChallenge API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AdminRespondToAuthChallenge.html>

use std::collections::HashMap;

use serde::Deserialize;
use serde_json::Value;
use uuid::Uuid;

use crate::{
    action::io::parse_request,
    error::{AppError, Result},
    storage::Storage,
    types::{ClientId, UserPoolId, UserStatus},
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
struct HttpHeader {
    #[serde(rename = "headerName")]
    header_name: Option<String>,
    #[serde(rename = "headerValue")]
    header_value: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ContextData {
    ip_address: Option<String>,
    server_name: Option<String>,
    server_path: Option<String>,
    http_headers: Option<Vec<HttpHeader>>,
    encoded_data: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Request {
    user_pool_id: UserPoolId,
    client_id: ClientId,
    challenge_name: String,
    challenge_responses: Option<HashMap<String, String>>,
    analytics_metadata: Option<AnalyticsMetadata>,
    client_metadata: Option<HashMap<String, String>>,
    context_data: Option<ContextData>,
    session: Option<String>,
}

pub async fn handler(storage: &Storage, body: Value) -> Result<Value> {
    let req: Request = parse_request(body)?;
    let _ = (
        &req.session,
        &req.client_metadata,
        req.analytics_metadata
            .as_ref()
            .map(|meta| &meta.analytics_endpoint_id),
        req.context_data.as_ref().map(|ctx| {
            (
                &ctx.ip_address,
                &ctx.server_name,
                &ctx.server_path,
                &ctx.encoded_data,
                ctx.http_headers.as_ref().map(|headers| {
                    headers
                        .iter()
                        .map(|header| (&header.header_name, &header.header_value))
                        .collect::<Vec<_>>()
                }),
            )
        }),
    );

    storage
        .get_user_pool(&req.user_pool_id)
        .await
        .ok_or(AppError::UserPoolNotFound)?;

    let client = storage
        .get_user_pool_client(&req.client_id)
        .await
        .ok_or(AppError::UserPoolClientNotFound)?;

    // Verify client belongs to the user pool
    if client.user_pool_id != req.user_pool_id {
        return Err(AppError::UserPoolClientNotFound);
    }

    match AuthChallengeName::parse(&req.challenge_name)? {
        AuthChallengeName::NewPasswordRequired => {
            let responses = req
                .challenge_responses
                .as_ref()
                .ok_or_else(|| {
                    AppError::InvalidParameter("ChallengeResponses required".to_string())
                })
                .map(ChallengeResponses::new)?;

            let new_password = responses.require("NEW_PASSWORD")?;
            validate_password(new_password)?;

            let user = if let Some(session) = req.session.as_deref() {
                let challenge = resolve_new_password_challenge(
                    storage,
                    session,
                    &req.client_id,
                    &req.user_pool_id,
                )
                .await?;

                let user = storage
                    .get_user(&challenge.user_id)
                    .await
                    .ok_or(AppError::UserNotFound)?;
                if let Some(username) = responses.get("USERNAME")
                    && username != user.username
                {
                    return Err(AppError::InvalidParameter("USERNAME mismatch".to_string()));
                }
                if let Some(user_id_for_srp) = responses.get("USER_ID_FOR_SRP") {
                    let expected = Uuid::parse_str(user_id_for_srp).map_err(|_| {
                        AppError::InvalidParameter("Invalid USER_ID_FOR_SRP".to_string())
                    })?;
                    if expected != user.id {
                        return Err(AppError::InvalidParameter(
                            "USER_ID_FOR_SRP mismatch".to_string(),
                        ));
                    }
                }
                user
            } else if let Some(username) = responses.get("USERNAME") {
                storage
                    .get_user_by_username(&req.user_pool_id, username)
                    .await
                    .ok_or(AppError::UserNotFound)?
            } else if let Some(user_id_for_srp) = responses.get("USER_ID_FOR_SRP") {
                let user_id = Uuid::parse_str(user_id_for_srp).map_err(|_| {
                    AppError::InvalidParameter("Invalid USER_ID_FOR_SRP".to_string())
                })?;

                let user = storage
                    .get_user(&user_id)
                    .await
                    .ok_or(AppError::UserNotFound)?;
                if user.user_pool_id != req.user_pool_id {
                    return Err(AppError::UserNotFound);
                }
                user
            } else {
                return Err(AppError::InvalidParameter(
                    "USERNAME or USER_ID_FOR_SRP required".to_string(),
                ));
            };

            if !user.enabled {
                return Err(AppError::UserDisabled);
            }

            if user.user_status != UserStatus::ForceChangePassword {
                return Err(AppError::InvalidParameter(
                    "User is not in FORCE_CHANGE_PASSWORD status".to_string(),
                ));
            }
            verify_secret_hash(&client, &user.username, responses.secret_hash())?;

            let user = complete_new_password_challenge(
                storage,
                &user,
                new_password,
                req.session.as_deref(),
            )
            .await?;

            Ok(build_auth_response(
                issue_authentication_result(
                    storage,
                    &client,
                    &req.client_id,
                    &req.user_pool_id,
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
                &req.user_pool_id,
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
                    &req.user_pool_id,
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
    use crate::action::user::helpers::{calculate_secret_hash, upsert_user_attribute};
    use crate::action::user::verify_software_token::generate_totp_code;
    use crate::action::user::{admin_create_user, admin_initiate_auth};
    use crate::action::user_pool::{create_user_pool, create_user_pool_client};
    use crate::types::UserPoolId;
    use serde_json::json;

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
        pool_id: &str,
        username: &str,
        password: &str,
    ) {
        admin_create_user::handler(
            storage,
            json!({
                "UserPoolId": pool_id,
                "Username": username,
            }),
        )
        .await
        .unwrap();

        crate::action::user::admin_set_user_password::handler(
            storage,
            json!({
                "UserPoolId": pool_id,
                "Username": username,
                "Password": password,
                "Permanent": true
            }),
        )
        .await
        .unwrap();

        let pool_id = UserPoolId::new(pool_id).unwrap();
        let mut user = storage
            .get_user_by_username(&pool_id, username)
            .await
            .unwrap();
        storage
            .add_user_auth_factor(&user.id, "SOFTWARE_TOKEN_MFA")
            .await;
        storage
            .save_software_token_secret(&user.id, "JBSWY3DPEHPK3PXP".to_string())
            .await;
        upsert_user_attribute(
            &mut user.attributes,
            "preferred_mfa_setting",
            Some("SOFTWARE_TOKEN_MFA".to_string()),
        );
        storage.update_user(user).await.unwrap();
    }

    #[tokio::test]
    async fn test_admin_respond_to_auth_challenge_new_password_required_success() {
        let storage = Storage::new();
        let (pool_id, client_id) = setup_pool_and_client(&storage).await;

        admin_create_user::handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "Username": "testuser",
                "TemporaryPassword": "TempPass123!"
            }),
        )
        .await
        .unwrap();

        let result = handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "ClientId": client_id,
                "ChallengeName": "NEW_PASSWORD_REQUIRED",
                "ChallengeResponses": {
                    "USERNAME": "testuser",
                    "NEW_PASSWORD": "NewPassword123!"
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

        // Verify the new password is now usable with admin auth.
        let auth_result = admin_initiate_auth::handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "ClientId": client_id,
                "AuthFlow": "ADMIN_USER_PASSWORD_AUTH",
                "AuthParameters": {
                    "USERNAME": "testuser",
                    "PASSWORD": "NewPassword123!"
                }
            }),
        )
        .await
        .unwrap();
        assert!(
            auth_result["AuthenticationResult"]["AccessToken"]
                .as_str()
                .is_some()
        );
    }

    #[tokio::test]
    async fn test_admin_respond_to_auth_challenge_missing_new_password() {
        let storage = Storage::new();
        let (pool_id, client_id) = setup_pool_and_client(&storage).await;

        admin_create_user::handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "Username": "testuser"
            }),
        )
        .await
        .unwrap();

        let result = handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "ClientId": client_id,
                "ChallengeName": "NEW_PASSWORD_REQUIRED",
                "ChallengeResponses": {
                    "USERNAME": "testuser"
                }
            }),
        )
        .await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AppError::InvalidParameter(_)));
    }

    #[tokio::test]
    async fn test_admin_respond_to_auth_challenge_not_force_change_password() {
        let storage = Storage::new();
        let (pool_id, client_id) = setup_pool_and_client(&storage).await;

        admin_create_user::handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "Username": "testuser",
                "TemporaryPassword": "TempPass123!"
            }),
        )
        .await
        .unwrap();

        // First successful response moves user to CONFIRMED status.
        handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "ClientId": client_id,
                "ChallengeName": "NEW_PASSWORD_REQUIRED",
                "ChallengeResponses": {
                    "USERNAME": "testuser",
                    "NEW_PASSWORD": "NewPassword123!"
                }
            }),
        )
        .await
        .unwrap();

        // A second response should fail because the user is no longer in FORCE_CHANGE_PASSWORD.
        let second_result = handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "ClientId": client_id,
                "ChallengeName": "NEW_PASSWORD_REQUIRED",
                "ChallengeResponses": {
                    "USERNAME": "testuser",
                    "NEW_PASSWORD": "AnotherPass123!"
                }
            }),
        )
        .await;

        assert!(second_result.is_err());
        assert!(matches!(
            second_result.unwrap_err(),
            AppError::InvalidParameter(_)
        ));
    }

    #[tokio::test]
    async fn test_admin_respond_to_auth_challenge_not_implemented_challenge() {
        let storage = Storage::new();
        let (pool_id, client_id) = setup_pool_and_client(&storage).await;

        let result = handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "ClientId": client_id,
                "ChallengeName": "SMS_MFA",
                "ChallengeResponses": {}
            }),
        )
        .await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AppError::NotImplemented(_)));
    }

    #[tokio::test]
    async fn test_admin_respond_to_auth_challenge_requires_secret_hash_for_secret_client() {
        let storage = Storage::new();

        let pool = create_user_pool::handler(&storage, json!({"PoolName": "test"}))
            .await
            .unwrap();
        let pool_id = pool["UserPool"]["Id"].as_str().unwrap().to_string();

        let client = create_user_pool_client::handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "ClientName": "secret-client",
                "GenerateSecret": true
            }),
        )
        .await
        .unwrap();
        let client_id = client["UserPoolClient"]["ClientId"].as_str().unwrap();
        let client_secret = client["UserPoolClient"]["ClientSecret"].as_str().unwrap();

        admin_create_user::handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "Username": "testuser",
                "TemporaryPassword": "TempPass123!"
            }),
        )
        .await
        .unwrap();

        let result = handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "ClientId": client_id,
                "ChallengeName": "NEW_PASSWORD_REQUIRED",
                "ChallengeResponses": {
                    "USERNAME": "testuser",
                    "NEW_PASSWORD": "NewPassword123!"
                }
            }),
        )
        .await;
        assert!(matches!(result, Err(AppError::NotAuthorized(_))));

        let result = handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "ClientId": client_id,
                "ChallengeName": "NEW_PASSWORD_REQUIRED",
                "ChallengeResponses": {
                    "USERNAME": "testuser",
                    "NEW_PASSWORD": "NewPassword123!",
                    "SECRET_HASH": calculate_secret_hash(client_id, client_secret, "testuser").unwrap()
                }
            }),
        )
        .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_admin_respond_to_auth_challenge_software_token_mfa_success() {
        let storage = Storage::new();
        let (pool_id, client_id) = setup_pool_and_client(&storage).await;

        create_confirmed_user_with_software_mfa(&storage, &pool_id, "testuser", "Password123!")
            .await;

        let initiated = admin_initiate_auth::handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "ClientId": client_id,
                "AuthFlow": "ADMIN_USER_PASSWORD_AUTH",
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
        let user_code =
            generate_totp_code("JBSWY3DPEHPK3PXP", chrono::Utc::now().timestamp()).unwrap();

        let result = handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "ClientId": client_id,
                "ChallengeName": "SOFTWARE_TOKEN_MFA",
                "Session": session,
                "ChallengeResponses": {
                    "USERNAME": "testuser",
                    "SOFTWARE_TOKEN_MFA_CODE": user_code
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
