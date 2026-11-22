//! AdminRespondToAuthChallenge API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AdminRespondToAuthChallenge.html>

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    action::io::{parse_request, to_response_value},
    error::{AppError, Result},
    storage::Storage,
    types::{ClientId, UserPoolId},
};

use super::auth_flow::{AuthApi, AuthContext, respond_to_auth_challenge};

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

/// What a step of a sign-in answers with: tokens once it is complete, or
/// the next challenge. Members that do not apply are left out.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Response {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    authentication_result: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    challenge_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    challenge_parameters: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    session: Option<String>,
}

pub async fn handler(storage: &Storage, body: Value) -> Result<Value> {
    let req: Request = parse_request(body)?;
    // Accepted for SDK compatibility; they feed analytics, threat
    // protection, and Lambda triggers, none of which the emulator runs.
    let _ = (
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

    let pool = storage
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

    let ctx = AuthContext {
        storage,
        pool: &pool,
        client: &client,
        api: AuthApi::Admin,
    };
    let outcome = respond_to_auth_challenge(
        &ctx,
        &req.challenge_name,
        req.session.as_deref(),
        &req.challenge_responses.unwrap_or_default(),
    )
    .await?;
    let response: Response = serde_json::from_value(outcome)
        .map_err(|e| AppError::Internal(format!("Invalid response: {e}")))?;
    to_response_value(response)
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
                "ExplicitAuthFlows": ["ALLOW_USER_PASSWORD_AUTH", "ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_USER_SRP_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
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

    async fn temporary_password_session(
        storage: &Storage,
        pool_id: &str,
        client_id: &str,
    ) -> String {
        admin_create_user::handler(
            storage,
            json!({
                "UserPoolId": pool_id,
                "Username": "testuser",
                "TemporaryPassword": "TempPass123!"
            }),
        )
        .await
        .unwrap();

        let challenge = admin_initiate_auth::handler(
            storage,
            json!({
                "UserPoolId": pool_id,
                "ClientId": client_id,
                "AuthFlow": "ADMIN_USER_PASSWORD_AUTH",
                "AuthParameters": {
                    "USERNAME": "testuser",
                    "PASSWORD": "TempPass123!"
                }
            }),
        )
        .await
        .unwrap();
        assert_eq!(challenge["ChallengeName"], "NEW_PASSWORD_REQUIRED");
        assert_eq!(
            challenge["ChallengeParameters"]["USER_ID_FOR_SRP"],
            "testuser"
        );
        assert_eq!(challenge["ChallengeParameters"]["requiredAttributes"], "[]");
        assert!(challenge.get("AuthenticationResult").is_none());
        challenge["Session"].as_str().unwrap().to_string()
    }

    #[tokio::test]
    async fn test_admin_respond_to_auth_challenge_new_password_required_success() {
        let storage = Storage::new();
        let (pool_id, client_id) = setup_pool_and_client(&storage).await;
        let session = temporary_password_session(&storage, &pool_id, &client_id).await;

        let result = handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "ClientId": client_id,
                "ChallengeName": "NEW_PASSWORD_REQUIRED",
                "Session": session,
                "ChallengeResponses": {
                    "USERNAME": "testuser",
                    "NEW_PASSWORD": "NewPassword123!"
                }
            }),
        )
        .await
        .unwrap();

        let tokens = &result["AuthenticationResult"];
        assert!(tokens["AccessToken"].as_str().is_some());
        assert!(tokens["IdToken"].as_str().is_some());
        assert!(tokens["RefreshToken"].as_str().is_some());
        assert_eq!(tokens["TokenType"], "Bearer");
        // A completed sign-in names no further challenge.
        assert!(result.get("ChallengeName").is_none());
        assert!(result.get("Session").is_none());

        // The new password is permanent.
        let signed_in = admin_initiate_auth::handler(
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
        assert!(signed_in["AuthenticationResult"]["AccessToken"].is_string());
    }

    #[tokio::test]
    async fn test_admin_respond_to_auth_challenge_missing_new_password() {
        let storage = Storage::new();
        let (pool_id, client_id) = setup_pool_and_client(&storage).await;
        let session = temporary_password_session(&storage, &pool_id, &client_id).await;

        let result = handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "ClientId": client_id,
                "ChallengeName": "NEW_PASSWORD_REQUIRED",
                "Session": session,
                "ChallengeResponses": {
                    "USERNAME": "testuser"
                }
            }),
        )
        .await;

        assert!(matches!(
            result,
            Err(AppError::InvalidParameter(message))
                if message == "Missing required parameter NEW_PASSWORD"
        ));
    }

    #[tokio::test]
    async fn test_admin_respond_to_auth_challenge_enforces_password_policy() {
        let storage = Storage::new();
        let (pool_id, client_id) = setup_pool_and_client(&storage).await;
        let session = temporary_password_session(&storage, &pool_id, &client_id).await;

        let request = |new_password: &str| {
            json!({
                "UserPoolId": pool_id,
                "ClientId": client_id,
                "ChallengeName": "NEW_PASSWORD_REQUIRED",
                "Session": session,
                "ChallengeResponses": {
                    "USERNAME": "testuser",
                    "NEW_PASSWORD": new_password
                }
            })
        };

        let result = handler(&storage, request("weakpassword")).await;
        assert!(matches!(result, Err(AppError::InvalidPassword(_))));

        // A rejected password leaves the session usable.
        let result = handler(&storage, request("NewPassword123!")).await.unwrap();
        assert!(result["AuthenticationResult"]["AccessToken"].is_string());
    }

    #[tokio::test]
    async fn test_admin_respond_to_auth_challenge_session_is_single_use() {
        let storage = Storage::new();
        let (pool_id, client_id) = setup_pool_and_client(&storage).await;
        let session = temporary_password_session(&storage, &pool_id, &client_id).await;

        let request = json!({
            "UserPoolId": pool_id,
            "ClientId": client_id,
            "ChallengeName": "NEW_PASSWORD_REQUIRED",
            "Session": session,
            "ChallengeResponses": {
                "USERNAME": "testuser",
                "NEW_PASSWORD": "NewPassword123!"
            }
        });
        handler(&storage, request.clone()).await.unwrap();

        let second_result = handler(&storage, request).await;
        assert!(matches!(
            second_result,
            Err(AppError::NotAuthorized(message)) if message == "Invalid session for the user."
        ));
    }

    #[tokio::test]
    async fn test_admin_respond_to_auth_challenge_requires_session() {
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
        assert!(matches!(
            result,
            Err(AppError::InvalidParameter(message))
                if message == "Missing required parameter Session"
        ));

        let result = handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "ClientId": client_id,
                "ChallengeName": "NOT_A_CHALLENGE",
                "ChallengeResponses": {}
            }),
        )
        .await;
        assert!(matches!(
            result,
            Err(AppError::InvalidParameter(message)) if message.contains("at 'challengeName'")
        ));
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
                "ExplicitAuthFlows": ["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
                "ClientName": "secret-client",
                "GenerateSecret": true
            }),
        )
        .await
        .unwrap();
        let client_id = client["UserPoolClient"]["ClientId"].as_str().unwrap();
        let client_secret = client["UserPoolClient"]["ClientSecret"].as_str().unwrap();
        let secret_hash = calculate_secret_hash(client_id, client_secret, "testuser").unwrap();

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

        let challenge = admin_initiate_auth::handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "ClientId": client_id,
                "AuthFlow": "ADMIN_USER_PASSWORD_AUTH",
                "AuthParameters": {
                    "USERNAME": "testuser",
                    "PASSWORD": "TempPass123!",
                    "SECRET_HASH": secret_hash
                }
            }),
        )
        .await
        .unwrap();
        let session = challenge["Session"].as_str().unwrap();

        let result = handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "ClientId": client_id,
                "ChallengeName": "NEW_PASSWORD_REQUIRED",
                "Session": session,
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
                "Session": session,
                "ChallengeResponses": {
                    "USERNAME": "testuser",
                    "NEW_PASSWORD": "NewPassword123!",
                    "SECRET_HASH": secret_hash
                }
            }),
        )
        .await
        .unwrap();
        assert!(result["AuthenticationResult"]["AccessToken"].is_string());
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
