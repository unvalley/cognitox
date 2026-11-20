//! AdminInitiateAuth API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AdminInitiateAuth.html>

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    action::io::{parse_request, to_response_value},
    error::{AppError, Result},
    storage::Storage,
    types::{ClientId, UserPoolId},
};

use super::auth_flow::{AuthApi, AuthContext, initiate_auth};

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
    auth_flow: String,
    auth_parameters: Option<HashMap<String, String>>,
    analytics_metadata: Option<AnalyticsMetadata>,
    context_data: Option<ContextData>,
    session: Option<String>,
    client_metadata: Option<HashMap<String, String>>,
}

/// What a step of a sign-in answers with: tokens once it is complete, or
/// the next challenge. Members that do not apply are left out.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Response {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    authentication_result: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    available_challenges: Option<Vec<String>>,
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
    let outcome = initiate_auth(
        &ctx,
        &req.auth_flow,
        &req.auth_parameters.unwrap_or_default(),
        req.session.as_deref(),
    )
    .await?;
    let response: Response = serde_json::from_value(outcome)
        .map_err(|e| AppError::Internal(format!("Invalid response: {e}")))?;
    to_response_value(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::user::admin_create_user;
    use crate::action::user::admin_set_user_password;
    use crate::action::user::helpers::upsert_user_attribute;
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
                "Username": username
            }),
        )
        .await
        .unwrap();

        admin_set_user_password::handler(
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
        upsert_user_attribute(
            &mut user.attributes,
            "preferred_mfa_setting",
            Some("SOFTWARE_TOKEN_MFA".to_string()),
        );
        storage.update_user(user).await.unwrap();
    }

    #[tokio::test]
    async fn test_admin_initiate_auth_success() {
        let storage = Storage::new();
        let (pool_id, client_id) = setup_pool_and_client(&storage).await;

        // Create user and set permanent password
        admin_create_user::handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "Username": "testuser"
            }),
        )
        .await
        .unwrap();

        admin_set_user_password::handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "Username": "testuser",
                "Password": "Password123!",
                "Permanent": true
            }),
        )
        .await
        .unwrap();

        let result = handler(
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
        .await;

        assert!(result.is_ok());
        let body = result.unwrap();
        assert!(
            body["AuthenticationResult"]["AccessToken"]
                .as_str()
                .is_some()
        );
        assert!(body["AuthenticationResult"]["IdToken"].as_str().is_some());
        assert!(
            body["AuthenticationResult"]["RefreshToken"]
                .as_str()
                .is_some()
        );
    }

    #[tokio::test]
    async fn test_admin_initiate_auth_force_change_password() {
        let storage = Storage::new();
        let (pool_id, client_id) = setup_pool_and_client(&storage).await;

        // Create user (will have FORCE_CHANGE_PASSWORD status)
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
                "AuthFlow": "ADMIN_USER_PASSWORD_AUTH",
                "AuthParameters": {
                    "USERNAME": "testuser",
                    "PASSWORD": "TempPass123!"
                }
            }),
        )
        .await;

        assert!(result.is_ok());
        let body = result.unwrap();
        assert_eq!(body["ChallengeName"], "NEW_PASSWORD_REQUIRED");
    }

    #[tokio::test]
    async fn test_admin_initiate_auth_invalid_password() {
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

        admin_set_user_password::handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "Username": "testuser",
                "Password": "Password123!",
                "Permanent": true
            }),
        )
        .await
        .unwrap();

        let result = handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "ClientId": client_id,
                "AuthFlow": "ADMIN_USER_PASSWORD_AUTH",
                "AuthParameters": {
                    "USERNAME": "testuser",
                    "PASSWORD": "WrongPassword!"
                }
            }),
        )
        .await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AppError::NotAuthorized(_)));
    }

    #[tokio::test]
    async fn test_admin_initiate_auth_pool_not_found() {
        let storage = Storage::new();

        let result = handler(
            &storage,
            json!({
                "UserPoolId": "local_nonexistent",
                "ClientId": "someclientid",
                "AuthFlow": "ADMIN_USER_PASSWORD_AUTH",
                "AuthParameters": {
                    "USERNAME": "testuser",
                    "PASSWORD": "Password123!"
                }
            }),
        )
        .await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AppError::UserPoolNotFound));
    }

    #[tokio::test]
    async fn test_admin_initiate_auth_refresh_token_client_mismatch() {
        let storage = Storage::new();
        let (pool_id, client_id1) = setup_pool_and_client(&storage).await;

        let client2 = create_user_pool_client::handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "ExplicitAuthFlows": ["ALLOW_USER_PASSWORD_AUTH", "ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_USER_SRP_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
                "ClientName": "test-client-2"
            }),
        )
        .await
        .unwrap();
        let client_id2 = client2["UserPoolClient"]["ClientId"].as_str().unwrap();

        admin_create_user::handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "Username": "testuser"
            }),
        )
        .await
        .unwrap();
        admin_set_user_password::handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "Username": "testuser",
                "Password": "Password123!",
                "Permanent": true
            }),
        )
        .await
        .unwrap();

        let auth = handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "ClientId": client_id1,
                "AuthFlow": "ADMIN_USER_PASSWORD_AUTH",
                "AuthParameters": {
                    "USERNAME": "testuser",
                    "PASSWORD": "Password123!"
                }
            }),
        )
        .await
        .unwrap();
        let refresh_token = auth["AuthenticationResult"]["RefreshToken"]
            .as_str()
            .unwrap();

        let refresh_result = handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "ClientId": client_id2,
                "AuthFlow": "REFRESH_TOKEN_AUTH",
                "AuthParameters": {
                    "REFRESH_TOKEN": refresh_token
                }
            }),
        )
        .await;

        assert!(matches!(
            refresh_result.unwrap_err(),
            AppError::InvalidRefreshToken
        ));
    }

    #[tokio::test]
    async fn test_admin_initiate_auth_returns_software_token_mfa_challenge() {
        let storage = Storage::new();
        let (pool_id, client_id) = setup_pool_and_client(&storage).await;

        create_confirmed_user_with_software_mfa(&storage, &pool_id, "testuser", "Password123!")
            .await;

        let result = handler(
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

        assert_eq!(result["ChallengeName"], "SOFTWARE_TOKEN_MFA");
        assert!(result["Session"].as_str().is_some());
    }
}
