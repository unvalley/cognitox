//! InitiateAuth API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_InitiateAuth.html>

use std::collections::HashMap;

use serde::Deserialize;
use serde_json::Value;

use crate::{
    action::io::parse_request,
    error::{AppError, Result},
    storage::Storage,
    types::ClientId,
};

use super::auth_flow::{
    AuthParameters, PasswordAuthResult, UserInitiateAuthFlow, authenticate_with_password,
    authenticate_with_refresh_token, build_auth_response, issue_authentication_result,
    require_refresh_token_auth_flow, require_user_password_auth_flow,
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
struct UserContextData {
    ip_address: Option<String>,
    server_name: Option<String>,
    server_path: Option<String>,
    http_headers: Option<Vec<HttpHeader>>,
    encoded_data: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Request {
    client_id: ClientId,
    auth_flow: String,
    auth_parameters: Option<HashMap<String, String>>,
    analytics_metadata: Option<AnalyticsMetadata>,
    user_context_data: Option<UserContextData>,
    session: Option<String>,
    client_metadata: Option<HashMap<String, String>>,
}

pub async fn handler(storage: &Storage, body: Value) -> Result<Value> {
    let req: Request = parse_request(body)?;
    let _ = (
        &req.session,
        &req.client_metadata,
        req.analytics_metadata
            .as_ref()
            .map(|meta| &meta.analytics_endpoint_id),
        req.user_context_data.as_ref().map(|ctx| {
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

    let client = storage
        .get_user_pool_client(&req.client_id)
        .await
        .ok_or(AppError::UserPoolClientNotFound)?;

    match UserInitiateAuthFlow::parse(&req.auth_flow)? {
        UserInitiateAuthFlow::UserPasswordAuth => {
            require_user_password_auth_flow(&client)?;
            let params = req
                .auth_parameters
                .as_ref()
                .ok_or_else(|| AppError::InvalidParameter("AuthParameters required".to_string()))
                .map(AuthParameters::new)?;

            let username = params.require("USERNAME")?;
            let password = params.require("PASSWORD")?;

            match authenticate_with_password(
                storage,
                &client,
                &req.client_id,
                &client.user_pool_id,
                username,
                password,
                params.secret_hash(),
            )
            .await?
            {
                PasswordAuthResult::Authenticated(user) => Ok(build_auth_response(
                    issue_authentication_result(
                        storage,
                        &client,
                        &req.client_id,
                        &client.user_pool_id,
                        &user,
                        true,
                        true,
                    )
                    .await?,
                )),
                PasswordAuthResult::Challenged(response) => Ok(response),
            }
        }
        UserInitiateAuthFlow::RefreshTokenAuth => {
            require_refresh_token_auth_flow(&client)?;
            let params = req
                .auth_parameters
                .as_ref()
                .ok_or_else(|| AppError::InvalidParameter("AuthParameters required".to_string()))
                .map(AuthParameters::new)?;

            let refresh_token = params.require("REFRESH_TOKEN")?;

            let user = authenticate_with_refresh_token(
                storage,
                &client,
                &req.client_id,
                &client.user_pool_id,
                refresh_token,
                params.secret_hash(),
            )
            .await?;

            Ok(build_auth_response(
                issue_authentication_result(
                    storage,
                    &client,
                    &req.client_id,
                    &client.user_pool_id,
                    &user,
                    false,
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

    use crate::action::user::helpers::{calculate_secret_hash, upsert_user_attribute};
    use crate::action::user::sign_up;
    use crate::action::user_pool::{create_user_pool, create_user_pool_client};
    use crate::types::UserPoolId;

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

    async fn create_confirmed_user(
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

        let user_sub = sign_up_result["UserSub"].as_str().unwrap();
        let user_id = uuid::Uuid::parse_str(user_sub).unwrap();

        // Confirm the user directly via storage
        storage.confirm_user(&user_id).await;
    }

    async fn create_confirmed_user_with_software_mfa(
        storage: &Storage,
        pool_id: &str,
        client_id: &str,
        username: &str,
        password: &str,
    ) {
        create_confirmed_user(storage, client_id, username, password).await;
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
    async fn test_initiate_auth_user_password_auth_success() {
        let storage = Storage::new();
        let (_pool_id, client_id) = setup_pool_and_client(&storage).await;

        create_confirmed_user(&storage, &client_id, "testuser", "Password123!").await;

        let result = handler(
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
        assert_eq!(body["AuthenticationResult"]["TokenType"], "Bearer");
    }

    #[tokio::test]
    async fn test_initiate_auth_invalid_password() {
        let storage = Storage::new();
        let (_pool_id, client_id) = setup_pool_and_client(&storage).await;

        create_confirmed_user(&storage, &client_id, "testuser", "Password123!").await;

        let result = handler(
            &storage,
            json!({
                "ClientId": client_id,
                "AuthFlow": "USER_PASSWORD_AUTH",
                "AuthParameters": {
                    "USERNAME": "testuser",
                    "PASSWORD": "WrongPassword!"
                }
            }),
        )
        .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_initiate_auth_user_not_confirmed() {
        let storage = Storage::new();
        let (_pool_id, client_id) = setup_pool_and_client(&storage).await;

        // Sign up but don't confirm
        sign_up::handler(
            &storage,
            json!({
                "ClientId": client_id,
                "Username": "testuser",
                "Password": "Password123!"
            }),
        )
        .await
        .unwrap();

        let result = handler(
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
        .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_initiate_auth_returns_software_token_mfa_challenge() {
        let storage = Storage::new();
        let (pool_id, client_id) = setup_pool_and_client(&storage).await;

        create_confirmed_user_with_software_mfa(
            &storage,
            &pool_id,
            &client_id,
            "testuser",
            "Password123!",
        )
        .await;

        let result = handler(
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

        assert_eq!(result["ChallengeName"], "SOFTWARE_TOKEN_MFA");
        assert!(result["Session"].as_str().is_some());
    }

    #[tokio::test]
    async fn test_initiate_auth_refresh_token_client_mismatch() {
        let storage = Storage::new();
        let (pool_id, client_id1) = setup_pool_and_client(&storage).await;

        let client2 = create_user_pool_client::handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "ClientName": "test-client-2"
            }),
        )
        .await
        .unwrap();
        let client_id2 = client2["UserPoolClient"]["ClientId"].as_str().unwrap();

        create_confirmed_user(&storage, &client_id1, "testuser", "Password123!").await;

        let auth = handler(
            &storage,
            json!({
                "ClientId": client_id1,
                "AuthFlow": "USER_PASSWORD_AUTH",
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
    async fn test_initiate_auth_requires_secret_hash_for_secret_client() {
        let storage = Storage::new();

        let pool = create_user_pool::handler(&storage, json!({"PoolName": "test"}))
            .await
            .unwrap();
        let pool_id = pool["UserPool"]["Id"].as_str().unwrap();

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

        let sign_up_result = sign_up::handler(
            &storage,
            json!({
                "ClientId": client_id,
                "Username": "testuser",
                "Password": "Password123!",
                "SecretHash": calculate_secret_hash(client_id, client_secret, "testuser").unwrap()
            }),
        )
        .await
        .unwrap();
        let user_sub = sign_up_result["UserSub"].as_str().unwrap();
        let user_id = uuid::Uuid::parse_str(user_sub).unwrap();
        storage.confirm_user(&user_id).await;

        let result = handler(
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
        .await;
        assert!(matches!(result, Err(AppError::NotAuthorized(_))));

        let result = handler(
            &storage,
            json!({
                "ClientId": client_id,
                "AuthFlow": "USER_PASSWORD_AUTH",
                "AuthParameters": {
                    "USERNAME": "testuser",
                    "PASSWORD": "Password123!",
                    "SECRET_HASH": calculate_secret_hash(client_id, client_secret, "testuser").unwrap()
                }
            }),
        )
        .await;
        assert!(result.is_ok());
    }
}
