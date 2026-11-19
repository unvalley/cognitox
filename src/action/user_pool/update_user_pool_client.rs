//! UpdateUserPoolClient API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_UpdateUserPoolClient.html>

use chrono::Utc;
use serde::Deserialize;
use serde_json::{Value, json};

use super::create_user_pool_client::{
    UserPoolClientConfigInput, apply_client_configuration, build_client_response,
    validate_user_pool_client_configuration,
};
use crate::{
    action::io::parse_request,
    error::{AppError, Result},
    storage::Storage,
    types::{ClientId, UserPoolId},
    validation::validate_client_name,
};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Request {
    user_pool_id: UserPoolId,
    client_id: ClientId,
    client_name: Option<String>,
    #[serde(default)]
    allowed_o_auth_flows: Option<Vec<crate::types::OAuthFlow>>,
    #[serde(default)]
    allowed_o_auth_scopes: Option<Vec<String>>,
    #[serde(default)]
    allowed_o_auth_flows_user_pool_client: Option<bool>,
    #[serde(default, rename = "CallbackURLs")]
    callback_urls: Option<Vec<String>>,
    #[serde(default, rename = "LogoutURLs")]
    logout_urls: Option<Vec<String>>,
    #[serde(default, rename = "DefaultRedirectURI")]
    default_redirect_uri: Option<String>,
    #[serde(default)]
    supported_identity_providers: Option<Vec<String>>,
    #[serde(default)]
    read_attributes: Option<Vec<String>>,
    #[serde(default)]
    write_attributes: Option<Vec<String>>,
    #[serde(default)]
    analytics_configuration: Option<crate::types::AnalyticsConfiguration>,
    #[serde(default)]
    explicit_auth_flows: Option<Vec<crate::types::ExplicitAuthFlow>>,
    #[serde(default)]
    auth_session_validity: Option<i32>,
    #[serde(default)]
    access_token_validity: Option<i32>,
    #[serde(default)]
    id_token_validity: Option<i32>,
    #[serde(default)]
    refresh_token_validity: Option<i32>,
    #[serde(default)]
    token_validity_units: Option<crate::types::TokenValidityUnits>,
    #[serde(default)]
    refresh_token_rotation: Option<crate::types::RefreshTokenRotationType>,
    #[serde(default)]
    enable_token_revocation: Option<bool>,
    #[serde(default)]
    prevent_user_existence_errors: Option<crate::types::PreventUserExistenceErrors>,
    #[serde(default)]
    enable_propagate_additional_user_context_data: Option<bool>,
}

impl Request {
    fn into_parts(
        self,
    ) -> (
        UserPoolId,
        ClientId,
        Option<String>,
        UserPoolClientConfigInput,
    ) {
        (
            self.user_pool_id,
            self.client_id,
            self.client_name,
            UserPoolClientConfigInput {
                allowed_o_auth_flows: self.allowed_o_auth_flows,
                allowed_o_auth_scopes: self.allowed_o_auth_scopes,
                allowed_o_auth_flows_user_pool_client: self.allowed_o_auth_flows_user_pool_client,
                callback_urls: self.callback_urls,
                logout_urls: self.logout_urls,
                default_redirect_uri: self.default_redirect_uri,
                supported_identity_providers: self.supported_identity_providers,
                read_attributes: self.read_attributes,
                write_attributes: self.write_attributes,
                analytics_configuration: self.analytics_configuration,
                explicit_auth_flows: self.explicit_auth_flows,
                auth_session_validity: self.auth_session_validity,
                access_token_validity: self.access_token_validity,
                id_token_validity: self.id_token_validity,
                refresh_token_validity: self.refresh_token_validity,
                token_validity_units: self.token_validity_units,
                refresh_token_rotation: self.refresh_token_rotation,
                enable_token_revocation: self.enable_token_revocation,
                prevent_user_existence_errors: self.prevent_user_existence_errors,
                enable_propagate_additional_user_context_data: self
                    .enable_propagate_additional_user_context_data,
            },
        )
    }
}

pub async fn handler(storage: &Storage, body: Value) -> Result<Value> {
    let req: Request = parse_request(body)?;
    let (user_pool_id, client_id, client_name, config) = req.into_parts();

    if let Some(ref name) = client_name {
        validate_client_name(name)?;
    }

    if !storage.user_pool_exists(&user_pool_id).await {
        return Err(AppError::UserPoolNotFound);
    }

    let updated = storage
        .update_user_pool_client_with(&client_id, |client| -> Result<Value> {
            if client.user_pool_id != user_pool_id {
                return Err(AppError::UserPoolClientNotFound);
            }

            // "If you don't provide a value for an attribute, Amazon Cognito
            // sets it to its default value": the request is the client's
            // whole configuration, validated on its own.
            validate_user_pool_client_configuration(
                &config,
                config.callback_urls.as_deref().unwrap_or_default(),
                config.logout_urls.as_deref().unwrap_or_default(),
                config.default_redirect_uri.as_deref(),
                client.client_secret.is_some(),
            )?;

            // The identity of the client stays: its ID, secret, creation
            // date, and, unless the request renames it, its name.
            if let Some(name) = client_name {
                client.client_name = name;
            }
            apply_client_configuration(client, config);
            client.last_modified_date = Utc::now();

            Ok(build_client_response(client))
        })
        .await
        .ok_or(AppError::UserPoolClientNotFound)?;
    let updated = updated?;

    Ok(json!({
        "UserPoolClient": updated
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::user_pool::{create_user_pool, create_user_pool_client};
    use serde_json::json;

    #[tokio::test]
    async fn test_update_user_pool_client_success() {
        let storage = Storage::new();

        // Create a user pool and client first
        let pool = create_user_pool::handler(&storage, json!({"PoolName": "test-pool"}))
            .await
            .unwrap();
        let pool_id = pool["UserPool"]["Id"].as_str().unwrap();

        let client = create_user_pool_client::handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "ClientName": "original-name"
            }),
        )
        .await
        .unwrap();
        let client_id = client["UserPoolClient"]["ClientId"].as_str().unwrap();

        // Update the client
        let result = handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "ClientId": client_id,
                "ClientName": "updated-name"
            }),
        )
        .await;

        assert!(result.is_ok());
        let body = result.unwrap();
        assert_eq!(body["UserPoolClient"]["ClientName"], "updated-name");
    }

    #[tokio::test]
    async fn test_update_user_pool_client_pool_not_found() {
        let storage = Storage::new();

        let result = handler(
            &storage,
            json!({
                "UserPoolId": "local_nonexistent123",
                "ClientId": "client12345678901234567",
                "ClientName": "new-name"
            }),
        )
        .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_update_user_pool_client_client_not_found() {
        let storage = Storage::new();

        let pool = create_user_pool::handler(&storage, json!({"PoolName": "test-pool"}))
            .await
            .unwrap();
        let pool_id = pool["UserPool"]["Id"].as_str().unwrap();

        let result = handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "ClientId": "nonexistent123456789012345",
                "ClientName": "new-name"
            }),
        )
        .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_update_user_pool_client_rejects_invalid_default_redirect_uri() {
        let storage = Storage::new();

        let pool = create_user_pool::handler(&storage, json!({"PoolName": "test-pool"}))
            .await
            .unwrap();
        let pool_id = pool["UserPool"]["Id"].as_str().unwrap();

        let client = create_user_pool_client::handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "ClientName": "original-name",
                "AllowedOAuthFlowsUserPoolClient": true,
                "AllowedOAuthFlows": ["code"],
                "CallbackURLs": ["https://example.com/callback"]
            }),
        )
        .await
        .unwrap();
        let client_id = client["UserPoolClient"]["ClientId"].as_str().unwrap();

        let result = handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "ClientId": client_id,
                "DefaultRedirectURI": "https://example.com/other"
            }),
        )
        .await;

        assert!(matches!(result, Err(AppError::InvalidParameter(_))));
    }

    #[tokio::test]
    async fn test_update_user_pool_client_updates_extended_configuration() {
        let storage = Storage::new();

        let pool = create_user_pool::handler(&storage, json!({"PoolName": "test-pool"}))
            .await
            .unwrap();
        let pool_id = pool["UserPool"]["Id"].as_str().unwrap();

        let client = create_user_pool_client::handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "ClientName": "original-name"
            }),
        )
        .await
        .unwrap();
        let client_id = client["UserPoolClient"]["ClientId"].as_str().unwrap();

        let result = handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "ClientId": client_id,
                "ReadAttributes": ["email"],
                "WriteAttributes": ["email", "custom:role"],
                "AnalyticsConfiguration": {
                    "ApplicationId": "analytics-app"
                },
                "AuthSessionValidity": 12,
                "RefreshTokenRotation": {
                    "Feature": "DISABLED",
                    "RetryGracePeriodSeconds": 0
                }
            }),
        )
        .await
        .unwrap();

        let client = &result["UserPoolClient"];
        assert_eq!(client["ReadAttributes"], json!(["email"]));
        assert_eq!(client["WriteAttributes"], json!(["email", "custom:role"]));
        assert_eq!(
            client["AnalyticsConfiguration"]["ApplicationId"],
            "analytics-app"
        );
        assert_eq!(client["AuthSessionValidity"], 12);
        assert_eq!(client["RefreshTokenRotation"]["Feature"], "DISABLED");
    }

    #[tokio::test]
    async fn test_update_user_pool_client_resets_what_the_request_leaves_out() {
        let storage = Storage::new();

        let pool = create_user_pool::handler(&storage, json!({"PoolName": "test-pool"}))
            .await
            .unwrap();
        let pool_id = pool["UserPool"]["Id"].as_str().unwrap();

        let created = create_user_pool_client::handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "ClientName": "original-name",
                "GenerateSecret": true,
                "ExplicitAuthFlows": ["ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
                "AllowedOAuthFlowsUserPoolClient": true,
                "AllowedOAuthFlows": ["code"],
                "AllowedOAuthScopes": ["openid"],
                "CallbackURLs": ["https://example.com/callback"],
                "ReadAttributes": ["email"],
                "AccessTokenValidity": 2,
                "RefreshTokenValidity": 7,
                "AuthSessionValidity": 10,
                "EnableTokenRevocation": false,
                "PreventUserExistenceErrors": "ENABLED"
            }),
        )
        .await
        .unwrap();
        let created = &created["UserPoolClient"];

        let updated = handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "ClientId": created["ClientId"],
                "ReadAttributes": ["name"]
            }),
        )
        .await
        .unwrap();
        let updated = &updated["UserPoolClient"];

        // What identifies the client is kept.
        for kept in ["ClientId", "ClientSecret", "ClientName", "CreationDate"] {
            assert_eq!(updated[kept], created[kept], "{kept} should be kept");
        }
        assert_eq!(updated["ReadAttributes"], json!(["name"]));

        // Everything else the request did not mention is back to its default.
        assert_eq!(
            updated["ExplicitAuthFlows"],
            json!([
                "ALLOW_CUSTOM_AUTH",
                "ALLOW_USER_SRP_AUTH",
                "ALLOW_REFRESH_TOKEN_AUTH"
            ])
        );
        assert_eq!(updated["AllowedOAuthFlowsUserPoolClient"], false);
        assert_eq!(updated["RefreshTokenValidity"], 30);
        assert_eq!(updated["AuthSessionValidity"], 3);
        assert_eq!(updated["EnableTokenRevocation"], true);
        for reset in [
            "AllowedOAuthFlows",
            "AllowedOAuthScopes",
            "CallbackURLs",
            "AccessTokenValidity",
            "PreventUserExistenceErrors",
        ] {
            assert!(updated.get(reset).is_none(), "{reset} should be reset");
        }
    }

    #[tokio::test]
    async fn test_update_user_pool_client_validates_the_request_on_its_own() {
        let storage = Storage::new();

        let pool = create_user_pool::handler(&storage, json!({"PoolName": "test-pool"}))
            .await
            .unwrap();
        let pool_id = pool["UserPool"]["Id"].as_str().unwrap();

        let created = create_user_pool_client::handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "ClientName": "original-name",
                "AllowedOAuthFlowsUserPoolClient": true,
                "AllowedOAuthFlows": ["code"],
                "CallbackURLs": ["https://example.com/callback"]
            }),
        )
        .await
        .unwrap();

        // The stored AllowedOAuthFlowsUserPoolClient does not carry over, so
        // OAuth settings without it are refused and nothing changes.
        let result = handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "ClientId": created["UserPoolClient"]["ClientId"],
                "CallbackURLs": ["https://example.com/other"]
            }),
        )
        .await;
        assert!(matches!(result, Err(AppError::InvalidParameter(_))));

        let described = crate::action::user_pool::describe_user_pool_client::handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "ClientId": created["UserPoolClient"]["ClientId"]
            }),
        )
        .await
        .unwrap();
        assert_eq!(
            described["UserPoolClient"]["CallbackURLs"],
            json!(["https://example.com/callback"])
        );
    }
}
