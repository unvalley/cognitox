//! UpdateUserPoolClient API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_UpdateUserPoolClient.html>

use chrono::Utc;
use serde::Deserialize;
use serde_json::{Value, json};

use super::create_user_pool_client::{
    UserPoolClientConfigInput, build_client_response, validate_user_pool_client_configuration,
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
    fn into_config(self) -> UserPoolClientConfigInput {
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
        }
    }
}

pub async fn handler(storage: &Storage, body: Value) -> Result<Value> {
    let req: Request = parse_request(body)?;
    let client_name = req.client_name.clone();
    let user_pool_id = req.user_pool_id.clone();
    let client_id = req.client_id.clone();
    let config = req.into_config();

    if let Some(ref name) = client_name {
        validate_client_name(name)?;
    }

    storage
        .get_user_pool(&user_pool_id)
        .await
        .ok_or(AppError::UserPoolNotFound)?;

    let mut client = storage
        .get_user_pool_client(&client_id)
        .await
        .ok_or(AppError::UserPoolClientNotFound)?;

    if client.user_pool_id != user_pool_id {
        return Err(AppError::UserPoolClientNotFound);
    }

    let callback_urls = config
        .callback_urls
        .clone()
        .unwrap_or_else(|| client.callback_urls.clone());
    let logout_urls = config
        .logout_urls
        .clone()
        .unwrap_or_else(|| client.logout_urls.clone());
    let default_redirect_uri = config
        .default_redirect_uri
        .as_deref()
        .or(client.default_redirect_uri.as_deref());
    let allowed_oauth_flows_user_pool_client = config
        .allowed_o_auth_flows_user_pool_client
        .unwrap_or(client.allowed_oauth_flows_user_pool_client);
    let validation_config = UserPoolClientConfigInput {
        allowed_o_auth_flows: config
            .allowed_o_auth_flows
            .clone()
            .or_else(|| Some(client.allowed_oauth_flows.clone())),
        allowed_o_auth_scopes: config
            .allowed_o_auth_scopes
            .clone()
            .or_else(|| Some(client.allowed_oauth_scopes.clone())),
        allowed_o_auth_flows_user_pool_client: Some(allowed_oauth_flows_user_pool_client),
        callback_urls: Some(callback_urls.clone()),
        logout_urls: Some(logout_urls.clone()),
        default_redirect_uri: default_redirect_uri.map(str::to_owned),
        supported_identity_providers: config
            .supported_identity_providers
            .clone()
            .or_else(|| Some(client.supported_identity_providers.clone())),
        read_attributes: config
            .read_attributes
            .clone()
            .or_else(|| Some(client.read_attributes.clone())),
        write_attributes: config
            .write_attributes
            .clone()
            .or_else(|| Some(client.write_attributes.clone())),
        analytics_configuration: config
            .analytics_configuration
            .clone()
            .or_else(|| client.analytics_configuration.clone()),
        explicit_auth_flows: config
            .explicit_auth_flows
            .clone()
            .or_else(|| Some(client.explicit_auth_flows.clone())),
        auth_session_validity: config
            .auth_session_validity
            .or(client.auth_session_validity),
        access_token_validity: config
            .access_token_validity
            .or(client.access_token_validity),
        id_token_validity: config.id_token_validity.or(client.id_token_validity),
        refresh_token_validity: config
            .refresh_token_validity
            .or(client.refresh_token_validity),
        token_validity_units: config
            .token_validity_units
            .clone()
            .or_else(|| client.token_validity_units.clone()),
        refresh_token_rotation: config
            .refresh_token_rotation
            .clone()
            .or_else(|| client.refresh_token_rotation.clone()),
        enable_token_revocation: config
            .enable_token_revocation
            .or(Some(client.enable_token_revocation)),
        prevent_user_existence_errors: config
            .prevent_user_existence_errors
            .or(client.prevent_user_existence_errors),
        enable_propagate_additional_user_context_data: config
            .enable_propagate_additional_user_context_data
            .or(Some(client.enable_propagate_additional_user_context_data)),
    };
    validate_user_pool_client_configuration(
        &validation_config,
        &callback_urls,
        &logout_urls,
        default_redirect_uri,
        client.client_secret.is_some(),
    )?;

    if let Some(name) = client_name {
        client.client_name = name;
    }

    if let Some(flows) = config.allowed_o_auth_flows {
        client.allowed_oauth_flows = flows;
    }

    if let Some(scopes) = config.allowed_o_auth_scopes {
        client.allowed_oauth_scopes = scopes;
    }

    if let Some(allowed) = config.allowed_o_auth_flows_user_pool_client {
        client.allowed_oauth_flows_user_pool_client = allowed;
    }

    if let Some(urls) = config.callback_urls {
        client.callback_urls = urls;
    }

    if let Some(urls) = config.logout_urls {
        client.logout_urls = urls;
    }

    if let Some(uri) = config.default_redirect_uri {
        client.default_redirect_uri = Some(uri);
    }

    if let Some(providers) = config.supported_identity_providers {
        client.supported_identity_providers = providers;
    }

    if let Some(attributes) = config.read_attributes {
        client.read_attributes = attributes;
    }

    if let Some(attributes) = config.write_attributes {
        client.write_attributes = attributes;
    }

    if let Some(analytics_configuration) = config.analytics_configuration {
        client.analytics_configuration = Some(analytics_configuration);
    }

    if let Some(flows) = config.explicit_auth_flows {
        client.explicit_auth_flows = flows;
    }

    if let Some(auth_session_validity) = config.auth_session_validity {
        client.auth_session_validity = Some(auth_session_validity);
    }

    if let Some(validity) = config.access_token_validity {
        client.access_token_validity = Some(validity);
    }

    if let Some(validity) = config.id_token_validity {
        client.id_token_validity = Some(validity);
    }

    if let Some(validity) = config.refresh_token_validity {
        client.refresh_token_validity = Some(validity);
    }

    if let Some(units) = config.token_validity_units {
        client.token_validity_units = Some(units);
    }

    if let Some(refresh_token_rotation) = config.refresh_token_rotation {
        client.refresh_token_rotation = Some(refresh_token_rotation);
    }

    if let Some(enabled) = config.enable_token_revocation {
        client.enable_token_revocation = enabled;
    }

    if let Some(prevent) = config.prevent_user_existence_errors {
        client.prevent_user_existence_errors = Some(prevent);
    }

    if let Some(enabled) = config.enable_propagate_additional_user_context_data {
        client.enable_propagate_additional_user_context_data = enabled;
    }

    // Update timestamp
    client.last_modified_date = Utc::now();

    let updated = storage
        .update_user_pool_client(client)
        .await
        .ok_or(AppError::Internal("Failed to update client".to_string()))?;

    Ok(json!({
        "UserPoolClient": build_client_response(&updated)
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
}
