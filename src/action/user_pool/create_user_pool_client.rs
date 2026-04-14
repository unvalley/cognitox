//! CreateUserPoolClient API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_CreateUserPoolClient.html>

use chrono::Utc;
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::{
    action::io::parse_request,
    error::{AppError, Result},
    storage::Storage,
    types::{
        ClientId, ExplicitAuthFlow, OAuthFlow, PreventUserExistenceErrors, TokenValidityUnits,
        UserPoolClient, UserPoolId,
    },
    validation::{
        validate_client_name, validate_explicit_auth_flows, validate_oauth_client_configuration,
        validate_token_validities,
    },
};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Request {
    user_pool_id: UserPoolId,
    client_name: String,
    generate_secret: Option<bool>,
    #[serde(default)]
    allowed_o_auth_flows: Option<Vec<OAuthFlow>>,
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
    explicit_auth_flows: Option<Vec<ExplicitAuthFlow>>,
    #[serde(default)]
    access_token_validity: Option<i32>,
    #[serde(default)]
    id_token_validity: Option<i32>,
    #[serde(default)]
    refresh_token_validity: Option<i32>,
    #[serde(default)]
    token_validity_units: Option<TokenValidityUnits>,
    #[serde(default)]
    enable_token_revocation: Option<bool>,
    #[serde(default)]
    prevent_user_existence_errors: Option<PreventUserExistenceErrors>,
    #[serde(default)]
    enable_propagate_additional_user_context_data: Option<bool>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct UserPoolClientConfigInput {
    #[serde(default)]
    pub(crate) allowed_o_auth_flows: Option<Vec<OAuthFlow>>,
    #[serde(default)]
    pub(crate) allowed_o_auth_scopes: Option<Vec<String>>,
    #[serde(default)]
    pub(crate) allowed_o_auth_flows_user_pool_client: Option<bool>,
    #[serde(default, rename = "CallbackURLs")]
    pub(crate) callback_urls: Option<Vec<String>>,
    #[serde(default, rename = "LogoutURLs")]
    pub(crate) logout_urls: Option<Vec<String>>,
    #[serde(default, rename = "DefaultRedirectURI")]
    pub(crate) default_redirect_uri: Option<String>,
    #[serde(default)]
    pub(crate) supported_identity_providers: Option<Vec<String>>,
    #[serde(default)]
    pub(crate) explicit_auth_flows: Option<Vec<ExplicitAuthFlow>>,
    #[serde(default)]
    pub(crate) access_token_validity: Option<i32>,
    #[serde(default)]
    pub(crate) id_token_validity: Option<i32>,
    #[serde(default)]
    pub(crate) refresh_token_validity: Option<i32>,
    #[serde(default)]
    pub(crate) token_validity_units: Option<TokenValidityUnits>,
    #[serde(default)]
    pub(crate) enable_token_revocation: Option<bool>,
    #[serde(default)]
    pub(crate) prevent_user_existence_errors: Option<PreventUserExistenceErrors>,
    #[serde(default)]
    pub(crate) enable_propagate_additional_user_context_data: Option<bool>,
}

pub(crate) fn validate_user_pool_client_configuration(
    config: &UserPoolClientConfigInput,
    callback_urls: &[String],
    logout_urls: &[String],
    default_redirect_uri: Option<&str>,
    generate_secret: bool,
) -> Result<()> {
    let allowed_oauth_flows = config.allowed_o_auth_flows.as_deref().unwrap_or(&[]);
    let explicit_auth_flows = config.explicit_auth_flows.as_deref().unwrap_or(&[]);
    let token_validity_units = config.token_validity_units.as_ref();

    validate_oauth_client_configuration(
        config
            .allowed_o_auth_flows_user_pool_client
            .unwrap_or(false),
        allowed_oauth_flows,
        callback_urls,
        logout_urls,
        default_redirect_uri,
        generate_secret,
    )?;
    validate_explicit_auth_flows(explicit_auth_flows)?;
    validate_token_validities(
        config.access_token_validity,
        config.id_token_validity,
        config.refresh_token_validity,
        token_validity_units.and_then(|units| units.access_token),
        token_validity_units.and_then(|units| units.id_token),
        token_validity_units.and_then(|units| units.refresh_token),
    )?;

    Ok(())
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
            explicit_auth_flows: self.explicit_auth_flows,
            access_token_validity: self.access_token_validity,
            id_token_validity: self.id_token_validity,
            refresh_token_validity: self.refresh_token_validity,
            token_validity_units: self.token_validity_units,
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
    let generate_secret = req.generate_secret.unwrap_or(false);
    let config = req.into_config();

    validate_client_name(&client_name)?;
    let callback_urls = config.callback_urls.clone().unwrap_or_default();
    let logout_urls = config.logout_urls.clone().unwrap_or_default();
    validate_user_pool_client_configuration(
        &config,
        &callback_urls,
        &logout_urls,
        config.default_redirect_uri.as_deref(),
        generate_secret,
    )?;

    storage
        .get_user_pool(&user_pool_id)
        .await
        .ok_or(AppError::UserPoolNotFound)?;

    let now = Utc::now();
    let client_id = ClientId::generate();
    let client_secret = if generate_secret {
        Some(Uuid::new_v4().to_string())
    } else {
        None
    };

    let client = UserPoolClient {
        client_id,
        user_pool_id,
        client_name,
        client_secret: client_secret.clone(),
        creation_date: now,
        last_modified_date: now,

        // OAuth configuration
        allowed_oauth_flows: config.allowed_o_auth_flows.unwrap_or_default(),
        allowed_oauth_scopes: config.allowed_o_auth_scopes.unwrap_or_default(),
        allowed_oauth_flows_user_pool_client: config
            .allowed_o_auth_flows_user_pool_client
            .unwrap_or(false),
        callback_urls,
        logout_urls,
        default_redirect_uri: config.default_redirect_uri,
        supported_identity_providers: config.supported_identity_providers.unwrap_or_default(),

        // Auth flows
        explicit_auth_flows: config.explicit_auth_flows.unwrap_or_default(),

        // Token validity
        access_token_validity: config.access_token_validity,
        id_token_validity: config.id_token_validity,
        refresh_token_validity: config.refresh_token_validity,
        token_validity_units: config.token_validity_units,

        // Security settings
        enable_token_revocation: config.enable_token_revocation.unwrap_or(true),
        prevent_user_existence_errors: config.prevent_user_existence_errors,
        enable_propagate_additional_user_context_data: config
            .enable_propagate_additional_user_context_data
            .unwrap_or(false),
    };

    let created = storage.create_user_pool_client(client).await;

    Ok(json!({
        "UserPoolClient": build_client_response(&created)
    }))
}

pub fn build_client_response(client: &UserPoolClient) -> Value {
    let mut response = json!({
        "ClientId": client.client_id,
        "UserPoolId": client.user_pool_id,
        "ClientName": client.client_name,
        "CreationDate": client.creation_date.timestamp(),
        "LastModifiedDate": client.last_modified_date.timestamp(),
        "AllowedOAuthFlowsUserPoolClient": client.allowed_oauth_flows_user_pool_client,
        "EnableTokenRevocation": client.enable_token_revocation,
        "EnablePropagateAdditionalUserContextData": client.enable_propagate_additional_user_context_data
    });

    if let Some(ref secret) = client.client_secret {
        response["ClientSecret"] = json!(secret);
    }

    if !client.allowed_oauth_flows.is_empty() {
        response["AllowedOAuthFlows"] = json!(client.allowed_oauth_flows);
    }

    if !client.allowed_oauth_scopes.is_empty() {
        response["AllowedOAuthScopes"] = json!(client.allowed_oauth_scopes);
    }

    if !client.callback_urls.is_empty() {
        response["CallbackURLs"] = json!(client.callback_urls);
    }

    if !client.logout_urls.is_empty() {
        response["LogoutURLs"] = json!(client.logout_urls);
    }

    if let Some(ref uri) = client.default_redirect_uri {
        response["DefaultRedirectURI"] = json!(uri);
    }

    if !client.supported_identity_providers.is_empty() {
        response["SupportedIdentityProviders"] = json!(client.supported_identity_providers);
    }

    if !client.explicit_auth_flows.is_empty() {
        response["ExplicitAuthFlows"] = json!(client.explicit_auth_flows);
    }

    if let Some(validity) = client.access_token_validity {
        response["AccessTokenValidity"] = json!(validity);
    }

    if let Some(validity) = client.id_token_validity {
        response["IdTokenValidity"] = json!(validity);
    }

    if let Some(validity) = client.refresh_token_validity {
        response["RefreshTokenValidity"] = json!(validity);
    }

    if let Some(ref units) = client.token_validity_units {
        let mut units_json = json!({});
        if let Some(ref access) = units.access_token {
            units_json["AccessToken"] = json!(access);
        }
        if let Some(ref id) = units.id_token {
            units_json["IdToken"] = json!(id);
        }
        if let Some(ref refresh) = units.refresh_token {
            units_json["RefreshToken"] = json!(refresh);
        }
        response["TokenValidityUnits"] = units_json;
    }

    if let Some(ref prevent) = client.prevent_user_existence_errors {
        response["PreventUserExistenceErrors"] = json!(prevent);
    }

    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::user_pool::create_user_pool;
    use serde_json::json;

    #[tokio::test]
    async fn test_create_user_pool_client_success() {
        let storage = Storage::new();

        // Create a user pool first
        let pool = create_user_pool::handler(&storage, json!({"PoolName": "test-pool"}))
            .await
            .unwrap();
        let pool_id = pool["UserPool"]["Id"].as_str().unwrap();

        // Create a client
        let result = handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "ClientName": "test-client"
            }),
        )
        .await;

        assert!(result.is_ok());
        let body = result.unwrap();
        assert!(body["UserPoolClient"]["ClientId"].as_str().is_some());
        assert_eq!(body["UserPoolClient"]["ClientName"], "test-client");
        assert_eq!(body["UserPoolClient"]["UserPoolId"], pool_id);
    }

    #[tokio::test]
    async fn test_create_user_pool_client_with_secret() {
        let storage = Storage::new();

        let pool = create_user_pool::handler(&storage, json!({"PoolName": "test-pool"}))
            .await
            .unwrap();
        let pool_id = pool["UserPool"]["Id"].as_str().unwrap();

        let result = handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "ClientName": "test-client",
                "GenerateSecret": true
            }),
        )
        .await;

        assert!(result.is_ok());
        let body = result.unwrap();
        assert!(body["UserPoolClient"]["ClientSecret"].as_str().is_some());
    }

    #[tokio::test]
    async fn test_create_user_pool_client_rejects_invalid_oauth_configuration() {
        let storage = Storage::new();

        let pool = create_user_pool::handler(&storage, json!({"PoolName": "test-pool"}))
            .await
            .unwrap();
        let pool_id = pool["UserPool"]["Id"].as_str().unwrap();

        let result = handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "ClientName": "test-client",
                "AllowedOAuthFlows": ["code"],
                "CallbackURLs": ["https://example.com/callback"]
            }),
        )
        .await;

        assert!(matches!(result, Err(AppError::InvalidParameter(_))));
    }

    #[tokio::test]
    async fn test_create_user_pool_client_rejects_invalid_token_validity() {
        let storage = Storage::new();

        let pool = create_user_pool::handler(&storage, json!({"PoolName": "test-pool"}))
            .await
            .unwrap();
        let pool_id = pool["UserPool"]["Id"].as_str().unwrap();

        let result = handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "ClientName": "test-client",
                "AccessTokenValidity": 1,
                "TokenValidityUnits": {
                    "AccessToken": "seconds"
                }
            }),
        )
        .await;

        assert!(matches!(result, Err(AppError::InvalidParameter(_))));
    }

    #[tokio::test]
    async fn test_create_user_pool_client_pool_not_found() {
        let storage = Storage::new();

        let result = handler(
            &storage,
            json!({
                "UserPoolId": "local_nonexistent123",
                "ClientName": "test-client"
            }),
        )
        .await;

        assert!(result.is_err());
    }
}
