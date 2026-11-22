//! CreateUserPoolClient API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_CreateUserPoolClient.html>

use chrono::Utc;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::{
    action::io::parse_request,
    error::{AppError, Result},
    storage::Storage,
    types::{
        AnalyticsConfiguration, ClientId, ExplicitAuthFlow, OAuthFlow, PreventUserExistenceErrors,
        RefreshTokenRotationType, TokenValidityUnits, UserPoolClient, UserPoolId,
    },
    validation::{
        validate_analytics_configuration, validate_auth_session_validity,
        validate_client_attribute_names, validate_client_name, validate_explicit_auth_flows,
        validate_oauth_client_configuration, validate_refresh_token_rotation,
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
    read_attributes: Option<Vec<String>>,
    #[serde(default)]
    write_attributes: Option<Vec<String>>,
    #[serde(default)]
    analytics_configuration: Option<AnalyticsConfiguration>,
    #[serde(default)]
    explicit_auth_flows: Option<Vec<ExplicitAuthFlow>>,
    #[serde(default)]
    auth_session_validity: Option<i32>,
    #[serde(default)]
    access_token_validity: Option<i32>,
    #[serde(default)]
    id_token_validity: Option<i32>,
    #[serde(default)]
    refresh_token_validity: Option<i32>,
    #[serde(default)]
    token_validity_units: Option<TokenValidityUnits>,
    #[serde(default)]
    refresh_token_rotation: Option<RefreshTokenRotationType>,
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
    pub(crate) read_attributes: Option<Vec<String>>,
    #[serde(default)]
    pub(crate) write_attributes: Option<Vec<String>>,
    #[serde(default)]
    pub(crate) analytics_configuration: Option<AnalyticsConfiguration>,
    #[serde(default)]
    pub(crate) explicit_auth_flows: Option<Vec<ExplicitAuthFlow>>,
    #[serde(default)]
    pub(crate) auth_session_validity: Option<i32>,
    #[serde(default)]
    pub(crate) access_token_validity: Option<i32>,
    #[serde(default)]
    pub(crate) id_token_validity: Option<i32>,
    #[serde(default)]
    pub(crate) refresh_token_validity: Option<i32>,
    #[serde(default)]
    pub(crate) token_validity_units: Option<TokenValidityUnits>,
    #[serde(default)]
    pub(crate) refresh_token_rotation: Option<RefreshTokenRotationType>,
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
    validate_client_attribute_names(
        "ReadAttributes",
        config.read_attributes.as_deref().unwrap_or(&[]),
    )?;
    validate_client_attribute_names(
        "WriteAttributes",
        config.write_attributes.as_deref().unwrap_or(&[]),
    )?;
    if let Some(analytics_configuration) = &config.analytics_configuration {
        validate_analytics_configuration(analytics_configuration)?;
    }
    if let Some(auth_session_validity) = config.auth_session_validity {
        validate_auth_session_validity(auth_session_validity)?;
    }
    validate_token_validities(
        config.access_token_validity,
        config.id_token_validity,
        config.refresh_token_validity,
        token_validity_units.and_then(|units| units.access_token),
        token_validity_units.and_then(|units| units.id_token),
        token_validity_units.and_then(|units| units.refresh_token),
    )?;
    if let Some(refresh_token_rotation) = &config.refresh_token_rotation {
        validate_refresh_token_rotation(refresh_token_rotation)?;
    }

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
    create(storage, body, ClientId::generate(), None).await
}

/// Create a client under a caller-chosen ID, as seeding does.
///
/// `client_secret` is used when `GenerateSecret` is set; otherwise a secret is generated.
pub(crate) async fn create(
    storage: &Storage,
    body: Value,
    client_id: ClientId,
    client_secret: Option<String>,
) -> Result<Value> {
    let req: Request = parse_request(body)?;
    let client_name = req.client_name.clone();
    let user_pool_id = req.user_pool_id.clone();
    let generate_secret = req.generate_secret.unwrap_or(false);
    let config = req.into_config();

    validate_client_name(&client_name)?;
    validate_user_pool_client_configuration(
        &config,
        config.callback_urls.as_deref().unwrap_or_default(),
        config.logout_urls.as_deref().unwrap_or_default(),
        config.default_redirect_uri.as_deref(),
        generate_secret,
    )?;

    storage
        .get_user_pool(&user_pool_id)
        .await
        .ok_or(AppError::UserPoolNotFound)?;

    let now = Utc::now();
    let client_secret =
        generate_secret.then(|| client_secret.unwrap_or_else(generate_client_secret));

    let mut client = UserPoolClient {
        client_id,
        user_pool_id,
        client_name,
        client_secret,
        creation_date: now,
        last_modified_date: now,

        allowed_oauth_flows: Vec::new(),
        allowed_oauth_scopes: Vec::new(),
        allowed_oauth_flows_user_pool_client: false,
        callback_urls: Vec::new(),
        logout_urls: Vec::new(),
        default_redirect_uri: None,
        supported_identity_providers: Vec::new(),
        read_attributes: Vec::new(),
        write_attributes: Vec::new(),
        analytics_configuration: None,
        explicit_auth_flows: Vec::new(),
        auth_session_validity: None,
        access_token_validity: None,
        id_token_validity: None,
        refresh_token_validity: None,
        token_validity_units: None,
        refresh_token_rotation: None,
        enable_token_revocation: true,
        prevent_user_existence_errors: None,
        enable_propagate_additional_user_context_data: false,
    };
    apply_client_configuration(&mut client, config);

    let created = storage.create_user_pool_client(client).await;

    Ok(json!({
        "UserPoolClient": build_client_response(&created)
    }))
}

/// Set every configurable setting of an app client from a request.
///
/// A setting the request leaves out gets Cognito's default. CreateUserPoolClient
/// and UpdateUserPoolClient share this: an update replaces the configuration
/// rather than patching it.
pub(crate) fn apply_client_configuration(
    client: &mut UserPoolClient,
    config: UserPoolClientConfigInput,
) {
    // OAuth configuration
    client.allowed_oauth_flows = config.allowed_o_auth_flows.unwrap_or_default();
    client.allowed_oauth_scopes = config.allowed_o_auth_scopes.unwrap_or_default();
    client.allowed_oauth_flows_user_pool_client = config
        .allowed_o_auth_flows_user_pool_client
        .unwrap_or(false);
    client.callback_urls = config.callback_urls.unwrap_or_default();
    client.logout_urls = config.logout_urls.unwrap_or_default();
    client.default_redirect_uri = config.default_redirect_uri;
    client.supported_identity_providers = config.supported_identity_providers.unwrap_or_default();
    client.read_attributes = config.read_attributes.unwrap_or_default();
    client.write_attributes = config.write_attributes.unwrap_or_default();
    client.analytics_configuration = config.analytics_configuration;

    // Auth flows
    client.explicit_auth_flows = config
        .explicit_auth_flows
        .unwrap_or_else(default_explicit_auth_flows);
    client.auth_session_validity = Some(
        config
            .auth_session_validity
            .unwrap_or(DEFAULT_AUTH_SESSION_VALIDITY_MINUTES),
    );

    // Token validity
    client.access_token_validity = config.access_token_validity;
    client.id_token_validity = config.id_token_validity;
    client.refresh_token_validity = Some(
        config
            .refresh_token_validity
            .unwrap_or(DEFAULT_REFRESH_TOKEN_VALIDITY_DAYS),
    );
    client.token_validity_units = config.token_validity_units;
    client.refresh_token_rotation = config.refresh_token_rotation;

    // Security settings
    client.enable_token_revocation = config.enable_token_revocation.unwrap_or(true);
    client.prevent_user_existence_errors = config.prevent_user_existence_errors;
    client.enable_propagate_additional_user_context_data = config
        .enable_propagate_additional_user_context_data
        .unwrap_or(false);
}

/// A client secret shaped like Cognito's: 51 lowercase letters and digits.
pub(crate) fn generate_client_secret() -> String {
    use rand::Rng;

    const CHARSET: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyz";
    let mut rng = rand::thread_rng();
    (0..51)
        .map(|_| CHARSET[rng.gen_range(0..CHARSET.len())] as char)
        .collect()
}

/// The flows an app client created without `ExplicitAuthFlows` supports.
pub(crate) fn default_explicit_auth_flows() -> Vec<ExplicitAuthFlow> {
    vec![
        ExplicitAuthFlow::AllowCustomAuth,
        ExplicitAuthFlow::AllowUserSrpAuth,
        ExplicitAuthFlow::AllowRefreshTokenAuth,
    ]
}

/// `AuthSessionValidity` when the request leaves it out.
const DEFAULT_AUTH_SESSION_VALIDITY_MINUTES: i32 = 3;

/// `RefreshTokenValidity` when the request leaves it out.
const DEFAULT_REFRESH_TOKEN_VALIDITY_DAYS: i32 = 30;

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

    if !client.read_attributes.is_empty() {
        response["ReadAttributes"] = json!(client.read_attributes);
    }

    if !client.write_attributes.is_empty() {
        response["WriteAttributes"] = json!(client.write_attributes);
    }

    if let Some(ref analytics_configuration) = client.analytics_configuration {
        response["AnalyticsConfiguration"] = json!(analytics_configuration);
    }

    // A client stored before the emulator recorded these defaults behaves
    // by them all the same, so it reads that way too.
    response["ExplicitAuthFlows"] = if client.explicit_auth_flows.is_empty() {
        json!(default_explicit_auth_flows())
    } else {
        json!(client.explicit_auth_flows)
    };
    response["AuthSessionValidity"] = json!(
        client
            .auth_session_validity
            .unwrap_or(DEFAULT_AUTH_SESSION_VALIDITY_MINUTES)
    );

    if let Some(validity) = client.access_token_validity {
        response["AccessTokenValidity"] = json!(validity);
    }

    if let Some(validity) = client.id_token_validity {
        response["IdTokenValidity"] = json!(validity);
    }

    response["RefreshTokenValidity"] = json!(
        client
            .refresh_token_validity
            .unwrap_or(DEFAULT_REFRESH_TOKEN_VALIDITY_DAYS)
    );

    // Cognito always returns the member, empty when no unit was chosen.
    response["TokenValidityUnits"] = json!({});
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

    if let Some(ref refresh_token_rotation) = client.refresh_token_rotation {
        response["RefreshTokenRotation"] = json!(refresh_token_rotation);
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
        // Cognito's secrets are 51 lowercase letters and digits.
        let secret = body["UserPoolClient"]["ClientSecret"].as_str().unwrap();
        assert_eq!(secret.len(), 51);
        assert!(
            secret
                .chars()
                .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit())
        );
    }

    #[tokio::test]
    async fn test_create_user_pool_client_returns_cognitos_defaults() {
        let storage = Storage::new();

        let pool = create_user_pool::handler(&storage, json!({"PoolName": "test-pool"}))
            .await
            .unwrap();
        let pool_id = pool["UserPool"]["Id"].as_str().unwrap();

        let body = handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "ClientName": "test-client"
            }),
        )
        .await
        .unwrap();

        let mut client = body["UserPoolClient"].clone();
        for generated in ["ClientId", "CreationDate", "LastModifiedDate"] {
            assert!(client.as_object_mut().unwrap().remove(generated).is_some());
        }
        assert_eq!(
            client,
            json!({
                "UserPoolId": pool_id,
                "ClientName": "test-client",
                "RefreshTokenValidity": 30,
                "TokenValidityUnits": {},
                "ExplicitAuthFlows": [
                    "ALLOW_CUSTOM_AUTH",
                    "ALLOW_USER_SRP_AUTH",
                    "ALLOW_REFRESH_TOKEN_AUTH"
                ],
                "AllowedOAuthFlowsUserPoolClient": false,
                "EnableTokenRevocation": true,
                "EnablePropagateAdditionalUserContextData": false,
                "AuthSessionValidity": 3
            })
        );
    }

    #[test]
    fn test_client_from_an_older_snapshot_reads_with_the_defaults_it_behaves_by() {
        // Stored before the emulator recorded the defaults: no explicit
        // flows, no session or refresh token validity.
        let client = UserPoolClient::new_for_test(
            ClientId::generate(),
            UserPoolId::new("us-east-1_Legacy").unwrap(),
        );

        let response = build_client_response(&client);
        assert_eq!(
            response["ExplicitAuthFlows"],
            json!([
                "ALLOW_CUSTOM_AUTH",
                "ALLOW_USER_SRP_AUTH",
                "ALLOW_REFRESH_TOKEN_AUTH"
            ])
        );
        assert_eq!(response["AuthSessionValidity"], 3);
        assert_eq!(response["RefreshTokenValidity"], 30);
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
    async fn test_create_user_pool_client_persists_extended_configuration() {
        let storage = Storage::new();

        let pool = create_user_pool::handler(&storage, json!({"PoolName": "test-pool"}))
            .await
            .unwrap();
        let pool_id = pool["UserPool"]["Id"].as_str().unwrap();

        let result = handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "ClientName": "typed-client",
                "ReadAttributes": ["email", "custom:role"],
                "WriteAttributes": ["email"],
                "AnalyticsConfiguration": {
                    "ApplicationId": "pinpoint-app"
                },
                "AuthSessionValidity": 5,
                "RefreshTokenRotation": {
                    "Feature": "ENABLED",
                    "RetryGracePeriodSeconds": 10
                }
            }),
        )
        .await
        .unwrap();

        let client = &result["UserPoolClient"];
        assert_eq!(client["ReadAttributes"], json!(["email", "custom:role"]));
        assert_eq!(client["WriteAttributes"], json!(["email"]));
        assert_eq!(
            client["AnalyticsConfiguration"]["ApplicationId"],
            "pinpoint-app"
        );
        assert_eq!(client["AuthSessionValidity"], 5);
        assert_eq!(client["RefreshTokenRotation"]["Feature"], "ENABLED");
        assert_eq!(
            client["RefreshTokenRotation"]["RetryGracePeriodSeconds"],
            10
        );
    }

    #[tokio::test]
    async fn test_create_user_pool_client_rejects_invalid_auth_session_validity() {
        let storage = Storage::new();

        let pool = create_user_pool::handler(&storage, json!({"PoolName": "test-pool"}))
            .await
            .unwrap();
        let pool_id = pool["UserPool"]["Id"].as_str().unwrap();

        let result = handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "ClientName": "bad-client",
                "AuthSessionValidity": 2
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
