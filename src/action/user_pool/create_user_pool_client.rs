//! CreateUserPoolClient API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_CreateUserPoolClient.html>

use chrono::Utc;
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::{
    error::{AppError, Result},
    storage::Storage,
    types::{ClientId, TokenValidityUnits, UserPoolClient, UserPoolId},
    validation::{validate_callback_url, validate_client_name},
};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Request {
    user_pool_id: UserPoolId,
    client_name: String,
    generate_secret: Option<bool>,

    // OAuth configuration
    allowed_o_auth_flows: Option<Vec<String>>,
    allowed_o_auth_scopes: Option<Vec<String>>,
    allowed_o_auth_flows_user_pool_client: Option<bool>,
    callback_u_r_ls: Option<Vec<String>>,
    logout_u_r_ls: Option<Vec<String>>,
    default_redirect_u_r_i: Option<String>,
    supported_identity_providers: Option<Vec<String>>,

    // Auth flows
    explicit_auth_flows: Option<Vec<String>>,

    // Token validity
    access_token_validity: Option<i32>,
    id_token_validity: Option<i32>,
    refresh_token_validity: Option<i32>,
    token_validity_units: Option<TokenValidityUnitsInput>,

    // Security settings
    enable_token_revocation: Option<bool>,
    prevent_user_existence_errors: Option<String>,
    enable_propagate_additional_user_context_data: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct TokenValidityUnitsInput {
    access_token: Option<String>,
    id_token: Option<String>,
    refresh_token: Option<String>,
}

pub async fn handler(storage: &Storage, body: Value) -> Result<Value> {
    let req: Request = serde_json::from_value(body)
        .map_err(|e| AppError::InvalidParameter(format!("Invalid request: {}", e)))?;

    // Validate input
    validate_client_name(&req.client_name)?;

    // Validate callback URLs if provided
    if let Some(urls) = &req.callback_u_r_ls {
        for url in urls {
            validate_callback_url(url)?;
        }
    }

    // Validate logout URLs if provided
    if let Some(urls) = &req.logout_u_r_ls {
        for url in urls {
            validate_callback_url(url)?;
        }
    }

    storage
        .get_user_pool(&req.user_pool_id)
        .await
        .ok_or(AppError::UserPoolNotFound)?;

    let now = Utc::now();
    let client_id = ClientId::generate();
    let client_secret = if req.generate_secret.unwrap_or(false) {
        Some(Uuid::new_v4().to_string())
    } else {
        None
    };

    let token_validity_units = req.token_validity_units.map(|t| TokenValidityUnits {
        access_token: t.access_token,
        id_token: t.id_token,
        refresh_token: t.refresh_token,
    });

    let client = UserPoolClient {
        client_id,
        user_pool_id: req.user_pool_id,
        client_name: req.client_name,
        client_secret: client_secret.clone(),
        creation_date: now,
        last_modified_date: now,

        // OAuth configuration
        allowed_oauth_flows: req.allowed_o_auth_flows.unwrap_or_default(),
        allowed_oauth_scopes: req.allowed_o_auth_scopes.unwrap_or_default(),
        allowed_oauth_flows_user_pool_client: req
            .allowed_o_auth_flows_user_pool_client
            .unwrap_or(false),
        callback_urls: req.callback_u_r_ls.unwrap_or_default(),
        logout_urls: req.logout_u_r_ls.unwrap_or_default(),
        default_redirect_uri: req.default_redirect_u_r_i,
        supported_identity_providers: req.supported_identity_providers.unwrap_or_default(),

        // Auth flows
        explicit_auth_flows: req.explicit_auth_flows.unwrap_or_default(),

        // Token validity
        access_token_validity: req.access_token_validity,
        id_token_validity: req.id_token_validity,
        refresh_token_validity: req.refresh_token_validity,
        token_validity_units,

        // Security settings
        enable_token_revocation: req.enable_token_revocation.unwrap_or(true),
        prevent_user_existence_errors: req.prevent_user_existence_errors,
        enable_propagate_additional_user_context_data: req
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
