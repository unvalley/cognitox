//! UpdateUserPoolClient API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_UpdateUserPoolClient.html>

use chrono::Utc;
use serde::Deserialize;
use serde_json::{Value, json};

use super::create_user_pool_client::build_client_response;
use crate::{
    error::{AppError, Result},
    storage::Storage,
    types::{ClientId, TokenValidityUnits, UserPoolId},
    validation::{validate_callback_url, validate_client_name},
};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Request {
    user_pool_id: UserPoolId,
    client_id: ClientId,
    client_name: Option<String>,

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

    // Validate client name if provided
    if let Some(ref name) = req.client_name {
        validate_client_name(name)?;
    }

    // Validate callback URLs if provided
    if let Some(ref urls) = req.callback_u_r_ls {
        for url in urls {
            validate_callback_url(url)?;
        }
    }

    // Validate logout URLs if provided
    if let Some(ref urls) = req.logout_u_r_ls {
        for url in urls {
            validate_callback_url(url)?;
        }
    }

    storage
        .get_user_pool(&req.user_pool_id)
        .await
        .ok_or(AppError::UserPoolNotFound)?;

    let mut client = storage
        .get_user_pool_client(&req.client_id)
        .await
        .ok_or(AppError::UserPoolClientNotFound)?;

    if client.user_pool_id != req.user_pool_id {
        return Err(AppError::UserPoolClientNotFound);
    }

    // Update fields if provided
    if let Some(name) = req.client_name {
        client.client_name = name;
    }

    if let Some(flows) = req.allowed_o_auth_flows {
        client.allowed_oauth_flows = flows;
    }

    if let Some(scopes) = req.allowed_o_auth_scopes {
        client.allowed_oauth_scopes = scopes;
    }

    if let Some(allowed) = req.allowed_o_auth_flows_user_pool_client {
        client.allowed_oauth_flows_user_pool_client = allowed;
    }

    if let Some(urls) = req.callback_u_r_ls {
        client.callback_urls = urls;
    }

    if let Some(urls) = req.logout_u_r_ls {
        client.logout_urls = urls;
    }

    if let Some(uri) = req.default_redirect_u_r_i {
        client.default_redirect_uri = Some(uri);
    }

    if let Some(providers) = req.supported_identity_providers {
        client.supported_identity_providers = providers;
    }

    if let Some(flows) = req.explicit_auth_flows {
        client.explicit_auth_flows = flows;
    }

    if let Some(validity) = req.access_token_validity {
        client.access_token_validity = Some(validity);
    }

    if let Some(validity) = req.id_token_validity {
        client.id_token_validity = Some(validity);
    }

    if let Some(validity) = req.refresh_token_validity {
        client.refresh_token_validity = Some(validity);
    }

    if let Some(units) = req.token_validity_units {
        client.token_validity_units = Some(TokenValidityUnits {
            access_token: units.access_token,
            id_token: units.id_token,
            refresh_token: units.refresh_token,
        });
    }

    if let Some(enabled) = req.enable_token_revocation {
        client.enable_token_revocation = enabled;
    }

    if let Some(prevent) = req.prevent_user_existence_errors {
        client.prevent_user_existence_errors = Some(prevent);
    }

    if let Some(enabled) = req.enable_propagate_additional_user_context_data {
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
}
