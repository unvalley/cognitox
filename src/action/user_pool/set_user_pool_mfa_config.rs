//! SetUserPoolMfaConfig API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_SetUserPoolMfaConfig.html>

use chrono::Utc;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::{
    action::io::parse_request,
    error::{AppError, Result},
    storage::Storage,
    types::{
        EmailMfaConfiguration, MfaConfiguration, SmsMfaConfiguration,
        SoftwareTokenMfaConfiguration, UserPoolId, WebAuthnConfiguration,
    },
    validation::validate_pool_mfa_configuration,
};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Request {
    user_pool_id: UserPoolId,
    #[serde(default)]
    mfa_configuration: Option<MfaConfiguration>,
    #[serde(default)]
    sms_mfa_configuration: Option<SmsMfaConfiguration>,
    #[serde(default)]
    software_token_mfa_configuration: Option<SoftwareTokenMfaConfiguration>,
    #[serde(default)]
    email_mfa_configuration: Option<EmailMfaConfiguration>,
    #[serde(default)]
    webauthn_configuration: Option<WebAuthnConfiguration>,
}

pub async fn handler(storage: &Storage, body: Value) -> Result<Value> {
    let req: Request = parse_request(body)?;

    validate_pool_mfa_configuration(
        req.mfa_configuration,
        req.sms_mfa_configuration.as_ref(),
        req.software_token_mfa_configuration.as_ref(),
        req.email_mfa_configuration.as_ref(),
        req.webauthn_configuration.as_ref(),
    )?;

    let mut pool = storage
        .get_user_pool(&req.user_pool_id)
        .await
        .ok_or(AppError::UserPoolNotFound)?;

    pool.mfa_configuration = req.mfa_configuration.or(pool.mfa_configuration);
    if req.sms_mfa_configuration.is_some() {
        pool.sms_mfa_configuration = req.sms_mfa_configuration;
    }
    if req.software_token_mfa_configuration.is_some() {
        pool.software_token_mfa_configuration = req.software_token_mfa_configuration;
    }
    if req.email_mfa_configuration.is_some() {
        pool.email_mfa_configuration = req.email_mfa_configuration;
    }
    if req.webauthn_configuration.is_some() {
        pool.webauthn_configuration = req.webauthn_configuration;
    }
    pool.last_modified_date = Utc::now();

    storage
        .update_user_pool(pool.clone())
        .await
        .ok_or(AppError::Internal(
            "Failed to update user pool MFA configuration".to_string(),
        ))?;

    Ok(json!({
        "MfaConfiguration": pool.mfa_configuration,
        "SmsMfaConfiguration": pool.sms_mfa_configuration,
        "SoftwareTokenMfaConfiguration": pool.software_token_mfa_configuration,
        "EmailMfaConfiguration": pool.email_mfa_configuration,
        "WebAuthnConfiguration": pool.webauthn_configuration
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::user_pool::{create_user_pool, get_user_pool_mfa_config};
    use serde_json::json;

    #[tokio::test]
    async fn test_set_user_pool_mfa_config_success() {
        let storage = Storage::new();

        let pool = create_user_pool::handler(&storage, json!({"PoolName": "test"}))
            .await
            .unwrap();
        let pool_id = pool["UserPool"]["Id"].as_str().unwrap();

        let result = handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "MfaConfiguration": "OPTIONAL",
                "SoftwareTokenMfaConfiguration": {
                    "Enabled": true
                }
            }),
        )
        .await
        .unwrap();

        assert_eq!(result["MfaConfiguration"], "OPTIONAL");
        assert_eq!(result["SoftwareTokenMfaConfiguration"]["Enabled"], true);

        let fetched = get_user_pool_mfa_config::handler(&storage, json!({ "UserPoolId": pool_id }))
            .await
            .unwrap();
        assert_eq!(fetched["MfaConfiguration"], "OPTIONAL");
        assert_eq!(fetched["SoftwareTokenMfaConfiguration"]["Enabled"], true);
    }

    #[tokio::test]
    async fn test_set_user_pool_mfa_config_invalid_value() {
        let storage = Storage::new();

        let pool = create_user_pool::handler(&storage, json!({"PoolName": "test"}))
            .await
            .unwrap();
        let pool_id = pool["UserPool"]["Id"].as_str().unwrap();

        let result = handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "MfaConfiguration": "ON"
            }),
        )
        .await;

        assert!(matches!(result, Err(AppError::InvalidParameter(_))));
    }

    #[tokio::test]
    async fn test_set_user_pool_mfa_config_pool_not_found() {
        let storage = Storage::new();

        let result = handler(
            &storage,
            json!({
                "UserPoolId": "local_nonexistent",
                "MfaConfiguration": "OFF"
            }),
        )
        .await;

        assert!(matches!(result, Err(AppError::UserPoolNotFound)));
    }
}
