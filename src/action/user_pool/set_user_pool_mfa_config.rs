//! SetUserPoolMfaConfig API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_SetUserPoolMfaConfig.html>

use serde::Deserialize;
use serde_json::{Value, json};

use crate::{
    error::{AppError, Result},
    storage::Storage,
    types::UserPoolId,
};

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct SmsMfaConfiguration {
    #[allow(dead_code)]
    sms_authentication_message: Option<String>,
    #[allow(dead_code)]
    sms_configuration: Option<SmsConfiguration>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct SmsConfiguration {
    #[allow(dead_code)]
    sns_caller_arn: Option<String>,
    #[allow(dead_code)]
    external_id: Option<String>,
    #[allow(dead_code)]
    sns_region: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct SoftwareTokenMfaConfiguration {
    #[allow(dead_code)]
    enabled: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Request {
    user_pool_id: UserPoolId,
    mfa_configuration: Option<String>,
    #[allow(dead_code)]
    sms_mfa_configuration: Option<SmsMfaConfiguration>,
    #[allow(dead_code)]
    email_mfa_configuration: Option<Value>,
    #[allow(dead_code)]
    software_token_mfa_configuration: Option<SoftwareTokenMfaConfiguration>,
    #[allow(dead_code)]
    web_authn_configuration: Option<Value>,
}

pub async fn handler(storage: &Storage, body: Value) -> Result<Value> {
    let req: Request = serde_json::from_value(body)
        .map_err(|e| AppError::InvalidParameter(format!("Invalid request: {}", e)))?;

    // Verify user pool exists
    storage
        .get_user_pool(&req.user_pool_id)
        .await
        .ok_or(AppError::UserPoolNotFound)?;

    // Validate MFA configuration value
    let mfa_config = req.mfa_configuration.as_deref().unwrap_or("OFF");
    if !matches!(mfa_config, "OFF" | "ON" | "OPTIONAL") {
        return Err(AppError::InvalidParameter(format!(
            "Invalid MfaConfiguration value: {}. Must be OFF, ON, or OPTIONAL",
            mfa_config
        )));
    }

    // Note: In a full implementation, we would store the MFA configuration
    // and enforce it during authentication. For the emulator, we accept
    // the configuration but MFA is not actually enforced.

    Ok(json!({
        "MfaConfiguration": mfa_config,
        "SmsMfaConfiguration": null,
        "SoftwareTokenMfaConfiguration": null
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::user_pool::create_user_pool;
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
        .await;

        assert!(result.is_ok());
        let body = result.unwrap();
        assert_eq!(body["MfaConfiguration"], "OPTIONAL");
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
                "MfaConfiguration": "INVALID"
            }),
        )
        .await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AppError::InvalidParameter(_)));
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

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AppError::UserPoolNotFound));
    }
}
