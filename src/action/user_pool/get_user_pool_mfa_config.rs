//! GetUserPoolMfaConfig API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_GetUserPoolMfaConfig.html>

use serde::Deserialize;
use serde_json::{Value, json};

use crate::{
    action::io::parse_request,
    error::{AppError, Result},
    storage::Storage,
    types::UserPoolId,
};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Request {
    user_pool_id: UserPoolId,
}

pub async fn handler(storage: &Storage, body: Value) -> Result<Value> {
    let req: Request = parse_request(body)?;

    let pool = storage
        .get_user_pool(&req.user_pool_id)
        .await
        .ok_or(AppError::UserPoolNotFound)?;

    Ok(json!({
        "MfaConfiguration": pool.mfa_configuration.unwrap_or(crate::types::MfaConfiguration::Off),
        "SmsMfaConfiguration": pool.sms_mfa_configuration,
        "SoftwareTokenMfaConfiguration": pool.software_token_mfa_configuration,
        "EmailMfaConfiguration": pool.email_mfa_configuration,
        "WebAuthnConfiguration": pool.webauthn_configuration
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::user_pool::{create_user_pool, set_user_pool_mfa_config};
    use serde_json::json;

    #[tokio::test]
    async fn test_get_user_pool_mfa_config_success() {
        let storage = Storage::new();

        let pool = create_user_pool::handler(&storage, json!({"PoolName": "test"}))
            .await
            .unwrap();
        let pool_id = pool["UserPool"]["Id"].as_str().unwrap();

        set_user_pool_mfa_config::handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "MfaConfiguration": "OPTIONAL",
                "SmsMfaConfiguration": {
                    "SmsAuthenticationMessage": "Code {####}",
                    "SmsConfiguration": {
                        "SnsCallerArn": "arn:aws:iam::123456789012:role/test"
                    }
                }
            }),
        )
        .await
        .unwrap();

        let result = handler(&storage, json!({ "UserPoolId": pool_id }))
            .await
            .unwrap();
        assert_eq!(result["MfaConfiguration"], "OPTIONAL");
        assert_eq!(
            result["SmsMfaConfiguration"]["SmsAuthenticationMessage"],
            "Code {####}"
        );
    }

    #[tokio::test]
    async fn test_get_user_pool_mfa_config_pool_not_found() {
        let storage = Storage::new();

        let result = handler(
            &storage,
            json!({
                "UserPoolId": "local_nonexistent"
            }),
        )
        .await;

        assert!(matches!(result, Err(AppError::UserPoolNotFound)));
    }
}
