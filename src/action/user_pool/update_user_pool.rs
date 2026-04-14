//! UpdateUserPool API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_UpdateUserPool.html>

use std::collections::HashMap;

use chrono::Utc;
use serde::Deserialize;
use serde_json::Value;

use crate::{
    action::io::parse_request,
    error::{AppError, Result},
    storage::Storage,
    types::UserPoolId,
    validation::validate_pool_name,
};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Request {
    user_pool_id: UserPoolId,
    #[serde(default)]
    account_recovery_setting: Option<Value>,
    #[serde(default)]
    admin_create_user_config: Option<Value>,
    #[serde(default)]
    auto_verified_attributes: Option<Vec<String>>,
    #[serde(default)]
    deletion_protection: Option<String>,
    #[serde(default)]
    device_configuration: Option<Value>,
    #[serde(default)]
    email_configuration: Option<Value>,
    #[serde(default)]
    email_verification_message: Option<String>,
    #[serde(default)]
    email_verification_subject: Option<String>,
    #[serde(default)]
    lambda_config: Option<Value>,
    #[serde(default)]
    mfa_configuration: Option<String>,
    #[serde(default)]
    policies: Option<Value>,
    #[serde(default)]
    pool_name: Option<String>,
    #[serde(default)]
    sms_authentication_message: Option<String>,
    #[serde(default)]
    sms_configuration: Option<Value>,
    #[serde(default)]
    sms_verification_message: Option<String>,
    #[serde(default)]
    user_attribute_update_settings: Option<Value>,
    #[serde(default)]
    user_pool_add_ons: Option<Value>,
    #[serde(default)]
    user_pool_tags: Option<HashMap<String, String>>,
    #[serde(default)]
    user_pool_tier: Option<String>,
    #[serde(default)]
    verification_message_template: Option<Value>,
}

pub async fn handler(storage: &Storage, body: Value) -> Result<Value> {
    let req: Request = parse_request(body)?;

    let mut pool = storage
        .get_user_pool(&req.user_pool_id)
        .await
        .ok_or(AppError::UserPoolNotFound)?;

    if let Some(pool_name) = req.pool_name {
        validate_pool_name(&pool_name)?;
        pool.name = pool_name.trim().to_string();
    }
    if let Some(value) = req.account_recovery_setting {
        pool.account_recovery_setting = Some(value);
    }
    if let Some(value) = req.admin_create_user_config {
        pool.admin_create_user_config = Some(value);
    }
    if let Some(value) = req.auto_verified_attributes {
        pool.auto_verified_attributes = Some(value);
    }
    if let Some(value) = req.deletion_protection {
        pool.deletion_protection = Some(value);
    }
    if let Some(value) = req.device_configuration {
        pool.device_configuration = Some(value);
    }
    if let Some(value) = req.email_configuration {
        pool.email_configuration = Some(value);
    }
    if let Some(value) = req.email_verification_message {
        pool.email_verification_message = Some(value);
    }
    if let Some(value) = req.email_verification_subject {
        pool.email_verification_subject = Some(value);
    }
    if let Some(value) = req.lambda_config {
        pool.lambda_config = Some(value);
    }
    if let Some(value) = req.mfa_configuration {
        pool.mfa_configuration = Some(value);
    }
    if let Some(value) = req.policies {
        pool.policies = Some(value);
    }
    if let Some(value) = req.sms_authentication_message {
        pool.sms_authentication_message = Some(value);
    }
    if let Some(value) = req.sms_configuration {
        pool.sms_configuration = Some(value);
    }
    if let Some(value) = req.sms_verification_message {
        pool.sms_verification_message = Some(value);
    }
    if let Some(value) = req.user_attribute_update_settings {
        pool.user_attribute_update_settings = Some(value);
    }
    if let Some(value) = req.user_pool_add_ons {
        pool.user_pool_add_ons = Some(value);
    }
    if let Some(value) = req.user_pool_tags {
        pool.user_pool_tags = Some(value);
    }
    if let Some(value) = req.user_pool_tier {
        pool.user_pool_tier = Some(value);
    }
    if let Some(value) = req.verification_message_template {
        pool.verification_message_template = Some(value);
    }

    pool.last_modified_date = Utc::now();

    storage.update_user_pool(pool).await;

    Ok(serde_json::json!({}))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::user_pool::create_user_pool;
    use serde_json::json;

    #[tokio::test]
    async fn test_update_user_pool_success() {
        let storage = Storage::new();

        let pool = create_user_pool::handler(&storage, json!({"PoolName": "test-pool"}))
            .await
            .unwrap();
        let pool_id = pool["UserPool"]["Id"].as_str().unwrap();

        let result = handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "PoolName": "updated-pool"
            }),
        )
        .await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), json!({}));

        let updated = storage
            .get_user_pool(&pool_id.parse().unwrap())
            .await
            .unwrap();
        assert_eq!(updated.name, "updated-pool");
    }

    #[tokio::test]
    async fn test_update_user_pool_invalid_name() {
        let storage = Storage::new();

        let pool = create_user_pool::handler(&storage, json!({"PoolName": "test-pool"}))
            .await
            .unwrap();
        let pool_id = pool["UserPool"]["Id"].as_str().unwrap();

        let result = handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "PoolName": "   "
            }),
        )
        .await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AppError::InvalidParameter(_)));
    }

    #[tokio::test]
    async fn test_update_user_pool_not_found() {
        let storage = Storage::new();

        let result = handler(
            &storage,
            json!({
                "UserPoolId": "local_nonexistent"
            }),
        )
        .await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AppError::UserPoolNotFound));
    }

    #[tokio::test]
    async fn test_update_user_pool_updates_configuration_fields() {
        let storage = Storage::new();

        let pool = create_user_pool::handler(&storage, json!({"PoolName": "test-pool"}))
            .await
            .unwrap();
        let pool_id = pool["UserPool"]["Id"].as_str().unwrap();

        handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "MfaConfiguration": "ON",
                "EmailVerificationSubject": "Verify your account",
                "UserPoolTags": {
                    "env": "dev"
                },
                "UserPoolTier": "PLUS"
            }),
        )
        .await
        .unwrap();

        let updated = storage
            .get_user_pool(&pool_id.parse().unwrap())
            .await
            .unwrap();
        assert_eq!(updated.mfa_configuration.as_deref(), Some("ON"));
        assert_eq!(
            updated.email_verification_subject.as_deref(),
            Some("Verify your account")
        );
        assert_eq!(
            updated
                .user_pool_tags
                .as_ref()
                .and_then(|tags| tags.get("env"))
                .map(String::as_str),
            Some("dev")
        );
        assert_eq!(updated.user_pool_tier.as_deref(), Some("PLUS"));
    }
}
