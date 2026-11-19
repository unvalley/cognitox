//! UpdateUserPool API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_UpdateUserPool.html>

use std::collections::HashMap;

use chrono::Utc;
use serde::Deserialize;
use serde_json::Value;

use crate::{
    action::io::parse_request,
    action::user_pool::create_user_pool::{UserPoolConfigInput, validate_user_pool_configuration},
    action::user_pool::defaults::apply_user_pool_defaults,
    error::{AppError, Result},
    storage::Storage,
    types::{
        AccountRecoverySetting, AdminCreateUserConfig, AutoVerifiedAttribute, DeletionProtection,
        DeviceConfiguration, EmailConfiguration, MfaConfiguration, SmsConfiguration,
        UserAttributeUpdateSettingsType, UserPoolAddOns, UserPoolId, UserPoolPolicies,
        UserPoolTier, VerificationMessageTemplate,
    },
    validation::validate_pool_name,
};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Request {
    user_pool_id: UserPoolId,
    #[serde(default)]
    account_recovery_setting: Option<AccountRecoverySetting>,
    #[serde(default)]
    admin_create_user_config: Option<AdminCreateUserConfig>,
    #[serde(default)]
    auto_verified_attributes: Option<Vec<AutoVerifiedAttribute>>,
    #[serde(default)]
    deletion_protection: Option<DeletionProtection>,
    #[serde(default)]
    device_configuration: Option<DeviceConfiguration>,
    #[serde(default)]
    email_configuration: Option<EmailConfiguration>,
    #[serde(default)]
    email_verification_message: Option<String>,
    #[serde(default)]
    email_verification_subject: Option<String>,
    #[serde(default)]
    lambda_config: Option<Value>,
    #[serde(default)]
    mfa_configuration: Option<MfaConfiguration>,
    #[serde(default)]
    policies: Option<UserPoolPolicies>,
    #[serde(default)]
    pool_name: Option<String>,
    #[serde(default)]
    sms_authentication_message: Option<String>,
    #[serde(default)]
    sms_configuration: Option<SmsConfiguration>,
    #[serde(default)]
    sms_verification_message: Option<String>,
    #[serde(default)]
    user_attribute_update_settings: Option<UserAttributeUpdateSettingsType>,
    #[serde(default)]
    user_pool_add_ons: Option<UserPoolAddOns>,
    #[serde(default)]
    user_pool_tags: Option<HashMap<String, String>>,
    #[serde(default)]
    user_pool_tier: Option<UserPoolTier>,
    #[serde(default)]
    verification_message_template: Option<VerificationMessageTemplate>,
}

pub async fn handler(storage: &Storage, body: Value) -> Result<Value> {
    let req: Request = parse_request(body)?;

    validate_user_pool_configuration(&UserPoolConfigInput {
        account_recovery_setting: req.account_recovery_setting.clone(),
        admin_create_user_config: req.admin_create_user_config.clone(),
        alias_attributes: None,
        auto_verified_attributes: None,
        deletion_protection: req.deletion_protection,
        device_configuration: req.device_configuration.clone(),
        email_configuration: req.email_configuration.clone(),
        email_verification_message: req.email_verification_message.clone(),
        email_verification_subject: req.email_verification_subject.clone(),
        lambda_config: req.lambda_config.clone(),
        mfa_configuration: req.mfa_configuration,
        policies: req.policies.clone(),
        schema_attributes: None,
        sms_authentication_message: req.sms_authentication_message.clone(),
        sms_configuration: req.sms_configuration.clone(),
        sms_verification_message: req.sms_verification_message.clone(),
        user_attribute_update_settings: req.user_attribute_update_settings.clone(),
        user_pool_add_ons: req.user_pool_add_ons.clone(),
        user_pool_tags: req.user_pool_tags.clone(),
        user_pool_tier: req.user_pool_tier,
        username_attributes: None,
        username_configuration: None,
        verification_message_template: req.verification_message_template.clone(),
    })?;

    let user_pool_id = req.user_pool_id.clone();
    let result = storage
        .update_user_pool_with(&user_pool_id, |pool| -> Result<()> {
            if let Some(pool_name) = req.pool_name {
                validate_pool_name(&pool_name)?;
                pool.name = pool_name.trim().to_string();
            }
            // "If you don't provide a value for an attribute, Amazon Cognito
            // sets it to its default value": the request replaces the pool's
            // configuration instead of patching it.
            pool.account_recovery_setting = req.account_recovery_setting;
            pool.admin_create_user_config = req.admin_create_user_config;
            pool.auto_verified_attributes = req.auto_verified_attributes;
            pool.device_configuration = req.device_configuration;
            pool.email_configuration = req.email_configuration;
            pool.email_verification_message = req.email_verification_message;
            pool.email_verification_subject = req.email_verification_subject;
            pool.lambda_config = req.lambda_config;
            pool.policies = req.policies;
            pool.sms_authentication_message = req.sms_authentication_message;
            pool.sms_configuration = req.sms_configuration;
            pool.sms_verification_message = req.sms_verification_message;
            pool.user_attribute_update_settings = req.user_attribute_update_settings;
            pool.user_pool_add_ons = req.user_pool_add_ons;
            pool.verification_message_template = req.verification_message_template;

            // Settings with a lifecycle of their own keep their value when
            // the request leaves them out.
            if let Some(value) = req.deletion_protection {
                pool.deletion_protection = Some(value);
            }
            if let Some(value) = req.mfa_configuration {
                pool.mfa_configuration = Some(value);
            }
            if let Some(value) = req.user_pool_tags {
                pool.user_pool_tags = Some(value);
            }
            if let Some(value) = req.user_pool_tier {
                pool.user_pool_tier = Some(value);
            }

            apply_user_pool_defaults(pool);
            pool.last_modified_date = Utc::now();
            Ok(())
        })
        .await
        .ok_or(AppError::UserPoolNotFound)?;
    result?;

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
        assert_eq!(updated.mfa_configuration, Some(MfaConfiguration::On));
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
        assert_eq!(updated.user_pool_tier, Some(UserPoolTier::Plus));
    }

    #[tokio::test]
    async fn test_update_user_pool_resets_what_the_request_leaves_out() {
        let storage = Storage::new();

        let pool = create_user_pool::handler(
            &storage,
            json!({
                "PoolName": "test-pool",
                "AutoVerifiedAttributes": ["email"],
                "LambdaConfig": {
                    "PreSignUp": "arn:aws:lambda:us-east-1:000000000000:function:pre"
                },
                "Policies": {
                    "PasswordPolicy": {"MinimumLength": 12, "RequireSymbols": true}
                },
                "AdminCreateUserConfig": {"AllowAdminCreateUserOnly": true},
                "DeletionProtection": "ACTIVE",
                "MfaConfiguration": "OPTIONAL",
                "UserPoolTier": "PLUS",
                "UserPoolTags": {"env": "dev"}
            }),
        )
        .await
        .unwrap();
        let pool_id: UserPoolId = pool["UserPool"]["Id"].as_str().unwrap().parse().unwrap();

        handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "SmsAuthenticationMessage": "Your code is {####}"
            }),
        )
        .await
        .unwrap();

        let updated = storage.get_user_pool(&pool_id).await.unwrap();
        assert_eq!(
            updated.sms_authentication_message.as_deref(),
            Some("Your code is {####}")
        );
        // Everything else the request could have set is back to its default.
        assert_eq!(updated.auto_verified_attributes, None);
        assert_eq!(updated.lambda_config, Some(json!({})));
        assert_eq!(
            updated
                .policies
                .as_ref()
                .and_then(|policies| policies.password_policy.clone()),
            Some(crate::validation::default_password_policy())
        );
        assert_eq!(
            updated
                .admin_create_user_config
                .as_ref()
                .and_then(|config| config.allow_admin_create_user_only),
            Some(false)
        );
        // The name and the settings with their own lifecycle stay.
        assert_eq!(updated.name, "test-pool");
        assert_eq!(
            updated.deletion_protection,
            Some(DeletionProtection::Active)
        );
        assert_eq!(updated.mfa_configuration, Some(MfaConfiguration::Optional));
        assert_eq!(updated.user_pool_tier, Some(UserPoolTier::Plus));
        assert_eq!(
            updated
                .user_pool_tags
                .as_ref()
                .and_then(|tags| tags.get("env"))
                .map(String::as_str),
            Some("dev")
        );
    }

    #[tokio::test]
    async fn test_update_user_pool_completes_a_partial_password_policy() {
        let storage = Storage::new();

        let pool = create_user_pool::handler(&storage, json!({"PoolName": "test-pool"}))
            .await
            .unwrap();
        let pool_id: UserPoolId = pool["UserPool"]["Id"].as_str().unwrap().parse().unwrap();

        handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "Policies": {"PasswordPolicy": {"MinimumLength": 6}}
            }),
        )
        .await
        .unwrap();

        let updated = storage.get_user_pool(&pool_id).await.unwrap();
        let policy = updated
            .policies
            .and_then(|policies| policies.password_policy)
            .unwrap();
        assert_eq!(policy.minimum_length, Some(6));
        assert_eq!(policy.require_symbols, Some(false));
        assert_eq!(policy.require_uppercase, Some(false));
        assert_eq!(policy.temporary_password_validity_days, Some(7));
    }
}
