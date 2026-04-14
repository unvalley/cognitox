//! CreateUserPool API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_CreateUserPool.html>

use std::collections::HashMap;

use chrono::Utc;
use serde::Deserialize;
use serde_json::{Map, Value, json};

use crate::{
    action::io::parse_request,
    error::Result,
    storage::Storage,
    types::{
        AliasAttribute, AutoVerifiedAttribute, DeletionProtection, MfaConfiguration, UserPool,
        UserPoolId, UserPoolPolicies, UserPoolTier, UsernameAttribute, UsernameConfiguration,
        VerificationMessageTemplate,
    },
    validation::{
        validate_code_delivery_message, validate_pool_name, validate_subject,
        validate_user_pool_policies, validate_verification_message_template,
    },
};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Request {
    pool_name: String,
    #[serde(default)]
    account_recovery_setting: Option<Value>,
    #[serde(default)]
    admin_create_user_config: Option<Value>,
    #[serde(default)]
    alias_attributes: Option<Vec<AliasAttribute>>,
    #[serde(default)]
    auto_verified_attributes: Option<Vec<AutoVerifiedAttribute>>,
    #[serde(default)]
    deletion_protection: Option<DeletionProtection>,
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
    mfa_configuration: Option<MfaConfiguration>,
    #[serde(default)]
    policies: Option<UserPoolPolicies>,
    #[serde(default, rename = "Schema")]
    schema_attributes: Option<Vec<Value>>,
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
    user_pool_tier: Option<UserPoolTier>,
    #[serde(default)]
    username_attributes: Option<Vec<UsernameAttribute>>,
    #[serde(default)]
    username_configuration: Option<UsernameConfiguration>,
    #[serde(default)]
    verification_message_template: Option<VerificationMessageTemplate>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct UserPoolConfigInput {
    #[serde(default)]
    pub(crate) account_recovery_setting: Option<Value>,
    #[serde(default)]
    pub(crate) admin_create_user_config: Option<Value>,
    #[serde(default)]
    pub(crate) alias_attributes: Option<Vec<AliasAttribute>>,
    #[serde(default)]
    pub(crate) auto_verified_attributes: Option<Vec<AutoVerifiedAttribute>>,
    #[serde(default)]
    pub(crate) deletion_protection: Option<DeletionProtection>,
    #[serde(default)]
    pub(crate) device_configuration: Option<Value>,
    #[serde(default)]
    pub(crate) email_configuration: Option<Value>,
    #[serde(default)]
    pub(crate) email_verification_message: Option<String>,
    #[serde(default)]
    pub(crate) email_verification_subject: Option<String>,
    #[serde(default)]
    pub(crate) lambda_config: Option<Value>,
    #[serde(default)]
    pub(crate) mfa_configuration: Option<MfaConfiguration>,
    #[serde(default)]
    pub(crate) policies: Option<UserPoolPolicies>,
    #[serde(default, rename = "Schema")]
    pub(crate) schema_attributes: Option<Vec<Value>>,
    #[serde(default)]
    pub(crate) sms_authentication_message: Option<String>,
    #[serde(default)]
    pub(crate) sms_configuration: Option<Value>,
    #[serde(default)]
    pub(crate) sms_verification_message: Option<String>,
    #[serde(default)]
    pub(crate) user_attribute_update_settings: Option<Value>,
    #[serde(default)]
    pub(crate) user_pool_add_ons: Option<Value>,
    #[serde(default)]
    pub(crate) user_pool_tags: Option<HashMap<String, String>>,
    #[serde(default)]
    pub(crate) user_pool_tier: Option<UserPoolTier>,
    #[serde(default)]
    pub(crate) username_attributes: Option<Vec<UsernameAttribute>>,
    #[serde(default)]
    pub(crate) username_configuration: Option<UsernameConfiguration>,
    #[serde(default)]
    pub(crate) verification_message_template: Option<VerificationMessageTemplate>,
}

pub(crate) fn validate_user_pool_configuration(config: &UserPoolConfigInput) -> Result<()> {
    if let Some(policies) = &config.policies {
        validate_user_pool_policies(policies)?;
    }

    if let Some(message) = &config.sms_authentication_message {
        validate_code_delivery_message("SmsAuthenticationMessage", message, 140)?;
    }

    if let Some(message) = &config.sms_verification_message {
        validate_code_delivery_message("SmsVerificationMessage", message, 140)?;
    }

    if let Some(message) = &config.email_verification_message {
        validate_code_delivery_message("EmailVerificationMessage", message, 20_000)?;
    }

    if let Some(subject) = &config.email_verification_subject {
        validate_subject("EmailVerificationSubject", subject)?;
    }

    if let Some(template) = &config.verification_message_template {
        validate_verification_message_template(template)?;
    }

    Ok(())
}

impl Request {
    fn into_config(self) -> UserPoolConfigInput {
        UserPoolConfigInput {
            account_recovery_setting: self.account_recovery_setting,
            admin_create_user_config: self.admin_create_user_config,
            alias_attributes: self.alias_attributes,
            auto_verified_attributes: self.auto_verified_attributes,
            deletion_protection: self.deletion_protection,
            device_configuration: self.device_configuration,
            email_configuration: self.email_configuration,
            email_verification_message: self.email_verification_message,
            email_verification_subject: self.email_verification_subject,
            lambda_config: self.lambda_config,
            mfa_configuration: self.mfa_configuration,
            policies: self.policies,
            schema_attributes: self.schema_attributes,
            sms_authentication_message: self.sms_authentication_message,
            sms_configuration: self.sms_configuration,
            sms_verification_message: self.sms_verification_message,
            user_attribute_update_settings: self.user_attribute_update_settings,
            user_pool_add_ons: self.user_pool_add_ons,
            user_pool_tags: self.user_pool_tags,
            user_pool_tier: self.user_pool_tier,
            username_attributes: self.username_attributes,
            username_configuration: self.username_configuration,
            verification_message_template: self.verification_message_template,
        }
    }
}

pub(crate) fn build_user_pool_view(pool: &UserPool, estimated_number_of_users: usize) -> Value {
    let mut view = Map::new();
    view.insert("Id".to_string(), json!(pool.id));
    view.insert("Name".to_string(), json!(pool.name));
    view.insert(
        "CreationDate".to_string(),
        json!(pool.creation_date.timestamp()),
    );
    view.insert(
        "LastModifiedDate".to_string(),
        json!(pool.last_modified_date.timestamp()),
    );
    view.insert(
        "EstimatedNumberOfUsers".to_string(),
        json!(estimated_number_of_users),
    );
    view.insert("Status".to_string(), json!("Enabled"));

    if let Some(value) = &pool.account_recovery_setting {
        view.insert("AccountRecoverySetting".to_string(), value.clone());
    }
    if let Some(value) = &pool.admin_create_user_config {
        view.insert("AdminCreateUserConfig".to_string(), value.clone());
    }
    if let Some(value) = &pool.alias_attributes {
        view.insert("AliasAttributes".to_string(), json!(value));
    }
    if let Some(value) = &pool.auto_verified_attributes {
        view.insert("AutoVerifiedAttributes".to_string(), json!(value));
    }
    if let Some(value) = &pool.deletion_protection {
        view.insert("DeletionProtection".to_string(), json!(value));
    }
    if let Some(value) = &pool.device_configuration {
        view.insert("DeviceConfiguration".to_string(), value.clone());
    }
    if let Some(value) = &pool.email_configuration {
        view.insert("EmailConfiguration".to_string(), value.clone());
    }
    if let Some(value) = &pool.email_verification_message {
        view.insert("EmailVerificationMessage".to_string(), json!(value));
    }
    if let Some(value) = &pool.email_verification_subject {
        view.insert("EmailVerificationSubject".to_string(), json!(value));
    }
    if let Some(value) = &pool.lambda_config {
        view.insert("LambdaConfig".to_string(), value.clone());
    }
    if let Some(value) = &pool.mfa_configuration {
        view.insert("MfaConfiguration".to_string(), json!(value));
    }
    if let Some(value) = &pool.policies {
        view.insert("Policies".to_string(), json!(value));
    }
    if let Some(value) = &pool.schema_attributes {
        view.insert("SchemaAttributes".to_string(), json!(value));
    }
    if let Some(value) = &pool.sms_authentication_message {
        view.insert("SmsAuthenticationMessage".to_string(), json!(value));
    }
    if let Some(value) = &pool.sms_configuration {
        view.insert("SmsConfiguration".to_string(), value.clone());
    }
    if let Some(value) = &pool.sms_verification_message {
        view.insert("SmsVerificationMessage".to_string(), json!(value));
    }
    if let Some(value) = &pool.user_attribute_update_settings {
        view.insert("UserAttributeUpdateSettings".to_string(), value.clone());
    }
    if let Some(value) = &pool.user_pool_add_ons {
        view.insert("UserPoolAddOns".to_string(), value.clone());
    }
    if let Some(value) = &pool.user_pool_tags {
        view.insert("UserPoolTags".to_string(), json!(value));
    }
    if let Some(value) = &pool.user_pool_tier {
        view.insert("UserPoolTier".to_string(), json!(value));
    }
    if let Some(value) = &pool.username_attributes {
        view.insert("UsernameAttributes".to_string(), json!(value));
    }
    if let Some(value) = &pool.username_configuration {
        view.insert("UsernameConfiguration".to_string(), json!(value));
    }
    if let Some(value) = &pool.verification_message_template {
        view.insert("VerificationMessageTemplate".to_string(), json!(value));
    }

    Value::Object(view)
}

pub async fn handler(storage: &Storage, body: Value) -> Result<Value> {
    let req: Request = parse_request(body)?;
    let pool_name = req.pool_name.clone();
    let config = req.into_config();

    validate_pool_name(&pool_name)?;
    validate_user_pool_configuration(&config)?;

    let now = Utc::now();
    let pool = UserPool {
        id: UserPoolId::new_local(),
        name: pool_name,
        creation_date: now,
        last_modified_date: now,
        account_recovery_setting: config.account_recovery_setting,
        admin_create_user_config: config.admin_create_user_config,
        alias_attributes: config.alias_attributes,
        auto_verified_attributes: config.auto_verified_attributes,
        deletion_protection: config.deletion_protection,
        device_configuration: config.device_configuration,
        email_configuration: config.email_configuration,
        email_verification_message: config.email_verification_message,
        email_verification_subject: config.email_verification_subject,
        lambda_config: config.lambda_config,
        mfa_configuration: config.mfa_configuration,
        sms_mfa_configuration: None,
        software_token_mfa_configuration: None,
        email_mfa_configuration: None,
        webauthn_configuration: None,
        policies: config.policies,
        schema_attributes: config.schema_attributes,
        sms_authentication_message: config.sms_authentication_message,
        sms_configuration: config.sms_configuration,
        sms_verification_message: config.sms_verification_message,
        user_attribute_update_settings: config.user_attribute_update_settings,
        user_pool_add_ons: config.user_pool_add_ons,
        user_pool_tags: config.user_pool_tags,
        user_pool_tier: config.user_pool_tier,
        username_attributes: config.username_attributes,
        username_configuration: config.username_configuration,
        verification_message_template: config.verification_message_template,
    };

    let created = storage.create_user_pool(pool).await;

    Ok(json!({
        "UserPool": build_user_pool_view(&created, 0)
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[tokio::test]
    async fn test_create_user_pool_success() {
        let storage = Storage::new();

        let result = handler(&storage, json!({"PoolName": "test-pool"})).await;

        assert!(result.is_ok());
        let body = result.unwrap();
        assert!(body["UserPool"]["Id"].as_str().is_some());
        assert_eq!(body["UserPool"]["Name"], "test-pool");
    }

    #[tokio::test]
    async fn test_create_user_pool_empty_name() {
        let storage = Storage::new();

        let result = handler(&storage, json!({"PoolName": ""})).await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_create_user_pool_missing_name() {
        let storage = Storage::new();

        let result = handler(&storage, json!({})).await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_create_user_pool_persists_configuration_fields() {
        let storage = Storage::new();

        let result = handler(
            &storage,
            json!({
                "PoolName": "configured-pool",
                "AliasAttributes": ["email"],
                "AutoVerifiedAttributes": ["email"],
                "UsernameConfiguration": {
                    "CaseSensitive": false
                },
                "Policies": {
                    "PasswordPolicy": {
                        "MinimumLength": 12
                    }
                },
                "Schema": [
                    {
                        "Name": "department",
                        "AttributeDataType": "String"
                    }
                ],
                "UserPoolTags": {
                    "env": "test"
                }
            }),
        )
        .await
        .unwrap();

        assert_eq!(result["UserPool"]["AliasAttributes"], json!(["email"]));
        assert_eq!(
            result["UserPool"]["AutoVerifiedAttributes"],
            json!(["email"])
        );
        assert_eq!(
            result["UserPool"]["UsernameConfiguration"]["CaseSensitive"],
            false
        );
        assert_eq!(
            result["UserPool"]["Policies"]["PasswordPolicy"]["MinimumLength"],
            12
        );
        assert_eq!(
            result["UserPool"]["SchemaAttributes"][0]["Name"],
            "department"
        );
        assert_eq!(result["UserPool"]["UserPoolTags"]["env"], "test");
    }
}
