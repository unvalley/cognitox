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
    types::{UserPool, UserPoolId},
    validation::validate_pool_name,
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
    alias_attributes: Option<Vec<String>>,
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
    user_pool_tier: Option<String>,
    #[serde(default)]
    username_attributes: Option<Vec<String>>,
    #[serde(default)]
    username_configuration: Option<Value>,
    #[serde(default)]
    verification_message_template: Option<Value>,
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
        view.insert("Policies".to_string(), value.clone());
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
        view.insert("UsernameConfiguration".to_string(), value.clone());
    }
    if let Some(value) = &pool.verification_message_template {
        view.insert("VerificationMessageTemplate".to_string(), value.clone());
    }

    Value::Object(view)
}

pub async fn handler(storage: &Storage, body: Value) -> Result<Value> {
    let req: Request = parse_request(body)?;

    validate_pool_name(&req.pool_name)?;

    let now = Utc::now();
    let pool = UserPool {
        id: UserPoolId::new_local(),
        name: req.pool_name,
        creation_date: now,
        last_modified_date: now,
        account_recovery_setting: req.account_recovery_setting,
        admin_create_user_config: req.admin_create_user_config,
        alias_attributes: req.alias_attributes,
        auto_verified_attributes: req.auto_verified_attributes,
        deletion_protection: req.deletion_protection,
        device_configuration: req.device_configuration,
        email_configuration: req.email_configuration,
        email_verification_message: req.email_verification_message,
        email_verification_subject: req.email_verification_subject,
        lambda_config: req.lambda_config,
        mfa_configuration: req.mfa_configuration,
        policies: req.policies,
        schema_attributes: req.schema_attributes,
        sms_authentication_message: req.sms_authentication_message,
        sms_configuration: req.sms_configuration,
        sms_verification_message: req.sms_verification_message,
        user_attribute_update_settings: req.user_attribute_update_settings,
        user_pool_add_ons: req.user_pool_add_ons,
        user_pool_tags: req.user_pool_tags,
        user_pool_tier: req.user_pool_tier,
        username_attributes: req.username_attributes,
        username_configuration: req.username_configuration,
        verification_message_template: req.verification_message_template,
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
