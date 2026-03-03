//! CreateUserPool API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_CreateUserPool.html>

use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    action::io::{parse_request, to_response_value},
    error::Result,
    storage::Storage,
    types::{UserPool, UserPoolId},
    validation::validate_pool_name,
};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
#[allow(dead_code)]
struct Request {
    pool_name: String,
    account_recovery_setting: Option<Value>,
    admin_create_user_config: Option<Value>,
    alias_attributes: Option<Value>,
    auto_verified_attributes: Option<Value>,
    deletion_protection: Option<Value>,
    device_configuration: Option<Value>,
    email_configuration: Option<Value>,
    email_verification_message: Option<Value>,
    email_verification_subject: Option<Value>,
    lambda_config: Option<Value>,
    mfa_configuration: Option<Value>,
    policies: Option<Value>,
    schema: Option<Value>,
    sms_authentication_message: Option<Value>,
    sms_configuration: Option<Value>,
    sms_verification_message: Option<Value>,
    user_attribute_update_settings: Option<Value>,
    username_attributes: Option<Value>,
    username_configuration: Option<Value>,
    user_pool_add_ons: Option<Value>,
    user_pool_tags: Option<Value>,
    user_pool_tier: Option<Value>,
    verification_message_template: Option<Value>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
struct Response {
    user_pool: UserPoolView,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
struct UserPoolView {
    id: UserPoolId,
    name: String,
    creation_date: i64,
    last_modified_date: i64,
}

pub async fn handler(storage: &Storage, body: Value) -> Result<Value> {
    let req: Request = parse_request(body)?;

    // Validate input
    validate_pool_name(&req.pool_name)?;

    let now = Utc::now();
    let pool_id = UserPoolId::new_local();

    let pool = UserPool {
        id: pool_id,
        name: req.pool_name,
        creation_date: now,
        last_modified_date: now,
    };

    let created = storage.create_user_pool(pool).await;

    to_response_value(Response {
        user_pool: UserPoolView {
            id: created.id,
            name: created.name,
            creation_date: created.creation_date.timestamp(),
            last_modified_date: created.last_modified_date.timestamp(),
        },
    })
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
}
