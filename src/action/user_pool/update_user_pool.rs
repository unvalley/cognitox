//! UpdateUserPool API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_UpdateUserPool.html>

use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    action::io::{parse_request, to_response_value},
    error::{AppError, Result},
    storage::Storage,
    types::UserPoolId,
};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
#[allow(dead_code)]
struct Request {
    user_pool_id: UserPoolId,
    pool_name: Option<String>,
    account_recovery_setting: Option<Value>,
    admin_create_user_config: Option<Value>,
    auto_verified_attributes: Option<Value>,
    deletion_protection: Option<Value>,
    device_configuration: Option<Value>,
    email_configuration: Option<Value>,
    email_verification_message: Option<Value>,
    email_verification_subject: Option<Value>,
    lambda_config: Option<Value>,
    mfa_configuration: Option<Value>,
    policies: Option<Value>,
    sms_authentication_message: Option<Value>,
    sms_configuration: Option<Value>,
    sms_verification_message: Option<Value>,
    user_attribute_update_settings: Option<Value>,
    user_pool_add_ons: Option<Value>,
    user_pool_tags: Option<Value>,
    user_pool_tier: Option<Value>,
    verification_message_template: Option<Value>,
}

#[derive(Debug, Serialize)]
struct Response {}

pub async fn handler(storage: &Storage, body: Value) -> Result<Value> {
    let req: Request = parse_request(body)?;

    let mut pool = storage
        .get_user_pool(&req.user_pool_id)
        .await
        .ok_or(AppError::UserPoolNotFound)?;

    if let Some(pool_name) = req.pool_name {
        pool.name = pool_name;
    }

    pool.last_modified_date = Utc::now();

    storage.update_user_pool(pool).await;

    to_response_value(Response {})
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
                "UserPoolId": pool_id
            }),
        )
        .await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), json!({}));
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
}
