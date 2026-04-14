//! AdminSetUserMFAPreference API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AdminSetUserMFAPreference.html>

use serde::Deserialize;
use serde_json::{Value, json};

use crate::{
    action::io::parse_request,
    error::{AppError, Result},
    storage::Storage,
    types::{UserMfaPreferenceSettings, UserPoolId},
};

use super::set_user_mfa_preference::apply_user_mfa_preferences;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Request {
    user_pool_id: UserPoolId,
    username: String,
    #[serde(rename = "SMSMfaSettings", default)]
    sms_mfa_settings: Option<UserMfaPreferenceSettings>,
    #[serde(default)]
    software_token_mfa_settings: Option<UserMfaPreferenceSettings>,
    #[serde(default)]
    email_mfa_settings: Option<UserMfaPreferenceSettings>,
}

pub async fn handler(storage: &Storage, body: Value) -> Result<Value> {
    let req: Request = parse_request(body)?;

    storage
        .get_user_pool(&req.user_pool_id)
        .await
        .ok_or(AppError::UserPoolNotFound)?;

    let mut user = storage
        .get_user_by_username(&req.user_pool_id, &req.username)
        .await
        .ok_or(AppError::UserNotFound)?;

    apply_user_mfa_preferences(
        storage,
        &mut user,
        req.sms_mfa_settings.as_ref(),
        req.software_token_mfa_settings.as_ref(),
        req.email_mfa_settings.as_ref(),
    )
    .await?;

    storage.update_user(user).await;

    Ok(json!({}))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::user::{admin_create_user, admin_get_user};
    use crate::action::user_pool::create_user_pool;
    use serde_json::json;

    async fn setup_pool_and_user(storage: &Storage) -> (String, String) {
        let pool = create_user_pool::handler(
            storage,
            json!({
                "PoolName": "test",
                "UserPoolTier": "ESSENTIALS"
            }),
        )
        .await
        .unwrap();
        let pool_id = pool["UserPool"]["Id"].as_str().unwrap().to_string();

        admin_create_user::handler(
            storage,
            json!({
                "UserPoolId": pool_id,
                "Username": "testuser",
                "UserAttributes": [
                    {"Name": "email", "Value": "test@example.com"},
                    {"Name": "phone_number", "Value": "+15555550100"}
                ]
            }),
        )
        .await
        .unwrap();

        (pool_id, "testuser".to_string())
    }

    #[tokio::test]
    async fn test_admin_set_user_mfa_preference_success() {
        let storage = Storage::new();
        let (pool_id, username) = setup_pool_and_user(&storage).await;

        let result = handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "Username": username,
                "SMSMfaSettings": {
                    "Enabled": true,
                    "PreferredMfa": false
                },
                "EmailMfaSettings": {
                    "Enabled": true,
                    "PreferredMfa": true
                }
            }),
        )
        .await;

        assert!(result.is_ok());
        let user = admin_get_user::handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "Username": "testuser"
            }),
        )
        .await
        .unwrap();
        assert_eq!(user["PreferredMfaSetting"], "EMAIL_OTP");
        assert_eq!(user["UserMFASettingList"], json!(["SMS_MFA", "EMAIL_OTP"]));
    }

    #[tokio::test]
    async fn test_admin_set_user_mfa_preference_user_not_found() {
        let storage = Storage::new();

        let pool = create_user_pool::handler(&storage, json!({"PoolName": "test"}))
            .await
            .unwrap();
        let pool_id = pool["UserPool"]["Id"].as_str().unwrap();

        let result = handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "Username": "nonexistent",
                "SoftwareTokenMfaSettings": {
                    "Enabled": true,
                    "PreferredMfa": true
                }
            }),
        )
        .await;

        assert!(matches!(result, Err(AppError::UserNotFound)));
    }

    #[tokio::test]
    async fn test_admin_set_user_mfa_preference_pool_not_found() {
        let storage = Storage::new();

        let result = handler(
            &storage,
            json!({
                "UserPoolId": "local_nonexistent",
                "Username": "testuser",
                "SoftwareTokenMfaSettings": {
                    "Enabled": true
                }
            }),
        )
        .await;

        assert!(matches!(result, Err(AppError::UserPoolNotFound)));
    }
}
