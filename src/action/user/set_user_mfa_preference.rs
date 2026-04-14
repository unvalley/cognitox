//! SetUserMFAPreference API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_SetUserMFAPreference.html>

use serde::Deserialize;
use serde_json::{Value, json};

use crate::{
    action::io::parse_request,
    error::{AppError, Result},
    storage::Storage,
    types::{User, UserMfaPreferenceSettings, UserPoolTier},
};

use super::helpers::{
    EMAIL_OTP_FACTOR, SMS_MFA_FACTOR, SOFTWARE_TOKEN_MFA_FACTOR, remove_user_attribute,
    upsert_user_attribute, verify_and_extract_user_id,
};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Request {
    access_token: String,
    #[serde(rename = "SMSMfaSettings", default)]
    sms_mfa_settings: Option<UserMfaPreferenceSettings>,
    #[serde(default)]
    software_token_mfa_settings: Option<UserMfaPreferenceSettings>,
    #[serde(default)]
    email_mfa_settings: Option<UserMfaPreferenceSettings>,
}

pub(crate) async fn apply_user_mfa_preferences(
    storage: &Storage,
    user: &mut User,
    sms_mfa_settings: Option<&UserMfaPreferenceSettings>,
    software_token_mfa_settings: Option<&UserMfaPreferenceSettings>,
    email_mfa_settings: Option<&UserMfaPreferenceSettings>,
) -> Result<()> {
    let pool = storage
        .get_user_pool(&user.user_pool_id)
        .await
        .ok_or(AppError::UserPoolNotFound)?;

    let mut preferred_factor: Option<&str> = None;
    for (settings, factor) in [
        (sms_mfa_settings, SMS_MFA_FACTOR),
        (software_token_mfa_settings, SOFTWARE_TOKEN_MFA_FACTOR),
        (email_mfa_settings, EMAIL_OTP_FACTOR),
    ] {
        if settings.and_then(|value| value.preferred_mfa) == Some(true) {
            if preferred_factor.is_some() {
                return Err(AppError::InvalidParameter(
                    "Only one MFA setting can be preferred".to_string(),
                ));
            }
            preferred_factor = Some(factor);
        }
    }

    if sms_mfa_settings.and_then(|value| value.enabled) == Some(true) && user.phone_number.is_none()
    {
        return Err(AppError::InvalidParameter(
            "SMS MFA requires a phone_number attribute".to_string(),
        ));
    }

    if email_mfa_settings.and_then(|value| value.enabled) == Some(true) && user.email.is_none() {
        return Err(AppError::InvalidParameter(
            "Email MFA requires an email attribute".to_string(),
        ));
    }

    if email_mfa_settings.is_some()
        && matches!(pool.user_pool_tier, None | Some(UserPoolTier::Lite))
    {
        return Err(AppError::InvalidParameter(
            "Email MFA requires UserPoolTier ESSENTIALS or PLUS".to_string(),
        ));
    }

    for (settings, factor) in [
        (sms_mfa_settings, SMS_MFA_FACTOR),
        (software_token_mfa_settings, SOFTWARE_TOKEN_MFA_FACTOR),
        (email_mfa_settings, EMAIL_OTP_FACTOR),
    ] {
        match settings.and_then(|value| value.enabled) {
            Some(true) => storage.add_user_auth_factor(&user.id, factor).await,
            Some(false) => storage.remove_user_auth_factor(&user.id, factor).await,
            None => {}
        }
    }

    if let Some(factor) = preferred_factor {
        storage.add_user_auth_factor(&user.id, factor).await;
        upsert_user_attribute(
            &mut user.attributes,
            "preferred_mfa_setting",
            Some(factor.to_string()),
        );
    } else if sms_mfa_settings.and_then(|value| value.preferred_mfa) == Some(false)
        || software_token_mfa_settings.and_then(|value| value.preferred_mfa) == Some(false)
        || email_mfa_settings.and_then(|value| value.preferred_mfa) == Some(false)
    {
        remove_user_attribute(&mut user.attributes, "preferred_mfa_setting");
    }

    Ok(())
}

pub async fn handler(storage: &Storage, body: Value) -> Result<Value> {
    let req: Request = parse_request(body)?;

    let user_id =
        verify_and_extract_user_id(&req.access_token).map_err(|_| AppError::InvalidAccessToken)?;

    let mut user = storage
        .get_user(&user_id)
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
    use crate::action::user::{get_user_auth_factors, initiate_auth, sign_up};
    use crate::action::user_pool::{create_user_pool, create_user_pool_client, update_user_pool};
    use serde_json::json;

    async fn setup_and_get_token(storage: &Storage) -> String {
        let pool = create_user_pool::handler(
            storage,
            json!({
                "PoolName": "test",
                "UserPoolTier": "ESSENTIALS"
            }),
        )
        .await
        .unwrap();
        let pool_id = pool["UserPool"]["Id"].as_str().unwrap();

        let client = create_user_pool_client::handler(
            storage,
            json!({
                "UserPoolId": pool_id,
                "ClientName": "test-client"
            }),
        )
        .await
        .unwrap();
        let client_id = client["UserPoolClient"]["ClientId"].as_str().unwrap();

        let sign_up_result = sign_up::handler(
            storage,
            json!({
                "ClientId": client_id,
                "Username": "testuser",
                "Password": "Password123!",
                "UserAttributes": [
                    {"Name": "email", "Value": "test@example.com"},
                    {"Name": "phone_number", "Value": "+15555550100"}
                ]
            }),
        )
        .await
        .unwrap();

        let user_sub = sign_up_result["UserSub"].as_str().unwrap();
        let user_id = uuid::Uuid::parse_str(user_sub).unwrap();
        storage.confirm_user(&user_id).await;

        let auth_result = initiate_auth::handler(
            storage,
            json!({
                "ClientId": client_id,
                "AuthFlow": "USER_PASSWORD_AUTH",
                "AuthParameters": {
                    "USERNAME": "testuser",
                    "PASSWORD": "Password123!"
                }
            }),
        )
        .await
        .unwrap();

        auth_result["AuthenticationResult"]["AccessToken"]
            .as_str()
            .unwrap()
            .to_string()
    }

    #[tokio::test]
    async fn test_set_user_mfa_preference_success() {
        let storage = Storage::new();
        let access_token = setup_and_get_token(&storage).await;

        let result = handler(
            &storage,
            json!({
                "AccessToken": access_token.clone(),
                "SMSMfaSettings": {
                    "Enabled": true,
                    "PreferredMfa": false
                },
                "SoftwareTokenMfaSettings": {
                    "Enabled": true,
                    "PreferredMfa": true
                }
            }),
        )
        .await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), json!({}));

        let factors =
            get_user_auth_factors::handler(&storage, json!({ "AccessToken": access_token }))
                .await
                .unwrap();
        assert_eq!(factors["PreferredMfaSetting"], "SOFTWARE_TOKEN_MFA");
        assert_eq!(
            factors["UserMFASettingList"],
            json!(["SMS_MFA", "SOFTWARE_TOKEN_MFA"])
        );
    }

    #[tokio::test]
    async fn test_set_user_mfa_preference_invalid_token() {
        let storage = Storage::new();

        let result = handler(
            &storage,
            json!({
                "AccessToken": "invalid-token",
                "SoftwareTokenMfaSettings": {
                    "Enabled": true,
                    "PreferredMfa": true
                }
            }),
        )
        .await;

        assert!(matches!(result, Err(AppError::InvalidAccessToken)));
    }

    #[tokio::test]
    async fn test_set_user_mfa_preference_email_requires_non_lite_pool() {
        let storage = Storage::new();
        let access_token = setup_and_get_token(&storage).await;

        let user_id = verify_and_extract_user_id(&access_token).unwrap();
        let user = storage.get_user(&user_id).await.unwrap();
        update_user_pool::handler(
            &storage,
            json!({
                "UserPoolId": user.user_pool_id,
                "UserPoolTier": "LITE"
            }),
        )
        .await
        .unwrap();

        let result = handler(
            &storage,
            json!({
                "AccessToken": access_token,
                "EmailMfaSettings": {
                    "Enabled": true
                }
            }),
        )
        .await;

        assert!(matches!(result, Err(AppError::InvalidParameter(_))));
    }
}
