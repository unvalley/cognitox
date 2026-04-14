//! SetUserSettings API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_SetUserSettings.html>

use serde::Deserialize;
use serde_json::{Value, json};

use crate::{
    action::io::parse_request,
    error::{AppError, Result},
    storage::Storage,
    types::UserMfaPreferenceSettings,
};

use super::{
    helpers::verify_and_extract_user_id, set_user_mfa_preference::apply_user_mfa_preferences,
};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct MFAOption {
    #[allow(dead_code)]
    delivery_medium: Option<String>,
    #[allow(dead_code)]
    attribute_name: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Request {
    access_token: String,
    #[serde(rename = "MFAOptions")]
    mfa_options: Vec<MFAOption>,
}

fn has_sms_mfa_option(mfa_options: &[MFAOption]) -> Result<bool> {
    if mfa_options.is_empty() {
        return Ok(false);
    }

    let is_sms_phone_option = |option: &MFAOption| {
        option.delivery_medium.as_deref() == Some("SMS")
            && option.attribute_name.as_deref() == Some("phone_number")
    };

    if mfa_options.iter().all(is_sms_phone_option) {
        Ok(true)
    } else {
        Err(AppError::InvalidParameter(
            "MFAOptions only supports SMS delivery to phone_number".to_string(),
        ))
    }
}

pub async fn handler(storage: &Storage, body: Value) -> Result<Value> {
    let req: Request = parse_request(body)?;

    let user_id =
        verify_and_extract_user_id(&req.access_token).map_err(|_| AppError::InvalidAccessToken)?;

    let mut user = storage
        .get_user(&user_id)
        .await
        .ok_or(AppError::UserNotFound)?;

    let sms_enabled = has_sms_mfa_option(&req.mfa_options)?;
    let sms_settings = UserMfaPreferenceSettings {
        enabled: Some(sms_enabled),
        preferred_mfa: None,
    };

    apply_user_mfa_preferences(storage, &mut user, Some(&sms_settings), None, None).await?;
    storage.update_user(user).await;

    Ok(json!({}))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::user::{get_user, initiate_auth, sign_up};
    use crate::action::user_pool::{create_user_pool, create_user_pool_client};
    use serde_json::json;

    async fn setup_and_get_token(storage: &Storage) -> String {
        let pool = create_user_pool::handler(storage, json!({"PoolName": "test"}))
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
    async fn test_set_user_settings_success() {
        let storage = Storage::new();
        let access_token = setup_and_get_token(&storage).await;

        let result = handler(
            &storage,
            json!({
                "AccessToken": access_token,
                "MFAOptions": [
                    {
                        "DeliveryMedium": "SMS",
                        "AttributeName": "phone_number"
                    }
                ]
            }),
        )
        .await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), json!({}));

        let user = get_user::handler(
            &storage,
            json!({
                "AccessToken": access_token
            }),
        )
        .await
        .unwrap();
        assert_eq!(user["UserMFASettingList"], json!(["SMS_MFA"]));
    }

    #[tokio::test]
    async fn test_set_user_settings_invalid_token() {
        let storage = Storage::new();

        let result = handler(
            &storage,
            json!({
                "AccessToken": "invalid-token",
                "MFAOptions": []
            }),
        )
        .await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AppError::InvalidAccessToken));
    }
}
