//! UpdateDeviceStatus API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_UpdateDeviceStatus.html>

use chrono::Utc;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::{
    error::{AppError, Result},
    storage::Storage,
};

use super::helpers::verify_and_extract_active_user_id;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Request {
    access_token: String,
    device_key: String,
    device_remembered_status: Option<String>,
}

pub async fn handler(storage: &Storage, body: Value) -> Result<Value> {
    let req: Request = serde_json::from_value(body)
        .map_err(|e| AppError::InvalidParameter(format!("Invalid request: {}", e)))?;

    let user_id = verify_and_extract_active_user_id(storage, &req.access_token)
        .await
        .map_err(|_| AppError::InvalidAccessToken)?;

    storage
        .get_user(&user_id)
        .await
        .ok_or(AppError::UserNotFound)?;

    let status = req
        .device_remembered_status
        .ok_or_else(|| {
            AppError::InvalidParameter("DeviceRememberedStatus is required".to_string())
        })?
        .to_lowercase();
    if status != "remembered" && status != "not_remembered" {
        return Err(AppError::InvalidParameter(
            "DeviceRememberedStatus must be remembered or not_remembered".to_string(),
        ));
    }

    let mut device = storage
        .get_device_for_user(&user_id, &req.device_key)
        .await
        .ok_or(AppError::DeviceNotFound)?;
    device.device_remembered_status = Some(status);
    device.device_last_modified_date = Utc::now();

    storage
        .update_device_for_user(device)
        .await
        .ok_or(AppError::DeviceNotFound)?;

    Ok(json!({}))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::user::{confirm_device, get_device, initiate_auth, sign_up};
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
                "Password": "Password123!"
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
    async fn test_update_device_status_success() {
        let storage = Storage::new();
        let access_token = setup_and_get_token(&storage).await;

        confirm_device::handler(
            &storage,
            json!({
                "AccessToken": access_token.clone(),
                "DeviceKey": "device-key"
            }),
        )
        .await
        .unwrap();

        let result = handler(
            &storage,
            json!({
                "AccessToken": access_token.clone(),
                "DeviceKey": "device-key",
                "DeviceRememberedStatus": "remembered"
            }),
        )
        .await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), json!({}));

        let fetched = get_device::handler(
            &storage,
            json!({
                "AccessToken": access_token,
                "DeviceKey": "device-key"
            }),
        )
        .await
        .unwrap();
        assert_eq!(fetched["Device"]["DeviceRememberedStatus"], "remembered");
    }
}
