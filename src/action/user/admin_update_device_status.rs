//! AdminUpdateDeviceStatus API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AdminUpdateDeviceStatus.html>

use chrono::Utc;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::{
    error::{AppError, Result},
    storage::Storage,
    types::UserPoolId,
};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Request {
    user_pool_id: UserPoolId,
    username: String,
    device_key: String,
    device_remembered_status: Option<String>,
}

pub async fn handler(storage: &Storage, body: Value) -> Result<Value> {
    let req: Request = serde_json::from_value(body)
        .map_err(|e| AppError::InvalidParameter(format!("Invalid request: {}", e)))?;

    storage
        .get_user_pool(&req.user_pool_id)
        .await
        .ok_or(AppError::UserPoolNotFound)?;

    let user = storage
        .get_user_by_username(&req.user_pool_id, &req.username)
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
        .get_device_for_user(&user.id, &req.device_key)
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
    use crate::action::user::{admin_create_user, admin_get_device};
    use crate::action::user_pool::create_user_pool;
    use crate::types::Device;
    use chrono::Utc;
    use serde_json::json;

    #[tokio::test]
    async fn test_admin_update_device_status_success() {
        let storage = Storage::new();

        let pool = create_user_pool::handler(&storage, json!({"PoolName": "test"}))
            .await
            .unwrap();
        let pool_id = pool["UserPool"]["Id"].as_str().unwrap();

        admin_create_user::handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "Username": "testuser"
            }),
        )
        .await
        .unwrap();

        let user_pool_id: crate::types::UserPoolId = pool_id.parse().unwrap();
        let user = storage
            .get_user_by_username(&user_pool_id, "testuser")
            .await
            .unwrap();
        let now = Utc::now();
        storage
            .put_device(Device {
                user_id: user.id,
                device_key: "device-key".to_string(),
                device_attributes: vec![],
                device_create_date: now,
                device_last_modified_date: now,
                device_last_authenticated_date: now,
                device_remembered_status: Some("not_remembered".to_string()),
            })
            .await;

        let result = handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "Username": "testuser",
                "DeviceKey": "device-key",
                "DeviceRememberedStatus": "remembered"
            }),
        )
        .await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), json!({}));

        let fetched = admin_get_device::handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "Username": "testuser",
                "DeviceKey": "device-key"
            }),
        )
        .await
        .unwrap();
        assert_eq!(fetched["Device"]["DeviceRememberedStatus"], "remembered");
    }
}
