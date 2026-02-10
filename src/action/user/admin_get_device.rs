//! AdminGetDevice API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AdminGetDevice.html>

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
}

pub async fn handler(storage: &Storage, body: Value) -> Result<Value> {
    let req: Request = serde_json::from_value(body)
        .map_err(|e| AppError::InvalidParameter(format!("Invalid request: {}", e)))?;

    storage
        .get_user_pool(&req.user_pool_id)
        .await
        .ok_or(AppError::UserPoolNotFound)?;

    storage
        .get_user_by_username(&req.user_pool_id, &req.username)
        .await
        .ok_or(AppError::UserNotFound)?;

    Ok(json!({
        "Device": {
            "DeviceKey": req.device_key,
            "DeviceAttributes": [],
            "DeviceCreateDate": Utc::now(),
            "DeviceLastModifiedDate": Utc::now(),
            "DeviceLastAuthenticatedDate": Utc::now()
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::user::admin_create_user;
    use crate::action::user_pool::create_user_pool;
    use serde_json::json;

    #[tokio::test]
    async fn test_admin_get_device_success() {
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

        let result = handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "Username": "testuser",
                "DeviceKey": "device-key"
            }),
        )
        .await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap()["Device"]["DeviceKey"], "device-key");
    }
}
