//! AdminListDevices API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AdminListDevices.html>

use serde::Deserialize;
use serde_json::{Value, json};

use crate::{
    action::user::helpers::build_device_response,
    error::{AppError, Result},
    storage::Storage,
    types::UserPoolId,
};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Request {
    user_pool_id: UserPoolId,
    username: String,
    limit: Option<u32>,
    pagination_token: Option<String>,
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

    let mut devices = storage.list_devices_for_user(&user.id).await;
    devices.sort_by(|a, b| a.device_key.cmp(&b.device_key));

    let limit = req.limit.unwrap_or(60) as usize;
    if limit == 0 {
        return Err(AppError::InvalidParameter(
            "Limit must be greater than 0".to_string(),
        ));
    }

    let start = req
        .pagination_token
        .as_deref()
        .map(|token| {
            token
                .parse::<usize>()
                .map_err(|_| AppError::InvalidParameter("Invalid PaginationToken".to_string()))
        })
        .transpose()?
        .unwrap_or(0);

    if start > devices.len() {
        return Err(AppError::InvalidParameter(
            "Invalid PaginationToken".to_string(),
        ));
    }

    let end = (start + limit).min(devices.len());
    let payload: Vec<Value> = devices[start..end]
        .iter()
        .map(build_device_response)
        .collect();

    let mut response = json!({ "Devices": payload });
    if end < devices.len() {
        response["PaginationToken"] = json!(end.to_string());
    }

    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::user::admin_create_user;
    use crate::action::user_pool::create_user_pool;
    use crate::types::Device;
    use chrono::Utc;
    use serde_json::json;

    #[tokio::test]
    async fn test_admin_list_devices_success() {
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
                device_remembered_status: Some("remembered".to_string()),
            })
            .await;

        let result = handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "Username": "testuser"
            }),
        )
        .await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap()["Devices"].as_array().unwrap().len(), 1);
    }
}
