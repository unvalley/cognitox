//! ListDevices API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_ListDevices.html>

use serde::Deserialize;
use serde_json::{Value, json};

use crate::{
    error::{AppError, Result},
    storage::Storage,
};

use super::helpers::{build_device_response, verify_and_extract_active_user_id};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Request {
    access_token: String,
    limit: Option<u32>,
    pagination_token: Option<String>,
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

    let mut devices = storage.list_devices_for_user(&user_id).await;
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

    Ok(json!({
        "Devices": payload,
        "PaginationToken": if end < devices.len() {
            Value::String(end.to_string())
        } else {
            Value::Null
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::user::{confirm_device, initiate_auth, sign_up};
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
    async fn test_list_devices_success() {
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
                "AccessToken": access_token.clone()
            }),
        )
        .await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap()["Devices"].as_array().unwrap().len(), 1);
    }
}
