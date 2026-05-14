//! ConfirmDevice API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_ConfirmDevice.html>

use chrono::Utc;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::{
    error::{AppError, Result},
    storage::Storage,
    types::{Device, UserAttribute},
};

use super::helpers::verify_and_extract_active_user_id;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Request {
    access_token: String,
    device_key: String,
    #[serde(default)]
    device_name: Option<String>,
    #[serde(default)]
    device_secret_verifier_config: Option<DeviceSecretVerifierConfig>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct DeviceSecretVerifierConfig {
    password_verifier: String,
    salt: String,
}

fn upsert_device_attribute(attributes: &mut Vec<UserAttribute>, name: &str, value: Option<String>) {
    if let Some(attribute) = attributes
        .iter_mut()
        .find(|attribute| attribute.name == name)
    {
        attribute.value = value;
    } else {
        attributes.push(UserAttribute {
            name: name.to_string(),
            value,
        });
    }
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

    if req.device_key.trim().is_empty() {
        return Err(AppError::InvalidParameter(
            "DeviceKey must not be empty".to_string(),
        ));
    }

    let now = Utc::now();
    let mut device =
        if let Some(mut existing) = storage.get_device_for_user(&user_id, &req.device_key).await {
            existing.device_last_modified_date = now;
            existing.device_last_authenticated_date = now;
            existing
        } else {
            Device {
                user_id,
                device_key: req.device_key,
                device_attributes: vec![],
                device_create_date: now,
                device_last_modified_date: now,
                device_last_authenticated_date: now,
                device_remembered_status: Some("not_remembered".to_string()),
            }
        };

    if let Some(device_name) = req.device_name {
        upsert_device_attribute(
            &mut device.device_attributes,
            "device_name",
            Some(device_name),
        );
    }

    if let Some(secret_verifier_config) = req.device_secret_verifier_config {
        upsert_device_attribute(
            &mut device.device_attributes,
            "device_password_verifier",
            Some(secret_verifier_config.password_verifier),
        );
        upsert_device_attribute(
            &mut device.device_attributes,
            "device_salt",
            Some(secret_verifier_config.salt),
        );
    }

    storage.put_device(device).await;

    Ok(json!({
        "UserConfirmationNecessary": false
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::user::{initiate_auth, sign_up};
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
    async fn test_confirm_device_success() {
        let storage = Storage::new();
        let access_token = setup_and_get_token(&storage).await;

        let result = handler(
            &storage,
            json!({
                "AccessToken": access_token,
                "DeviceKey": "device-key"
            }),
        )
        .await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap()["UserConfirmationNecessary"], false);
    }

    #[tokio::test]
    async fn test_confirm_device_accepts_device_metadata() {
        let storage = Storage::new();
        let access_token = setup_and_get_token(&storage).await;

        handler(
            &storage,
            json!({
                "AccessToken": access_token.clone(),
                "DeviceKey": "device-key",
                "DeviceName": "MacBook Pro",
                "DeviceSecretVerifierConfig": {
                    "PasswordVerifier": "verifier",
                    "Salt": "salt"
                }
            }),
        )
        .await
        .unwrap();

        let user_id = verify_and_extract_active_user_id(&storage, &access_token)
            .await
            .unwrap();
        let device = storage
            .get_device_for_user(&user_id, "device-key")
            .await
            .unwrap();

        assert!(device.device_attributes.iter().any(|attribute| {
            attribute.name == "device_name" && attribute.value.as_deref() == Some("MacBook Pro")
        }));
        assert!(device.device_attributes.iter().any(|attribute| {
            attribute.name == "device_password_verifier"
                && attribute.value.as_deref() == Some("verifier")
        }));
        assert!(device.device_attributes.iter().any(|attribute| {
            attribute.name == "device_salt" && attribute.value.as_deref() == Some("salt")
        }));
    }
}
