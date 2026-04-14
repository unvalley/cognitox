//! AdminGetUser API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AdminGetUser.html>

use serde::Deserialize;
use serde_json::{Value, json};

use crate::action::user::helpers::{
    build_mfa_options, build_user_attributes, preferred_mfa_setting,
};
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
    let user_mfa_setting_list = storage.list_user_auth_factors(&user.id).await;
    let preferred_mfa_setting = preferred_mfa_setting(&user, &user_mfa_setting_list);

    Ok(json!({
        "Username": user.username,
        "Enabled": user.enabled,
        "UserStatus": user.user_status,
        "UserCreateDate": user.creation_date.timestamp(),
        "UserLastModifiedDate": user.last_modified_date.timestamp(),
        "UserAttributes": build_user_attributes(&user),
        "MFAOptions": build_mfa_options(&user),
        "PreferredMfaSetting": preferred_mfa_setting,
        "UserMFASettingList": user_mfa_setting_list
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::user::admin_create_user;
    use crate::action::user_pool::create_user_pool;
    use serde_json::json;

    #[tokio::test]
    async fn test_admin_get_user_success() {
        let storage = Storage::new();

        let pool = create_user_pool::handler(&storage, json!({"PoolName": "test"}))
            .await
            .unwrap();
        let pool_id = pool["UserPool"]["Id"].as_str().unwrap();

        // Create a user first
        admin_create_user::handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "Username": "testuser",
                "UserAttributes": [
                    {"Name": "email", "Value": "test@example.com"}
                ]
            }),
        )
        .await
        .unwrap();

        // Get the user
        let result = handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "Username": "testuser"
            }),
        )
        .await;

        assert!(result.is_ok());
        let body = result.unwrap();
        assert_eq!(body["Username"], "testuser");
        assert_eq!(body["Enabled"], true);
        assert_eq!(body["UserStatus"], "FORCE_CHANGE_PASSWORD");
        assert!(
            body["UserAttributes"]
                .as_array()
                .unwrap()
                .iter()
                .any(|attribute| {
                    attribute["Name"] == "sub" && attribute["Value"].as_str().is_some()
                })
        );
    }

    #[tokio::test]
    async fn test_admin_get_user_not_found() {
        let storage = Storage::new();

        let pool = create_user_pool::handler(&storage, json!({"PoolName": "test"}))
            .await
            .unwrap();
        let pool_id = pool["UserPool"]["Id"].as_str().unwrap();

        let result = handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "Username": "nonexistent"
            }),
        )
        .await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AppError::UserNotFound));
    }

    #[tokio::test]
    async fn test_admin_get_user_invalid_request() {
        let storage = Storage::new();

        let result = handler(&storage, json!({})).await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_admin_get_user_pool_not_found() {
        let storage = Storage::new();

        let result = handler(
            &storage,
            json!({
                "UserPoolId": "us-east-1_Missing",
                "Username": "testuser"
            }),
        )
        .await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AppError::UserPoolNotFound));
    }
}
