//! DeleteUserAttributes API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_DeleteUserAttributes.html>

use chrono::Utc;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::{
    error::{AppError, Result},
    storage::Storage,
};

use super::helpers::{
    EMAIL_OTP_FACTOR, SMS_MFA_FACTOR, apply_user_attribute_deletions,
    verify_and_extract_active_user_id,
};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Request {
    access_token: String,
    user_attribute_names: Vec<String>,
}

pub async fn handler(storage: &Storage, body: Value) -> Result<Value> {
    let req: Request = serde_json::from_value(body)
        .map_err(|e| AppError::InvalidParameter(format!("Invalid request: {}", e)))?;

    let user_id = verify_and_extract_active_user_id(storage, &req.access_token)
        .await
        .map_err(|_| AppError::InvalidAccessToken)?;

    let mut user = storage
        .get_user(&user_id)
        .await
        .ok_or(AppError::UserNotFound)?;
    let deletion = apply_user_attribute_deletions(&mut user, &req.user_attribute_names);

    if deletion.email_deleted {
        storage
            .remove_user_auth_factor(&user.id, EMAIL_OTP_FACTOR)
            .await;
    }

    if deletion.phone_deleted {
        storage
            .remove_user_auth_factor(&user.id, SMS_MFA_FACTOR)
            .await;
    }

    user.last_modified_date = Utc::now();

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
                    {"Name": "email", "Value": "test@example.com"},
                    {"Name": "custom:role", "Value": "admin"}
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
    async fn test_delete_user_attributes_success() {
        let storage = Storage::new();
        let access_token = setup_and_get_token(&storage).await;

        let result = handler(
            &storage,
            json!({
                "AccessToken": access_token,
                "UserAttributeNames": ["custom:role"]
            }),
        )
        .await;

        assert!(result.is_ok());

        // Verify the attribute was deleted
        let user = get_user::handler(
            &storage,
            json!({
                "AccessToken": access_token
            }),
        )
        .await
        .unwrap();

        let attrs = user["UserAttributes"].as_array().unwrap();
        assert!(attrs.iter().all(|a| a["Name"] != "custom:role"));
        // Email should still exist
        assert!(attrs.iter().any(|a| a["Name"] == "email"));
    }

    #[tokio::test]
    async fn test_delete_user_attributes_invalid_token() {
        let storage = Storage::new();

        let result = handler(
            &storage,
            json!({
                "AccessToken": "invalid-token",
                "UserAttributeNames": ["email"]
            }),
        )
        .await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AppError::InvalidAccessToken));
    }

    #[tokio::test]
    async fn test_delete_user_attributes_removes_canonical_email_from_response() {
        let storage = Storage::new();
        let access_token = setup_and_get_token(&storage).await;

        handler(
            &storage,
            json!({
                "AccessToken": access_token.clone(),
                "UserAttributeNames": ["email"]
            }),
        )
        .await
        .unwrap();

        let user = get_user::handler(
            &storage,
            json!({
                "AccessToken": access_token
            }),
        )
        .await
        .unwrap();

        let attrs = user["UserAttributes"].as_array().unwrap();
        assert!(attrs.iter().all(|a| a["Name"] != "email"));
        assert!(attrs.iter().all(|a| a["Name"] != "email_verified"));
    }
}
