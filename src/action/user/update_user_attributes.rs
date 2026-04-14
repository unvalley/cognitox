//! UpdateUserAttributes API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_UpdateUserAttributes.html>

use chrono::Utc;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::{
    error::{AppError, Result},
    storage::Storage,
    types::UserAttribute,
};

use super::helpers::verify_and_extract_user_id;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Request {
    access_token: String,
    user_attributes: Vec<UserAttribute>,
    #[serde(default)]
    client_metadata: Option<std::collections::HashMap<String, String>>,
}

pub async fn handler(storage: &Storage, body: Value) -> Result<Value> {
    let req: Request = serde_json::from_value(body)
        .map_err(|e| AppError::InvalidParameter(format!("Invalid request: {}", e)))?;
    let _ = &req.client_metadata;

    let user_id =
        verify_and_extract_user_id(&req.access_token).map_err(|_| AppError::InvalidAccessToken)?;

    let mut user = storage
        .get_user(&user_id)
        .await
        .ok_or(AppError::UserNotFound)?;

    // Update or add attributes
    for new_attr in req.user_attributes {
        if let Some(existing) = user.attributes.iter_mut().find(|a| a.name == new_attr.name) {
            existing.value = new_attr.value;
        } else {
            user.attributes.push(new_attr);
        }
    }

    // Update special fields if they are in the attributes
    for attr in &user.attributes {
        match attr.name.as_str() {
            "email" => user.email = attr.value.clone(),
            "phone_number" => user.phone_number = attr.value.clone(),
            _ => {}
        }
    }

    user.last_modified_date = Utc::now();

    storage.update_user(user).await;

    Ok(json!({
        "CodeDeliveryDetailsList": []
    }))
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
                    {"Name": "email", "Value": "old@example.com"}
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
    async fn test_update_user_attributes_success() {
        let storage = Storage::new();
        let access_token = setup_and_get_token(&storage).await;

        let result = handler(
            &storage,
            json!({
                "AccessToken": access_token,
                "UserAttributes": [
                    {"Name": "email", "Value": "new@example.com"},
                    {"Name": "custom:role", "Value": "admin"}
                ]
            }),
        )
        .await;

        assert!(result.is_ok());

        // Verify the update
        let user = get_user::handler(
            &storage,
            json!({
                "AccessToken": access_token
            }),
        )
        .await
        .unwrap();

        let attrs = user["UserAttributes"].as_array().unwrap();
        let email_attr = attrs.iter().find(|a| a["Name"] == "email").unwrap();
        assert_eq!(email_attr["Value"], "new@example.com");
    }

    #[tokio::test]
    async fn test_update_user_attributes_invalid_token() {
        let storage = Storage::new();

        let result = handler(
            &storage,
            json!({
                "AccessToken": "invalid-token",
                "UserAttributes": [
                    {"Name": "email", "Value": "test@example.com"}
                ]
            }),
        )
        .await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AppError::InvalidAccessToken));
    }
}
