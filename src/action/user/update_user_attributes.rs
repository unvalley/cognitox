//! UpdateUserAttributes API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_UpdateUserAttributes.html>

use chrono::Utc;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::{
    action::io::parse_request,
    error::{AppError, Result},
    storage::Storage,
    types::{AutoVerifiedAttribute, UserAttribute},
    validation::{validate_email, validate_phone_number},
};

use super::helpers::{
    apply_user_attribute_updates, mask_email, mask_phone_number, upsert_user_attribute,
    verify_and_extract_user_id,
};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Request {
    access_token: String,
    user_attributes: Vec<UserAttribute>,
    #[serde(default)]
    client_metadata: Option<std::collections::HashMap<String, String>>,
}

pub async fn handler(storage: &Storage, body: Value) -> Result<Value> {
    let req: Request = parse_request(body)?;
    let _ = &req.client_metadata;

    let user_id =
        verify_and_extract_user_id(&req.access_token).map_err(|_| AppError::InvalidAccessToken)?;

    let mut user = storage
        .get_user(&user_id)
        .await
        .ok_or(AppError::UserNotFound)?;

    let pool = storage
        .get_user_pool(&user.user_pool_id)
        .await
        .ok_or(AppError::UserPoolNotFound)?;

    for new_attr in &req.user_attributes {
        match new_attr.name.as_str() {
            "email" => {
                if let Some(value) = new_attr.value.as_deref() {
                    validate_email(value)?;
                }
            }
            "phone_number" => {
                if let Some(value) = new_attr.value.as_deref() {
                    validate_phone_number(value)?;
                }
            }
            _ => {}
        }
    }

    let changes = apply_user_attribute_updates(&mut user, req.user_attributes);

    if changes.email_updated && !changes.email_verified_explicit {
        upsert_user_attribute(
            &mut user.attributes,
            "email_verified",
            Some("false".to_string()),
        );
    }
    if changes.phone_updated && !changes.phone_verified_explicit {
        upsert_user_attribute(
            &mut user.attributes,
            "phone_number_verified",
            Some("false".to_string()),
        );
    }

    let mut code_delivery_details_list = Vec::new();
    if changes.email_updated
        && pool
            .auto_verified_attributes
            .as_ref()
            .is_some_and(|attrs| attrs.contains(&AutoVerifiedAttribute::Email))
        && let Some(email) = user.email.as_deref()
    {
        code_delivery_details_list.push(json!({
            "AttributeName": "email",
            "DeliveryMedium": "EMAIL",
            "Destination": mask_email(email)
        }));
    }
    if changes.phone_updated
        && pool
            .auto_verified_attributes
            .as_ref()
            .is_some_and(|attrs| attrs.contains(&AutoVerifiedAttribute::PhoneNumber))
        && let Some(phone_number) = user.phone_number.as_deref()
    {
        code_delivery_details_list.push(json!({
            "AttributeName": "phone_number",
            "DeliveryMedium": "SMS",
            "Destination": mask_phone_number(phone_number)
        }));
    }

    user.last_modified_date = Utc::now();

    storage.update_user(user).await;

    Ok(json!({
        "CodeDeliveryDetailsList": code_delivery_details_list
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
