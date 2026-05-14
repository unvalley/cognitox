//! GetUserAttributeVerificationCode API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_GetUserAttributeVerificationCode.html>

use chrono::{Duration, Utc};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::{
    error::{AppError, Result},
    storage::Storage,
    types::ConfirmationCode,
};

use super::helpers::{
    generate_confirmation_code, mask_email, mask_phone_number, verify_and_extract_active_user_id,
};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Request {
    access_token: String,
    attribute_name: String,
    #[serde(default)]
    client_metadata: Option<std::collections::HashMap<String, String>>,
}

pub async fn handler(storage: &Storage, body: Value) -> Result<Value> {
    let req: Request = serde_json::from_value(body)
        .map_err(|e| AppError::InvalidParameter(format!("Invalid request: {}", e)))?;
    let _ = &req.client_metadata;

    let user_id = verify_and_extract_active_user_id(storage, &req.access_token)
        .await
        .map_err(|_| AppError::InvalidAccessToken)?;

    let user = storage
        .get_user(&user_id)
        .await
        .ok_or(AppError::UserNotFound)?;

    // Generate verification code
    let code = generate_confirmation_code();
    let confirmation_code = ConfirmationCode {
        user_id: user.id,
        code: code.clone(),
        expires_at: Utc::now() + Duration::hours(24),
    };

    storage.save_confirmation_code(confirmation_code).await;

    // Determine delivery details based on attribute
    let (destination, delivery_medium) = match req.attribute_name.as_str() {
        "email" => {
            let dest = user.email.as_deref().map(mask_email).ok_or_else(|| {
                AppError::InvalidParameter("User does not have an email attribute".to_string())
            })?;
            (dest, "EMAIL")
        }
        "phone_number" => {
            let dest = user
                .phone_number
                .as_deref()
                .map(mask_phone_number)
                .ok_or_else(|| {
                    AppError::InvalidParameter(
                        "User does not have a phone_number attribute".to_string(),
                    )
                })?;
            (dest, "SMS")
        }
        _ => {
            return Err(AppError::InvalidParameter(format!(
                "Invalid attribute name: {}",
                req.attribute_name
            )));
        }
    };

    Ok(json!({
        "CodeDeliveryDetails": {
            "AttributeName": req.attribute_name,
            "DeliveryMedium": delivery_medium,
            "Destination": destination
        }
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
                "Password": "Password123!",
                "UserAttributes": [
                    {"Name": "email", "Value": "test@example.com"}
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
    async fn test_get_user_attribute_verification_code_email() {
        let storage = Storage::new();
        let access_token = setup_and_get_token(&storage).await;

        let result = handler(
            &storage,
            json!({
                "AccessToken": access_token,
                "AttributeName": "email"
            }),
        )
        .await;

        assert!(result.is_ok());
        let body = result.unwrap();
        assert_eq!(body["CodeDeliveryDetails"]["AttributeName"], "email");
        assert_eq!(body["CodeDeliveryDetails"]["DeliveryMedium"], "EMAIL");
    }

    #[tokio::test]
    async fn test_get_user_attribute_verification_code_invalid_token() {
        let storage = Storage::new();

        let result = handler(
            &storage,
            json!({
                "AccessToken": "invalid-token",
                "AttributeName": "email"
            }),
        )
        .await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AppError::InvalidAccessToken));
    }

    #[tokio::test]
    async fn test_get_user_attribute_verification_code_invalid_attribute() {
        let storage = Storage::new();
        let access_token = setup_and_get_token(&storage).await;

        let result = handler(
            &storage,
            json!({
                "AccessToken": access_token,
                "AttributeName": "invalid_attribute"
            }),
        )
        .await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AppError::InvalidParameter(_)));
    }

    #[tokio::test]
    async fn test_get_user_attribute_verification_code_missing_phone_number() {
        let storage = Storage::new();
        let access_token = setup_and_get_token(&storage).await;

        let result = handler(
            &storage,
            json!({
                "AccessToken": access_token,
                "AttributeName": "phone_number"
            }),
        )
        .await;

        assert!(matches!(result, Err(AppError::InvalidParameter(_))));
    }
}
