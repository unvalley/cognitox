//! VerifyUserAttribute API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_VerifyUserAttribute.html>

use chrono::Utc;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::{
    error::{AppError, Result},
    storage::Storage,
    types::UserAttribute,
};

use super::helpers::{normalize_confirmation_code, verify_and_extract_active_user_id};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Request {
    access_token: String,
    attribute_name: String,
    code: String,
}

pub async fn handler(storage: &Storage, body: Value) -> Result<Value> {
    let req: Request = serde_json::from_value(body)
        .map_err(|e| AppError::InvalidParameter(format!("Invalid request: {}", e)))?;

    // Validate attribute name
    let verified_attr_name = match req.attribute_name.as_str() {
        "email" => "email_verified",
        "phone_number" => "phone_number_verified",
        _ => {
            return Err(AppError::InvalidParameter(format!(
                "Invalid attribute name for verification: {}",
                req.attribute_name
            )));
        }
    };

    let user_id = verify_and_extract_active_user_id(storage, &req.access_token)
        .await
        .map_err(|_| AppError::InvalidAccessToken)?;

    let mut user = storage
        .get_user(&user_id)
        .await
        .ok_or(AppError::UserNotFound)?;

    // Verify the confirmation code
    let stored_code = storage
        .get_confirmation_code(&user_id)
        .await
        .ok_or(AppError::InvalidConfirmationCode)?;

    if stored_code.attribute_name.as_deref() != Some(req.attribute_name.as_str()) {
        return Err(AppError::InvalidConfirmationCode);
    }

    if stored_code.expires_at < Utc::now() {
        return Err(AppError::ExpiredCode);
    }

    let normalized_input = normalize_confirmation_code(&req.code);
    let normalized_stored = normalize_confirmation_code(&stored_code.code);

    if normalized_input != normalized_stored {
        return Err(AppError::InvalidConfirmationCode);
    }

    // Code is valid, mark the attribute as verified
    // Remove existing verified attribute if present
    user.attributes
        .retain(|attr| attr.name != verified_attr_name);

    // Add the verified attribute
    user.attributes.push(UserAttribute {
        name: verified_attr_name.to_string(),
        value: Some("true".to_string()),
    });

    user.last_modified_date = Utc::now();

    storage.update_user(user).await;

    // Delete the used confirmation code
    storage.delete_confirmation_code(&user_id).await;

    Ok(json!({}))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::user::{
        get_user, get_user_attribute_verification_code, initiate_auth, sign_up,
    };
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
    async fn test_verify_user_attribute_email_success() {
        let storage = Storage::new();
        let access_token = setup_and_get_token(&storage).await;

        // Request verification code
        let code_result = get_user_attribute_verification_code::handler(
            &storage,
            json!({
                "AccessToken": access_token,
                "AttributeName": "email"
            }),
        )
        .await
        .unwrap();

        assert_eq!(code_result["CodeDeliveryDetails"]["AttributeName"], "email");

        // Get the code from storage (in real scenario, user receives via email)
        let user_id = verify_and_extract_active_user_id(&storage, &access_token)
            .await
            .unwrap();
        let stored_code = storage.get_confirmation_code(&user_id).await.unwrap();

        // Verify the attribute
        let result = handler(
            &storage,
            json!({
                "AccessToken": access_token,
                "AttributeName": "email",
                "Code": stored_code.code
            }),
        )
        .await;

        assert!(result.is_ok());

        // Verify the email_verified attribute was set
        let user_info = get_user::handler(
            &storage,
            json!({
                "AccessToken": access_token
            }),
        )
        .await
        .unwrap();

        let attrs = user_info["UserAttributes"].as_array().unwrap();
        let email_verified = attrs.iter().find(|a| a["Name"] == "email_verified");
        assert!(email_verified.is_some());
        assert_eq!(email_verified.unwrap()["Value"], "true");
    }

    #[tokio::test]
    async fn test_verify_user_attribute_invalid_code() {
        let storage = Storage::new();
        let access_token = setup_and_get_token(&storage).await;

        // Request verification code first
        get_user_attribute_verification_code::handler(
            &storage,
            json!({
                "AccessToken": access_token,
                "AttributeName": "email"
            }),
        )
        .await
        .unwrap();

        // Try to verify with wrong code
        let result = handler(
            &storage,
            json!({
                "AccessToken": access_token,
                "AttributeName": "email",
                "Code": "WRONG-CODE-1234"
            }),
        )
        .await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            AppError::InvalidConfirmationCode
        ));
    }

    #[tokio::test]
    async fn test_verify_user_attribute_rejects_code_for_different_attribute() {
        let storage = Storage::new();
        let access_token = setup_and_get_token(&storage).await;

        get_user_attribute_verification_code::handler(
            &storage,
            json!({
                "AccessToken": access_token,
                "AttributeName": "email"
            }),
        )
        .await
        .unwrap();

        let user_id = verify_and_extract_active_user_id(&storage, &access_token)
            .await
            .unwrap();
        let stored_code = storage.get_confirmation_code(&user_id).await.unwrap();

        let result = handler(
            &storage,
            json!({
                "AccessToken": access_token,
                "AttributeName": "phone_number",
                "Code": stored_code.code
            }),
        )
        .await;

        assert!(matches!(result, Err(AppError::InvalidConfirmationCode)));
    }

    #[tokio::test]
    async fn test_verify_user_attribute_invalid_attribute() {
        let storage = Storage::new();
        let access_token = setup_and_get_token(&storage).await;

        let result = handler(
            &storage,
            json!({
                "AccessToken": access_token,
                "AttributeName": "invalid_attribute",
                "Code": "123456"
            }),
        )
        .await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AppError::InvalidParameter(_)));
    }

    #[tokio::test]
    async fn test_verify_user_attribute_invalid_token() {
        let storage = Storage::new();

        let result = handler(
            &storage,
            json!({
                "AccessToken": "invalid-token",
                "AttributeName": "email",
                "Code": "123456"
            }),
        )
        .await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AppError::InvalidAccessToken));
    }
}
