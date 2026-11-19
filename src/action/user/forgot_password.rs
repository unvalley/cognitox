//! ForgotPassword API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_ForgotPassword.html>

use chrono::{Duration, Utc};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::{
    action::io::parse_request,
    error::{AppError, Result},
    storage::Storage,
    types::{ClientId, PasswordResetCode, UserStatus},
    validation::validate_username,
};

use super::helpers::{
    generate_confirmation_code, hides_user_existence, recovery_delivery, simulated_code_delivery,
    verify_secret_hash,
};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Request {
    client_id: ClientId,
    username: String,
    #[serde(default)]
    analytics_metadata: Option<Value>,
    #[serde(default)]
    client_metadata: Option<std::collections::HashMap<String, String>>,
    #[serde(default)]
    secret_hash: Option<String>,
    #[serde(default)]
    user_context_data: Option<Value>,
}

pub async fn handler(storage: &Storage, body: Value) -> Result<Value> {
    let req: Request = parse_request(body)?;
    let _ = (
        &req.analytics_metadata,
        &req.client_metadata,
        &req.secret_hash,
        &req.user_context_data,
    );

    validate_username(&req.username)?;

    let client = storage
        .get_user_pool_client(&req.client_id)
        .await
        .ok_or(AppError::UserPoolClientNotFound)?;
    verify_secret_hash(&client, &req.username, req.secret_hash.as_deref())?;

    let pool = storage
        .get_user_pool(&client.user_pool_id)
        .await
        .ok_or(AppError::UserPoolNotFound)?;

    let Some(user) = storage
        .get_user_by_username(&client.user_pool_id, &req.username)
        .await
    else {
        // An app client that hides user existence pretends a code went out.
        return if hides_user_existence(&client) {
            Ok(json!({
                "CodeDeliveryDetails": simulated_code_delivery(&req.username)
            }))
        } else {
            Err(AppError::UserNotFound)
        };
    };

    if !user.enabled {
        return Err(AppError::UserDisabled);
    }

    // A user who has yet to replace a temporary password has no password
    // of their own to recover.
    if user.user_status == UserStatus::ForceChangePassword {
        return Err(AppError::NotAuthorized(
            "User password cannot be reset in the current state.".to_string(),
        ));
    }

    let code_delivery_details = recovery_delivery(&pool, &user, true)?;

    let code = generate_confirmation_code();
    let reset_code = PasswordResetCode {
        user_id: user.id,
        code: code.clone(),
        expires_at: Utc::now() + Duration::hours(1),
    };

    storage.save_password_reset_code(reset_code).await;

    tracing::debug!("ForgotPassword code for {}: {}", req.username, code);

    Ok(json!({
        "CodeDeliveryDetails": code_delivery_details
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    use crate::action::user::sign_up;
    use crate::action::user_pool::{create_user_pool, create_user_pool_client};

    async fn setup_pool_and_client(storage: &Storage) -> (String, String) {
        let pool = create_user_pool::handler(
            storage,
            json!({"PoolName": "test", "AutoVerifiedAttributes": ["email", "phone_number"]}),
        )
        .await
        .unwrap();
        let pool_id = pool["UserPool"]["Id"].as_str().unwrap().to_string();

        let client = create_user_pool_client::handler(
            storage,
            json!({
                "UserPoolId": pool_id,
                "ExplicitAuthFlows": ["ALLOW_USER_PASSWORD_AUTH", "ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_USER_SRP_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
                "ClientName": "test-client"
            }),
        )
        .await
        .unwrap();
        let client_id = client["UserPoolClient"]["ClientId"]
            .as_str()
            .unwrap()
            .to_string();

        (pool_id, client_id)
    }

    #[tokio::test]
    async fn test_forgot_password_success() {
        let storage = Storage::new();
        let (_pool_id, client_id) = setup_pool_and_client(&storage).await;

        // Sign up a user with email
        let sign_up_result = sign_up::handler(
            &storage,
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
        crate::action::user::test_support::confirm_with_code(&storage, &client_id, &user_id).await;

        let result = handler(
            &storage,
            json!({
                "ClientId": client_id,
                "Username": "testuser"
            }),
        )
        .await;

        assert!(result.is_ok());
        let body = result.unwrap();
        assert_eq!(body["CodeDeliveryDetails"]["DeliveryMedium"], "EMAIL");
        assert_eq!(body["CodeDeliveryDetails"]["Destination"], "t***@e***");

        // Verify password reset code was saved
        let reset_code = storage.get_password_reset_code(&user_id).await;
        assert!(reset_code.is_some());
    }

    #[tokio::test]
    async fn test_forgot_password_user_not_found() {
        let storage = Storage::new();
        let (_pool_id, client_id) = setup_pool_and_client(&storage).await;

        let result = handler(
            &storage,
            json!({
                "ClientId": client_id,
                "Username": "nonexistent"
            }),
        )
        .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_forgot_password_invalid_client() {
        let storage = Storage::new();

        let result = handler(
            &storage,
            json!({
                "ClientId": "invalid-client-id",
                "Username": "testuser"
            }),
        )
        .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_forgot_password_requires_confirmed_user() {
        let storage = Storage::new();
        let (_pool_id, client_id) = setup_pool_and_client(&storage).await;

        sign_up::handler(
            &storage,
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

        let result = handler(
            &storage,
            json!({
                "ClientId": client_id,
                "Username": "testuser"
            }),
        )
        .await;

        // An unconfirmed user has no verified address to send the code to.
        assert!(matches!(
            result,
            Err(AppError::InvalidParameter(message))
                if message == "Cannot reset password for the user as there is no registered/verified email or phone_number"
        ));
    }

    #[tokio::test]
    async fn test_forgot_password_uses_sms_when_phone_number_is_only_delivery_target() {
        let storage = Storage::new();
        let (_pool_id, client_id) = setup_pool_and_client(&storage).await;

        let sign_up_result = sign_up::handler(
            &storage,
            json!({
                "ClientId": client_id,
                "Username": "smsuser",
                "Password": "Password123!",
                "UserAttributes": [
                    {"Name": "phone_number", "Value": "+15555550100"}
                ]
            }),
        )
        .await
        .unwrap();

        let user_sub = sign_up_result["UserSub"].as_str().unwrap();
        let user_id = uuid::Uuid::parse_str(user_sub).unwrap();
        crate::action::user::test_support::confirm_with_code(&storage, &client_id, &user_id).await;

        let result = handler(
            &storage,
            json!({
                "ClientId": client_id,
                "Username": "smsuser"
            }),
        )
        .await
        .unwrap();

        assert_eq!(
            result["CodeDeliveryDetails"]["AttributeName"],
            "phone_number"
        );
        assert_eq!(result["CodeDeliveryDetails"]["DeliveryMedium"], "SMS");
    }

    #[tokio::test]
    async fn test_forgot_password_requires_delivery_attribute() {
        let storage = Storage::new();
        let (_pool_id, client_id) = setup_pool_and_client(&storage).await;

        let sign_up_result = sign_up::handler(
            &storage,
            json!({
                "ClientId": client_id,
                "Username": "nodelivery",
                "Password": "Password123!"
            }),
        )
        .await
        .unwrap();

        let user_sub = sign_up_result["UserSub"].as_str().unwrap();
        let user_id = uuid::Uuid::parse_str(user_sub).unwrap();
        storage.confirm_user(&user_id).await;

        let result = handler(
            &storage,
            json!({
                "ClientId": client_id,
                "Username": "nodelivery"
            }),
        )
        .await;

        assert!(matches!(result, Err(AppError::InvalidParameter(_))));
    }

    #[tokio::test]
    async fn test_forgot_password_hides_unknown_users_when_the_client_asks() {
        let storage = Storage::new();
        let (pool_id, _client_id) = setup_pool_and_client(&storage).await;
        let client = create_user_pool_client::handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "ClientName": "quiet-client",
                "PreventUserExistenceErrors": "ENABLED"
            }),
        )
        .await
        .unwrap();

        let body = handler(
            &storage,
            json!({
                "ClientId": client["UserPoolClient"]["ClientId"],
                "Username": "nobody@example.com"
            }),
        )
        .await
        .unwrap();
        assert_eq!(body["CodeDeliveryDetails"]["DeliveryMedium"], "EMAIL");
        assert_eq!(body["CodeDeliveryDetails"]["Destination"], "n***@e***");
    }

    #[tokio::test]
    async fn test_forgot_password_refuses_a_temporary_password() {
        let storage = Storage::new();
        let (pool_id, client_id) = setup_pool_and_client(&storage).await;
        crate::action::user::admin_create_user::handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "Username": "invited",
                "UserAttributes": [
                    {"Name": "email", "Value": "invited@example.com"},
                    {"Name": "email_verified", "Value": "true"}
                ]
            }),
        )
        .await
        .unwrap();

        let result = handler(
            &storage,
            json!({
                "ClientId": client_id,
                "Username": "invited"
            }),
        )
        .await;
        assert!(matches!(
            result,
            Err(AppError::NotAuthorized(message))
                if message == "User password cannot be reset in the current state."
        ));
    }
}
