//! ConfirmSignUp API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_ConfirmSignUp.html>

use chrono::Utc;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::{
    action::io::parse_request,
    error::{AppError, Result},
    storage::Storage,
    types::{AutoVerifiedAttribute, ClientId, UserStatus},
    validation::{validate_confirmation_code, validate_username},
};

use super::helpers::{
    confirmation_attribute, ensure_alias_free, hides_user_existence, normalize_confirmation_code,
    upsert_user_attribute, verify_secret_hash,
};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Request {
    client_id: ClientId,
    username: String,
    confirmation_code: String,
    #[serde(default)]
    analytics_metadata: Option<Value>,
    #[serde(default)]
    client_metadata: Option<std::collections::HashMap<String, String>>,
    #[serde(default)]
    force_alias_creation: Option<bool>,
    #[serde(default)]
    secret_hash: Option<String>,
    #[serde(default)]
    session: Option<String>,
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
    validate_confirmation_code(&req.confirmation_code)?;

    let client = storage
        .get_user_pool_client(&req.client_id)
        .await
        .ok_or(AppError::UserPoolClientNotFound)?;
    verify_secret_hash(&client, &req.username, req.secret_hash.as_deref())?;

    let mut user = storage
        .get_user_by_username(&client.user_pool_id, &req.username)
        .await
        .ok_or(if hides_user_existence(&client) {
            AppError::ExpiredCode
        } else {
            AppError::UserNotFound
        })?;

    if user.user_status == UserStatus::Confirmed {
        return Err(AppError::NotAuthorized(
            "User cannot be confirmed. Current status is CONFIRMED".to_string(),
        ));
    }

    // Without a pending code there is nothing to match against; Cognito
    // answers as it does for a code that has expired.
    let confirmation = storage
        .get_confirmation_code(&user.id)
        .await
        .ok_or(AppError::ExpiredCode)?;

    // Normalize codes for comparison (removes dashes, converts to uppercase)
    if normalize_confirmation_code(&confirmation.code)
        != normalize_confirmation_code(&req.confirmation_code)
    {
        return Err(AppError::InvalidConfirmationCode);
    }

    if confirmation.expires_at < Utc::now() {
        storage.delete_confirmation_code(&user.id).await;
        return Err(AppError::ExpiredCode);
    }

    // Returning the code proves control of the address or number it was
    // sent to.
    let pool = storage
        .get_user_pool(&client.user_pool_id)
        .await
        .ok_or(AppError::UserPoolNotFound)?;
    if let Some(attribute) = confirmation_attribute(&pool, &user) {
        let (name, verified_attribute, value) = match attribute {
            AutoVerifiedAttribute::Email => ("email", "email_verified", user.email.clone()),
            AutoVerifiedAttribute::PhoneNumber => (
                "phone_number",
                "phone_number_verified",
                user.phone_number.clone(),
            ),
        };
        // The verified value becomes a sign-in alias. If another user holds
        // it, confirmation fails unless the caller asks to take it over.
        if let Err(taken) = ensure_alias_free(storage, &pool, &user, name).await {
            if req.force_alias_creation != Some(true) {
                return Err(taken);
            }
            while let Some(owner) = match value.as_deref() {
                Some(value) => storage.get_user_by_alias(&pool.id, value).await,
                None => None,
            } {
                storage
                    .update_user_with(&owner.id, |owner| {
                        upsert_user_attribute(
                            &mut owner.attributes,
                            verified_attribute,
                            Some("false".to_string()),
                        );
                    })
                    .await;
            }
        }
        upsert_user_attribute(
            &mut user.attributes,
            verified_attribute,
            Some("true".to_string()),
        );
    }

    user.user_status = UserStatus::Confirmed;
    user.last_modified_date = Utc::now();
    storage.update_user(user).await;
    storage
        .delete_confirmation_code(&confirmation.user_id)
        .await;

    let mut response = json!({});
    if let Some(session) = req.session {
        response["Session"] = json!(session);
    }
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    use crate::action::user::sign_up;
    use crate::action::user_pool::{create_user_pool, create_user_pool_client};
    use crate::types::UserPoolId;

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
    async fn test_confirm_sign_up_success() {
        let storage = Storage::new();
        let (pool_id, client_id) = setup_pool_and_client(&storage).await;

        // Sign up a user first
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

        // Get the confirmation code from storage
        let confirmation = storage.get_confirmation_code(&user_id).await.unwrap();

        let result = handler(
            &storage,
            json!({
                "ClientId": client_id,
                "Username": "testuser",
                "ConfirmationCode": confirmation.code
            }),
        )
        .await;

        assert!(result.is_ok());

        // Verify user is confirmed
        let pool_id_typed: UserPoolId = pool_id.parse().unwrap();
        let user = storage
            .get_user_by_username(&pool_id_typed, "testuser")
            .await
            .unwrap();
        assert_eq!(user.user_status, UserStatus::Confirmed);
    }

    #[tokio::test]
    async fn test_confirm_sign_up_invalid_code() {
        let storage = Storage::new();
        let (_pool_id, client_id) = setup_pool_and_client(&storage).await;

        // Sign up a user first
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
                "Username": "testuser",
                "ConfirmationCode": "WRONG-CODE-HERE"
            }),
        )
        .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_confirm_sign_up_user_not_found() {
        let storage = Storage::new();
        let (_pool_id, client_id) = setup_pool_and_client(&storage).await;

        let result = handler(
            &storage,
            json!({
                "ClientId": client_id,
                "Username": "nonexistent",
                "ConfirmationCode": "123456"
            }),
        )
        .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_confirm_sign_up_confirmed_user_is_rejected() {
        let storage = Storage::new();
        let (pool_id, client_id) = setup_pool_and_client(&storage).await;

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
        storage.confirm_user(&user_id).await;

        let result = handler(
            &storage,
            json!({
                "ClientId": client_id,
                "Username": "testuser",
                "ConfirmationCode": "SOME-CODE"
            }),
        )
        .await;

        assert!(matches!(result, Err(AppError::NotAuthorized(_))));

        let pool_id_typed: UserPoolId = pool_id.parse().unwrap();
        let user = storage
            .get_user_by_username(&pool_id_typed, "testuser")
            .await
            .unwrap();
        assert_eq!(user.user_status, UserStatus::Confirmed);
    }

    #[tokio::test]
    async fn test_confirm_sign_up_expired_code() {
        let storage = Storage::new();
        let (_pool_id, client_id) = setup_pool_and_client(&storage).await;

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
        let mut confirmation = storage.get_confirmation_code(&user_id).await.unwrap();
        confirmation.expires_at = Utc::now() - chrono::Duration::minutes(1);
        storage.save_confirmation_code(confirmation.clone()).await;

        let result = handler(
            &storage,
            json!({
                "ClientId": client_id,
                "Username": "testuser",
                "ConfirmationCode": confirmation.code
            }),
        )
        .await;

        assert!(matches!(result, Err(AppError::ExpiredCode)));
        assert!(storage.get_confirmation_code(&user_id).await.is_none());
    }
}
