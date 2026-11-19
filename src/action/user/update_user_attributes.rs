//! UpdateUserAttributes API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_UpdateUserAttributes.html>

use chrono::{Duration, Utc};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::{
    action::io::parse_request,
    error::{AppError, Result},
    storage::Storage,
    types::{AutoVerifiedAttribute, ConfirmationCode, UserAttribute, UserPool},
    validation::{validate_email, validate_phone_number},
};

use super::helpers::{
    AttributeWriter, apply_user_attribute_updates, generate_confirmation_code, mask_email,
    mask_phone_number, upsert_user_attribute, validate_attribute_write,
    verify_access_token_with_client,
};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Request {
    access_token: String,
    user_attributes: Vec<UserAttribute>,
    #[serde(default)]
    client_metadata: Option<std::collections::HashMap<String, String>>,
}

/// An email address or phone number, the two attributes Cognito verifies.
struct Verifiable {
    name: &'static str,
    kind: AutoVerifiedAttribute,
    medium: &'static str,
}

const VERIFIABLE: [Verifiable; 2] = [
    Verifiable {
        name: "email",
        kind: AutoVerifiedAttribute::Email,
        medium: "EMAIL",
    },
    Verifiable {
        name: "phone_number",
        kind: AutoVerifiedAttribute::PhoneNumber,
        medium: "SMS",
    },
];

fn auto_verifies(pool: &UserPool, kind: AutoVerifiedAttribute) -> bool {
    pool.auto_verified_attributes
        .as_ref()
        .is_some_and(|attributes| attributes.contains(&kind))
}

fn verifies_before_update(pool: &UserPool, kind: AutoVerifiedAttribute) -> bool {
    pool.user_attribute_update_settings
        .as_ref()
        .and_then(|settings| {
            settings
                .attributes_require_verification_before_update
                .as_ref()
        })
        .is_some_and(|attributes| attributes.contains(&kind))
}

pub async fn handler(storage: &Storage, body: Value) -> Result<Value> {
    let req: Request = parse_request(body)?;
    let _ = &req.client_metadata;

    let (user_id, client) = verify_access_token_with_client(storage, &req.access_token).await?;

    let mut user = storage
        .get_user(&user_id)
        .await
        .ok_or(AppError::UserNotFound)?;

    let pool = storage
        .get_user_pool(&user.user_pool_id)
        .await
        .ok_or(AppError::UserPoolNotFound)?;

    validate_attribute_write(
        &pool,
        AttributeWriter::Client(client.as_ref()),
        &req.user_attributes,
        true,
    )?;

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

    // A new email address or phone number has to be verified again. When the
    // user pool verifies the attribute, Cognito sends a code right away, and
    // with `AttributesRequireVerificationBeforeUpdate` the old value stays
    // in place until that code comes back.
    let mut updates = req.user_attributes;
    let mut code_delivery_details_list = Vec::new();
    for verifiable in &VERIFIABLE {
        let Some(new_value) = updates
            .iter()
            .find(|attribute| attribute.name == verifiable.name)
            .and_then(|attribute| attribute.value.clone())
        else {
            continue;
        };
        let current = match verifiable.kind {
            AutoVerifiedAttribute::Email => user.email.as_deref(),
            AutoVerifiedAttribute::PhoneNumber => user.phone_number.as_deref(),
        };
        if current == Some(new_value.as_str()) {
            continue;
        }

        let deferred = verifies_before_update(&pool, verifiable.kind);
        if deferred {
            updates.retain(|attribute| attribute.name != verifiable.name);
            storage
                .set_pending_attribute_update(&user.id, verifiable.name, new_value.clone())
                .await;
        }

        if auto_verifies(&pool, verifiable.kind) || deferred {
            let code = generate_confirmation_code();
            tracing::debug!(
                "Verification code for {} of {}: {}",
                verifiable.name,
                user.username,
                code
            );
            storage
                .save_confirmation_code(ConfirmationCode {
                    user_id: user.id,
                    attribute_name: Some(verifiable.name.to_string()),
                    code,
                    expires_at: Utc::now() + Duration::hours(24),
                })
                .await;
            code_delivery_details_list.push(json!({
                "AttributeName": verifiable.name,
                "DeliveryMedium": verifiable.medium,
                "Destination": match verifiable.kind {
                    AutoVerifiedAttribute::Email => mask_email(&new_value),
                    AutoVerifiedAttribute::PhoneNumber => mask_phone_number(&new_value),
                }
            }));
        }
    }

    let changes = apply_user_attribute_updates(&mut user, updates);

    if changes.email_updated {
        upsert_user_attribute(
            &mut user.attributes,
            "email_verified",
            Some("false".to_string()),
        );
    }
    if changes.phone_updated {
        upsert_user_attribute(
            &mut user.attributes,
            "phone_number_verified",
            Some("false".to_string()),
        );
    }

    user.last_modified_date = Utc::now();

    storage.update_user(user).await;

    let mut response = json!({});
    if !code_delivery_details_list.is_empty() {
        response["CodeDeliveryDetailsList"] = json!(code_delivery_details_list);
    }
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::user::{get_user, initiate_auth, sign_up};
    use crate::action::user_pool::{create_user_pool, create_user_pool_client};
    use serde_json::json;

    async fn setup_and_get_token(storage: &Storage) -> String {
        let pool = create_user_pool::handler(storage, json!({"PoolName": "test", "Schema": [{"Name": "role", "AttributeDataType": "String"}]}))
            .await
            .unwrap();
        let pool_id = pool["UserPool"]["Id"].as_str().unwrap();

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

    async fn signed_in_user(pool_settings: Value, client_settings: Value) -> (Storage, String) {
        let storage = Storage::new();
        let mut pool_request = json!({
            "PoolName": "test",
            "AutoVerifiedAttributes": ["email"],
            "Schema": [
                {"Name": "role", "AttributeDataType": "String"},
                {"Name": "tenant", "AttributeDataType": "String", "Mutable": false}
            ]
        });
        pool_request
            .as_object_mut()
            .unwrap()
            .extend(pool_settings.as_object().unwrap().clone());
        let pool = create_user_pool::handler(&storage, pool_request)
            .await
            .unwrap();

        let mut client_request = json!({
            "UserPoolId": pool["UserPool"]["Id"],
            "ClientName": "test-client",
            "ExplicitAuthFlows": ["ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"]
        });
        client_request
            .as_object_mut()
            .unwrap()
            .extend(client_settings.as_object().unwrap().clone());
        let client = create_user_pool_client::handler(&storage, client_request)
            .await
            .unwrap();
        let client_id = client["UserPoolClient"]["ClientId"].as_str().unwrap();

        let signed_up = sign_up::handler(
            &storage,
            json!({
                "ClientId": client_id,
                "Username": "testuser",
                "Password": "Password123!",
                "UserAttributes": [
                    {"Name": "email", "Value": "old@example.com"},
                    {"Name": "custom:tenant", "Value": "acme"}
                ]
            }),
        )
        .await
        .unwrap();
        let user_id = uuid::Uuid::parse_str(signed_up["UserSub"].as_str().unwrap()).unwrap();
        crate::action::user::test_support::confirm_with_code(&storage, client_id, &user_id).await;

        let auth = initiate_auth::handler(
            &storage,
            json!({
                "ClientId": client_id,
                "AuthFlow": "USER_PASSWORD_AUTH",
                "AuthParameters": {"USERNAME": "testuser", "PASSWORD": "Password123!"}
            }),
        )
        .await
        .unwrap();
        let access_token = auth["AuthenticationResult"]["AccessToken"]
            .as_str()
            .unwrap()
            .to_string();
        (storage, access_token)
    }

    async fn attribute(storage: &Storage, access_token: &str, name: &str) -> Option<String> {
        let user = get_user::handler(storage, json!({"AccessToken": access_token}))
            .await
            .unwrap();
        user["UserAttributes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|attribute| attribute["Name"] == name)
            .and_then(|attribute| attribute["Value"].as_str().map(str::to_string))
    }

    #[tokio::test]
    async fn test_new_email_is_unverified_and_gets_a_code() {
        let (storage, access_token) = signed_in_user(json!({}), json!({})).await;
        assert_eq!(
            attribute(&storage, &access_token, "email_verified")
                .await
                .as_deref(),
            Some("true")
        );

        let body = handler(
            &storage,
            json!({
                "AccessToken": access_token,
                "UserAttributes": [{"Name": "email", "Value": "new@example.com"}]
            }),
        )
        .await
        .unwrap();
        assert_eq!(
            body["CodeDeliveryDetailsList"],
            json!([{
                "AttributeName": "email",
                "DeliveryMedium": "EMAIL",
                "Destination": "n***@e***"
            }])
        );
        assert_eq!(
            attribute(&storage, &access_token, "email").await.as_deref(),
            Some("new@example.com")
        );
        assert_eq!(
            attribute(&storage, &access_token, "email_verified")
                .await
                .as_deref(),
            Some("false")
        );
    }

    #[tokio::test]
    async fn test_email_change_can_wait_for_verification() {
        let (storage, access_token) = signed_in_user(
            json!({
                "UserAttributeUpdateSettings": {
                    "AttributesRequireVerificationBeforeUpdate": ["email"]
                }
            }),
            json!({}),
        )
        .await;

        handler(
            &storage,
            json!({
                "AccessToken": access_token,
                "UserAttributes": [{"Name": "email", "Value": "new@example.com"}]
            }),
        )
        .await
        .unwrap();
        // The verified address stays until the code for the new one returns.
        assert_eq!(
            attribute(&storage, &access_token, "email").await.as_deref(),
            Some("old@example.com")
        );
        assert_eq!(
            attribute(&storage, &access_token, "email_verified")
                .await
                .as_deref(),
            Some("true")
        );

        let user = get_user::handler(&storage, json!({"AccessToken": access_token}))
            .await
            .unwrap();
        let user_id = uuid::Uuid::parse_str(
            user["UserAttributes"]
                .as_array()
                .unwrap()
                .iter()
                .find(|attribute| attribute["Name"] == "sub")
                .unwrap()["Value"]
                .as_str()
                .unwrap(),
        )
        .unwrap();
        let code = storage.get_confirmation_code(&user_id).await.unwrap().code;
        crate::action::user::verify_user_attribute::handler(
            &storage,
            json!({
                "AccessToken": access_token,
                "AttributeName": "email",
                "Code": code
            }),
        )
        .await
        .unwrap();

        assert_eq!(
            attribute(&storage, &access_token, "email").await.as_deref(),
            Some("new@example.com")
        );
        assert_eq!(
            attribute(&storage, &access_token, "email_verified")
                .await
                .as_deref(),
            Some("true")
        );
    }

    #[tokio::test]
    async fn test_schema_and_client_permissions_bound_updates() {
        let (storage, access_token) = signed_in_user(json!({}), json!({})).await;
        let update = |attributes: Value| {
            handler(
                &storage,
                json!({"AccessToken": access_token, "UserAttributes": attributes}),
            )
        };

        assert!(matches!(
            update(json!([{"Name": "custom:unknown", "Value": "x"}])).await,
            Err(AppError::InvalidParameter(message))
                if message == "Attributes did not conform to the schema: Type for attribute {custom:unknown} could not be determined"
        ));
        assert!(matches!(
            update(json!([{"Name": "custom:tenant", "Value": "other"}])).await,
            Err(AppError::InvalidParameter(message))
                if message == "user.custom:tenant: Attribute cannot be updated."
        ));
        // Users cannot declare their own address verified.
        assert!(matches!(
            update(json!([{"Name": "email_verified", "Value": "true"}])).await,
            Err(AppError::NotAuthorized(message))
                if message == "A client attempted to write unauthorized attribute"
        ));
        update(json!([{"Name": "custom:role", "Value": "admin"}]))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_client_read_and_write_attributes_apply() {
        let (storage, access_token) = signed_in_user(
            json!({}),
            json!({
                "ReadAttributes": ["email", "custom:tenant"],
                "WriteAttributes": ["email", "custom:tenant", "name"]
            }),
        )
        .await;

        assert!(matches!(
            handler(
                &storage,
                json!({
                    "AccessToken": access_token,
                    "UserAttributes": [{"Name": "custom:role", "Value": "admin"}]
                }),
            )
            .await,
            Err(AppError::NotAuthorized(_))
        ));
        handler(
            &storage,
            json!({
                "AccessToken": access_token,
                "UserAttributes": [{"Name": "name", "Value": "Tester"}]
            }),
        )
        .await
        .unwrap();

        // `name` was written but is not among the readable attributes.
        assert_eq!(attribute(&storage, &access_token, "name").await, None);
        assert_eq!(
            attribute(&storage, &access_token, "custom:tenant")
                .await
                .as_deref(),
            Some("acme")
        );
        assert!(attribute(&storage, &access_token, "sub").await.is_some());
    }
}
