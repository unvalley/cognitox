//! AdminLinkProviderForUser API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AdminLinkProviderForUser.html>

use serde::Deserialize;
use serde_json::{Value, json};

use crate::{
    error::{AppError, Result},
    storage::Storage,
    types::{ProviderUserIdentifier, User, UserPoolId},
};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Request {
    user_pool_id: UserPoolId,
    destination_user: ProviderUserIdentifierRequest,
    source_user: ProviderUserIdentifierRequest,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ProviderUserIdentifierRequest {
    provider_name: String,
    #[serde(default)]
    provider_attribute_name: Option<String>,
    provider_attribute_value: String,
}

impl ProviderUserIdentifierRequest {
    fn into_identifier(self) -> Result<ProviderUserIdentifier> {
        if self.provider_name.trim().is_empty() || self.provider_attribute_value.trim().is_empty() {
            return Err(AppError::InvalidParameter(
                "ProviderName and ProviderAttributeValue are required".to_string(),
            ));
        }

        Ok(ProviderUserIdentifier {
            provider_name: self.provider_name,
            provider_attribute_name: self.provider_attribute_name,
            provider_attribute_value: self.provider_attribute_value,
        })
    }
}

async fn resolve_destination_user(
    storage: &Storage,
    user_pool_id: &UserPoolId,
    destination: ProviderUserIdentifier,
) -> Result<User> {
    if destination.provider_name != "Cognito" {
        return Err(AppError::InvalidParameter(
            "DestinationUser must use the Cognito provider".to_string(),
        ));
    }

    if destination.provider_attribute_name.as_deref() == Some("Cognito_Subject") {
        let user_id = destination
            .provider_attribute_value
            .parse()
            .map_err(|_| AppError::InvalidParameter("Invalid Cognito subject".to_string()))?;
        let user = storage
            .get_user(&user_id)
            .await
            .ok_or(AppError::UserNotFound)?;
        if user.user_pool_id != *user_pool_id {
            return Err(AppError::UserNotFound);
        }
        return Ok(user);
    }

    storage
        .get_user_by_username(user_pool_id, &destination.provider_attribute_value)
        .await
        .ok_or(AppError::UserNotFound)
}

pub async fn handler(storage: &Storage, body: Value) -> Result<Value> {
    let req: Request = serde_json::from_value(body)
        .map_err(|e| AppError::InvalidParameter(format!("Invalid request: {}", e)))?;

    storage
        .get_user_pool(&req.user_pool_id)
        .await
        .ok_or(AppError::UserPoolNotFound)?;

    let destination_user = resolve_destination_user(
        storage,
        &req.user_pool_id,
        req.destination_user.into_identifier()?,
    )
    .await?;
    let source_user = req.source_user.into_identifier()?;

    if source_user.provider_name == "Cognito" {
        return Err(AppError::InvalidParameter(
            "SourceUser must be a federated provider".to_string(),
        ));
    }

    storage
        .get_identity_provider(&req.user_pool_id, &source_user.provider_name)
        .await
        .ok_or(AppError::IdentityProviderNotFound)?;

    storage
        .link_federated_user(req.user_pool_id, destination_user.id, source_user)
        .await;

    Ok(json!({}))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::user::{admin_create_user, admin_get_user};
    use crate::action::user_pool::{create_identity_provider, create_user_pool};

    #[tokio::test]
    async fn test_admin_link_provider_for_user_success() {
        let storage = Storage::new();
        let pool = create_user_pool::handler(&storage, json!({"PoolName": "test"}))
            .await
            .unwrap();
        let pool_id = pool["UserPool"]["Id"].as_str().unwrap();

        admin_create_user::handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "Username": "local-user"
            }),
        )
        .await
        .unwrap();
        create_identity_provider::handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "ProviderName": "Google",
                "ProviderType": "OIDC"
            }),
        )
        .await
        .unwrap();

        let result = handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "DestinationUser": {
                    "ProviderName": "Cognito",
                    "ProviderAttributeValue": "local-user"
                },
                "SourceUser": {
                    "ProviderName": "Google",
                    "ProviderAttributeName": "Cognito_Subject",
                    "ProviderAttributeValue": "google-user"
                }
            }),
        )
        .await
        .unwrap();

        assert_eq!(result, json!({}));

        let link = storage
            .get_federated_user_link(
                &pool_id.parse().unwrap(),
                &ProviderUserIdentifier {
                    provider_name: "Google".to_string(),
                    provider_attribute_name: Some("Cognito_Subject".to_string()),
                    provider_attribute_value: "google-user".to_string(),
                },
            )
            .await;
        assert!(link.is_some());
        let user = admin_get_user::handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "Username": "local-user"
            }),
        )
        .await
        .unwrap();
        assert_eq!(user["Username"], "local-user");
    }
}
