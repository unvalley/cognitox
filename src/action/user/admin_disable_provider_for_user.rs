//! AdminDisableProviderForUser API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AdminDisableProviderForUser.html>

use serde::Deserialize;
use serde_json::{Value, json};

use crate::{
    error::{AppError, Result},
    storage::Storage,
    types::{ProviderUserIdentifier, UserPoolId},
};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Request {
    user_pool_id: UserPoolId,
    user: ProviderUserIdentifierRequest,
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

pub async fn handler(storage: &Storage, body: Value) -> Result<Value> {
    let req: Request = serde_json::from_value(body)
        .map_err(|e| AppError::InvalidParameter(format!("Invalid request: {}", e)))?;

    storage
        .get_user_pool(&req.user_pool_id)
        .await
        .ok_or(AppError::UserPoolNotFound)?;

    let user = req.user.into_identifier()?;
    storage
        .unlink_federated_user(&req.user_pool_id, &user)
        .await
        .ok_or(AppError::UserNotFound)?;

    Ok(json!({}))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::user::{admin_create_user, admin_link_provider_for_user};
    use crate::action::user_pool::{create_identity_provider, create_user_pool};

    #[tokio::test]
    async fn test_admin_disable_provider_for_user_success() {
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
        admin_link_provider_for_user::handler(
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
                    "ProviderAttributeValue": "abc123"
                }
            }),
        )
        .await
        .unwrap();

        let result = handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "User": {
                    "ProviderName": "Google",
                    "ProviderAttributeName": "Cognito_Subject",
                    "ProviderAttributeValue": "abc123"
                }
            }),
        )
        .await
        .unwrap();

        assert_eq!(result, json!({}));
        assert!(
            storage
                .get_federated_user_link(
                    &pool_id.parse().unwrap(),
                    &ProviderUserIdentifier {
                        provider_name: "Google".to_string(),
                        provider_attribute_name: Some("Cognito_Subject".to_string()),
                        provider_attribute_value: "abc123".to_string(),
                    },
                )
                .await
                .is_none()
        );
    }
}
