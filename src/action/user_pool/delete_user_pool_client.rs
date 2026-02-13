//! DeleteUserPoolClient API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_DeleteUserPoolClient.html>

use serde::Deserialize;
use serde_json::{Value, json};

use crate::{
    error::{AppError, Result},
    storage::Storage,
    types::{ClientId, UserPoolId},
};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Request {
    #[allow(dead_code)]
    user_pool_id: UserPoolId,
    client_id: ClientId,
}

pub async fn handler(storage: &Storage, body: Value) -> Result<Value> {
    let req: Request = serde_json::from_value(body)
        .map_err(|e| AppError::InvalidParameter(format!("Invalid request: {}", e)))?;

    storage
        .delete_user_pool_client(&req.client_id)
        .await
        .ok_or(AppError::UserPoolClientNotFound)?;

    Ok(json!({}))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::user_pool::{
        create_managed_login_branding, create_terms, create_user_pool, create_user_pool_client,
        set_risk_configuration, set_ui_customization,
    };
    use serde_json::json;

    #[tokio::test]
    async fn test_delete_user_pool_client_success() {
        let storage = Storage::new();

        // Create a user pool and client first
        let pool = create_user_pool::handler(&storage, json!({"PoolName": "test-pool"}))
            .await
            .unwrap();
        let pool_id = pool["UserPool"]["Id"].as_str().unwrap();

        let client = create_user_pool_client::handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "ClientName": "test-client"
            }),
        )
        .await
        .unwrap();
        let client_id = client["UserPoolClient"]["ClientId"].as_str().unwrap();

        // Delete the client
        let result = handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "ClientId": client_id
            }),
        )
        .await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), json!({}));

        // Verify it's deleted
        assert!(
            storage
                .get_user_pool_client(&client_id.parse().unwrap())
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn test_delete_user_pool_client_not_found() {
        let storage = Storage::new();

        let result = handler(
            &storage,
            json!({
                "UserPoolId": "local_pool123",
                "ClientId": "nonexistent123456789012345"
            }),
        )
        .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_delete_user_pool_client_cascades_client_scoped_data() {
        let storage = Storage::new();

        let pool = create_user_pool::handler(&storage, json!({"PoolName": "test-pool"}))
            .await
            .unwrap();
        let pool_id = pool["UserPool"]["Id"].as_str().unwrap();

        let client = create_user_pool_client::handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "ClientName": "test-client"
            }),
        )
        .await
        .unwrap();
        let client_id = client["UserPoolClient"]["ClientId"].as_str().unwrap();

        create_managed_login_branding::handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "ClientId": client_id
            }),
        )
        .await
        .unwrap();

        let terms = create_terms::handler(
            &storage,
            json!({
                "TermsName": "terms-v1",
                "ClientId": client_id,
                "UserPoolId": pool_id,
                "TermsSource": "https://example.com/terms"
            }),
        )
        .await
        .unwrap();
        let terms_id = terms["Terms"]["TermsId"].as_str().unwrap().to_string();

        set_ui_customization::handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "ClientId": client_id,
                "CSS": "body { color: blue; }"
            }),
        )
        .await
        .unwrap();

        set_risk_configuration::handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "ClientId": client_id,
                "CompromisedCredentialsRiskConfiguration": {
                    "Actions": {
                        "EventAction": "NO_ACTION"
                    }
                }
            }),
        )
        .await
        .unwrap();

        handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "ClientId": client_id
            }),
        )
        .await
        .unwrap();

        let parsed_pool_id = pool_id.parse().unwrap();
        let parsed_client_id = client_id.parse().unwrap();

        assert!(
            storage
                .get_managed_login_branding_by_client(&parsed_client_id)
                .await
                .is_none()
        );
        assert!(storage.get_terms_by_id(&terms_id).await.is_none());
        assert!(
            storage
                .get_ui_customization(&parsed_pool_id, Some(&parsed_client_id))
                .await
                .is_none()
        );
        assert!(
            storage
                .get_risk_configuration(&parsed_pool_id, Some(&parsed_client_id))
                .await
                .is_none()
        );
    }
}
