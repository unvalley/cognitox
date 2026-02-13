//! DeleteUserPool API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_DeleteUserPool.html>

use serde::Deserialize;
use serde_json::{Value, json};

use crate::{
    error::{AppError, Result},
    storage::Storage,
    types::UserPoolId,
};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Request {
    user_pool_id: UserPoolId,
}

pub async fn handler(storage: &Storage, body: Value) -> Result<Value> {
    let req: Request = serde_json::from_value(body)
        .map_err(|e| AppError::InvalidParameter(format!("Invalid request: {}", e)))?;

    storage
        .delete_user_pool(&req.user_pool_id)
        .await
        .ok_or(AppError::UserPoolNotFound)?;

    Ok(json!({}))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::{
        group::{admin_add_user_to_group, create_group},
        user::sign_up,
        user_pool::{
            create_managed_login_branding, create_terms, create_user_pool, create_user_pool_client,
            set_ui_customization,
        },
    };
    use serde_json::json;

    #[tokio::test]
    async fn test_delete_user_pool_success() {
        let storage = Storage::new();

        // Create a user pool first
        let pool = create_user_pool::handler(&storage, json!({"PoolName": "test-pool"}))
            .await
            .unwrap();
        let pool_id = pool["UserPool"]["Id"].as_str().unwrap();

        // Delete the user pool
        let result = handler(&storage, json!({"UserPoolId": pool_id})).await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), json!({}));

        // Verify it's deleted
        assert!(
            storage
                .get_user_pool(&pool_id.parse().unwrap())
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn test_delete_user_pool_not_found() {
        let storage = Storage::new();

        let result = handler(&storage, json!({"UserPoolId": "local_nonexistent123"})).await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_delete_user_pool_missing_id() {
        let storage = Storage::new();

        let result = handler(&storage, json!({})).await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_delete_user_pool_cascades_related_data() {
        let storage = Storage::new();

        let pool = create_user_pool::handler(&storage, json!({"PoolName": "cascade-pool"}))
            .await
            .unwrap();
        let pool_id = pool["UserPool"]["Id"].as_str().unwrap();

        let client = create_user_pool_client::handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "ClientName": "cascade-client"
            }),
        )
        .await
        .unwrap();
        let client_id = client["UserPoolClient"]["ClientId"].as_str().unwrap();

        let sign_up_result = sign_up::handler(
            &storage,
            json!({
                "ClientId": client_id,
                "Username": "cascade-user",
                "Password": "Password123!"
            }),
        )
        .await
        .unwrap();
        let user_id = sign_up_result["UserSub"].as_str().unwrap().parse().unwrap();

        create_group::handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "GroupName": "admins"
            }),
        )
        .await
        .unwrap();

        admin_add_user_to_group::handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "Username": "cascade-user",
                "GroupName": "admins"
            }),
        )
        .await
        .unwrap();

        create_managed_login_branding::handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "UseCognitoProvidedValues": true
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
        let terms_id = terms["Terms"]["TermsId"].as_str().unwrap();

        set_ui_customization::handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "CSS": "body { color: red; }"
            }),
        )
        .await
        .unwrap();

        handler(&storage, json!({"UserPoolId": pool_id}))
            .await
            .unwrap();

        let parsed_pool_id = pool_id.parse().unwrap();
        let parsed_client_id = client_id.parse().unwrap();

        assert!(storage.get_user_pool(&parsed_pool_id).await.is_none());
        assert!(
            storage
                .get_user_pool_client(&parsed_client_id)
                .await
                .is_none()
        );
        assert!(storage.get_user(&user_id).await.is_none());
        assert!(
            storage
                .get_managed_login_branding_by_user_pool(&parsed_pool_id)
                .await
                .is_none()
        );
        assert!(storage.get_terms_by_id(terms_id).await.is_none());
        assert!(
            storage
                .get_ui_customization(&parsed_pool_id, None)
                .await
                .is_none()
        );
        assert!(storage.list_groups(&parsed_pool_id).await.is_empty());
    }
}
