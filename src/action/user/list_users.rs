//! ListUsers API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_ListUsers.html>

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
    limit: Option<u32>,
}

pub async fn handler(storage: &Storage, body: Value) -> Result<Value> {
    let req: Request = serde_json::from_value(body)
        .map_err(|e| AppError::InvalidParameter(format!("Invalid request: {}", e)))?;

    storage
        .get_user_pool(&req.user_pool_id)
        .await
        .ok_or(AppError::UserPoolNotFound)?;

    let users = storage.list_users(&req.user_pool_id).await;
    let limit = req.limit.unwrap_or(60) as usize;

    let users_json: Vec<_> = users
        .into_iter()
        .take(limit)
        .map(|u| {
            json!({
                "Username": u.username,
                "Enabled": u.enabled,
                "UserStatus": u.user_status,
                "UserCreateDate": u.creation_date.timestamp(),
                "UserLastModifiedDate": u.last_modified_date.timestamp(),
                "Attributes": u.attributes.iter().map(|a| {
                    json!({
                        "Name": a.name,
                        "Value": a.value
                    })
                }).collect::<Vec<_>>()
            })
        })
        .collect();

    Ok(json!({
        "Users": users_json
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    use crate::action::user::sign_up;
    use crate::action::user_pool::{create_user_pool, create_user_pool_client};

    async fn setup_pool_and_client(storage: &Storage) -> (String, String) {
        let pool = create_user_pool::handler(storage, json!({"PoolName": "test"}))
            .await
            .unwrap();
        let pool_id = pool["UserPool"]["Id"].as_str().unwrap().to_string();

        let client = create_user_pool_client::handler(
            storage,
            json!({
                "UserPoolId": pool_id,
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
    async fn test_list_users_success() {
        let storage = Storage::new();
        let (pool_id, client_id) = setup_pool_and_client(&storage).await;

        // Create a few users
        for i in 0..3 {
            sign_up::handler(
                &storage,
                json!({
                    "ClientId": client_id,
                    "Username": format!("testuser{}", i),
                    "Password": "Password123!"
                }),
            )
            .await
            .unwrap();
        }

        let result = handler(
            &storage,
            json!({
                "UserPoolId": pool_id
            }),
        )
        .await;

        assert!(result.is_ok());
        let body = result.unwrap();
        let users = body["Users"].as_array().unwrap();
        assert_eq!(users.len(), 3);
    }

    #[tokio::test]
    async fn test_list_users_with_limit() {
        let storage = Storage::new();
        let (pool_id, client_id) = setup_pool_and_client(&storage).await;

        // Create several users
        for i in 0..5 {
            sign_up::handler(
                &storage,
                json!({
                    "ClientId": client_id,
                    "Username": format!("testuser{}", i),
                    "Password": "Password123!"
                }),
            )
            .await
            .unwrap();
        }

        let result = handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "Limit": 2
            }),
        )
        .await;

        assert!(result.is_ok());
        let body = result.unwrap();
        let users = body["Users"].as_array().unwrap();
        assert_eq!(users.len(), 2);
    }

    #[tokio::test]
    async fn test_list_users_empty_pool() {
        let storage = Storage::new();
        let (pool_id, _client_id) = setup_pool_and_client(&storage).await;

        let result = handler(
            &storage,
            json!({
                "UserPoolId": pool_id
            }),
        )
        .await;

        assert!(result.is_ok());
        let body = result.unwrap();
        let users = body["Users"].as_array().unwrap();
        assert!(users.is_empty());
    }
}
