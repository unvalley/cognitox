//! ListUserPoolClients API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_ListUserPoolClients.html>

use serde::Deserialize;
use serde_json::{Value, json};

use crate::{
    action::pagination::{page_size, paginate},
    error::{AppError, Result},
    storage::Storage,
    types::UserPoolId,
};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Request {
    user_pool_id: UserPoolId,
    max_results: Option<i32>,
    next_token: Option<String>,
}

pub async fn handler(storage: &Storage, body: Value) -> Result<Value> {
    let req: Request = crate::action::io::parse_request(body)?;
    let max_results = page_size(req.max_results, "maxResults", 1, 60)?;

    storage
        .get_user_pool(&req.user_pool_id)
        .await
        .ok_or(AppError::UserPoolNotFound)?;

    let mut clients = storage.list_user_pool_clients(&req.user_pool_id).await;
    clients.sort_by(|a, b| a.client_id.as_str().cmp(b.client_id.as_str()));

    let page = paginate(clients.len(), max_results, req.next_token.as_deref())?;
    let user_pool_clients: Vec<_> = clients[page.start..page.end]
        .iter()
        .map(|c| {
            json!({
                "ClientId": c.client_id,
                "UserPoolId": c.user_pool_id,
                "ClientName": c.client_name
            })
        })
        .collect();

    let mut response = json!({
        "UserPoolClients": user_pool_clients
    });
    if let Some(next_token) = page.next_token {
        response["NextToken"] = json!(next_token);
    }

    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::user_pool::{create_user_pool, create_user_pool_client};
    use serde_json::json;

    #[tokio::test]
    async fn test_list_user_pool_clients_empty() {
        let storage = Storage::new();

        let pool = create_user_pool::handler(&storage, json!({"PoolName": "test-pool"}))
            .await
            .unwrap();
        let pool_id = pool["UserPool"]["Id"].as_str().unwrap();

        let result = handler(&storage, json!({"UserPoolId": pool_id})).await;

        assert!(result.is_ok());
        let body = result.unwrap();
        assert_eq!(body["UserPoolClients"].as_array().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn test_list_user_pool_clients_success() {
        let storage = Storage::new();

        let pool = create_user_pool::handler(&storage, json!({"PoolName": "test-pool"}))
            .await
            .unwrap();
        let pool_id = pool["UserPool"]["Id"].as_str().unwrap();

        // Create some clients
        create_user_pool_client::handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "ClientName": "client-1"
            }),
        )
        .await
        .unwrap();
        create_user_pool_client::handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "ClientName": "client-2"
            }),
        )
        .await
        .unwrap();

        let result = handler(&storage, json!({"UserPoolId": pool_id})).await;

        assert!(result.is_ok());
        let body = result.unwrap();
        assert_eq!(body["UserPoolClients"].as_array().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn test_list_user_pool_clients_with_max_results() {
        let storage = Storage::new();

        let pool = create_user_pool::handler(&storage, json!({"PoolName": "test-pool"}))
            .await
            .unwrap();
        let pool_id = pool["UserPool"]["Id"].as_str().unwrap();

        // Create three clients
        for i in 1..=3 {
            create_user_pool_client::handler(
                &storage,
                json!({
                    "UserPoolId": pool_id,
                    "ClientName": format!("client-{}", i)
                }),
            )
            .await
            .unwrap();
        }

        let result = handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "MaxResults": 2
            }),
        )
        .await;

        assert!(result.is_ok());
        let body = result.unwrap();
        assert_eq!(body["UserPoolClients"].as_array().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn test_list_user_pool_clients_with_pagination() {
        let storage = Storage::new();

        let pool = create_user_pool::handler(&storage, json!({"PoolName": "test-pool"}))
            .await
            .unwrap();
        let pool_id = pool["UserPool"]["Id"].as_str().unwrap();

        for i in 1..=3 {
            create_user_pool_client::handler(
                &storage,
                json!({
                    "UserPoolId": pool_id,
                    "ClientName": format!("client-{}", i)
                }),
            )
            .await
            .unwrap();
        }

        let first = handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "MaxResults": 2
            }),
        )
        .await
        .unwrap();

        assert_eq!(first["UserPoolClients"].as_array().unwrap().len(), 2);
        assert_eq!(first["NextToken"], "2");

        let second = handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "MaxResults": 2,
                "NextToken": "2"
            }),
        )
        .await
        .unwrap();

        assert_eq!(second["UserPoolClients"].as_array().unwrap().len(), 1);
        // The last page carries no token at all.
        assert!(second.get("NextToken").is_none());
    }

    #[tokio::test]
    async fn test_list_user_pool_clients_max_results_is_bounded() {
        let storage = Storage::new();

        let pool = create_user_pool::handler(&storage, json!({"PoolName": "test-pool"}))
            .await
            .unwrap();
        let pool_id = pool["UserPool"]["Id"].as_str().unwrap();

        for (value, relation) in [
            (0, "greater than or equal to 1"),
            (61, "less than or equal to 60"),
        ] {
            let result = handler(
                &storage,
                json!({"UserPoolId": pool_id, "MaxResults": value}),
            )
            .await;
            assert!(matches!(
                result,
                Err(AppError::InvalidParameter(message))
                    if message == format!("1 validation error detected: Value '{value}' at 'maxResults' failed to satisfy constraint: Member must have value {relation}")
            ));
        }
    }
}
