//! ListResourceServers API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_ListResourceServers.html>

use serde::Deserialize;
use serde_json::{Value, json};

use crate::{
    action::{
        pagination::{page_size, paginate},
        user_pool::create_resource_server::build_resource_server_response,
    },
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
    let max_results = page_size(req.max_results, "maxResults", 1, 50)?;

    storage
        .get_user_pool(&req.user_pool_id)
        .await
        .ok_or(AppError::UserPoolNotFound)?;

    let mut resource_servers = storage.list_resource_servers(&req.user_pool_id).await;
    resource_servers.sort_by(|a, b| a.identifier.cmp(&b.identifier));

    let page = paginate(
        resource_servers.len(),
        max_results,
        req.next_token.as_deref(),
    )?;
    let list: Vec<Value> = resource_servers[page.start..page.end]
        .iter()
        .map(build_resource_server_response)
        .collect();

    let mut response = json!({
        "ResourceServers": list
    });
    if let Some(next_token) = page.next_token {
        response["NextToken"] = json!(next_token);
    }

    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::user_pool::{create_resource_server, create_user_pool};
    use serde_json::json;

    #[tokio::test]
    async fn test_list_resource_servers_success() {
        let storage = Storage::new();

        let pool = create_user_pool::handler(&storage, json!({"PoolName": "test-pool"}))
            .await
            .unwrap();
        let user_pool_id = pool["UserPool"]["Id"].as_str().unwrap();

        create_resource_server::handler(
            &storage,
            json!({
                "UserPoolId": user_pool_id,
                "Identifier": "api-1",
                "Name": "API 1"
            }),
        )
        .await
        .unwrap();
        create_resource_server::handler(
            &storage,
            json!({
                "UserPoolId": user_pool_id,
                "Identifier": "api-2",
                "Name": "API 2"
            }),
        )
        .await
        .unwrap();

        let result = handler(
            &storage,
            json!({
                "UserPoolId": user_pool_id
            }),
        )
        .await
        .unwrap();

        assert_eq!(result["ResourceServers"].as_array().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn test_list_resource_servers_with_pagination() {
        let storage = Storage::new();

        let pool = create_user_pool::handler(&storage, json!({"PoolName": "test-pool"}))
            .await
            .unwrap();
        let user_pool_id = pool["UserPool"]["Id"].as_str().unwrap();

        for i in 1..=3 {
            create_resource_server::handler(
                &storage,
                json!({
                    "UserPoolId": user_pool_id,
                    "Identifier": format!("api-{}", i),
                    "Name": format!("API {}", i)
                }),
            )
            .await
            .unwrap();
        }

        let first = handler(
            &storage,
            json!({
                "UserPoolId": user_pool_id,
                "MaxResults": 2
            }),
        )
        .await
        .unwrap();

        assert_eq!(first["ResourceServers"].as_array().unwrap().len(), 2);
        assert!(first["NextToken"].as_str().is_some());

        let second = handler(
            &storage,
            json!({
                "UserPoolId": user_pool_id,
                "MaxResults": 2,
                "NextToken": first["NextToken"]
            }),
        )
        .await
        .unwrap();
        assert_eq!(second["ResourceServers"].as_array().unwrap().len(), 1);
        assert!(second.get("NextToken").is_none());
    }

    #[tokio::test]
    async fn test_list_resource_servers_max_results_is_bounded() {
        let storage = Storage::new();

        let pool = create_user_pool::handler(&storage, json!({"PoolName": "test-pool"}))
            .await
            .unwrap();
        let user_pool_id = pool["UserPool"]["Id"].as_str().unwrap();

        // This operation pages by at most 50.
        let result = handler(
            &storage,
            json!({"UserPoolId": user_pool_id, "MaxResults": 51}),
        )
        .await;
        assert!(matches!(
            result,
            Err(AppError::InvalidParameter(message))
                if message == "1 validation error detected: Value '51' at 'maxResults' failed to satisfy constraint: Member must have value less than or equal to 50"
        ));
    }
}
