//! ListResourceServers API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_ListResourceServers.html>

use serde::Deserialize;
use serde_json::{Value, json};

use crate::{
    action::user_pool::create_resource_server::build_resource_server_response,
    error::{AppError, Result},
    storage::Storage,
    types::UserPoolId,
};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Request {
    user_pool_id: UserPoolId,
    max_results: Option<u32>,
    next_token: Option<String>,
}

pub async fn handler(storage: &Storage, body: Value) -> Result<Value> {
    let req: Request = serde_json::from_value(body)
        .map_err(|e| AppError::InvalidParameter(format!("Invalid request: {}", e)))?;

    storage
        .get_user_pool(&req.user_pool_id)
        .await
        .ok_or(AppError::UserPoolNotFound)?;

    let mut resource_servers = storage.list_resource_servers(&req.user_pool_id).await;
    resource_servers.sort_by(|a, b| a.identifier.cmp(&b.identifier));

    let max_results = req.max_results.unwrap_or(60) as usize;
    if max_results == 0 {
        return Err(AppError::InvalidParameter(
            "MaxResults must be greater than 0".to_string(),
        ));
    }

    let start = req
        .next_token
        .as_deref()
        .map(|token| {
            token
                .parse::<usize>()
                .map_err(|_| AppError::InvalidParameter("Invalid NextToken".to_string()))
        })
        .transpose()?
        .unwrap_or(0);

    if start > resource_servers.len() {
        return Err(AppError::InvalidParameter("Invalid NextToken".to_string()));
    }

    let end = (start + max_results).min(resource_servers.len());
    let list: Vec<Value> = resource_servers[start..end]
        .iter()
        .map(build_resource_server_response)
        .collect();

    let mut response = json!({
        "ResourceServers": list
    });
    if end < resource_servers.len() {
        response["NextToken"] = json!(end.to_string());
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
    }
}
