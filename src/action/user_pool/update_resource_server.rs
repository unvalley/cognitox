//! UpdateResourceServer API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_UpdateResourceServer.html>

use serde::Deserialize;
use serde_json::{Value, json};

use crate::{
    action::user_pool::create_resource_server::build_resource_server_response,
    error::{AppError, Result},
    storage::Storage,
    types::{ResourceServerScope, UserPoolId},
};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Request {
    user_pool_id: UserPoolId,
    identifier: String,
    name: String,
    #[serde(default)]
    scopes: Vec<ScopeInput>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ScopeInput {
    scope_name: String,
    scope_description: String,
}

pub async fn handler(storage: &Storage, body: Value) -> Result<Value> {
    let req: Request = serde_json::from_value(body)
        .map_err(|e| AppError::InvalidParameter(format!("Invalid request: {}", e)))?;

    storage
        .get_user_pool(&req.user_pool_id)
        .await
        .ok_or(AppError::UserPoolNotFound)?;

    let mut resource_server = storage
        .get_resource_server(&req.user_pool_id, &req.identifier)
        .await
        .ok_or(AppError::ResourceServerNotFound)?;

    resource_server.name = req.name;
    resource_server.scopes = req
        .scopes
        .into_iter()
        .map(|scope| ResourceServerScope {
            scope_name: scope.scope_name,
            scope_description: scope.scope_description,
        })
        .collect();

    let updated = storage
        .update_resource_server(resource_server)
        .await
        .ok_or(AppError::ResourceServerNotFound)?;

    Ok(json!({
        "ResourceServer": build_resource_server_response(&updated)
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::user_pool::{create_resource_server, create_user_pool};
    use serde_json::json;

    #[tokio::test]
    async fn test_update_resource_server_success() {
        let storage = Storage::new();

        let pool = create_user_pool::handler(&storage, json!({"PoolName": "test-pool"}))
            .await
            .unwrap();
        let user_pool_id = pool["UserPool"]["Id"].as_str().unwrap();

        create_resource_server::handler(
            &storage,
            json!({
                "UserPoolId": user_pool_id,
                "Identifier": "api",
                "Name": "Old API"
            }),
        )
        .await
        .unwrap();

        let result = handler(
            &storage,
            json!({
                "UserPoolId": user_pool_id,
                "Identifier": "api",
                "Name": "My API"
            }),
        )
        .await
        .unwrap();

        assert_eq!(result["ResourceServer"]["Name"], "My API");
    }
}
