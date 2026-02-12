//! CreateResourceServer API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_CreateResourceServer.html>

use serde::Deserialize;
use serde_json::{Value, json};

use crate::{
    error::{AppError, Result},
    storage::Storage,
    types::{ResourceServer, ResourceServerScope, UserPoolId},
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

    if req.identifier.trim().is_empty() {
        return Err(AppError::InvalidParameter(
            "Identifier must not be empty".to_string(),
        ));
    }
    if req.name.trim().is_empty() {
        return Err(AppError::InvalidParameter(
            "Name must not be empty".to_string(),
        ));
    }
    if storage
        .get_resource_server(&req.user_pool_id, &req.identifier)
        .await
        .is_some()
    {
        return Err(AppError::ResourceServerAlreadyExists);
    }

    let resource_server = ResourceServer {
        user_pool_id: req.user_pool_id,
        identifier: req.identifier,
        name: req.name,
        scopes: req
            .scopes
            .into_iter()
            .map(|scope| ResourceServerScope {
                scope_name: scope.scope_name,
                scope_description: scope.scope_description,
            })
            .collect(),
    };
    let created = storage.create_resource_server(resource_server).await;

    Ok(json!({
        "ResourceServer": build_resource_server_response(&created)
    }))
}

pub(crate) fn build_resource_server_response(resource_server: &ResourceServer) -> Value {
    let scopes: Vec<Value> = resource_server
        .scopes
        .iter()
        .map(|scope| {
            json!({
                "ScopeName": scope.scope_name,
                "ScopeDescription": scope.scope_description
            })
        })
        .collect();

    json!({
        "UserPoolId": resource_server.user_pool_id,
        "Identifier": resource_server.identifier,
        "Name": resource_server.name,
        "Scopes": scopes
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::user_pool::create_user_pool;
    use serde_json::json;

    #[tokio::test]
    async fn test_create_resource_server_success() {
        let storage = Storage::new();

        let pool = create_user_pool::handler(&storage, json!({"PoolName": "test-pool"}))
            .await
            .unwrap();
        let user_pool_id = pool["UserPool"]["Id"].as_str().unwrap();

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

        assert_eq!(result["ResourceServer"]["Identifier"], "api");
        assert_eq!(result["ResourceServer"]["Name"], "My API");
    }
}
