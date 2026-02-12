//! DescribeResourceServer API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_DescribeResourceServer.html>

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
    identifier: String,
}

pub async fn handler(storage: &Storage, body: Value) -> Result<Value> {
    let req: Request = serde_json::from_value(body)
        .map_err(|e| AppError::InvalidParameter(format!("Invalid request: {}", e)))?;

    storage
        .get_user_pool(&req.user_pool_id)
        .await
        .ok_or(AppError::UserPoolNotFound)?;

    let resource_server = storage
        .get_resource_server(&req.user_pool_id, &req.identifier)
        .await
        .ok_or(AppError::ResourceServerNotFound)?;

    Ok(json!({
        "ResourceServer": build_resource_server_response(&resource_server)
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::user_pool::{create_resource_server, create_user_pool};
    use serde_json::json;

    #[tokio::test]
    async fn test_describe_resource_server_success() {
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
                "Name": "ResourceServer"
            }),
        )
        .await
        .unwrap();

        let result = handler(
            &storage,
            json!({
                "UserPoolId": user_pool_id,
                "Identifier": "api"
            }),
        )
        .await
        .unwrap();

        assert_eq!(result["ResourceServer"]["Identifier"], "api");
        assert_eq!(result["ResourceServer"]["Name"], "ResourceServer");
    }
}
