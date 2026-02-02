//! ListUserPoolClients API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_ListUserPoolClients.html>

use serde::Deserialize;
use serde_json::{Value, json};

use crate::{
    error::{AppError, Result},
    storage::Storage,
};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Request {
    user_pool_id: String,
    max_results: Option<u32>,
    #[allow(dead_code)]
    next_token: Option<String>,
}

pub async fn handler(storage: &Storage, body: Value) -> Result<Value> {
    let req: Request = serde_json::from_value(body)
        .map_err(|e| AppError::Internal(format!("Invalid request: {}", e)))?;

    let clients = storage.list_user_pool_clients(&req.user_pool_id).await;
    let max_results = req.max_results.unwrap_or(60) as usize;

    let user_pool_clients: Vec<_> = clients
        .into_iter()
        .take(max_results)
        .map(|c| {
            json!({
                "ClientId": c.client_id,
                "UserPoolId": c.user_pool_id,
                "ClientName": c.client_name
            })
        })
        .collect();

    Ok(json!({
        "UserPoolClients": user_pool_clients
    }))
}
