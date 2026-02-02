//! ListUserPools API implementation

use serde::Deserialize;
use serde_json::{Value, json};

use crate::{
    error::{AppError, Result},
    storage::Storage,
};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Request {
    max_results: Option<u32>,
    #[allow(dead_code)]
    next_token: Option<String>,
}

pub async fn handler(storage: &Storage, body: Value) -> Result<Value> {
    let req: Request = serde_json::from_value(body)
        .map_err(|e| AppError::Internal(format!("Invalid request: {}", e)))?;

    let pools = storage.list_user_pools().await;
    let max_results = req.max_results.unwrap_or(60) as usize;

    let user_pools: Vec<_> = pools
        .into_iter()
        .take(max_results)
        .map(|p| {
            json!({
                "Id": p.id,
                "Name": p.name,
                "CreationDate": p.creation_date.timestamp(),
                "LastModifiedDate": p.last_modified_date.timestamp()
            })
        })
        .collect();

    Ok(json!({
        "UserPools": user_pools
    }))
}
