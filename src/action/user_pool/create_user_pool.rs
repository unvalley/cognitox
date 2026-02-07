//! CreateUserPool API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_CreateUserPool.html>

use chrono::Utc;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::{
    error::{AppError, Result},
    storage::Storage,
    types::{UserPool, UserPoolId},
    validation::validate_pool_name,
};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Request {
    pool_name: String,
}

pub async fn handler(storage: &Storage, body: Value) -> Result<Value> {
    let req: Request = serde_json::from_value(body)
        .map_err(|e| AppError::InvalidParameter(format!("Invalid request: {}", e)))?;

    // Validate input
    validate_pool_name(&req.pool_name)?;

    let now = Utc::now();
    let pool_id = UserPoolId::new_local();

    let pool = UserPool {
        id: pool_id,
        name: req.pool_name,
        creation_date: now,
        last_modified_date: now,
    };

    let created = storage.create_user_pool(pool).await;

    Ok(json!({
        "UserPool": {
            "Id": created.id,
            "Name": created.name,
            "CreationDate": created.creation_date.timestamp(),
            "LastModifiedDate": created.last_modified_date.timestamp()
        }
    }))
}
