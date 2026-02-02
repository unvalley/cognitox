//! CreateUserPoolClient API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_CreateUserPoolClient.html>

use chrono::Utc;
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::{
    error::{AppError, Result},
    storage::Storage,
    types::UserPoolClient,
};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Request {
    user_pool_id: String,
    client_name: String,
    generate_secret: Option<bool>,
}

pub async fn handler(storage: &Storage, body: Value) -> Result<Value> {
    let req: Request = serde_json::from_value(body)
        .map_err(|e| AppError::Internal(format!("Invalid request: {}", e)))?;

    storage
        .get_user_pool(&req.user_pool_id)
        .await
        .ok_or(AppError::UserPoolNotFound)?;

    let now = Utc::now();
    let client_id = Uuid::new_v4().to_string().replace("-", "")[..26].to_string();
    let client_secret = if req.generate_secret.unwrap_or(false) {
        Some(Uuid::new_v4().to_string())
    } else {
        None
    };

    let client = UserPoolClient {
        client_id,
        user_pool_id: req.user_pool_id,
        client_name: req.client_name,
        client_secret: client_secret.clone(),
        creation_date: now,
        last_modified_date: now,
    };

    let created = storage.create_user_pool_client(client).await;

    let mut response = json!({
        "UserPoolClient": {
            "ClientId": created.client_id,
            "UserPoolId": created.user_pool_id,
            "ClientName": created.client_name,
            "CreationDate": created.creation_date.timestamp(),
            "LastModifiedDate": created.last_modified_date.timestamp()
        }
    });

    if let Some(secret) = client_secret {
        response["UserPoolClient"]["ClientSecret"] = json!(secret);
    }

    Ok(response)
}
