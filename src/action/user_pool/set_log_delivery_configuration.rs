//! SetLogDeliveryConfiguration API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_SetLogDeliveryConfiguration.html>

use serde::Deserialize;
use serde_json::{Value, json};

use crate::{
    error::{AppError, Result},
    storage::Storage,
    types::UserPoolId,
};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Request {
    user_pool_id: UserPoolId,
    #[serde(default)]
    log_configurations: Vec<Value>,
}

pub async fn handler(storage: &Storage, body: Value) -> Result<Value> {
    let req: Request = serde_json::from_value(body)
        .map_err(|e| AppError::InvalidParameter(format!("Invalid request: {}", e)))?;

    storage
        .get_user_pool(&req.user_pool_id)
        .await
        .ok_or(AppError::UserPoolNotFound)?;

    storage
        .set_log_delivery_configuration(&req.user_pool_id, req.log_configurations.clone())
        .await;

    Ok(json!({
        "LogDeliveryConfiguration": {
            "UserPoolId": req.user_pool_id,
            "LogConfigurations": req.log_configurations
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::user_pool::create_user_pool;

    #[tokio::test]
    async fn test_set_log_delivery_configuration_success() {
        let storage = Storage::new();
        let pool = create_user_pool::handler(&storage, json!({"PoolName": "pool"}))
            .await
            .unwrap();
        let pool_id = pool["UserPool"]["Id"].as_str().unwrap();

        let result = handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "LogConfigurations": [{"LogLevel": "INFO"}]
            }),
        )
        .await
        .unwrap();

        assert_eq!(
            result["LogDeliveryConfiguration"]["LogConfigurations"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
    }
}
