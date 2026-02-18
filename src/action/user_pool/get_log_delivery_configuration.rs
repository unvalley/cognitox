//! GetLogDeliveryConfiguration API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_GetLogDeliveryConfiguration.html>

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
}

pub async fn handler(storage: &Storage, body: Value) -> Result<Value> {
    let req: Request = serde_json::from_value(body)
        .map_err(|e| AppError::InvalidParameter(format!("Invalid request: {}", e)))?;

    storage
        .get_user_pool(&req.user_pool_id)
        .await
        .ok_or(AppError::UserPoolNotFound)?;

    let log_configurations = storage
        .get_log_delivery_configuration(&req.user_pool_id)
        .await
        .unwrap_or_default();

    Ok(json!({
        "LogDeliveryConfiguration": {
            "UserPoolId": req.user_pool_id,
            "LogConfigurations": log_configurations
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::user_pool::{
        create_user_pool, get_log_delivery_configuration, set_log_delivery_configuration,
    };

    #[tokio::test]
    async fn test_get_log_delivery_configuration_success() {
        let storage = Storage::new();
        let pool = create_user_pool::handler(&storage, json!({"PoolName": "pool"}))
            .await
            .unwrap();
        let pool_id = pool["UserPool"]["Id"].as_str().unwrap();

        set_log_delivery_configuration::handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "LogConfigurations": [{"LogLevel": "INFO"}]
            }),
        )
        .await
        .unwrap();

        let result =
            get_log_delivery_configuration::handler(&storage, json!({"UserPoolId": pool_id}))
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
