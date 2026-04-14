//! DescribeRiskConfiguration API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_DescribeRiskConfiguration.html>

use serde::Deserialize;
use serde_json::{Value, json};

use crate::{
    error::{AppError, Result},
    storage::Storage,
    types::{ClientId, UserPoolId},
};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Request {
    user_pool_id: UserPoolId,
    #[serde(default)]
    client_id: Option<ClientId>,
}

pub async fn handler(storage: &Storage, body: Value) -> Result<Value> {
    let req: Request = serde_json::from_value(body)
        .map_err(|e| AppError::InvalidParameter(format!("Invalid request: {}", e)))?;

    storage
        .get_user_pool(&req.user_pool_id)
        .await
        .ok_or(AppError::UserPoolNotFound)?;

    let cfg = storage
        .get_risk_configuration(&req.user_pool_id, req.client_id.as_ref())
        .await
        .unwrap_or_else(|| {
            json!({
                "UserPoolId": req.user_pool_id,
                "ClientId": req.client_id,
            })
        });

    Ok(json!({
        "RiskConfiguration": cfg
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::user_pool::{create_user_pool, set_risk_configuration};

    #[tokio::test]
    async fn test_describe_risk_configuration_success() {
        let storage = Storage::new();
        let pool = create_user_pool::handler(&storage, json!({"PoolName": "pool"}))
            .await
            .unwrap();
        let pool_id = pool["UserPool"]["Id"].as_str().unwrap();

        set_risk_configuration::handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "CompromisedCredentialsRiskConfiguration": {
                    "Actions": {"EventAction": "BLOCK"}
                }
            }),
        )
        .await
        .unwrap();

        let result = handler(&storage, json!({"UserPoolId": pool_id}))
            .await
            .unwrap();

        assert!(result["RiskConfiguration"]["CompromisedCredentialsRiskConfiguration"].is_object());
    }
}
