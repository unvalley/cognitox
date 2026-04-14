//! SetRiskConfiguration API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_SetRiskConfiguration.html>

use serde::Deserialize;
use serde_json::{Map, Value, json};

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
    #[serde(default)]
    account_takeover_risk_configuration: Option<Value>,
    #[serde(default)]
    compromised_credentials_risk_configuration: Option<Value>,
    #[serde(default)]
    risk_exception_configuration: Option<Value>,
}

pub async fn handler(storage: &Storage, body: Value) -> Result<Value> {
    let req: Request = serde_json::from_value(body.clone())
        .map_err(|e| AppError::InvalidParameter(format!("Invalid request: {}", e)))?;

    storage
        .get_user_pool(&req.user_pool_id)
        .await
        .ok_or(AppError::UserPoolNotFound)?;

    let mut cfg = body
        .as_object()
        .cloned()
        .unwrap_or_else(Map::<String, Value>::new);
    cfg.insert(
        "UserPoolId".to_string(),
        Value::String(req.user_pool_id.to_string()),
    );
    if let Some(client_id) = req.client_id.as_ref() {
        cfg.insert("ClientId".to_string(), Value::String(client_id.to_string()));
    }
    if let Some(value) = req.account_takeover_risk_configuration {
        cfg.insert("AccountTakeoverRiskConfiguration".to_string(), value);
    }
    if let Some(value) = req.compromised_credentials_risk_configuration {
        cfg.insert("CompromisedCredentialsRiskConfiguration".to_string(), value);
    }
    if let Some(value) = req.risk_exception_configuration {
        cfg.insert("RiskExceptionConfiguration".to_string(), value);
    }

    let cfg_value = Value::Object(cfg);
    storage
        .set_risk_configuration(&req.user_pool_id, req.client_id.as_ref(), cfg_value.clone())
        .await;

    Ok(json!({
        "RiskConfiguration": cfg_value
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::user_pool::create_user_pool;

    #[tokio::test]
    async fn test_set_risk_configuration_success() {
        let storage = Storage::new();
        let pool = create_user_pool::handler(&storage, json!({"PoolName": "pool"}))
            .await
            .unwrap();
        let pool_id = pool["UserPool"]["Id"].as_str().unwrap();

        let result = handler(
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

        assert!(result["RiskConfiguration"]["CompromisedCredentialsRiskConfiguration"].is_object());
    }
}
