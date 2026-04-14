//! GetUICustomization API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_GetUICustomization.html>

use chrono::Utc;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::{
    error::{AppError, Result},
    storage::Storage,
    types::{ClientId, UiCustomization, UserPoolId},
};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Request {
    user_pool_id: UserPoolId,
    #[serde(default)]
    client_id: Option<ClientId>,
}

fn to_json(customization: &UiCustomization) -> Value {
    json!({
        "UserPoolId": customization.user_pool_id,
        "ClientId": customization.client_id,
        "CSS": customization.css,
        "CSSVersion": customization.css_version,
        "ImageUrl": customization.image_url,
        "CreationDate": customization.creation_date.timestamp(),
        "LastModifiedDate": customization.last_modified_date.timestamp()
    })
}

pub async fn handler(storage: &Storage, body: Value) -> Result<Value> {
    let req: Request = serde_json::from_value(body)
        .map_err(|e| AppError::InvalidParameter(format!("Invalid request: {}", e)))?;

    storage
        .get_user_pool(&req.user_pool_id)
        .await
        .ok_or(AppError::UserPoolNotFound)?;

    let customization = storage
        .get_ui_customization(&req.user_pool_id, req.client_id.as_ref())
        .await
        .unwrap_or(UiCustomization {
            user_pool_id: req.user_pool_id,
            client_id: req.client_id,
            css: None,
            css_version: "0".to_string(),
            image_url: None,
            creation_date: Utc::now(),
            last_modified_date: Utc::now(),
        });

    Ok(json!({
        "UICustomization": to_json(&customization)
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::user_pool::{create_user_pool, get_ui_customization, set_ui_customization};

    #[tokio::test]
    async fn test_get_ui_customization_success() {
        let storage = Storage::new();
        let pool = create_user_pool::handler(&storage, json!({"PoolName": "pool"}))
            .await
            .unwrap();
        let pool_id = pool["UserPool"]["Id"].as_str().unwrap();

        set_ui_customization::handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "CSS": ".banner { color: red; }"
            }),
        )
        .await
        .unwrap();

        let result = get_ui_customization::handler(&storage, json!({"UserPoolId": pool_id}))
            .await
            .unwrap();

        assert_eq!(result["UICustomization"]["CSS"], ".banner { color: red; }");
    }
}
