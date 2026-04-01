//! SetUICustomization API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_SetUICustomization.html>

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
    #[serde(default, rename = "CSS")]
    css: Option<String>,
    #[serde(default, rename = "ImageFile")]
    image_file: Option<String>,
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

    if let Some(client_id) = req.client_id.as_ref() {
        storage
            .get_user_pool_client(client_id)
            .await
            .ok_or(AppError::UserPoolClientNotFound)?;
    }

    let now = Utc::now();
    let current = storage
        .get_ui_customization(&req.user_pool_id, req.client_id.as_ref())
        .await;

    let customization = UiCustomization {
        user_pool_id: req.user_pool_id,
        client_id: req.client_id,
        css: req.css,
        css_version: uuid::Uuid::now_v7().to_string(),
        image_url: req
            .image_file
            .map(|_| "/ui/customization/logo.png".to_string()),
        creation_date: current.as_ref().map(|c| c.creation_date).unwrap_or(now),
        last_modified_date: now,
    };

    let saved = storage.set_ui_customization(customization).await;

    Ok(json!({"UICustomization": to_json(&saved)}))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::user_pool::{create_user_pool, set_ui_customization};

    #[tokio::test]
    async fn test_set_ui_customization_success() {
        let storage = Storage::new();
        let pool = create_user_pool::handler(&storage, json!({"PoolName": "pool"}))
            .await
            .unwrap();
        let pool_id = pool["UserPool"]["Id"].as_str().unwrap();

        let result = set_ui_customization::handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "CSS": ".banner { color: red; }"
            }),
        )
        .await
        .unwrap();

        assert_eq!(result["UICustomization"]["CSS"], ".banner { color: red; }");
    }
}
