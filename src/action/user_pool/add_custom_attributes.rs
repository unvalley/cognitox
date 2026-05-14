//! AddCustomAttributes API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AddCustomAttributes.html>

use serde::Deserialize;
use serde_json::{Value, json};

use crate::{
    error::{AppError, Result},
    storage::Storage,
    types::{SchemaAttributeType, UserPoolId},
    validation::validate_schema_attributes,
};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Request {
    user_pool_id: UserPoolId,
    custom_attributes: Vec<SchemaAttributeType>,
}

pub async fn handler(storage: &Storage, body: Value) -> Result<Value> {
    let req: Request = serde_json::from_value(body)
        .map_err(|e| AppError::InvalidParameter(format!("Invalid request: {}", e)))?;

    // Validate custom attributes
    if req.custom_attributes.is_empty() {
        return Err(AppError::InvalidParameter(
            "CustomAttributes must contain at least one attribute".to_string(),
        ));
    }

    if req.custom_attributes.len() > 25 {
        return Err(AppError::InvalidParameter(
            "CustomAttributes cannot contain more than 25 attributes".to_string(),
        ));
    }

    // Validate attribute names
    validate_schema_attributes(&req.custom_attributes)?;

    for attr in &req.custom_attributes {
        if !attr.name.chars().all(|c| c.is_alphanumeric() || c == '_') {
            return Err(AppError::InvalidParameter(format!(
                "Invalid attribute name: {}",
                attr.name
            )));
        }
    }

    let mut seen = std::collections::HashSet::new();
    for attr in &req.custom_attributes {
        if !seen.insert(attr.name.clone()) {
            return Err(AppError::InvalidParameter(format!(
                "Duplicate custom attribute: {}",
                attr.name
            )));
        }
    }

    storage
        .update_user_pool_with(&req.user_pool_id, |pool| {
            let schema = pool.schema_attributes.get_or_insert_with(Vec::new);
            for attr in &req.custom_attributes {
                if schema.iter().any(|existing| existing.name == attr.name) {
                    return Err(AppError::InvalidParameter(format!(
                        "Custom attribute already exists: {}",
                        attr.name
                    )));
                }
            }
            schema.extend(req.custom_attributes);
            pool.last_modified_date = chrono::Utc::now();
            Ok(())
        })
        .await
        .ok_or(AppError::UserPoolNotFound)??;

    Ok(json!({}))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::user_pool::{create_user_pool, describe_user_pool};
    use serde_json::json;

    #[tokio::test]
    async fn test_add_custom_attributes_success() {
        let storage = Storage::new();

        let pool = create_user_pool::handler(&storage, json!({"PoolName": "test"}))
            .await
            .unwrap();
        let pool_id = pool["UserPool"]["Id"].as_str().unwrap();

        let result = handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "CustomAttributes": [
                    {
                        "Name": "department",
                        "AttributeDataType": "String",
                        "Mutable": true,
                        "Required": false
                    }
                ]
            }),
        )
        .await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), json!({}));

        let described = describe_user_pool::handler(&storage, json!({"UserPoolId": pool_id}))
            .await
            .unwrap();
        let schema = described["UserPool"]["SchemaAttributes"]
            .as_array()
            .unwrap();
        assert!(schema.iter().any(|attr| attr["Name"] == "department"));
    }

    #[tokio::test]
    async fn test_add_custom_attributes_pool_not_found() {
        let storage = Storage::new();

        let result = handler(
            &storage,
            json!({
                "UserPoolId": "local_nonexistent",
                "CustomAttributes": [
                    {
                        "Name": "department",
                        "AttributeDataType": "String"
                    }
                ]
            }),
        )
        .await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AppError::UserPoolNotFound));
    }

    #[tokio::test]
    async fn test_add_custom_attributes_empty_list() {
        let storage = Storage::new();

        let pool = create_user_pool::handler(&storage, json!({"PoolName": "test"}))
            .await
            .unwrap();
        let pool_id = pool["UserPool"]["Id"].as_str().unwrap();

        let result = handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "CustomAttributes": []
            }),
        )
        .await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AppError::InvalidParameter(_)));
    }

    #[tokio::test]
    async fn test_add_custom_attributes_invalid_name() {
        let storage = Storage::new();

        let pool = create_user_pool::handler(&storage, json!({"PoolName": "test"}))
            .await
            .unwrap();
        let pool_id = pool["UserPool"]["Id"].as_str().unwrap();

        let result = handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "CustomAttributes": [
                    {
                        "Name": "invalid-name",
                        "AttributeDataType": "String"
                    }
                ]
            }),
        )
        .await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AppError::InvalidParameter(_)));
    }

    #[tokio::test]
    async fn test_add_custom_attributes_duplicate_existing() {
        let storage = Storage::new();

        let pool = create_user_pool::handler(
            &storage,
            json!({
                "PoolName": "test",
                "Schema": [
                    {
                        "Name": "department",
                        "AttributeDataType": "String"
                    }
                ]
            }),
        )
        .await
        .unwrap();
        let pool_id = pool["UserPool"]["Id"].as_str().unwrap();

        let result = handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "CustomAttributes": [
                    {
                        "Name": "department",
                        "AttributeDataType": "String"
                    }
                ]
            }),
        )
        .await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AppError::InvalidParameter(_)));
    }
}
