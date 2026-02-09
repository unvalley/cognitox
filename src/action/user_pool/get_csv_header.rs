//! GetCSVHeader API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_GetCSVHeader.html>

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

/// Default CSV header fields for user import
const CSV_HEADER: &[&str] = &[
    "cognito:username",
    "cognito:mfa_enabled",
    "email_verified",
    "phone_number_verified",
    "email",
    "phone_number",
    "name",
    "given_name",
    "family_name",
    "middle_name",
    "nickname",
    "preferred_username",
    "profile",
    "picture",
    "website",
    "gender",
    "birthdate",
    "zoneinfo",
    "locale",
    "address",
    "updated_at",
];

pub async fn handler(storage: &Storage, body: Value) -> Result<Value> {
    let req: Request = serde_json::from_value(body)
        .map_err(|e| AppError::InvalidParameter(format!("Invalid request: {}", e)))?;

    // Verify user pool exists
    storage
        .get_user_pool(&req.user_pool_id)
        .await
        .ok_or(AppError::UserPoolNotFound)?;

    // Return the CSV header for user import
    Ok(json!({
        "UserPoolId": req.user_pool_id.as_str(),
        "CSVHeader": CSV_HEADER
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::user_pool::create_user_pool;
    use serde_json::json;

    #[tokio::test]
    async fn test_get_csv_header_success() {
        let storage = Storage::new();

        let pool = create_user_pool::handler(&storage, json!({"PoolName": "test"}))
            .await
            .unwrap();
        let pool_id = pool["UserPool"]["Id"].as_str().unwrap();

        let result = handler(
            &storage,
            json!({
                "UserPoolId": pool_id
            }),
        )
        .await;

        assert!(result.is_ok());
        let body = result.unwrap();
        assert_eq!(body["UserPoolId"], pool_id);
        let csv_header = body["CSVHeader"].as_array().unwrap();
        assert!(!csv_header.is_empty());
        assert!(csv_header.iter().any(|h| h == "cognito:username"));
        assert!(csv_header.iter().any(|h| h == "email"));
    }

    #[tokio::test]
    async fn test_get_csv_header_pool_not_found() {
        let storage = Storage::new();

        let result = handler(
            &storage,
            json!({
                "UserPoolId": "local_nonexistent"
            }),
        )
        .await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AppError::UserPoolNotFound));
    }
}
