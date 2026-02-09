//! GetSigningCertificate API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_GetSigningCertificate.html>

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

/// A placeholder self-signed certificate for testing/emulation purposes
const PLACEHOLDER_CERTIFICATE: &str = r#"-----BEGIN CERTIFICATE-----
MIICpDCCAYwCCQDU+pQ4P0xLwDANBgkqhkiG9w0BAQsFADAUMRIwEAYDVQQDDAls
b2NhbGhvc3QwHhcNMjQwMTAxMDAwMDAwWhcNMzQwMTAxMDAwMDAwWjAUMRIwEAYD
VQQDDAlsb2NhbGhvc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC7
o5e7SzmwnTGBdT8qYhP5lO7v/PLACEHOLDER+CERTIFICATE+FOR+TESTING+ONLY
NOT+A+REAL+CERTIFICATE/7h6V5XPLACEHOLDER123456789ABCDEF0123456789
ABC/DEF/GHI/JKL+MNO+PQR+STU+VWX+YZ0123456789+PLACEHOLDER+CERT12
-----END CERTIFICATE-----"#;

pub async fn handler(storage: &Storage, body: Value) -> Result<Value> {
    let req: Request = serde_json::from_value(body)
        .map_err(|e| AppError::InvalidParameter(format!("Invalid request: {}", e)))?;

    // Verify user pool exists
    storage
        .get_user_pool(&req.user_pool_id)
        .await
        .ok_or(AppError::UserPoolNotFound)?;

    // Return a placeholder certificate for emulation
    Ok(json!({
        "Certificate": PLACEHOLDER_CERTIFICATE
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::user_pool::create_user_pool;
    use serde_json::json;

    #[tokio::test]
    async fn test_get_signing_certificate_success() {
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
        assert!(body["Certificate"].as_str().is_some());
        assert!(
            body["Certificate"]
                .as_str()
                .unwrap()
                .contains("BEGIN CERTIFICATE")
        );
    }

    #[tokio::test]
    async fn test_get_signing_certificate_pool_not_found() {
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
