//! DescribeUserPool API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_DescribeUserPool.html>

use serde::Deserialize;
use serde_json::{Value, json};

use crate::{
    action::{io::parse_request, user_pool::create_user_pool::build_user_pool_view},
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
    let req: Request = parse_request(body)?;

    if !storage.user_pool_exists(&req.user_pool_id).await {
        return Err(AppError::UserPoolNotFound);
    }

    let estimated_number_of_users = storage.count_users(&req.user_pool_id).await;
    let mut user_pool = storage
        .with_user_pool(&req.user_pool_id, |pool| {
            build_user_pool_view(pool, estimated_number_of_users)
        })
        .await
        .ok_or(AppError::UserPoolNotFound)?;

    // A pool with a hosted UI domain names it: the prefix as `Domain`, a
    // domain with its own certificate as `CustomDomain`.
    if let Some(domain) = storage
        .get_user_pool_domain_by_user_pool_id(&req.user_pool_id)
        .await
    {
        let member = if domain.custom_domain_config.is_some() {
            "CustomDomain"
        } else {
            "Domain"
        };
        user_pool[member] = json!(domain.domain);
    }

    Ok(json!({
        "UserPool": user_pool
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::user_pool::create_user_pool;
    use serde_json::json;

    #[tokio::test]
    async fn test_describe_user_pool_success() {
        let storage = Storage::new();

        let pool = create_user_pool::handler(&storage, json!({"PoolName": "test-pool"}))
            .await
            .unwrap();
        let pool_id = pool["UserPool"]["Id"].as_str().unwrap();

        let result = handler(&storage, json!({"UserPoolId": pool_id})).await;

        assert!(result.is_ok());
        let body = result.unwrap();
        assert_eq!(body["UserPool"]["Id"], pool_id);
        assert_eq!(body["UserPool"]["Name"], "test-pool");
        assert!(body["UserPool"]["CreationDate"].is_number());
        assert!(body["UserPool"]["LastModifiedDate"].is_number());
    }

    #[tokio::test]
    async fn test_describe_user_pool_not_found() {
        let storage = Storage::new();

        let result = handler(&storage, json!({"UserPoolId": "local_nonexistent123"})).await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_describe_user_pool_missing_id() {
        let storage = Storage::new();

        let result = handler(&storage, json!({})).await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_describe_user_pool_returns_saved_configuration() {
        let storage = Storage::new();

        let pool = create_user_pool::handler(
            &storage,
            json!({
                "PoolName": "configured-pool",
                "AliasAttributes": ["email"],
                "MfaConfiguration": "OPTIONAL",
                "UserPoolTier": "ESSENTIALS"
            }),
        )
        .await
        .unwrap();
        let pool_id = pool["UserPool"]["Id"].as_str().unwrap();

        let body = handler(&storage, json!({"UserPoolId": pool_id}))
            .await
            .unwrap();

        assert_eq!(body["UserPool"]["AliasAttributes"], json!(["email"]));
        assert_eq!(body["UserPool"]["MfaConfiguration"], "OPTIONAL");
        assert_eq!(body["UserPool"]["UserPoolTier"], "ESSENTIALS");
    }

    #[tokio::test]
    async fn test_describe_user_pool_returns_cognitos_defaults() {
        let storage = Storage::new();

        let pool = create_user_pool::handler(&storage, json!({"PoolName": "bare-pool"}))
            .await
            .unwrap();
        let pool_id = pool["UserPool"]["Id"].as_str().unwrap();

        let body = handler(&storage, json!({"UserPoolId": pool_id}))
            .await
            .unwrap();
        let described = &body["UserPool"];

        // What creation returned is what the pool keeps reporting.
        let mut created = pool["UserPool"].clone();
        created["LastModifiedDate"] = described["LastModifiedDate"].clone();
        assert_eq!(&created, described);

        let region = pool_id.split_once('_').unwrap().0;
        assert_eq!(
            described["Arn"],
            format!("arn:aws:cognito-idp:{region}:000000000000:userpool/{pool_id}")
        );
        assert_eq!(
            described["Policies"],
            json!({
                "PasswordPolicy": {
                    "MinimumLength": 8,
                    "RequireUppercase": true,
                    "RequireLowercase": true,
                    "RequireNumbers": true,
                    "RequireSymbols": true,
                    "TemporaryPasswordValidityDays": 7
                },
                "SignInPolicy": {
                    "AllowedFirstAuthFactors": ["PASSWORD"]
                }
            })
        );
        assert_eq!(described["MfaConfiguration"], "OFF");
        assert_eq!(described["DeletionProtection"], "INACTIVE");
        assert_eq!(described["LambdaConfig"], json!({}));
        assert_eq!(described["UserPoolTier"], "ESSENTIALS");
        assert_eq!(described["EstimatedNumberOfUsers"], 0);
        assert_eq!(
            described["VerificationMessageTemplate"],
            json!({"DefaultEmailOption": "CONFIRM_WITH_CODE"})
        );
        assert_eq!(
            described["EmailConfiguration"],
            json!({"EmailSendingAccount": "COGNITO_DEFAULT"})
        );
        assert_eq!(
            described["AdminCreateUserConfig"],
            json!({
                "AllowAdminCreateUserOnly": false,
                "UnusedAccountValidityDays": 7
            })
        );
        assert_eq!(
            described["AccountRecoverySetting"],
            json!({
                "RecoveryMechanisms": [
                    {"Name": "verified_email", "Priority": 1},
                    {"Name": "verified_phone_number", "Priority": 2}
                ]
            })
        );
        assert_eq!(
            described["UsernameConfiguration"],
            json!({"CaseSensitive": true})
        );

        let schema = described["SchemaAttributes"].as_array().unwrap();
        assert_eq!(schema.len(), 21);
        assert_eq!(
            schema[0],
            json!({
                "Name": "sub",
                "AttributeDataType": "String",
                "DeveloperOnlyAttribute": false,
                "Mutable": false,
                "Required": true,
                "StringAttributeConstraints": {"MinLength": "1", "MaxLength": "2048"}
            })
        );
        // Nothing the caller did not set is reported as configured.
        for member in ["AutoVerifiedAttributes", "AliasAttributes", "Domain"] {
            assert!(described.get(member).is_none(), "{member} should be absent");
        }
    }

    #[tokio::test]
    async fn test_describe_user_pool_names_its_domain() {
        let storage = Storage::new();

        let pool = create_user_pool::handler(&storage, json!({"PoolName": "domain-pool"}))
            .await
            .unwrap();
        let pool_id = pool["UserPool"]["Id"].as_str().unwrap();
        crate::action::user_pool::create_user_pool_domain::handler(
            &storage,
            json!({"UserPoolId": pool_id, "Domain": "my-prefix"}),
        )
        .await
        .unwrap();

        let body = handler(&storage, json!({"UserPoolId": pool_id}))
            .await
            .unwrap();
        assert_eq!(body["UserPool"]["Domain"], "my-prefix");
        assert!(body["UserPool"].get("CustomDomain").is_none());
    }

    #[tokio::test]
    async fn test_describe_user_pool_completes_a_pool_from_an_older_snapshot() {
        let storage = Storage::new();
        let id: UserPoolId = "us-east-1_Legacy".parse().unwrap();
        // Stored before the emulator recorded Cognito's defaults.
        storage
            .create_user_pool(crate::types::UserPool::new_for_test(id.clone()))
            .await;

        let body = handler(&storage, json!({"UserPoolId": id})).await.unwrap();
        let described = &body["UserPool"];
        assert_eq!(described["MfaConfiguration"], "OFF");
        assert_eq!(described["Policies"]["PasswordPolicy"]["MinimumLength"], 8);
        assert_eq!(described["SchemaAttributes"].as_array().unwrap().len(), 21);
    }
}
