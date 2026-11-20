//! CreateGroup API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_CreateGroup.html>

use chrono::Utc;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::{
    action::group::build_group_response,
    error::{AppError, Result},
    storage::Storage,
    types::{Group, UserPoolId},
    validation::{validate_group_name, validate_group_settings},
};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Request {
    user_pool_id: UserPoolId,
    group_name: String,
    description: Option<String>,
    role_arn: Option<String>,
    precedence: Option<i32>,
}

pub async fn handler(storage: &Storage, body: Value) -> Result<Value> {
    let req: Request = crate::action::io::parse_request(body)?;

    // Validate input
    validate_group_name(&req.group_name)?;
    validate_group_settings(
        req.description.as_deref(),
        req.role_arn.as_deref(),
        req.precedence,
    )?;

    storage
        .get_user_pool(&req.user_pool_id)
        .await
        .ok_or(AppError::UserPoolNotFound)?;

    if storage
        .get_group(&req.user_pool_id, &req.group_name)
        .await
        .is_some()
    {
        return Err(AppError::GroupAlreadyExists);
    }

    let now = Utc::now();
    let group = Group {
        group_name: req.group_name,
        user_pool_id: req.user_pool_id,
        description: req.description,
        role_arn: req.role_arn,
        precedence: req.precedence,
        creation_date: now,
        last_modified_date: now,
    };

    let created = storage.create_group(group).await;

    Ok(json!({
        "Group": build_group_response(&created)
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::user_pool::create_user_pool;
    use serde_json::json;

    #[tokio::test]
    async fn test_create_group_success() {
        let storage = Storage::new();

        let pool = create_user_pool::handler(&storage, json!({"PoolName": "test-pool"}))
            .await
            .unwrap();
        let pool_id = pool["UserPool"]["Id"].as_str().unwrap();

        let result = handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "GroupName": "admins",
                "Description": "Admin group",
                "Precedence": 1
            }),
        )
        .await;

        assert!(result.is_ok());
        let body = result.unwrap();
        assert_eq!(body["Group"]["GroupName"], "admins");
        assert_eq!(body["Group"]["Description"], "Admin group");
        assert_eq!(body["Group"]["Precedence"], 1);
        // No role was given, so the group has no RoleArn member.
        assert!(body["Group"].get("RoleArn").is_none());
        assert!(body["Group"]["CreationDate"].is_number());
    }

    #[tokio::test]
    async fn test_create_group_duplicate() {
        let storage = Storage::new();

        let pool = create_user_pool::handler(&storage, json!({"PoolName": "test-pool"}))
            .await
            .unwrap();
        let pool_id = pool["UserPool"]["Id"].as_str().unwrap();

        handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "GroupName": "admins"
            }),
        )
        .await
        .unwrap();

        let result = handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "GroupName": "admins"
            }),
        )
        .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_create_group_pool_not_found() {
        let storage = Storage::new();

        let result = handler(
            &storage,
            json!({
                "UserPoolId": "local_nonexistent",
                "GroupName": "admins"
            }),
        )
        .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_create_group_reports_constraint_violations_like_cognito() {
        let storage = Storage::new();

        let pool = create_user_pool::handler(&storage, json!({"PoolName": "test-pool"}))
            .await
            .unwrap();
        let pool_id = pool["UserPool"]["Id"].as_str().unwrap();

        let message = |result: Result<Value>| match result {
            Err(AppError::InvalidParameter(message)) => message,
            other => panic!("expected InvalidParameterException, got {other:?}"),
        };

        assert_eq!(
            message(handler(&storage, json!({"UserPoolId": pool_id, "GroupName": ""})).await),
            "1 validation error detected: Value '' at 'groupName' failed to satisfy constraint: Member must have length greater than or equal to 1"
        );
        assert_eq!(
            message(
                handler(
                    &storage,
                    json!({"UserPoolId": pool_id, "GroupName": "two words"})
                )
                .await
            ),
            r"1 validation error detected: Value 'two words' at 'groupName' failed to satisfy constraint: Member must satisfy regular expression pattern: [\p{L}\p{M}\p{S}\p{N}\p{P}]+"
        );
        assert_eq!(
            message(
                handler(
                    &storage,
                    json!({"UserPoolId": pool_id, "GroupName": "admins", "Precedence": -1})
                )
                .await
            ),
            "1 validation error detected: Value '-1' at 'precedence' failed to satisfy constraint: Member must have value greater than or equal to 0"
        );
        assert_eq!(
            message(
                handler(
                    &storage,
                    json!({"UserPoolId": pool_id, "GroupName": "admins", "RoleArn": "not-an-arn"})
                )
                .await
            ),
            "1 validation error detected: Value 'not-an-arn' at 'roleArn' failed to satisfy constraint: Member must have length greater than or equal to 20"
        );
    }

    #[tokio::test]
    async fn test_create_group_duplicate_is_group_exists_exception() {
        let storage = Storage::new();

        let pool = create_user_pool::handler(&storage, json!({"PoolName": "test-pool"}))
            .await
            .unwrap();
        let pool_id = pool["UserPool"]["Id"].as_str().unwrap();

        handler(
            &storage,
            json!({"UserPoolId": pool_id, "GroupName": "admins"}),
        )
        .await
        .unwrap();
        let error = handler(
            &storage,
            json!({"UserPoolId": pool_id, "GroupName": "admins"}),
        )
        .await
        .unwrap_err();

        assert_eq!(error.status_and_type().1, "GroupExistsException");
        assert_eq!(error.to_string(), "A group with the name already exists.");
    }
}
