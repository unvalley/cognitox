//! AdminListGroupsForUser API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AdminListGroupsForUser.html>

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
    username: String,
    #[serde(default = "default_limit")]
    limit: i32,
    next_token: Option<String>,
}

fn default_limit() -> i32 {
    60
}

pub async fn handler(storage: &Storage, body: Value) -> Result<Value> {
    let req: Request = serde_json::from_value(body)
        .map_err(|e| AppError::InvalidParameter(format!("Invalid request: {}", e)))?;

    storage
        .get_user_pool(&req.user_pool_id)
        .await
        .ok_or(AppError::UserPoolNotFound)?;

    if req.limit <= 0 {
        return Err(AppError::InvalidParameter(
            "Limit must be greater than 0".to_string(),
        ));
    }

    let user = storage
        .get_user_by_username(&req.user_pool_id, &req.username)
        .await
        .ok_or(AppError::UserNotFound)?;

    let mut group_names = storage.get_groups_for_user(&user.id).await;
    group_names.sort();

    let start = req
        .next_token
        .as_deref()
        .map(|token| {
            token
                .parse::<usize>()
                .map_err(|_| AppError::InvalidParameter("Invalid NextToken".to_string()))
        })
        .transpose()?
        .unwrap_or(0);

    if start > group_names.len() {
        return Err(AppError::InvalidParameter("Invalid NextToken".to_string()));
    }

    let end = (start + req.limit as usize).min(group_names.len());

    let mut groups_json = Vec::new();
    for group_name in &group_names[start..end] {
        if let Some(group) = storage.get_group(&req.user_pool_id, group_name).await {
            groups_json.push(json!({
                "GroupName": group.group_name,
                "UserPoolId": group.user_pool_id,
                "Description": group.description,
                "RoleArn": group.role_arn,
                "Precedence": group.precedence,
                "CreationDate": group.creation_date.timestamp(),
                "LastModifiedDate": group.last_modified_date.timestamp()
            }));
        }
    }

    let mut response = json!({
        "Groups": groups_json
    });
    if end < group_names.len() {
        response["NextToken"] = json!(end.to_string());
    }

    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::group::{admin_add_user_to_group, create_group};
    use crate::action::user::admin_create_user;
    use crate::action::user_pool::create_user_pool;
    use serde_json::json;

    #[tokio::test]
    async fn test_admin_list_groups_for_user_empty() {
        let storage = Storage::new();

        let pool = create_user_pool::handler(&storage, json!({"PoolName": "test-pool"}))
            .await
            .unwrap();
        let pool_id = pool["UserPool"]["Id"].as_str().unwrap();

        admin_create_user::handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "Username": "testuser",
                "TemporaryPassword": "TempPass123!"
            }),
        )
        .await
        .unwrap();

        let result = handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "Username": "testuser"
            }),
        )
        .await;

        assert!(result.is_ok());
        let body = result.unwrap();
        assert_eq!(body["Groups"].as_array().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn test_admin_list_groups_for_user_with_groups() {
        let storage = Storage::new();

        let pool = create_user_pool::handler(&storage, json!({"PoolName": "test-pool"}))
            .await
            .unwrap();
        let pool_id = pool["UserPool"]["Id"].as_str().unwrap();

        create_group::handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "GroupName": "admins"
            }),
        )
        .await
        .unwrap();

        create_group::handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "GroupName": "users"
            }),
        )
        .await
        .unwrap();

        admin_create_user::handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "Username": "testuser",
                "TemporaryPassword": "TempPass123!"
            }),
        )
        .await
        .unwrap();

        admin_add_user_to_group::handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "Username": "testuser",
                "GroupName": "admins"
            }),
        )
        .await
        .unwrap();

        admin_add_user_to_group::handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "Username": "testuser",
                "GroupName": "users"
            }),
        )
        .await
        .unwrap();

        let result = handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "Username": "testuser"
            }),
        )
        .await;

        assert!(result.is_ok());
        let body = result.unwrap();
        assert_eq!(body["Groups"].as_array().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn test_admin_list_groups_for_user_not_found() {
        let storage = Storage::new();

        let pool = create_user_pool::handler(&storage, json!({"PoolName": "test-pool"}))
            .await
            .unwrap();
        let pool_id = pool["UserPool"]["Id"].as_str().unwrap();

        let result = handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "Username": "nonexistent"
            }),
        )
        .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_admin_list_groups_for_user_with_pagination() {
        let storage = Storage::new();

        let pool = create_user_pool::handler(&storage, json!({"PoolName": "test-pool"}))
            .await
            .unwrap();
        let pool_id = pool["UserPool"]["Id"].as_str().unwrap();

        for group_name in ["admins", "developers", "users"] {
            create_group::handler(
                &storage,
                json!({
                    "UserPoolId": pool_id,
                    "GroupName": group_name
                }),
            )
            .await
            .unwrap();
        }

        admin_create_user::handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "Username": "testuser",
                "TemporaryPassword": "TempPass123!"
            }),
        )
        .await
        .unwrap();

        for group_name in ["admins", "developers", "users"] {
            admin_add_user_to_group::handler(
                &storage,
                json!({
                    "UserPoolId": pool_id,
                    "Username": "testuser",
                    "GroupName": group_name
                }),
            )
            .await
            .unwrap();
        }

        let first = handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "Username": "testuser",
                "Limit": 2
            }),
        )
        .await
        .unwrap();

        assert_eq!(first["Groups"].as_array().unwrap().len(), 2);
        assert_eq!(first["NextToken"], "2");

        let second = handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "Username": "testuser",
                "Limit": 2,
                "NextToken": "2"
            }),
        )
        .await
        .unwrap();

        assert_eq!(second["Groups"].as_array().unwrap().len(), 1);
        assert!(second.get("NextToken").is_none());
    }
}
