//! ListGroups API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_ListGroups.html>

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

    let mut groups = storage.list_groups(&req.user_pool_id).await;
    groups.sort_by(|a, b| a.group_name.cmp(&b.group_name));

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

    if start > groups.len() {
        return Err(AppError::InvalidParameter("Invalid NextToken".to_string()));
    }

    let end = (start + req.limit as usize).min(groups.len());
    let groups_json: Vec<Value> = groups[start..end]
        .iter()
        .map(|g| {
            json!({
                "GroupName": g.group_name,
                "UserPoolId": g.user_pool_id,
                "Description": g.description,
                "RoleArn": g.role_arn,
                "Precedence": g.precedence,
                "CreationDate": g.creation_date.timestamp(),
                "LastModifiedDate": g.last_modified_date.timestamp()
            })
        })
        .collect();

    let mut response = json!({
        "Groups": groups_json
    });
    if end < groups.len() {
        response["NextToken"] = json!(end.to_string());
    }

    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::group::create_group;
    use crate::action::user_pool::create_user_pool;
    use serde_json::json;

    #[tokio::test]
    async fn test_list_groups_empty() {
        let storage = Storage::new();

        let pool = create_user_pool::handler(&storage, json!({"PoolName": "test-pool"}))
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
        assert_eq!(body["Groups"].as_array().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn test_list_groups_multiple() {
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

        let result = handler(
            &storage,
            json!({
                "UserPoolId": pool_id
            }),
        )
        .await;

        assert!(result.is_ok());
        let body = result.unwrap();
        assert_eq!(body["Groups"].as_array().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn test_list_groups_pool_not_found() {
        let storage = Storage::new();

        let result = handler(
            &storage,
            json!({
                "UserPoolId": "local_nonexistent"
            }),
        )
        .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_list_groups_with_pagination() {
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

        let first = handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
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
