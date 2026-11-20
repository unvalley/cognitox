//! ListGroups API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_ListGroups.html>

use serde::Deserialize;
use serde_json::{Value, json};

use crate::{
    action::{
        group::build_group_response,
        pagination::{page_size, paginate},
    },
    error::{AppError, Result},
    storage::Storage,
    types::UserPoolId,
};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Request {
    user_pool_id: UserPoolId,
    limit: Option<i32>,
    next_token: Option<String>,
}

pub async fn handler(storage: &Storage, body: Value) -> Result<Value> {
    let req: Request = crate::action::io::parse_request(body)?;
    let limit = page_size(req.limit, "limit", 0, 60)?;

    storage
        .get_user_pool(&req.user_pool_id)
        .await
        .ok_or(AppError::UserPoolNotFound)?;

    let mut groups = storage.list_groups(&req.user_pool_id).await;
    groups.sort_by(|a, b| a.group_name.cmp(&b.group_name));

    let page = paginate(groups.len(), limit, req.next_token.as_deref())?;
    let groups_json: Vec<Value> = groups[page.start..page.end]
        .iter()
        .map(build_group_response)
        .collect();

    let mut response = json!({
        "Groups": groups_json
    });
    if let Some(next_token) = page.next_token {
        response["NextToken"] = json!(next_token);
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

    #[tokio::test]
    async fn test_list_groups_omits_what_a_group_does_not_have() {
        let storage = Storage::new();

        let pool = create_user_pool::handler(&storage, json!({"PoolName": "test-pool"}))
            .await
            .unwrap();
        let pool_id = pool["UserPool"]["Id"].as_str().unwrap();

        create_group::handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "GroupName": "bare"
            }),
        )
        .await
        .unwrap();
        create_group::handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "GroupName": "full",
                "Description": "Everything set",
                "RoleArn": "arn:aws:iam::000000000000:role/full",
                "Precedence": 5
            }),
        )
        .await
        .unwrap();

        let body = handler(&storage, json!({"UserPoolId": pool_id}))
            .await
            .unwrap();
        let groups = body["Groups"].as_array().unwrap();
        assert!(body.get("NextToken").is_none());

        let bare = groups[0].as_object().unwrap();
        assert_eq!(bare["GroupName"], "bare");
        for absent in ["Description", "RoleArn", "Precedence"] {
            assert!(!bare.contains_key(absent), "{absent} should be absent");
        }
        assert!(bare["CreationDate"].is_number());
        assert!(bare["LastModifiedDate"].is_number());

        assert_eq!(groups[1]["Description"], "Everything set");
        assert_eq!(groups[1]["RoleArn"], "arn:aws:iam::000000000000:role/full");
        assert_eq!(groups[1]["Precedence"], 5);
    }

    #[tokio::test]
    async fn test_list_groups_limit_is_bounded() {
        let storage = Storage::new();

        let pool = create_user_pool::handler(&storage, json!({"PoolName": "test-pool"}))
            .await
            .unwrap();
        let pool_id = pool["UserPool"]["Id"].as_str().unwrap();

        let result = handler(&storage, json!({"UserPoolId": pool_id, "Limit": 61})).await;
        assert!(matches!(
            result,
            Err(AppError::InvalidParameter(message))
                if message == "1 validation error detected: Value '61' at 'limit' failed to satisfy constraint: Member must have value less than or equal to 60"
        ));

        let result = handler(&storage, json!({"UserPoolId": pool_id, "Limit": -1})).await;
        assert!(matches!(
            result,
            Err(AppError::InvalidParameter(message))
                if message == "1 validation error detected: Value '-1' at 'limit' failed to satisfy constraint: Member must have value greater than or equal to 0"
        ));

        // The operation accepts 0, which asks for no particular page size.
        handler(&storage, json!({"UserPoolId": pool_id, "Limit": 0}))
            .await
            .unwrap();
    }
}
