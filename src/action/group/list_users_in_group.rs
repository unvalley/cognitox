//! ListUsersInGroup API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_ListUsersInGroup.html>

use serde::Deserialize;
use serde_json::{Value, json};

use crate::{
    action::{
        pagination::{page_size, paginate},
        user::helpers::build_user_attributes,
    },
    error::{AppError, Result},
    storage::Storage,
    types::UserPoolId,
};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Request {
    user_pool_id: UserPoolId,
    group_name: String,
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

    storage
        .get_group(&req.user_pool_id, &req.group_name)
        .await
        .ok_or(AppError::GroupNotFound)?;

    let mut users = storage
        .get_users_in_group(&req.user_pool_id, &req.group_name)
        .await;
    users.sort_by(|a, b| a.username.cmp(&b.username));

    let page = paginate(users.len(), limit, req.next_token.as_deref())?;
    let users_json: Vec<Value> = users[page.start..page.end]
        .iter()
        .map(|u| {
            json!({
                "Username": u.username,
                "Attributes": build_user_attributes(u),
                "UserCreateDate": u.creation_date.timestamp(),
                "UserLastModifiedDate": u.last_modified_date.timestamp(),
                "Enabled": u.enabled,
                "UserStatus": u.user_status
            })
        })
        .collect();

    let mut response = json!({
        "Users": users_json
    });
    if let Some(next_token) = page.next_token {
        response["NextToken"] = json!(next_token);
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
    async fn test_list_users_in_group_empty() {
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

        let result = handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "GroupName": "admins"
            }),
        )
        .await;

        assert!(result.is_ok());
        let body = result.unwrap();
        assert_eq!(body["Users"].as_array().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn test_list_users_in_group_with_users() {
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

        let result = handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "GroupName": "admins"
            }),
        )
        .await;

        assert!(result.is_ok());
        let body = result.unwrap();
        assert_eq!(body["Users"].as_array().unwrap().len(), 1);
        assert_eq!(body["Users"][0]["Username"], "testuser");
    }

    #[tokio::test]
    async fn test_list_users_in_group_not_found() {
        let storage = Storage::new();

        let pool = create_user_pool::handler(&storage, json!({"PoolName": "test-pool"}))
            .await
            .unwrap();
        let pool_id = pool["UserPool"]["Id"].as_str().unwrap();

        let result = handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "GroupName": "nonexistent"
            }),
        )
        .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_list_users_in_group_with_pagination() {
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

        for username in ["alice", "bob", "charlie"] {
            admin_create_user::handler(
                &storage,
                json!({
                    "UserPoolId": pool_id,
                    "Username": username,
                    "TemporaryPassword": "TempPass123!"
                }),
            )
            .await
            .unwrap();

            admin_add_user_to_group::handler(
                &storage,
                json!({
                    "UserPoolId": pool_id,
                    "Username": username,
                    "GroupName": "admins"
                }),
            )
            .await
            .unwrap();
        }

        let first = handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "GroupName": "admins",
                "Limit": 2
            }),
        )
        .await
        .unwrap();

        assert_eq!(first["Users"].as_array().unwrap().len(), 2);
        assert_eq!(first["NextToken"], "2");

        let second = handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "GroupName": "admins",
                "Limit": 2,
                "NextToken": "2"
            }),
        )
        .await
        .unwrap();

        assert_eq!(second["Users"].as_array().unwrap().len(), 1);
        assert!(second.get("NextToken").is_none());
    }

    #[tokio::test]
    async fn test_list_users_in_group_returns_user_type_items() {
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
        let created = admin_create_user::handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "Username": "testuser",
                "TemporaryPassword": "TempPass123!",
                "UserAttributes": [{"Name": "email", "Value": "test@example.com"}]
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

        let body = handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "GroupName": "admins"
            }),
        )
        .await
        .unwrap();
        assert!(body.get("NextToken").is_none());

        let user = &body["Users"][0];
        assert_eq!(user["Username"], "testuser");
        assert_eq!(user["Enabled"], true);
        assert_eq!(user["UserStatus"], "FORCE_CHANGE_PASSWORD");
        assert!(user["UserCreateDate"].is_number());
        assert!(user["UserLastModifiedDate"].is_number());
        // The same attributes AdminCreateUser reported, `sub` included.
        assert_eq!(user["Attributes"], created["User"]["Attributes"]);
        let attributes = user["Attributes"].as_array().unwrap();
        assert!(
            attributes
                .iter()
                .any(|attribute| attribute["Name"] == "sub")
        );
        assert!(
            attributes
                .iter()
                .any(|attribute| attribute["Name"] == "email"
                    && attribute["Value"] == "test@example.com")
        );
    }

    #[tokio::test]
    async fn test_list_users_in_group_limit_is_bounded() {
        let storage = Storage::new();

        let pool = create_user_pool::handler(&storage, json!({"PoolName": "test-pool"}))
            .await
            .unwrap();
        let pool_id = pool["UserPool"]["Id"].as_str().unwrap();

        let result = handler(
            &storage,
            json!({"UserPoolId": pool_id, "GroupName": "admins", "Limit": 61}),
        )
        .await;
        assert!(matches!(
            result,
            Err(AppError::InvalidParameter(message))
                if message == "1 validation error detected: Value '61' at 'limit' failed to satisfy constraint: Member must have value less than or equal to 60"
        ));
    }
}
