//! ListUsers API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_ListUsers.html>

use serde::Deserialize;
use serde_json::{Value, json};

use crate::{
    action::user::helpers::{build_user_attributes, find_user_attribute_value},
    error::{AppError, Result},
    storage::Storage,
    types::{User, UserPoolId},
};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Request {
    user_pool_id: UserPoolId,
    limit: Option<u32>,
    filter: Option<String>,
}

/// Attributes that `Filter` can search on. Custom attributes are not searchable.
const SEARCHABLE_ATTRIBUTES: [&str; 10] = [
    "username",
    "email",
    "phone_number",
    "name",
    "given_name",
    "family_name",
    "preferred_username",
    "cognito:user_status",
    "status",
    "sub",
];

/// A parsed `Filter` expression: `AttributeName Filter-Type "AttributeValue"`,
/// where the filter type is `=` (exact match) or `^=` (prefix match).
struct Filter {
    attribute: String,
    value: String,
    prefix: bool,
}

impl Filter {
    fn parse(filter: &str) -> Result<Self> {
        let invalid = || AppError::InvalidParameter(format!("Invalid search filter: {filter}"));

        let (attribute, value) = filter.split_once('=').ok_or_else(invalid)?;
        let (attribute, prefix) = match attribute.trim().strip_suffix('^') {
            Some(attribute) => (attribute.trim_end(), true),
            None => (attribute.trim(), false),
        };
        if !SEARCHABLE_ATTRIBUTES.contains(&attribute) {
            return Err(AppError::InvalidParameter(format!(
                "Invalid search attribute: {attribute}"
            )));
        }
        let value = value
            .trim()
            .strip_prefix('"')
            .and_then(|value| value.strip_suffix('"'))
            .ok_or_else(invalid)?;

        Ok(Self {
            attribute: attribute.to_string(),
            value: value.replace(r#"\""#, "\""),
            prefix,
        })
    }

    fn matches(&self, user: &User) -> bool {
        let actual = match self.attribute.as_str() {
            "username" => Some(user.username.clone()),
            "sub" => Some(user.id.to_string()),
            "email" => user.email.clone(),
            "phone_number" => user.phone_number.clone(),
            "status" => Some(if user.enabled { "Enabled" } else { "Disabled" }.to_string()),
            // The user status is the only attribute matched case-insensitively.
            "cognito:user_status" => {
                let status = json!(user.user_status);
                let status = status.as_str().unwrap_or_default().to_lowercase();
                let expected = self.value.to_lowercase();
                return if self.prefix {
                    status.starts_with(&expected)
                } else {
                    status == expected
                };
            }
            attribute => find_user_attribute_value(&user.attributes, attribute),
        };

        actual.is_some_and(|actual| {
            if self.prefix {
                actual.starts_with(&self.value)
            } else {
                actual == self.value
            }
        })
    }
}

pub async fn handler(storage: &Storage, body: Value) -> Result<Value> {
    let req: Request = serde_json::from_value(body)
        .map_err(|e| AppError::InvalidParameter(format!("Invalid request: {}", e)))?;

    storage
        .get_user_pool(&req.user_pool_id)
        .await
        .ok_or(AppError::UserPoolNotFound)?;

    let mut users = storage.list_users(&req.user_pool_id).await;
    if let Some(filter) = req.filter.as_deref().filter(|filter| !filter.is_empty()) {
        let filter = Filter::parse(filter)?;
        users.retain(|user| filter.matches(user));
    }
    let limit = req.limit.unwrap_or(60) as usize;

    let users_json: Vec<_> = users
        .into_iter()
        .take(limit)
        .map(|u| {
            json!({
                "Username": u.username,
                "Enabled": u.enabled,
                "UserStatus": u.user_status,
                "UserCreateDate": u.creation_date.timestamp(),
                "UserLastModifiedDate": u.last_modified_date.timestamp(),
                "Attributes": build_user_attributes(&u)
            })
        })
        .collect();

    Ok(json!({
        "Users": users_json
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    use crate::action::user::sign_up;
    use crate::action::user_pool::{create_user_pool, create_user_pool_client};

    async fn setup_pool_and_client(storage: &Storage) -> (String, String) {
        let pool = create_user_pool::handler(storage, json!({"PoolName": "test"}))
            .await
            .unwrap();
        let pool_id = pool["UserPool"]["Id"].as_str().unwrap().to_string();

        let client = create_user_pool_client::handler(
            storage,
            json!({
                "UserPoolId": pool_id,
                "ClientName": "test-client"
            }),
        )
        .await
        .unwrap();
        let client_id = client["UserPoolClient"]["ClientId"]
            .as_str()
            .unwrap()
            .to_string();

        (pool_id, client_id)
    }

    #[tokio::test]
    async fn test_list_users_success() {
        let storage = Storage::new();
        let (pool_id, client_id) = setup_pool_and_client(&storage).await;

        // Create a few users
        for i in 0..3 {
            sign_up::handler(
                &storage,
                json!({
                    "ClientId": client_id,
                    "Username": format!("testuser{}", i),
                    "Password": "Password123!"
                }),
            )
            .await
            .unwrap();
        }

        let result = handler(
            &storage,
            json!({
                "UserPoolId": pool_id
            }),
        )
        .await;

        assert!(result.is_ok());
        let body = result.unwrap();
        let users = body["Users"].as_array().unwrap();
        assert_eq!(users.len(), 3);
        assert!(
            users[0]["Attributes"]
                .as_array()
                .unwrap()
                .iter()
                .any(|attribute| attribute["Name"] == "sub")
        );
    }

    #[tokio::test]
    async fn test_list_users_with_limit() {
        let storage = Storage::new();
        let (pool_id, client_id) = setup_pool_and_client(&storage).await;

        // Create several users
        for i in 0..5 {
            sign_up::handler(
                &storage,
                json!({
                    "ClientId": client_id,
                    "Username": format!("testuser{}", i),
                    "Password": "Password123!"
                }),
            )
            .await
            .unwrap();
        }

        let result = handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "Limit": 2
            }),
        )
        .await;

        assert!(result.is_ok());
        let body = result.unwrap();
        let users = body["Users"].as_array().unwrap();
        assert_eq!(users.len(), 2);
    }

    #[tokio::test]
    async fn test_list_users_with_filter() {
        use crate::action::user::admin_create_user;

        let storage = Storage::new();
        let (pool_id, _client_id) = setup_pool_and_client(&storage).await;
        for (username, email) in [
            ("alice", "alice@example.com"),
            ("alicia", "alicia@example.org"),
            ("bob", "bob@example.com"),
        ] {
            admin_create_user::handler(
                &storage,
                json!({
                    "UserPoolId": pool_id,
                    "Username": username,
                    "UserAttributes": [{"Name": "email", "Value": email}]
                }),
            )
            .await
            .unwrap();
        }

        for (filter, expected) in [
            (r#"email = "bob@example.com""#, vec!["bob"]),
            (r#"email="bob@example.com""#, vec!["bob"]),
            (r#"username ^= "ali""#, vec!["alice", "alicia"]),
            (r#"email = "bob""#, vec![]),
            (
                r#"cognito:user_status = "force_change_password""#,
                vec!["alice", "alicia", "bob"],
            ),
            (r#"status = "Disabled""#, vec![]),
            ("", vec!["alice", "alicia", "bob"]),
        ] {
            let body = handler(&storage, json!({"UserPoolId": pool_id, "Filter": filter}))
                .await
                .unwrap();
            let mut usernames: Vec<_> = body["Users"]
                .as_array()
                .unwrap()
                .iter()
                .map(|user| user["Username"].as_str().unwrap().to_string())
                .collect();
            usernames.sort();
            assert_eq!(usernames, expected, "filter: {filter}");
        }
    }

    #[tokio::test]
    async fn test_list_users_rejects_invalid_filter() {
        let storage = Storage::new();
        let (pool_id, _client_id) = setup_pool_and_client(&storage).await;

        for filter in [r#"custom:team = "a""#, "email", "email = bob@example.com"] {
            let result = handler(&storage, json!({"UserPoolId": pool_id, "Filter": filter})).await;
            assert!(
                matches!(result, Err(AppError::InvalidParameter(_))),
                "filter: {filter}"
            );
        }
    }

    #[tokio::test]
    async fn test_list_users_empty_pool() {
        let storage = Storage::new();
        let (pool_id, _client_id) = setup_pool_and_client(&storage).await;

        let result = handler(
            &storage,
            json!({
                "UserPoolId": pool_id
            }),
        )
        .await;

        assert!(result.is_ok());
        let body = result.unwrap();
        let users = body["Users"].as_array().unwrap();
        assert!(users.is_empty());
    }
}
