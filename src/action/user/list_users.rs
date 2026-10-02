//! ListUsers API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_ListUsers.html>

use serde::Deserialize;
use serde_json::{Value, json};

use crate::{
    action::user::helpers::build_user_attributes,
    error::{AppError, Result},
    storage::Storage,
    types::{User, UserPoolId},
};

const MAX_LIMIT: usize = 60;
const MAX_FILTER_LENGTH: usize = 256;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Request {
    user_pool_id: UserPoolId,
    attributes_to_get: Option<Vec<String>>,
    filter: Option<String>,
    limit: Option<usize>,
    pagination_token: Option<String>,
}

/// Attributes that ListUsers can filter on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FilterAttribute {
    Username,
    Email,
    PhoneNumber,
    Name,
    GivenName,
    FamilyName,
    PreferredUsername,
    UserStatus,
    Status,
    Sub,
}

impl FilterAttribute {
    fn parse(name: &str) -> Option<Self> {
        Some(match name {
            "username" => Self::Username,
            "email" => Self::Email,
            "phone_number" => Self::PhoneNumber,
            "name" => Self::Name,
            "given_name" => Self::GivenName,
            "family_name" => Self::FamilyName,
            "preferred_username" => Self::PreferredUsername,
            "cognito:user_status" => Self::UserStatus,
            "status" => Self::Status,
            "sub" => Self::Sub,
            _ => return None,
        })
    }

    fn value(self, user: &User) -> Option<String> {
        let attribute = |name: &str| {
            user.attributes
                .iter()
                .find(|attribute| attribute.name == name)
                .and_then(|attribute| attribute.value.clone())
        };
        match self {
            Self::Username => Some(user.username.clone()),
            Self::Email => user.email.clone(),
            Self::PhoneNumber => user.phone_number.clone(),
            Self::Name => attribute("name"),
            Self::GivenName => attribute("given_name"),
            Self::FamilyName => attribute("family_name"),
            Self::PreferredUsername => attribute("preferred_username"),
            Self::UserStatus => serde_json::to_value(user.user_status)
                .ok()
                .and_then(|value| value.as_str().map(str::to_string)),
            Self::Status => Some(if user.enabled { "Enabled" } else { "Disabled" }.to_string()),
            Self::Sub => Some(user.id.to_string()),
        }
    }

    /// `cognito:user_status` is the only case-insensitive filter attribute.
    fn case_insensitive(self) -> bool {
        self == Self::UserStatus
    }
}

#[derive(Debug, PartialEq, Eq)]
enum FilterOperator {
    Equals,
    StartsWith,
}

/// Parsed `AttributeName Filter-Type "AttributeValue"` expression.
#[derive(Debug)]
struct UserFilter {
    attribute: FilterAttribute,
    operator: FilterOperator,
    value: String,
}

impl UserFilter {
    fn parse(filter: &str) -> Result<Option<Self>> {
        let invalid = || AppError::InvalidParameter(format!("Invalid filter: {filter}"));

        if filter.len() > MAX_FILTER_LENGTH {
            return Err(AppError::InvalidParameter(format!(
                "Filter must be at most {MAX_FILTER_LENGTH} characters"
            )));
        }
        let filter_expr = filter.trim();
        if filter_expr.is_empty() {
            return Ok(None);
        }

        let operator_start = filter_expr.find(['=', '^']).ok_or_else(invalid)?;
        let attribute =
            FilterAttribute::parse(filter_expr[..operator_start].trim()).ok_or_else(invalid)?;
        let rest = &filter_expr[operator_start..];
        let (operator, rest) = if let Some(rest) = rest.strip_prefix("^=") {
            (FilterOperator::StartsWith, rest)
        } else if let Some(rest) = rest.strip_prefix('=') {
            (FilterOperator::Equals, rest)
        } else {
            return Err(invalid());
        };

        let quoted = rest
            .trim()
            .strip_prefix('"')
            .and_then(|rest| rest.strip_suffix('"'))
            .ok_or_else(invalid)?;
        let mut value = String::with_capacity(quoted.len());
        let mut chars = quoted.chars();
        while let Some(c) = chars.next() {
            match c {
                '\\' => value.push(chars.next().ok_or_else(invalid)?),
                '"' => return Err(invalid()),
                c => value.push(c),
            }
        }

        Ok(Some(Self {
            attribute,
            operator,
            value,
        }))
    }

    fn matches(&self, user: &User) -> bool {
        let Some(actual) = self.attribute.value(user) else {
            return false;
        };
        let (actual, expected) = if self.attribute.case_insensitive() {
            (actual.to_lowercase(), self.value.to_lowercase())
        } else {
            (actual, self.value.clone())
        };
        match self.operator {
            FilterOperator::Equals => actual == expected,
            FilterOperator::StartsWith => actual.starts_with(&expected),
        }
    }
}

pub async fn handler(storage: &Storage, body: Value) -> Result<Value> {
    let req: Request = serde_json::from_value(body)
        .map_err(|e| AppError::InvalidParameter(format!("Invalid request: {}", e)))?;

    let limit = match req.limit {
        None | Some(0) => MAX_LIMIT,
        Some(limit) if limit <= MAX_LIMIT => limit,
        Some(_) => {
            return Err(AppError::InvalidParameter(format!(
                "Limit must be less than or equal to {MAX_LIMIT}"
            )));
        }
    };
    let filter = req
        .filter
        .as_deref()
        .map(UserFilter::parse)
        .transpose()?
        .flatten();

    storage
        .get_user_pool(&req.user_pool_id)
        .await
        .ok_or(AppError::UserPoolNotFound)?;

    let mut users: Vec<User> = storage
        .list_users(&req.user_pool_id)
        .await
        .into_iter()
        .filter(|user| filter.as_ref().is_none_or(|filter| filter.matches(user)))
        .collect();
    // Stable order so that pagination tokens remain meaningful between calls.
    users.sort_by(|a, b| a.username.cmp(&b.username));

    let start = req
        .pagination_token
        .as_deref()
        .map(|token| {
            token
                .parse::<usize>()
                .ok()
                .filter(|start| *start <= users.len())
                .ok_or_else(|| AppError::InvalidParameter("Invalid PaginationToken".to_string()))
        })
        .transpose()?
        .unwrap_or(0);
    let end = (start + limit).min(users.len());

    let users_json: Vec<_> = users[start..end]
        .iter()
        .map(|u| {
            let mut attributes = build_user_attributes(u);
            if let Some(names) = &req.attributes_to_get {
                attributes.retain(|attribute| {
                    attribute["Name"]
                        .as_str()
                        .is_some_and(|name| names.iter().any(|n| n == name))
                });
            }
            json!({
                "Username": u.username,
                "Enabled": u.enabled,
                "UserStatus": u.user_status,
                "UserCreateDate": u.creation_date.timestamp(),
                "UserLastModifiedDate": u.last_modified_date.timestamp(),
                "Attributes": attributes
            })
        })
        .collect();

    let mut response = json!({
        "Users": users_json
    });
    if end < users.len() {
        response["PaginationToken"] = json!(end.to_string());
    }

    Ok(response)
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

    async fn sign_up_users(storage: &Storage, client_id: &str, users: &[(&str, &str)]) {
        for (username, email) in users {
            sign_up::handler(
                storage,
                json!({
                    "ClientId": client_id,
                    "Username": username,
                    "Password": "Password123!",
                    "UserAttributes": [
                        {"Name": "email", "Value": email},
                        {"Name": "given_name", "Value": format!("Given {username}")}
                    ]
                }),
            )
            .await
            .unwrap();
        }
    }

    async fn usernames(storage: &Storage, request: Value) -> Vec<String> {
        handler(storage, request).await.unwrap()["Users"]
            .as_array()
            .unwrap()
            .iter()
            .map(|user| user["Username"].as_str().unwrap().to_string())
            .collect()
    }

    #[tokio::test]
    async fn test_list_users_filter() {
        let storage = Storage::new();
        let (pool_id, client_id) = setup_pool_and_client(&storage).await;
        sign_up_users(
            &storage,
            &client_id,
            &[
                ("alice", "alice@example.com"),
                ("bob", "bob@example.com"),
                ("bobby", "bobby@example.org"),
            ],
        )
        .await;
        let bob = storage
            .get_user_by_username(&UserPoolId::new(&pool_id).unwrap(), "bob")
            .await
            .unwrap();
        storage.confirm_user(&bob.id).await;

        let cases = [
            (r#"email = "bob@example.com""#, vec!["bob"]),
            (r#"email ^= "bob""#, vec!["bob", "bobby"]),
            (r#"email^="bob""#, vec!["bob", "bobby"]),
            (r#"email ^= "BOB""#, vec![]),
            (r#"username = "alice""#, vec!["alice"]),
            (r#"given_name ^= "Given b""#, vec!["bob", "bobby"]),
            (r#"cognito:user_status = "confirmed""#, vec!["bob"]),
            (r#"status = "Enabled""#, vec!["alice", "bob", "bobby"]),
            (r#"status = "enabled""#, vec![]),
            (r#"family_name = "x""#, vec![]),
            (&format!(r#"sub = "{}""#, bob.id), vec!["bob"]),
            ("", vec!["alice", "bob", "bobby"]),
        ];
        for (filter, expected) in cases {
            assert_eq!(
                usernames(&storage, json!({ "UserPoolId": pool_id, "Filter": filter })).await,
                expected,
                "filter: {filter}"
            );
        }
    }

    #[tokio::test]
    async fn test_list_users_filter_unescapes_quotes() {
        let storage = Storage::new();
        let (pool_id, client_id) = setup_pool_and_client(&storage).await;
        sign_up_users(&storage, &client_id, &[("quote\"user", "q@example.com")]).await;

        assert_eq!(
            usernames(
                &storage,
                json!({ "UserPoolId": pool_id, "Filter": r#"username = "quote\"user""# })
            )
            .await,
            vec!["quote\"user"]
        );
    }

    #[tokio::test]
    async fn test_list_users_invalid_filter() {
        let storage = Storage::new();
        let (pool_id, _client_id) = setup_pool_and_client(&storage).await;

        for filter in [
            "email",
            r#"email = bob"#,
            r#"email != "bob""#,
            r#"email = "bob"#,
            r#"custom:tenant = "x""#,
            r#"email = "a"b""#,
        ] {
            let result =
                handler(&storage, json!({ "UserPoolId": pool_id, "Filter": filter })).await;
            assert!(
                matches!(result, Err(AppError::InvalidParameter(_))),
                "filter: {filter}"
            );
        }
    }

    #[tokio::test]
    async fn test_list_users_pagination() {
        let storage = Storage::new();
        let (pool_id, client_id) = setup_pool_and_client(&storage).await;
        sign_up_users(
            &storage,
            &client_id,
            &[
                ("carol", "carol@example.com"),
                ("alice", "alice@example.com"),
                ("bob", "bob@example.com"),
            ],
        )
        .await;

        let mut collected = Vec::new();
        let mut token: Option<String> = None;
        loop {
            let mut request = json!({ "UserPoolId": pool_id, "Limit": 2 });
            if let Some(token) = &token {
                request["PaginationToken"] = json!(token);
            }
            let body = handler(&storage, request).await.unwrap();
            for user in body["Users"].as_array().unwrap() {
                collected.push(user["Username"].as_str().unwrap().to_string());
            }
            match body["PaginationToken"].as_str() {
                Some(next) => token = Some(next.to_string()),
                None => break,
            }
        }
        assert_eq!(collected, vec!["alice", "bob", "carol"]);

        let result = handler(
            &storage,
            json!({ "UserPoolId": pool_id, "PaginationToken": "not-a-token" }),
        )
        .await;
        assert!(matches!(result, Err(AppError::InvalidParameter(_))));

        let result = handler(&storage, json!({ "UserPoolId": pool_id, "Limit": 61 })).await;
        assert!(matches!(result, Err(AppError::InvalidParameter(_))));
    }

    #[tokio::test]
    async fn test_list_users_attributes_to_get() {
        let storage = Storage::new();
        let (pool_id, client_id) = setup_pool_and_client(&storage).await;
        sign_up_users(&storage, &client_id, &[("alice", "alice@example.com")]).await;

        let body = handler(
            &storage,
            json!({ "UserPoolId": pool_id, "AttributesToGet": ["email"] }),
        )
        .await
        .unwrap();
        assert_eq!(
            body["Users"][0]["Attributes"],
            json!([{ "Name": "email", "Value": "alice@example.com" }])
        );

        let body = handler(
            &storage,
            json!({ "UserPoolId": pool_id, "AttributesToGet": [] }),
        )
        .await
        .unwrap();
        assert_eq!(body["Users"][0]["Attributes"], json!([]));
    }
}
