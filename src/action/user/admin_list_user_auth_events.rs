//! AdminListUserAuthEvents API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AdminListUserAuthEvents.html>

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
    max_results: Option<u32>,
    next_token: Option<String>,
}

pub async fn handler(storage: &Storage, body: Value) -> Result<Value> {
    let req: Request = serde_json::from_value(body)
        .map_err(|e| AppError::InvalidParameter(format!("Invalid request: {}", e)))?;

    storage
        .get_user_pool(&req.user_pool_id)
        .await
        .ok_or(AppError::UserPoolNotFound)?;

    let user = storage
        .get_user_by_username(&req.user_pool_id, &req.username)
        .await
        .ok_or(AppError::UserNotFound)?;

    let mut events = storage.list_auth_events_for_user(&user.id).await;
    events.sort_by(|a, b| b.creation_date.cmp(&a.creation_date));

    let max_results = req.max_results.unwrap_or(60) as usize;
    if max_results == 0 {
        return Err(AppError::InvalidParameter(
            "MaxResults must be greater than 0".to_string(),
        ));
    }

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

    if start > events.len() {
        return Err(AppError::InvalidParameter("Invalid NextToken".to_string()));
    }

    let end = (start + max_results).min(events.len());
    let payload: Vec<Value> = events[start..end]
        .iter()
        .map(|event| {
            let mut value = json!({
                "EventId": event.event_id,
                "EventType": event.event_type,
                "CreationDate": event.creation_date.timestamp(),
                "EventResponse": event.event_response
            });
            if let Some(feedback_value) = &event.feedback_value {
                value["FeedbackValue"] = json!(feedback_value);
            }
            if let Some(feedback_provided_by) = &event.feedback_provided_by {
                value["FeedbackProvidedBy"] = json!(feedback_provided_by);
            }
            if let Some(feedback_date) = event.feedback_date {
                value["FeedbackDate"] = json!(feedback_date.timestamp());
            }
            value
        })
        .collect();

    let mut response = json!({
        "AuthEvents": payload
    });
    if end < events.len() {
        response["NextToken"] = json!(end.to_string());
    }

    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        action::user::{admin_create_user, admin_initiate_auth, admin_set_user_password},
        action::user_pool::{create_user_pool, create_user_pool_client},
    };
    use serde_json::json;

    #[tokio::test]
    async fn test_admin_list_user_auth_events_success() {
        let storage = Storage::new();

        let pool = create_user_pool::handler(&storage, json!({"PoolName": "test"}))
            .await
            .unwrap();
        let pool_id = pool["UserPool"]["Id"].as_str().unwrap();
        let client = create_user_pool_client::handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "ClientName": "test-client"
            }),
        )
        .await
        .unwrap();
        let client_id = client["UserPoolClient"]["ClientId"].as_str().unwrap();

        admin_create_user::handler(
            &storage,
            json!({"UserPoolId": pool_id, "Username": "testuser"}),
        )
        .await
        .unwrap();
        admin_set_user_password::handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "Username": "testuser",
                "Password": "Password123!",
                "Permanent": true
            }),
        )
        .await
        .unwrap();
        admin_initiate_auth::handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "ClientId": client_id,
                "AuthFlow": "ADMIN_USER_PASSWORD_AUTH",
                "AuthParameters": {
                    "USERNAME": "testuser",
                    "PASSWORD": "Password123!"
                }
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
        .await
        .unwrap();

        assert_eq!(result["AuthEvents"].as_array().unwrap().len(), 1);
    }
}
