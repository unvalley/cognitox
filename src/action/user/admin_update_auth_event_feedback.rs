//! AdminUpdateAuthEventFeedback API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AdminUpdateAuthEventFeedback.html>

use chrono::Utc;
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
    event_id: String,
    feedback_value: String,
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

    if req.feedback_value != "Valid" && req.feedback_value != "Invalid" {
        return Err(AppError::InvalidParameter(
            "FeedbackValue must be Valid or Invalid".to_string(),
        ));
    }

    let mut event = storage
        .get_auth_event(&req.event_id)
        .await
        .ok_or(AppError::AuthEventNotFound)?;
    if event.user_id != user.id {
        return Err(AppError::AuthEventNotFound);
    }

    event.feedback_value = Some(req.feedback_value);
    event.feedback_provided_by = Some("Admin".to_string());
    event.feedback_date = Some(Utc::now());

    storage
        .update_auth_event(event)
        .await
        .ok_or(AppError::AuthEventNotFound)?;

    Ok(json!({}))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::user::{admin_create_user, admin_initiate_auth, admin_set_user_password};
    use crate::action::user_pool::create_user_pool;
    use crate::action::user_pool::create_user_pool_client;
    use serde_json::json;

    #[tokio::test]
    async fn test_admin_update_auth_event_feedback_success() {
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
            json!({
                "UserPoolId": pool_id,
                "Username": "testuser"
            }),
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

        let user_pool_id: UserPoolId = pool_id.parse().unwrap();
        let user = storage
            .get_user_by_username(&user_pool_id, "testuser")
            .await
            .unwrap();
        let event_id = storage.list_auth_events_for_user(&user.id).await[0]
            .event_id
            .clone();

        let result = handler(
            &storage,
            json!({
                "UserPoolId": pool_id,
                "Username": "testuser",
                "EventId": event_id,
                "FeedbackValue": "Valid"
            }),
        )
        .await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), json!({}));
    }
}
