//! UpdateAuthEventFeedback API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_UpdateAuthEventFeedback.html>

use chrono::Utc;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::{
    error::{AppError, Result},
    storage::Storage,
};

use super::helpers::verify_and_extract_user_id;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Request {
    access_token: String,
    event_id: String,
    feedback_value: String,
}

pub async fn handler(storage: &Storage, body: Value) -> Result<Value> {
    let req: Request = serde_json::from_value(body)
        .map_err(|e| AppError::InvalidParameter(format!("Invalid request: {}", e)))?;

    let user_id =
        verify_and_extract_user_id(&req.access_token).map_err(|_| AppError::InvalidAccessToken)?;

    storage
        .get_user(&user_id)
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
    if event.user_id != user_id {
        return Err(AppError::AuthEventNotFound);
    }

    event.feedback_value = Some(req.feedback_value);
    event.feedback_provided_by = Some("User".to_string());
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
    use crate::action::user::{initiate_auth, sign_up};
    use crate::action::user_pool::{create_user_pool, create_user_pool_client};
    use serde_json::json;

    async fn setup_and_get_token(storage: &Storage) -> String {
        let pool = create_user_pool::handler(storage, json!({"PoolName": "test"}))
            .await
            .unwrap();
        let pool_id = pool["UserPool"]["Id"].as_str().unwrap();

        let client = create_user_pool_client::handler(
            storage,
            json!({
                "UserPoolId": pool_id,
                "ClientName": "test-client"
            }),
        )
        .await
        .unwrap();
        let client_id = client["UserPoolClient"]["ClientId"].as_str().unwrap();

        let sign_up_result = sign_up::handler(
            storage,
            json!({
                "ClientId": client_id,
                "Username": "testuser",
                "Password": "Password123!"
            }),
        )
        .await
        .unwrap();

        let user_sub = sign_up_result["UserSub"].as_str().unwrap();
        let user_id = uuid::Uuid::parse_str(user_sub).unwrap();
        storage.confirm_user(&user_id).await;

        let auth_result = initiate_auth::handler(
            storage,
            json!({
                "ClientId": client_id,
                "AuthFlow": "USER_PASSWORD_AUTH",
                "AuthParameters": {
                    "USERNAME": "testuser",
                    "PASSWORD": "Password123!"
                }
            }),
        )
        .await
        .unwrap();

        auth_result["AuthenticationResult"]["AccessToken"]
            .as_str()
            .unwrap()
            .to_string()
    }

    #[tokio::test]
    async fn test_update_auth_event_feedback_success() {
        let storage = Storage::new();
        let access_token = setup_and_get_token(&storage).await;
        let user_id = verify_and_extract_user_id(&access_token).unwrap();
        let event_id = storage.list_auth_events_for_user(&user_id).await[0]
            .event_id
            .clone();

        let result = handler(
            &storage,
            json!({
                "AccessToken": access_token,
                "EventId": event_id,
                "FeedbackValue": "Valid"
            }),
        )
        .await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), json!({}));
    }
}
