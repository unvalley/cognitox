//! AWS Cognito Identity Provider API handler
//!
//! This module implements the main entry point for Cognito User Pools API requests.
//! Requests are routed based on the `X-Amz-Target` header.

use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use serde_json::Value;
use tracing::{info, warn};

use super::extractor::AmzJson;
use crate::{
    action::{user, user_pool},
    error::AppError,
    storage::Storage,
};

/// Target header prefix for Cognito operations
const TARGET_PREFIX: &str = "AWSCognitoIdentityProviderService.";

/// Handle incoming Cognito API requests
pub async fn handle_request(
    State(storage): State<Storage>,
    headers: HeaderMap,
    AmzJson(body): AmzJson<Value>,
) -> impl IntoResponse {
    let target = headers
        .get("x-amz-target")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    info!("Received request with target: {}", target);

    let operation = target.strip_prefix(TARGET_PREFIX).unwrap_or(target);

    let result = dispatch_operation(&storage, operation, body).await;

    match result {
        Ok(response) => (
            StatusCode::OK,
            [("content-type", "application/x-amz-json-1.1")],
            Json(response),
        )
            .into_response(),
        Err(e) => e.into_response(),
    }
}

/// Dispatch to the appropriate operation handler
async fn dispatch_operation(
    storage: &Storage,
    operation: &str,
    body: Value,
) -> Result<Value, AppError> {
    match operation {
        // User Pool Operations
        "CreateUserPool" => user_pool::create_user_pool::handler(storage, body).await,
        "DeleteUserPool" => user_pool::delete_user_pool::handler(storage, body).await,
        "DescribeUserPool" => user_pool::describe_user_pool::handler(storage, body).await,
        "ListUserPools" => user_pool::list_user_pools::handler(storage, body).await,

        // User Pool Client Operations
        "CreateUserPoolClient" => user_pool::create_user_pool_client::handler(storage, body).await,
        "DeleteUserPoolClient" => user_pool::delete_user_pool_client::handler(storage, body).await,
        "ListUserPoolClients" => user_pool::list_user_pool_clients::handler(storage, body).await,

        // User Operations
        "SignUp" => user::sign_up::handler(storage, body).await,
        "ConfirmSignUp" => user::confirm_sign_up::handler(storage, body).await,
        "ResendConfirmationCode" => user::resend_confirmation_code::handler(storage, body).await,
        "InitiateAuth" => user::initiate_auth::handler(storage, body).await,
        "RespondToAuthChallenge" => user::respond_to_auth_challenge::handler(storage, body).await,
        "GetUser" => user::get_user::handler(storage, body).await,
        "DeleteUser" => user::delete_user::handler(storage, body).await,
        "ListUsers" => user::list_users::handler(storage, body).await,

        // Admin Operations
        "AdminCreateUser" => user::admin_create_user::handler(storage, body).await,
        "AdminDeleteUser" => user::admin_delete_user::handler(storage, body).await,
        "AdminGetUser" => user::admin_get_user::handler(storage, body).await,

        // Not implemented operations
        _ => {
            warn!("Operation not implemented: {}", operation);
            Err(AppError::NotImplemented(operation.to_string()))
        }
    }
}
