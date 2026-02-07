//! Validation and error case tests
//!
//! Tests for input validation and error handling

mod common;

use common::TestClient;
use serde_json::json;

// =============================================================================
// Username validation tests
// =============================================================================

#[tokio::test]
async fn test_sign_up_empty_username() {
    let client = TestClient::new();

    // Create user pool and client
    let pool_response = client
        .cognito_request("CreateUserPool", json!({"PoolName": "test-pool"}))
        .await;
    let pool_id = pool_response["UserPool"]["Id"].as_str().unwrap();

    let client_response = client
        .cognito_request(
            "CreateUserPoolClient",
            json!({
                "UserPoolId": pool_id,
                "ClientName": "test-client"
            }),
        )
        .await;
    let client_id = client_response["UserPoolClient"]["ClientId"]
        .as_str()
        .unwrap();

    // Try to sign up with empty username
    let response = client
        .cognito_request_raw(
            "SignUp",
            json!({
                "ClientId": client_id,
                "Username": "",
                "Password": "password123"
            }),
        )
        .await;

    assert_eq!(response.status(), 400);
    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["__type"], "InvalidParameterException");
}

#[tokio::test]
async fn test_sign_up_username_with_spaces() {
    let client = TestClient::new();

    let pool_response = client
        .cognito_request("CreateUserPool", json!({"PoolName": "test-pool"}))
        .await;
    let pool_id = pool_response["UserPool"]["Id"].as_str().unwrap();

    let client_response = client
        .cognito_request(
            "CreateUserPoolClient",
            json!({
                "UserPoolId": pool_id,
                "ClientName": "test-client"
            }),
        )
        .await;
    let client_id = client_response["UserPoolClient"]["ClientId"]
        .as_str()
        .unwrap();

    // Try to sign up with username containing spaces
    let response = client
        .cognito_request_raw(
            "SignUp",
            json!({
                "ClientId": client_id,
                "Username": "user name",
                "Password": "password123"
            }),
        )
        .await;

    assert_eq!(response.status(), 400);
    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["__type"], "InvalidParameterException");
}

// =============================================================================
// Password validation tests
// =============================================================================

#[tokio::test]
async fn test_sign_up_password_too_short() {
    let client = TestClient::new();

    let pool_response = client
        .cognito_request("CreateUserPool", json!({"PoolName": "test-pool"}))
        .await;
    let pool_id = pool_response["UserPool"]["Id"].as_str().unwrap();

    let client_response = client
        .cognito_request(
            "CreateUserPoolClient",
            json!({
                "UserPoolId": pool_id,
                "ClientName": "test-client"
            }),
        )
        .await;
    let client_id = client_response["UserPoolClient"]["ClientId"]
        .as_str()
        .unwrap();

    // Try to sign up with password that's too short (less than 6 chars)
    let response = client
        .cognito_request_raw(
            "SignUp",
            json!({
                "ClientId": client_id,
                "Username": "testuser",
                "Password": "12345"
            }),
        )
        .await;

    assert_eq!(response.status(), 400);
    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["__type"], "InvalidParameterException");
}

#[tokio::test]
async fn test_change_password_new_password_too_short() {
    let client = TestClient::new();

    // Create user pool, client, and user
    let pool_response = client
        .cognito_request("CreateUserPool", json!({"PoolName": "test-pool"}))
        .await;
    let pool_id = pool_response["UserPool"]["Id"].as_str().unwrap();

    let client_response = client
        .cognito_request(
            "CreateUserPoolClient",
            json!({
                "UserPoolId": pool_id,
                "ClientName": "test-client"
            }),
        )
        .await;
    let client_id = client_response["UserPoolClient"]["ClientId"]
        .as_str()
        .unwrap();

    // Sign up and confirm user
    client
        .cognito_request(
            "SignUp",
            json!({
                "ClientId": client_id,
                "Username": "testuser",
                "Password": "password123"
            }),
        )
        .await;

    client
        .cognito_request(
            "AdminConfirmSignUp",
            json!({
                "UserPoolId": pool_id,
                "Username": "testuser"
            }),
        )
        .await;

    // Login to get access token
    let auth_response = client
        .cognito_request(
            "InitiateAuth",
            json!({
                "ClientId": client_id,
                "AuthFlow": "USER_PASSWORD_AUTH",
                "AuthParameters": {
                    "USERNAME": "testuser",
                    "PASSWORD": "password123"
                }
            }),
        )
        .await;
    let access_token = auth_response["AuthenticationResult"]["AccessToken"]
        .as_str()
        .unwrap();

    // Try to change password to a short password
    let response = client
        .cognito_request_raw(
            "ChangePassword",
            json!({
                "AccessToken": access_token,
                "PreviousPassword": "password123",
                "ProposedPassword": "12345"
            }),
        )
        .await;

    assert_eq!(response.status(), 400);
    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["__type"], "InvalidParameterException");
}

// =============================================================================
// Email validation tests
// =============================================================================

#[tokio::test]
async fn test_sign_up_invalid_email() {
    let client = TestClient::new();

    let pool_response = client
        .cognito_request("CreateUserPool", json!({"PoolName": "test-pool"}))
        .await;
    let pool_id = pool_response["UserPool"]["Id"].as_str().unwrap();

    let client_response = client
        .cognito_request(
            "CreateUserPoolClient",
            json!({
                "UserPoolId": pool_id,
                "ClientName": "test-client"
            }),
        )
        .await;
    let client_id = client_response["UserPoolClient"]["ClientId"]
        .as_str()
        .unwrap();

    // Try to sign up with invalid email
    let response = client
        .cognito_request_raw(
            "SignUp",
            json!({
                "ClientId": client_id,
                "Username": "testuser",
                "Password": "password123",
                "UserAttributes": [
                    {"Name": "email", "Value": "notanemail"}
                ]
            }),
        )
        .await;

    assert_eq!(response.status(), 400);
    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["__type"], "InvalidParameterException");
}

// =============================================================================
// User disabled tests
// =============================================================================

#[tokio::test]
async fn test_initiate_auth_disabled_user() {
    let client = TestClient::new();

    // Create user pool and client
    let pool_response = client
        .cognito_request("CreateUserPool", json!({"PoolName": "test-pool"}))
        .await;
    let pool_id = pool_response["UserPool"]["Id"].as_str().unwrap();

    let client_response = client
        .cognito_request(
            "CreateUserPoolClient",
            json!({
                "UserPoolId": pool_id,
                "ClientName": "test-client"
            }),
        )
        .await;
    let client_id = client_response["UserPoolClient"]["ClientId"]
        .as_str()
        .unwrap();

    // Sign up and confirm user
    client
        .cognito_request(
            "SignUp",
            json!({
                "ClientId": client_id,
                "Username": "testuser",
                "Password": "password123"
            }),
        )
        .await;

    client
        .cognito_request(
            "AdminConfirmSignUp",
            json!({
                "UserPoolId": pool_id,
                "Username": "testuser"
            }),
        )
        .await;

    // Disable the user
    client
        .cognito_request(
            "AdminDisableUser",
            json!({
                "UserPoolId": pool_id,
                "Username": "testuser"
            }),
        )
        .await;

    // Try to login with disabled user
    let response = client
        .cognito_request_raw(
            "InitiateAuth",
            json!({
                "ClientId": client_id,
                "AuthFlow": "USER_PASSWORD_AUTH",
                "AuthParameters": {
                    "USERNAME": "testuser",
                    "PASSWORD": "password123"
                }
            }),
        )
        .await;

    assert_eq!(response.status(), 400);
    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["__type"], "UserDisabledException");
}

#[tokio::test]
async fn test_refresh_token_disabled_user() {
    let client = TestClient::new();

    // Create user pool and client
    let pool_response = client
        .cognito_request("CreateUserPool", json!({"PoolName": "test-pool"}))
        .await;
    let pool_id = pool_response["UserPool"]["Id"].as_str().unwrap();

    let client_response = client
        .cognito_request(
            "CreateUserPoolClient",
            json!({
                "UserPoolId": pool_id,
                "ClientName": "test-client"
            }),
        )
        .await;
    let client_id = client_response["UserPoolClient"]["ClientId"]
        .as_str()
        .unwrap();

    // Sign up and confirm user
    client
        .cognito_request(
            "SignUp",
            json!({
                "ClientId": client_id,
                "Username": "testuser",
                "Password": "password123"
            }),
        )
        .await;

    client
        .cognito_request(
            "AdminConfirmSignUp",
            json!({
                "UserPoolId": pool_id,
                "Username": "testuser"
            }),
        )
        .await;

    // Login to get refresh token
    let auth_response = client
        .cognito_request(
            "InitiateAuth",
            json!({
                "ClientId": client_id,
                "AuthFlow": "USER_PASSWORD_AUTH",
                "AuthParameters": {
                    "USERNAME": "testuser",
                    "PASSWORD": "password123"
                }
            }),
        )
        .await;
    let refresh_token = auth_response["AuthenticationResult"]["RefreshToken"]
        .as_str()
        .unwrap();

    // Disable the user after they got a refresh token
    client
        .cognito_request(
            "AdminDisableUser",
            json!({
                "UserPoolId": pool_id,
                "Username": "testuser"
            }),
        )
        .await;

    // Try to use refresh token with disabled user
    let response = client
        .cognito_request_raw(
            "InitiateAuth",
            json!({
                "ClientId": client_id,
                "AuthFlow": "REFRESH_TOKEN_AUTH",
                "AuthParameters": {
                    "REFRESH_TOKEN": refresh_token
                }
            }),
        )
        .await;

    assert_eq!(response.status(), 400);
    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["__type"], "UserDisabledException");
}

// =============================================================================
// Refresh token invalidation tests
// =============================================================================

#[tokio::test]
async fn test_refresh_token_after_global_signout() {
    let client = TestClient::new();

    // Create user pool and client
    let pool_response = client
        .cognito_request("CreateUserPool", json!({"PoolName": "test-pool"}))
        .await;
    let pool_id = pool_response["UserPool"]["Id"].as_str().unwrap();

    let client_response = client
        .cognito_request(
            "CreateUserPoolClient",
            json!({
                "UserPoolId": pool_id,
                "ClientName": "test-client"
            }),
        )
        .await;
    let client_id = client_response["UserPoolClient"]["ClientId"]
        .as_str()
        .unwrap();

    // Sign up and confirm user
    client
        .cognito_request(
            "SignUp",
            json!({
                "ClientId": client_id,
                "Username": "testuser",
                "Password": "password123"
            }),
        )
        .await;

    client
        .cognito_request(
            "AdminConfirmSignUp",
            json!({
                "UserPoolId": pool_id,
                "Username": "testuser"
            }),
        )
        .await;

    // Login to get tokens
    let auth_response = client
        .cognito_request(
            "InitiateAuth",
            json!({
                "ClientId": client_id,
                "AuthFlow": "USER_PASSWORD_AUTH",
                "AuthParameters": {
                    "USERNAME": "testuser",
                    "PASSWORD": "password123"
                }
            }),
        )
        .await;
    let access_token = auth_response["AuthenticationResult"]["AccessToken"]
        .as_str()
        .unwrap();
    let refresh_token = auth_response["AuthenticationResult"]["RefreshToken"]
        .as_str()
        .unwrap();

    // Global sign out
    client
        .cognito_request(
            "GlobalSignOut",
            json!({
                "AccessToken": access_token
            }),
        )
        .await;

    // Try to use refresh token after sign out
    let response = client
        .cognito_request_raw(
            "InitiateAuth",
            json!({
                "ClientId": client_id,
                "AuthFlow": "REFRESH_TOKEN_AUTH",
                "AuthParameters": {
                    "REFRESH_TOKEN": refresh_token
                }
            }),
        )
        .await;

    assert_eq!(response.status(), 401);
    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["__type"], "NotAuthorizedException");
}

// =============================================================================
// URL validation tests
// =============================================================================

#[tokio::test]
async fn test_create_client_invalid_callback_url() {
    let client = TestClient::new();

    let pool_response = client
        .cognito_request("CreateUserPool", json!({"PoolName": "test-pool"}))
        .await;
    let pool_id = pool_response["UserPool"]["Id"].as_str().unwrap();

    // Try to create client with invalid callback URL
    let response = client
        .cognito_request_raw(
            "CreateUserPoolClient",
            json!({
                "UserPoolId": pool_id,
                "ClientName": "test-client",
                "CallbackURLs": ["not-a-valid-url"]
            }),
        )
        .await;

    assert_eq!(response.status(), 400);
    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["__type"], "InvalidParameterException");
}

// =============================================================================
// Pool name validation tests
// =============================================================================

#[tokio::test]
async fn test_create_user_pool_empty_name() {
    let client = TestClient::new();

    let response = client
        .cognito_request_raw("CreateUserPool", json!({"PoolName": ""}))
        .await;

    assert_eq!(response.status(), 400);
    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["__type"], "InvalidParameterException");
}

// =============================================================================
// Group name validation tests
// =============================================================================

#[tokio::test]
async fn test_create_group_empty_name() {
    let client = TestClient::new();

    let pool_response = client
        .cognito_request("CreateUserPool", json!({"PoolName": "test-pool"}))
        .await;
    let pool_id = pool_response["UserPool"]["Id"].as_str().unwrap();

    let response = client
        .cognito_request_raw(
            "CreateGroup",
            json!({
                "UserPoolId": pool_id,
                "GroupName": ""
            }),
        )
        .await;

    assert_eq!(response.status(), 400);
    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["__type"], "InvalidParameterException");
}

// =============================================================================
// UserPoolId format validation tests
// =============================================================================

#[tokio::test]
async fn test_describe_user_pool_invalid_id_format() {
    let client = TestClient::new();

    // UserPoolId must match pattern [\w-]+_[0-9a-zA-Z]+
    // "invalid" doesn't have underscore separator
    let response = client
        .cognito_request_raw(
            "DescribeUserPool",
            json!({
                "UserPoolId": "invalid"
            }),
        )
        .await;

    assert_eq!(response.status(), 400);
    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["__type"], "InvalidParameterException");
}

#[tokio::test]
async fn test_describe_user_pool_id_too_long() {
    let client = TestClient::new();

    // UserPoolId max length is 55 characters
    let long_id = format!("local_{}", "a".repeat(50));
    let response = client
        .cognito_request_raw(
            "DescribeUserPool",
            json!({
                "UserPoolId": long_id
            }),
        )
        .await;

    assert_eq!(response.status(), 400);
    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["__type"], "InvalidParameterException");
}

// =============================================================================
// UpdateUserPoolClient validation tests
// =============================================================================

#[tokio::test]
async fn test_update_user_pool_client_invalid_callback_url() {
    let client = TestClient::new();

    let pool_response = client
        .cognito_request("CreateUserPool", json!({"PoolName": "test-pool"}))
        .await;
    let pool_id = pool_response["UserPool"]["Id"].as_str().unwrap();

    let client_response = client
        .cognito_request(
            "CreateUserPoolClient",
            json!({
                "UserPoolId": pool_id,
                "ClientName": "test-client"
            }),
        )
        .await;
    let client_id = client_response["UserPoolClient"]["ClientId"]
        .as_str()
        .unwrap();

    // Try to update client with invalid callback URL
    let response = client
        .cognito_request_raw(
            "UpdateUserPoolClient",
            json!({
                "UserPoolId": pool_id,
                "ClientId": client_id,
                "CallbackURLs": ["not-a-valid-url"]
            }),
        )
        .await;

    assert_eq!(response.status(), 400);
    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["__type"], "InvalidParameterException");
}
