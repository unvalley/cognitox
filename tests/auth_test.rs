//! Authentication flow tests

mod common;

use axum::http::StatusCode;
use serde_json::json;

use common::TestClient;

async fn setup_pool_and_client(client: &TestClient) -> (String, String) {
    let (_, pool_body) = client
        .request("CreateUserPool", json!({ "PoolName": "TestPool" }))
        .await;

    let pool_id = pool_body["UserPool"]["Id"].as_str().unwrap().to_string();

    let (_, client_body) = client
        .request(
            "CreateUserPoolClient",
            json!({ "UserPoolId": pool_id, "ClientName": "TestClient" }),
        )
        .await;

    let client_id = client_body["UserPoolClient"]["ClientId"]
        .as_str()
        .unwrap()
        .to_string();

    (pool_id, client_id)
}

#[tokio::test]
async fn test_sign_up_and_confirm_flow() {
    let client = TestClient::new();
    let (_, client_id) = setup_pool_and_client(&client).await;

    // Sign up
    let (status, _) = client
        .request(
            "SignUp",
            json!({
                "ClientId": client_id,
                "Username": "testuser",
                "Password": "Password123!",
                "UserAttributes": [
                    { "Name": "email", "Value": "test@example.com" }
                ]
            }),
        )
        .await;

    assert_eq!(status, StatusCode::OK);

    // Try to authenticate before confirmation - should fail
    let (status, body) = client
        .request(
            "InitiateAuth",
            json!({
                "ClientId": client_id,
                "AuthFlow": "USER_PASSWORD_AUTH",
                "AuthParameters": {
                    "USERNAME": "testuser",
                    "PASSWORD": "Password123!"
                }
            }),
        )
        .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["__type"], "UserNotConfirmedException");
}

#[tokio::test]
async fn test_initiate_auth_user_not_found() {
    let client = TestClient::new();
    let (_, client_id) = setup_pool_and_client(&client).await;

    let (status, body) = client
        .request(
            "InitiateAuth",
            json!({
                "ClientId": client_id,
                "AuthFlow": "USER_PASSWORD_AUTH",
                "AuthParameters": {
                    "USERNAME": "nonexistent",
                    "PASSWORD": "Password123!"
                }
            }),
        )
        .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["__type"], "UserNotFoundException");
}

#[tokio::test]
async fn test_initiate_auth_invalid_client() {
    let client = TestClient::new();

    let (status, body) = client
        .request(
            "InitiateAuth",
            json!({
                "ClientId": "invalid-client-id",
                "AuthFlow": "USER_PASSWORD_AUTH",
                "AuthParameters": {
                    "USERNAME": "testuser",
                    "PASSWORD": "Password123!"
                }
            }),
        )
        .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["__type"], "ResourceNotFoundException");
}

#[tokio::test]
async fn test_resend_confirmation_code() {
    let client = TestClient::new();
    let (_, client_id) = setup_pool_and_client(&client).await;

    // Sign up first
    client
        .request(
            "SignUp",
            json!({
                "ClientId": client_id,
                "Username": "testuser",
                "Password": "Password123!",
                "UserAttributes": [
                    { "Name": "email", "Value": "test@example.com" }
                ]
            }),
        )
        .await;

    let (status, body) = client
        .request(
            "ResendConfirmationCode",
            json!({
                "ClientId": client_id,
                "Username": "testuser"
            }),
        )
        .await;

    assert_eq!(status, StatusCode::OK);
    assert!(body["CodeDeliveryDetails"].is_object());
}

#[tokio::test]
async fn test_resend_confirmation_code_user_not_found() {
    let client = TestClient::new();
    let (_, client_id) = setup_pool_and_client(&client).await;

    let (status, body) = client
        .request(
            "ResendConfirmationCode",
            json!({
                "ClientId": client_id,
                "Username": "nonexistent"
            }),
        )
        .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["__type"], "UserNotFoundException");
}

#[tokio::test]
async fn test_confirm_sign_up_invalid_code() {
    let client = TestClient::new();
    let (_, client_id) = setup_pool_and_client(&client).await;

    // Sign up first
    client
        .request(
            "SignUp",
            json!({
                "ClientId": client_id,
                "Username": "testuser",
                "Password": "Password123!"
            }),
        )
        .await;

    let (status, body) = client
        .request(
            "ConfirmSignUp",
            json!({
                "ClientId": client_id,
                "Username": "testuser",
                "ConfirmationCode": "000000"
            }),
        )
        .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["__type"], "CodeMismatchException");
}

#[tokio::test]
async fn test_not_implemented_operation() {
    let client = TestClient::new();

    let (status, body) = client.request("SomeUnknownOperation", json!({})).await;

    assert_eq!(status, StatusCode::NOT_IMPLEMENTED);
    assert_eq!(body["__type"], "NotImplementedException");
}

#[tokio::test]
async fn test_change_password() {
    let client = TestClient::new();
    let (pool_id, client_id) = setup_pool_and_client(&client).await;

    // Create and confirm user
    client
        .request(
            "AdminCreateUser",
            json!({
                "UserPoolId": pool_id,
                "Username": "testuser"
            }),
        )
        .await;

    client
        .request(
            "AdminConfirmSignUp",
            json!({
                "UserPoolId": pool_id,
                "Username": "testuser"
            }),
        )
        .await;

    // Set initial password
    client
        .request(
            "AdminSetUserPassword",
            json!({
                "UserPoolId": pool_id,
                "Username": "testuser",
                "Password": "OldPassword123!",
                "Permanent": true
            }),
        )
        .await;

    // Authenticate to get access token
    let (_, auth_body) = client
        .request(
            "InitiateAuth",
            json!({
                "ClientId": client_id,
                "AuthFlow": "USER_PASSWORD_AUTH",
                "AuthParameters": {
                    "USERNAME": "testuser",
                    "PASSWORD": "OldPassword123!"
                }
            }),
        )
        .await;

    let access_token = auth_body["AuthenticationResult"]["AccessToken"]
        .as_str()
        .unwrap();

    // Change password
    let (status, _) = client
        .request(
            "ChangePassword",
            json!({
                "AccessToken": access_token,
                "PreviousPassword": "OldPassword123!",
                "ProposedPassword": "NewPassword456!"
            }),
        )
        .await;

    assert_eq!(status, StatusCode::OK);

    // Verify new password works
    let (status, _) = client
        .request(
            "InitiateAuth",
            json!({
                "ClientId": client_id,
                "AuthFlow": "USER_PASSWORD_AUTH",
                "AuthParameters": {
                    "USERNAME": "testuser",
                    "PASSWORD": "NewPassword456!"
                }
            }),
        )
        .await;

    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn test_change_password_wrong_previous() {
    let client = TestClient::new();
    let (pool_id, client_id) = setup_pool_and_client(&client).await;

    // Create and confirm user
    client
        .request(
            "AdminCreateUser",
            json!({
                "UserPoolId": pool_id,
                "Username": "testuser"
            }),
        )
        .await;

    client
        .request(
            "AdminConfirmSignUp",
            json!({
                "UserPoolId": pool_id,
                "Username": "testuser"
            }),
        )
        .await;

    client
        .request(
            "AdminSetUserPassword",
            json!({
                "UserPoolId": pool_id,
                "Username": "testuser",
                "Password": "Password123!",
                "Permanent": true
            }),
        )
        .await;

    let (_, auth_body) = client
        .request(
            "InitiateAuth",
            json!({
                "ClientId": client_id,
                "AuthFlow": "USER_PASSWORD_AUTH",
                "AuthParameters": {
                    "USERNAME": "testuser",
                    "PASSWORD": "Password123!"
                }
            }),
        )
        .await;

    let access_token = auth_body["AuthenticationResult"]["AccessToken"]
        .as_str()
        .unwrap();

    // Try to change with wrong previous password
    let (status, body) = client
        .request(
            "ChangePassword",
            json!({
                "AccessToken": access_token,
                "PreviousPassword": "WrongPassword!",
                "ProposedPassword": "NewPassword456!"
            }),
        )
        .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["__type"], "InvalidPasswordException");
}

#[tokio::test]
async fn test_forgot_password() {
    let client = TestClient::new();
    let (pool_id, client_id) = setup_pool_and_client(&client).await;

    // Create user with email
    client
        .request(
            "AdminCreateUser",
            json!({
                "UserPoolId": pool_id,
                "Username": "testuser",
                "UserAttributes": [
                    { "Name": "email", "Value": "test@example.com" }
                ]
            }),
        )
        .await;

    let (status, body) = client
        .request(
            "ForgotPassword",
            json!({
                "ClientId": client_id,
                "Username": "testuser"
            }),
        )
        .await;

    assert_eq!(status, StatusCode::OK);
    assert!(body["CodeDeliveryDetails"].is_object());
    assert_eq!(body["CodeDeliveryDetails"]["DeliveryMedium"], "EMAIL");
}

#[tokio::test]
async fn test_global_sign_out() {
    let client = TestClient::new();
    let (pool_id, client_id) = setup_pool_and_client(&client).await;

    // Create and confirm user
    client
        .request(
            "AdminCreateUser",
            json!({
                "UserPoolId": pool_id,
                "Username": "testuser"
            }),
        )
        .await;

    client
        .request(
            "AdminConfirmSignUp",
            json!({
                "UserPoolId": pool_id,
                "Username": "testuser"
            }),
        )
        .await;

    client
        .request(
            "AdminSetUserPassword",
            json!({
                "UserPoolId": pool_id,
                "Username": "testuser",
                "Password": "Password123!",
                "Permanent": true
            }),
        )
        .await;

    let (_, auth_body) = client
        .request(
            "InitiateAuth",
            json!({
                "ClientId": client_id,
                "AuthFlow": "USER_PASSWORD_AUTH",
                "AuthParameters": {
                    "USERNAME": "testuser",
                    "PASSWORD": "Password123!"
                }
            }),
        )
        .await;

    let access_token = auth_body["AuthenticationResult"]["AccessToken"]
        .as_str()
        .unwrap();

    // Global sign out
    let (status, _) = client
        .request(
            "GlobalSignOut",
            json!({
                "AccessToken": access_token
            }),
        )
        .await;

    assert_eq!(status, StatusCode::OK);
}
