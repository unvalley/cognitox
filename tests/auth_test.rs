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
