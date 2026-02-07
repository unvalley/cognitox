//! Hosted UI tests

mod common;

use axum::http::StatusCode;
use common::TestClient;
use serde_json::json;

#[tokio::test]
async fn test_login_page_renders() {
    let client = TestClient::new();

    // Create user pool and client
    let (_, pool_body) = client
        .request("CreateUserPool", json!({ "PoolName": "test-pool" }))
        .await;
    let user_pool_id = pool_body["UserPool"]["Id"].as_str().unwrap();

    let (_, client_body) = client
        .request(
            "CreateUserPoolClient",
            json!({
                "UserPoolId": user_pool_id,
                "ClientName": "test-client",
                "CallbackURLs": ["https://example.com/callback"]
            }),
        )
        .await;
    let client_id = client_body["UserPoolClient"]["ClientId"].as_str().unwrap();

    // Get login page
    let response = client
        .get(&format!(
            "/login?response_type=code&client_id={}&redirect_uri=https://example.com/callback&scope=openid",
            client_id
        ))
        .await;

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.body_string();
    assert!(body.contains("<title>"));
    assert!(body.contains("Sign In"));
    assert!(body.contains("Username"));
    assert!(body.contains("Password"));
}

#[tokio::test]
async fn test_signup_page_renders() {
    let client = TestClient::new();

    // Create user pool and client
    let (_, pool_body) = client
        .request("CreateUserPool", json!({ "PoolName": "test-pool" }))
        .await;
    let user_pool_id = pool_body["UserPool"]["Id"].as_str().unwrap();

    let (_, client_body) = client
        .request(
            "CreateUserPoolClient",
            json!({
                "UserPoolId": user_pool_id,
                "ClientName": "test-client",
                "CallbackURLs": ["https://example.com/callback"]
            }),
        )
        .await;
    let client_id = client_body["UserPoolClient"]["ClientId"].as_str().unwrap();

    // Get signup page
    let response = client
        .get(&format!(
            "/signup?response_type=code&client_id={}&redirect_uri=https://example.com/callback&scope=openid",
            client_id
        ))
        .await;

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.body_string();
    assert!(body.contains("Create Account"));
    assert!(body.contains("Email"));
}

#[tokio::test]
async fn test_login_page_with_branding() {
    let client = TestClient::new();

    // Create user pool and client
    let (_, pool_body) = client
        .request("CreateUserPool", json!({ "PoolName": "test-pool" }))
        .await;
    let user_pool_id = pool_body["UserPool"]["Id"].as_str().unwrap();

    let (_, client_body) = client
        .request(
            "CreateUserPoolClient",
            json!({
                "UserPoolId": user_pool_id,
                "ClientName": "test-client",
                "CallbackURLs": ["https://example.com/callback"]
            }),
        )
        .await;
    let client_id = client_body["UserPoolClient"]["ClientId"].as_str().unwrap();

    // Create branding
    client
        .request(
            "CreateManagedLoginBranding",
            json!({
                "UserPoolId": user_pool_id,
                "Settings": {
                    "PageTitle": "Custom Login Page",
                    "SignInHeader": "Welcome to MyApp",
                    "Colors": {
                        "PrimaryColor": "#ff6600"
                    }
                }
            }),
        )
        .await;

    // Get login page - should show custom branding
    let response = client
        .get(&format!(
            "/login?response_type=code&client_id={}&redirect_uri=https://example.com/callback&scope=openid",
            client_id
        ))
        .await;

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.body_string();
    assert!(body.contains("Custom Login Page"));
    assert!(body.contains("Welcome to MyApp"));
    assert!(body.contains("#ff6600"));
}

#[tokio::test]
async fn test_forgot_password_page() {
    let client = TestClient::new();

    // Create user pool and client
    let (_, pool_body) = client
        .request("CreateUserPool", json!({ "PoolName": "test-pool" }))
        .await;
    let user_pool_id = pool_body["UserPool"]["Id"].as_str().unwrap();

    let (_, client_body) = client
        .request(
            "CreateUserPoolClient",
            json!({
                "UserPoolId": user_pool_id,
                "ClientName": "test-client",
                "CallbackURLs": ["https://example.com/callback"]
            }),
        )
        .await;
    let client_id = client_body["UserPoolClient"]["ClientId"].as_str().unwrap();

    // Get forgot password page
    let response = client
        .get(&format!(
            "/forgot-password?response_type=code&client_id={}&redirect_uri=https://example.com/callback&scope=openid",
            client_id
        ))
        .await;

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.body_string();
    assert!(body.contains("Reset Password"));
}
