//! OAuth 2.0 endpoint tests

mod common;

use axum::http::StatusCode;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use hmac::{Hmac, Mac};
use serde_json::json;
use sha2::Sha256;

use common::TestClient;

fn calculate_secret_hash(client_id: &str, client_secret: &str, username: &str) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(client_secret.as_bytes()).unwrap();
    mac.update(username.as_bytes());
    mac.update(client_id.as_bytes());
    BASE64_STANDARD.encode(mac.finalize().into_bytes())
}

async fn setup_user_and_client(client: &TestClient) -> (String, String, String, String) {
    // Create user pool
    let (_, pool_body) = client
        .request("CreateUserPool", json!({ "PoolName": "TestPool" }))
        .await;
    let pool_id = pool_body["UserPool"]["Id"].as_str().unwrap().to_string();

    // Create client with OAuth settings
    let (_, client_body) = client
        .request(
            "CreateUserPoolClient",
            json!({
                "UserPoolId": pool_id,
                "ClientName": "OAuthClient",
                "AllowedOAuthFlows": ["code", "implicit"],
                "AllowedOAuthScopes": ["openid", "email", "profile"],
                "AllowedOAuthFlowsUserPoolClient": true,
                "CallbackURLs": ["https://example.com/callback"],
                "GenerateSecret": false
            }),
        )
        .await;
    let client_id = client_body["UserPoolClient"]["ClientId"]
        .as_str()
        .unwrap()
        .to_string();

    // Create and confirm user
    client
        .request(
            "SignUp",
            json!({
                "ClientId": client_id,
                "Username": "testuser",
                "Password": "Test123!",
                "UserAttributes": [
                    { "Name": "email", "Value": "test@example.com" }
                ]
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

    (
        pool_id,
        client_id,
        "testuser".to_string(),
        "Test123!".to_string(),
    )
}

async fn setup_user_and_confidential_client(
    client: &TestClient,
) -> (String, String, String, String, String) {
    let (_, pool_body) = client
        .request(
            "CreateUserPool",
            json!({ "PoolName": "TestPoolWithSecret" }),
        )
        .await;
    let pool_id = pool_body["UserPool"]["Id"].as_str().unwrap().to_string();

    let (_, client_body) = client
        .request(
            "CreateUserPoolClient",
            json!({
                "UserPoolId": pool_id,
                "ClientName": "OAuthClientWithSecret",
                "AllowedOAuthFlows": ["code", "implicit"],
                "AllowedOAuthScopes": ["openid", "email", "profile"],
                "AllowedOAuthFlowsUserPoolClient": true,
                "CallbackURLs": ["https://example.com/callback"],
                "GenerateSecret": true
            }),
        )
        .await;
    let client_id = client_body["UserPoolClient"]["ClientId"]
        .as_str()
        .unwrap()
        .to_string();
    let client_secret = client_body["UserPoolClient"]["ClientSecret"]
        .as_str()
        .unwrap()
        .to_string();

    client
        .request(
            "SignUp",
            json!({
                "ClientId": client_id,
                "Username": "testuser",
                "Password": "Test123!",
                "SecretHash": calculate_secret_hash(&client_id, &client_secret, "testuser"),
                "UserAttributes": [
                    { "Name": "email", "Value": "test@example.com" }
                ]
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

    (
        pool_id,
        client_id,
        client_secret,
        "testuser".to_string(),
        "Test123!".to_string(),
    )
}

#[tokio::test]
async fn test_openid_configuration() {
    let client = TestClient::new();

    let response = client.get("/.well-known/openid-configuration").await;

    assert_eq!(response.status(), StatusCode::OK);

    let body: serde_json::Value = response.json().await.unwrap();
    assert!(body["authorization_endpoint"].as_str().is_some());
    assert!(body["token_endpoint"].as_str().is_some());
    assert!(body["userinfo_endpoint"].as_str().is_some());
    assert!(body["jwks_uri"].as_str().is_some());
}

#[tokio::test]
async fn test_jwks_endpoint() {
    let client = TestClient::new();

    let response = client.get("/.well-known/jwks.json").await;

    assert_eq!(response.status(), StatusCode::OK);

    let body: serde_json::Value = response.json().await.unwrap();
    assert!(body["keys"].is_array());
    let keys = body["keys"].as_array().unwrap();
    assert!(!keys.is_empty());
    assert_eq!(keys[0]["kty"], "RSA");
    assert_eq!(keys[0]["alg"], "RS256");
}

#[tokio::test]
async fn test_authorization_code_flow() {
    let client = TestClient::new();
    let (_, client_id, username, password) = setup_user_and_client(&client).await;

    // Request authorization code with direct auth (for testing)
    let auth_url = format!(
        "/oauth2/authorize?response_type=code&client_id={}&redirect_uri={}&scope={}&username={}&password={}",
        client_id, "https://example.com/callback", "openid%20email", username, password
    );

    let response = client.get(&auth_url).await;

    // Should redirect with code
    assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);

    let location = response
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(location.contains("code="));
    assert!(location.starts_with("https://example.com/callback"));

    // Extract code from redirect URL
    let code = location
        .split("code=")
        .nth(1)
        .unwrap()
        .split('&')
        .next()
        .unwrap();

    // Exchange code for tokens
    let token_response = client
        .post_form(
            "/oauth2/token",
            &[
                ("grant_type", "authorization_code"),
                ("code", code),
                ("client_id", &client_id),
                ("redirect_uri", "https://example.com/callback"),
            ],
        )
        .await;

    assert_eq!(token_response.status(), StatusCode::OK);

    let token_body: serde_json::Value = token_response.json().await.unwrap();
    assert!(token_body["access_token"].as_str().is_some());
    assert!(token_body["id_token"].as_str().is_some());
    assert!(token_body["refresh_token"].as_str().is_some());
    assert_eq!(token_body["token_type"], "Bearer");
}

#[tokio::test]
async fn test_authorization_code_flow_returns_json_redirect_for_xhr_login() {
    let client = TestClient::new();
    let (_, client_id, username, password) = setup_user_and_client(&client).await;

    let auth_url = format!(
        "/oauth2/authorize?response_type=code&client_id={}&redirect_uri={}&scope={}&username={}&password={}",
        client_id, "https://example.com/callback", "openid%20email", username, password
    );

    let response = client
        .get_with_headers(
            &auth_url,
            &[
                ("accept", "application/json"),
                ("x-requested-with", "XMLHttpRequest"),
            ],
        )
        .await;

    assert_eq!(response.status(), StatusCode::OK);

    let body: serde_json::Value = response.json().await.unwrap();
    let redirect_url = body["redirectUrl"].as_str().unwrap();
    assert!(redirect_url.contains("code="));
    assert!(redirect_url.starts_with("https://example.com/callback"));
}

#[tokio::test]
async fn test_authorization_code_flow_with_pkce() {
    let client = TestClient::new();
    let (_, client_id, username, password) = setup_user_and_client(&client).await;

    // Generate PKCE code verifier and challenge
    let code_verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    // S256 hash of code_verifier
    let code_challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    // Request authorization code with PKCE
    let auth_url = format!(
        "/oauth2/authorize?response_type=code&client_id={}&redirect_uri={}&scope={}&code_challenge={}&code_challenge_method=S256&username={}&password={}",
        client_id, "https://example.com/callback", "openid", code_challenge, username, password
    );

    let response = client.get(&auth_url).await;
    assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);

    let location = response
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap();
    let code = location
        .split("code=")
        .nth(1)
        .unwrap()
        .split('&')
        .next()
        .unwrap();

    // Exchange code for tokens with code_verifier
    let token_response = client
        .post_form(
            "/oauth2/token",
            &[
                ("grant_type", "authorization_code"),
                ("code", code),
                ("client_id", &client_id),
                ("redirect_uri", "https://example.com/callback"),
                ("code_verifier", code_verifier),
            ],
        )
        .await;

    assert_eq!(token_response.status(), StatusCode::OK);

    let token_body: serde_json::Value = token_response.json().await.unwrap();
    assert!(token_body["access_token"].as_str().is_some());
}

#[tokio::test]
async fn test_refresh_token_flow() {
    let client = TestClient::new();
    let (_, client_id, username, password) = setup_user_and_client(&client).await;

    // Get initial tokens
    let auth_url = format!(
        "/oauth2/authorize?response_type=code&client_id={}&redirect_uri={}&scope={}&username={}&password={}",
        client_id, "https://example.com/callback", "openid", username, password
    );

    let response = client.get(&auth_url).await;
    let location = response
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap();
    let code = location
        .split("code=")
        .nth(1)
        .unwrap()
        .split('&')
        .next()
        .unwrap();

    let token_response = client
        .post_form(
            "/oauth2/token",
            &[
                ("grant_type", "authorization_code"),
                ("code", code),
                ("client_id", &client_id),
                ("redirect_uri", "https://example.com/callback"),
            ],
        )
        .await;

    let token_body: serde_json::Value = token_response.json().await.unwrap();
    let refresh_token = token_body["refresh_token"].as_str().unwrap();

    // Use refresh token to get new access token
    let refresh_response = client
        .post_form(
            "/oauth2/token",
            &[
                ("grant_type", "refresh_token"),
                ("refresh_token", refresh_token),
                ("client_id", &client_id),
            ],
        )
        .await;

    assert_eq!(refresh_response.status(), StatusCode::OK);

    let refresh_body: serde_json::Value = refresh_response.json().await.unwrap();
    assert!(refresh_body["access_token"].as_str().is_some());
}

#[tokio::test]
async fn test_refresh_token_flow_requires_client_secret_for_confidential_client() {
    let client = TestClient::new();
    let (_, client_id, client_secret, username, password) =
        setup_user_and_confidential_client(&client).await;

    let auth_url = format!(
        "/oauth2/authorize?response_type=code&client_id={}&redirect_uri={}&scope={}&username={}&password={}",
        client_id, "https://example.com/callback", "openid", username, password
    );

    let response = client.get(&auth_url).await;
    let location = response
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap();
    let code = location
        .split("code=")
        .nth(1)
        .unwrap()
        .split('&')
        .next()
        .unwrap();

    let token_response = client
        .post_form(
            "/oauth2/token",
            &[
                ("grant_type", "authorization_code"),
                ("code", code),
                ("client_id", &client_id),
                ("client_secret", &client_secret),
                ("redirect_uri", "https://example.com/callback"),
            ],
        )
        .await;
    assert_eq!(token_response.status(), StatusCode::OK);
    let token_body: serde_json::Value = token_response.json().await.unwrap();
    let refresh_token = token_body["refresh_token"].as_str().unwrap();

    let refresh_response = client
        .post_form(
            "/oauth2/token",
            &[
                ("grant_type", "refresh_token"),
                ("refresh_token", refresh_token),
                ("client_id", &client_id),
            ],
        )
        .await;
    assert_eq!(refresh_response.status(), StatusCode::BAD_REQUEST);
    let refresh_body: serde_json::Value = refresh_response.json().await.unwrap();
    assert_eq!(refresh_body["error"], "invalid_client");
}

#[tokio::test]
async fn test_refresh_token_flow_rejects_disabled_user() {
    let client = TestClient::new();
    let (pool_id, client_id, username, password) = setup_user_and_client(&client).await;

    let auth_url = format!(
        "/oauth2/authorize?response_type=code&client_id={}&redirect_uri={}&scope={}&username={}&password={}",
        client_id, "https://example.com/callback", "openid", username, password
    );

    let response = client.get(&auth_url).await;
    let location = response
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap();
    let code = location
        .split("code=")
        .nth(1)
        .unwrap()
        .split('&')
        .next()
        .unwrap();

    let token_response = client
        .post_form(
            "/oauth2/token",
            &[
                ("grant_type", "authorization_code"),
                ("code", code),
                ("client_id", &client_id),
                ("redirect_uri", "https://example.com/callback"),
            ],
        )
        .await;
    assert_eq!(token_response.status(), StatusCode::OK);
    let token_body: serde_json::Value = token_response.json().await.unwrap();
    let refresh_token = token_body["refresh_token"].as_str().unwrap();

    let (status, _) = client
        .request(
            "AdminDisableUser",
            json!({
                "UserPoolId": pool_id,
                "Username": username
            }),
        )
        .await;
    assert_eq!(status, StatusCode::OK);

    let refresh_response = client
        .post_form(
            "/oauth2/token",
            &[
                ("grant_type", "refresh_token"),
                ("refresh_token", refresh_token),
                ("client_id", &client_id),
            ],
        )
        .await;
    assert_eq!(refresh_response.status(), StatusCode::BAD_REQUEST);
    let refresh_body: serde_json::Value = refresh_response.json().await.unwrap();
    assert_eq!(refresh_body["error"], "invalid_grant");
}

#[tokio::test]
async fn test_refresh_token_flow_rejects_client_id_mismatch() {
    let client = TestClient::new();
    let (pool_id, client_id, username, password) = setup_user_and_client(&client).await;

    let (_, second_client_body) = client
        .request(
            "CreateUserPoolClient",
            json!({
                "UserPoolId": pool_id,
                "ClientName": "OAuthClient2",
                "AllowedOAuthFlows": ["code", "implicit"],
                "AllowedOAuthScopes": ["openid", "email", "profile"],
                "AllowedOAuthFlowsUserPoolClient": true,
                "CallbackURLs": ["https://example.com/callback"],
                "GenerateSecret": false
            }),
        )
        .await;
    let second_client_id = second_client_body["UserPoolClient"]["ClientId"]
        .as_str()
        .unwrap();

    let auth_url = format!(
        "/oauth2/authorize?response_type=code&client_id={}&redirect_uri={}&scope={}&username={}&password={}",
        client_id, "https://example.com/callback", "openid", username, password
    );

    let response = client.get(&auth_url).await;
    let location = response
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap();
    let code = location
        .split("code=")
        .nth(1)
        .unwrap()
        .split('&')
        .next()
        .unwrap();

    let token_response = client
        .post_form(
            "/oauth2/token",
            &[
                ("grant_type", "authorization_code"),
                ("code", code),
                ("client_id", &client_id),
                ("redirect_uri", "https://example.com/callback"),
            ],
        )
        .await;
    assert_eq!(token_response.status(), StatusCode::OK);
    let token_body: serde_json::Value = token_response.json().await.unwrap();
    let refresh_token = token_body["refresh_token"].as_str().unwrap();

    let refresh_response = client
        .post_form(
            "/oauth2/token",
            &[
                ("grant_type", "refresh_token"),
                ("refresh_token", refresh_token),
                ("client_id", second_client_id),
            ],
        )
        .await;
    assert_eq!(refresh_response.status(), StatusCode::BAD_REQUEST);
    let refresh_body: serde_json::Value = refresh_response.json().await.unwrap();
    assert_eq!(refresh_body["error"], "invalid_grant");
}

#[tokio::test]
async fn test_userinfo_endpoint() {
    let client = TestClient::new();
    let (_, client_id, username, password) = setup_user_and_client(&client).await;

    // Get tokens
    let auth_url = format!(
        "/oauth2/authorize?response_type=code&client_id={}&redirect_uri={}&scope={}&username={}&password={}",
        client_id, "https://example.com/callback", "openid%20email", username, password
    );

    let response = client.get(&auth_url).await;
    let location = response
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap();
    let code = location
        .split("code=")
        .nth(1)
        .unwrap()
        .split('&')
        .next()
        .unwrap();

    let token_response = client
        .post_form(
            "/oauth2/token",
            &[
                ("grant_type", "authorization_code"),
                ("code", code),
                ("client_id", &client_id),
                ("redirect_uri", "https://example.com/callback"),
            ],
        )
        .await;

    let token_body: serde_json::Value = token_response.json().await.unwrap();
    let access_token = token_body["access_token"].as_str().unwrap();

    // Call userinfo endpoint
    let userinfo_response = client.get_with_auth("/oauth2/userInfo", access_token).await;

    if userinfo_response.status() != StatusCode::OK {
        let body: serde_json::Value = userinfo_response.json().await.unwrap();
        panic!("UserInfo failed: {:?}", body);
    }

    let userinfo_body: serde_json::Value = userinfo_response.json().await.unwrap();
    assert!(userinfo_body["sub"].as_str().is_some());
    assert_eq!(userinfo_body["username"], "testuser");
    assert_eq!(userinfo_body["email"], "test@example.com");
}

#[tokio::test]
async fn test_invalid_client() {
    let client = TestClient::new();

    let auth_url = "/oauth2/authorize?response_type=code&client_id=invalid&redirect_uri=https://example.com/callback&scope=openid";

    let response = client.get(auth_url).await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["error"], "invalid_client");
}

#[tokio::test]
async fn test_authorize_rejects_client_without_oauth_enabled() {
    let client = TestClient::new();
    let (_, pool_body) = client
        .request("CreateUserPool", json!({ "PoolName": "TestPool" }))
        .await;
    let pool_id = pool_body["UserPool"]["Id"].as_str().unwrap().to_string();

    let (_, client_body) = client
        .request(
            "CreateUserPoolClient",
            json!({
                "UserPoolId": pool_id,
                "ClientName": "OAuthClient"
            }),
        )
        .await;
    let client_id = client_body["UserPoolClient"]["ClientId"]
        .as_str()
        .unwrap()
        .to_string();

    let response = client
        .get(&format!(
            "/oauth2/authorize?response_type=code&client_id={}&redirect_uri=https://example.com/callback&scope=openid",
            client_id
        ))
        .await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["error"], "unauthorized_client");
}

#[tokio::test]
async fn test_authorize_rejects_client_without_code_flow() {
    let client = TestClient::new();
    let (_, pool_body) = client
        .request("CreateUserPool", json!({ "PoolName": "TestPool" }))
        .await;
    let pool_id = pool_body["UserPool"]["Id"].as_str().unwrap().to_string();

    let (_, client_body) = client
        .request(
            "CreateUserPoolClient",
            json!({
                "UserPoolId": pool_id,
                "ClientName": "OAuthClient",
                "AllowedOAuthScopes": ["openid"],
                "CallbackURLs": ["https://example.com/callback"],
                "AllowedOAuthFlowsUserPoolClient": true
            }),
        )
        .await;
    let client_id = client_body["UserPoolClient"]["ClientId"]
        .as_str()
        .unwrap()
        .to_string();

    let response = client
        .get(&format!(
            "/oauth2/authorize?response_type=code&client_id={}&redirect_uri=https://example.com/callback&scope=openid",
            client_id
        ))
        .await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["error"], "unauthorized_client");
}

#[tokio::test]
async fn test_invalid_authorization_code() {
    let client = TestClient::new();
    let (_, client_id, _, _) = setup_user_and_client(&client).await;

    let token_response = client
        .post_form(
            "/oauth2/token",
            &[
                ("grant_type", "authorization_code"),
                ("code", "invalid_code"),
                ("client_id", &client_id),
                ("redirect_uri", "https://example.com/callback"),
            ],
        )
        .await;

    assert_eq!(token_response.status(), StatusCode::BAD_REQUEST);

    let body: serde_json::Value = token_response.json().await.unwrap();
    assert_eq!(body["error"], "invalid_grant");
}
