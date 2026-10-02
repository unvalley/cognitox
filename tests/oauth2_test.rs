//! OAuth 2.0 endpoint tests

mod common;

use axum::http::StatusCode;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use cognitox::jwt::{verify_access_token, verify_id_token};
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
async fn test_user_pool_discovery_and_jwks() {
    let client = TestClient::new();
    let (pool_id, _, _, _) = setup_user_and_client(&client).await;

    let response = client
        .get(&format!("/{pool_id}/.well-known/openid-configuration"))
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let discovery: serde_json::Value = response.json().await.unwrap();
    let issuer = discovery["issuer"].as_str().unwrap();
    assert!(issuer.ends_with(&format!("/{pool_id}")));
    assert_eq!(
        discovery["jwks_uri"],
        format!("{issuer}/.well-known/jwks.json")
    );

    let response = client
        .get(&format!("/{pool_id}/.well-known/jwks.json"))
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let jwks: serde_json::Value = response.json().await.unwrap();
    let root_jwks: serde_json::Value = client
        .get("/.well-known/jwks.json")
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(jwks, root_jwks);

    for path in [
        "/us-east-1_missing/.well-known/openid-configuration",
        "/us-east-1_missing/.well-known/jwks.json",
        "/not-a-pool/.well-known/jwks.json",
    ] {
        assert_eq!(client.get(path).await.status(), StatusCode::NOT_FOUND);
    }
}

#[tokio::test]
async fn test_authorization_code_flow() {
    let client = TestClient::new();
    let (pool_id, client_id, username, password) = setup_user_and_client(&client).await;

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

    let discovery: serde_json::Value = client
        .get(&format!("/{pool_id}/.well-known/openid-configuration"))
        .await
        .json()
        .await
        .unwrap();
    let id_token = token_body["id_token"].as_str().unwrap();
    let claims = verify_id_token(id_token, &client_id).unwrap().claims;
    assert_eq!(claims.iss, discovery["issuer"].as_str().unwrap());

    let access_token = token_body["access_token"].as_str().unwrap();
    let access_claims = verify_access_token(access_token).unwrap().claims;
    assert_eq!(access_claims.iss, claims.iss);
    assert_eq!(
        access_claims.origin_jti.as_deref(),
        Some(claims.origin_jti.as_str())
    );

    // Refreshed tokens keep the origin_jti of the refresh token's session.
    let refresh_token = token_body["refresh_token"].as_str().unwrap();
    let refreshed: serde_json::Value = client
        .post_form(
            "/oauth2/token",
            &[
                ("grant_type", "refresh_token"),
                ("client_id", &client_id),
                ("refresh_token", refresh_token),
            ],
        )
        .await
        .json()
        .await
        .unwrap();
    let refreshed_claims = verify_access_token(refreshed["access_token"].as_str().unwrap())
        .unwrap()
        .claims;
    assert_eq!(refreshed_claims.origin_jti, access_claims.origin_jti);
    assert_ne!(refreshed_claims.jti, access_claims.jti);
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
async fn test_authorization_code_flow_accepts_email_alias_login() {
    let client = TestClient::new();
    let (_, client_id, _, password) = setup_user_and_client(&client).await;

    let auth_url = format!(
        "/oauth2/authorize?response_type=code&client_id={}&redirect_uri={}&scope={}&username={}&password={}",
        client_id, "https://example.com/callback", "openid%20email", "test@example.com", password
    );

    let response = client.get(&auth_url).await;

    assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
    let location = response
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(location.contains("code="));
}

#[tokio::test]
async fn test_authorization_redirect_encodes_state() {
    let client = TestClient::new();
    let (_, client_id, username, password) = setup_user_and_client(&client).await;

    let auth_url = format!(
        "/oauth2/authorize?response_type=code&client_id={}&redirect_uri={}&scope={}&state={}&username={}&password={}",
        client_id,
        "https://example.com/callback",
        "openid",
        "a%20b%26c%3D%3Cx%3E",
        username,
        password
    );

    let response = client.get(&auth_url).await;
    assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);

    let location = response
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(location.contains("state=a%20b%26c%3D%3Cx%3E"));
    assert!(!location.contains("state=a b&c=<x>"));
}

#[tokio::test]
async fn test_login_html_escapes_hidden_values() {
    let client = TestClient::new();
    let (_, client_id, _, _) = setup_user_and_client(&client).await;

    let response = client
        .get(&format!(
            "/oauth2/authorize?response_type=code&client_id={}&redirect_uri=https://example.com/callback&scope=openid&state=%22%3E%3Cscript%3Ealert(1)%3C%2Fscript%3E",
            client_id
        ))
        .await;

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.body_string();
    assert!(body.contains("&quot;&gt;&lt;script&gt;alert(1)&lt;/script&gt;"));
    assert!(!body.contains("\"><script>alert(1)</script>"));
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
    assert_eq!(userinfo_body["email_verified"], true);
    assert!(userinfo_body.get("phone_number").is_none());
    assert!(userinfo_body.get("phone_number_verified").is_none());
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
async fn test_logout_redirects_to_allowed_logout_uri() {
    let client = TestClient::new();
    let (_, pool_body) = client
        .request("CreateUserPool", json!({ "PoolName": "LogoutPool" }))
        .await;
    let pool_id = pool_body["UserPool"]["Id"].as_str().unwrap().to_string();

    let (_, client_body) = client
        .request(
            "CreateUserPoolClient",
            json!({
                "UserPoolId": pool_id,
                "ClientName": "LogoutClient",
                "AllowedOAuthFlowsUserPoolClient": true,
                "LogoutURLs": ["http://localhost:3000/"]
            }),
        )
        .await;
    let client_id = client_body["UserPoolClient"]["ClientId"]
        .as_str()
        .unwrap()
        .to_string();

    let response = client
        .get(&format!(
            "/logout?client_id={}&logout_uri={}",
            client_id,
            urlencoding::encode("http://localhost:3000/")
        ))
        .await;

    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        response.headers().get("location").unwrap(),
        "http://localhost:3000/"
    );
}

#[tokio::test]
async fn test_logout_rejects_disallowed_logout_uri() {
    let client = TestClient::new();
    let (_, pool_body) = client
        .request("CreateUserPool", json!({ "PoolName": "LogoutPool" }))
        .await;
    let pool_id = pool_body["UserPool"]["Id"].as_str().unwrap().to_string();

    let (_, client_body) = client
        .request(
            "CreateUserPoolClient",
            json!({
                "UserPoolId": pool_id,
                "ClientName": "LogoutClient",
                "AllowedOAuthFlowsUserPoolClient": true,
                "LogoutURLs": ["http://localhost:3000/"]
            }),
        )
        .await;
    let client_id = client_body["UserPoolClient"]["ClientId"]
        .as_str()
        .unwrap()
        .to_string();

    let response = client
        .get(&format!(
            "/logout?client_id={}&logout_uri={}",
            client_id,
            urlencoding::encode("http://evil.example/")
        ))
        .await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["error"], "invalid_request");
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
async fn test_authorize_rejects_disallowed_scope() {
    let client = TestClient::new();
    let (_, client_id, username, password) = setup_user_and_client(&client).await;

    let auth_url = format!(
        "/oauth2/authorize?response_type=code&client_id={}&redirect_uri={}&scope={}&username={}&password={}",
        client_id, "https://example.com/callback", "openid%20phone", username, password
    );

    let response = client.get(&auth_url).await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["error"], "invalid_scope");
}

#[tokio::test]
async fn test_client_credentials_returns_jwt_access_token() {
    let client = TestClient::new();
    let (_, pool_body) = client
        .request(
            "CreateUserPool",
            json!({ "PoolName": "ClientCredentialsPool" }),
        )
        .await;
    let pool_id = pool_body["UserPool"]["Id"].as_str().unwrap().to_string();

    let (_, client_body) = client
        .request(
            "CreateUserPoolClient",
            json!({
                "UserPoolId": pool_id,
                "ClientName": "MachineClient",
                "GenerateSecret": true,
                "AllowedOAuthFlows": ["client_credentials"],
                "AllowedOAuthScopes": ["api/read"],
                "AllowedOAuthFlowsUserPoolClient": true
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

    let token_response = client
        .post_form(
            "/oauth2/token",
            &[
                ("grant_type", "client_credentials"),
                ("client_id", &client_id),
                ("client_secret", &client_secret),
                ("scope", "api/read"),
            ],
        )
        .await;

    assert_eq!(token_response.status(), StatusCode::OK);
    let body: serde_json::Value = token_response.json().await.unwrap();
    let access_token = body["access_token"].as_str().unwrap();
    assert_eq!(access_token.split('.').count(), 3);

    let claims = verify_access_token(access_token).unwrap().claims;
    assert_eq!(claims.client_id, client_id);
    assert_eq!(claims.scope, "api/read");
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

async fn request_authorization_code(
    client: &TestClient,
    client_id: &str,
    username: &str,
    password: &str,
) -> String {
    let response = client
        .get(&format!(
            "/oauth2/authorize?response_type=code&client_id={client_id}&redirect_uri=https://example.com/callback&scope=openid&username={username}&password={}",
            urlencoding::encode(password)
        ))
        .await;
    assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
    let location = response.headers()["location"].to_str().unwrap();
    reqwest::Url::parse(location)
        .unwrap()
        .query_pairs()
        .find(|(name, _)| name == "code")
        .unwrap()
        .1
        .into_owned()
}

fn basic_auth(client_id: &str, client_secret: &str) -> String {
    format!(
        "Basic {}",
        BASE64_STANDARD.encode(format!("{client_id}:{client_secret}"))
    )
}

#[tokio::test]
async fn test_basic_auth_authorization_code_and_refresh_flow() {
    let client = TestClient::new();
    let (pool_id, client_id, client_secret, username, password) =
        setup_user_and_confidential_client(&client).await;
    let code = request_authorization_code(&client, &client_id, &username, &password).await;
    let authorization = basic_auth(&client_id, &client_secret);
    let params = [
        ("grant_type", "authorization_code"),
        ("code", code.as_str()),
        ("redirect_uri", "https://example.com/callback"),
    ];
    let response = client
        .post_form_with_headers(
            "/oauth2/token",
            &params,
            &[("authorization", &authorization)],
        )
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body: serde_json::Value = response.json().await.unwrap();
    let claims = verify_access_token(body["access_token"].as_str().unwrap())
        .unwrap()
        .claims;
    assert_eq!(claims.client_id, client_id);
    assert!(body["id_token"].as_str().is_some());

    let replay = client
        .post_form_with_headers(
            "/oauth2/token",
            &params,
            &[("authorization", &authorization)],
        )
        .await;
    assert_eq!(replay.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        replay.json::<serde_json::Value>().await.unwrap()["error"],
        "invalid_grant"
    );

    let other_client = client
        .cognito_request(
            "CreateUserPoolClient",
            json!({
                "UserPoolId": pool_id,
                "ClientName": "OtherClient",
                "GenerateSecret": true
            }),
        )
        .await;
    let other_authorization = basic_auth(
        other_client["UserPoolClient"]["ClientId"].as_str().unwrap(),
        other_client["UserPoolClient"]["ClientSecret"]
            .as_str()
            .unwrap(),
    );
    let response = client
        .post_form_with_headers(
            "/oauth2/token",
            &[
                ("grant_type", "refresh_token"),
                ("refresh_token", body["refresh_token"].as_str().unwrap()),
            ],
            &[("authorization", &other_authorization)],
        )
        .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response.json::<serde_json::Value>().await.unwrap()["error"],
        "invalid_grant"
    );

    let response = client
        .post_form_with_headers(
            "/oauth2/token",
            &[
                ("grant_type", "refresh_token"),
                ("refresh_token", body["refresh_token"].as_str().unwrap()),
            ],
            &[("authorization", &authorization)],
        )
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let refreshed: serde_json::Value = response.json().await.unwrap();
    let claims = verify_access_token(refreshed["access_token"].as_str().unwrap())
        .unwrap()
        .claims;
    assert_eq!(claims.client_id, client_id);
    assert_eq!(
        claims.sub,
        verify_id_token(body["id_token"].as_str().unwrap(), &client_id)
            .unwrap()
            .claims
            .sub
    );
    assert!(refreshed.get("refresh_token").is_none());
}

#[tokio::test]
async fn test_basic_auth_client_credentials_flow() {
    let client = TestClient::new();
    let pool = client
        .cognito_request("CreateUserPool", json!({"PoolName": "BasicAuthPool"}))
        .await;
    let app = client
        .cognito_request(
            "CreateUserPoolClient",
            json!({
                "UserPoolId": pool["UserPool"]["Id"],
                "ClientName": "BasicAuthClient",
                "GenerateSecret": true,
                "AllowedOAuthFlows": ["client_credentials"],
                "AllowedOAuthScopes": ["api/read"],
                "AllowedOAuthFlowsUserPoolClient": true
            }),
        )
        .await;
    let client_id = app["UserPoolClient"]["ClientId"].as_str().unwrap();
    let secret = app["UserPoolClient"]["ClientSecret"].as_str().unwrap();
    // OAuth Basic credentials use form encoding before base64 encoding.
    let encoded_id = client_id
        .bytes()
        .map(|b| format!("%{b:02X}"))
        .collect::<String>();
    let encoded_secret = secret
        .bytes()
        .map(|b| format!("%{b:02X}"))
        .collect::<String>();
    for (index, authorization) in [
        basic_auth(client_id, secret),
        basic_auth(&encoded_id, &encoded_secret).replacen("Basic ", "bAsIc   ", 1),
    ]
    .into_iter()
    .enumerate()
    {
        let mut params = vec![("grant_type", "client_credentials"), ("scope", "api/read")];
        if index == 1 {
            params.push(("client_id", client_id));
        }
        let response = client
            .post_form_with_headers(
                "/oauth2/token",
                &params,
                &[("authorization", &authorization)],
            )
            .await;
        assert_eq!(response.status(), StatusCode::OK);
        let body: serde_json::Value = response.json().await.unwrap();
        let claims = verify_access_token(body["access_token"].as_str().unwrap())
            .unwrap()
            .claims;
        assert_eq!(claims.client_id, client_id);
        assert_eq!(claims.scope, "api/read");
        assert!(body.get("id_token").is_none());
        assert!(body.get("refresh_token").is_none());
    }
}

#[tokio::test]
async fn test_invalid_client_authentication_preserves_authorization_code() {
    let client = TestClient::new();
    let (_, client_id, secret, username, password) =
        setup_user_and_confidential_client(&client).await;
    let code = request_authorization_code(&client, &client_id, &username, &password).await;
    for provided_secret in [None, Some("wrong-secret")] {
        let mut params = vec![
            ("grant_type", "authorization_code"),
            ("code", code.as_str()),
            ("client_id", client_id.as_str()),
            ("redirect_uri", "https://example.com/callback"),
        ];
        if let Some(provided_secret) = provided_secret {
            params.push(("client_secret", provided_secret));
        }
        let response = client.post_form("/oauth2/token", &params).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            response.json::<serde_json::Value>().await.unwrap()["error"],
            "invalid_client"
        );
    }
    let response = client
        .post_form(
            "/oauth2/token",
            &[
                ("grant_type", "authorization_code"),
                ("code", &code),
                ("client_id", &client_id),
                ("client_secret", &secret),
                ("redirect_uri", "https://example.com/callback"),
            ],
        )
        .await;
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_basic_auth_rejects_invalid_or_ambiguous_credentials() {
    let client = TestClient::new();
    let (_, client_id, secret, username, password) =
        setup_user_and_confidential_client(&client).await;
    let code = request_authorization_code(&client, &client_id, &username, &password).await;
    let authorization = basic_auth(&client_id, &secret);
    let invalid_headers = [
        "Bearer invalid".to_string(),
        "Basic".to_string(),
        "Basic !!!".to_string(),
        format!("Basic {}", BASE64_STANDARD.encode("no-colon")),
        format!("Basic {}", BASE64_STANDARD.encode([0xff, b':', 0xff])),
        basic_auth(&client_id, "%FF"),
        basic_auth(&client_id, "wrong-secret"),
        basic_auth(&client_id, ""),
        basic_auth("", &secret),
    ];
    let params = [
        ("grant_type", "authorization_code"),
        ("code", code.as_str()),
        ("redirect_uri", "https://example.com/callback"),
    ];
    for invalid_header in &invalid_headers {
        let response = client
            .post_form_with_headers(
                "/oauth2/token",
                &params,
                &[("authorization", invalid_header)],
            )
            .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body: serde_json::Value = response.json().await.unwrap();
        assert_eq!(body["error"], "invalid_client");
        assert!(!body.to_string().contains(&secret));
    }
    for (extra, headers) in [
        (
            vec![("client_secret", secret.as_str())],
            vec![("authorization", authorization.as_str())],
        ),
        (
            vec![("client_id", "another-client")],
            vec![("authorization", authorization.as_str())],
        ),
        (
            vec![],
            vec![
                ("authorization", authorization.as_str()),
                ("authorization", authorization.as_str()),
            ],
        ),
    ] {
        let mut ambiguous_params = params.to_vec();
        ambiguous_params.extend(extra);
        let response = client
            .post_form_with_headers("/oauth2/token", &ambiguous_params, &headers)
            .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            response.json::<serde_json::Value>().await.unwrap()["error"],
            "invalid_request"
        );
    }
    // A malformed header must not silently fall back to valid form credentials.
    let mut form_params = params.to_vec();
    form_params.extend([
        ("client_id", client_id.as_str()),
        ("client_secret", secret.as_str()),
    ]);
    let response = client
        .post_form_with_headers(
            "/oauth2/token",
            &form_params,
            &[("authorization", "Basic !!!")],
        )
        .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let response = client
        .post_form_with_headers(
            "/oauth2/token",
            &params,
            &[("authorization", &authorization)],
        )
        .await;
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_public_client_requires_explicit_identity_without_secret() {
    let client = TestClient::new();
    let (_, client_id, username, password) = setup_user_and_client(&client).await;
    let code = request_authorization_code(&client, &client_id, &username, &password).await;
    let params = [
        ("grant_type", "authorization_code"),
        ("code", code.as_str()),
        ("client_id", client_id.as_str()),
        ("redirect_uri", "https://example.com/callback"),
    ];
    // Public clients cannot authenticate with a fabricated or empty secret.
    for secret in ["", "fabricated-secret"] {
        let authorization = basic_auth(&client_id, secret);
        let response = client
            .post_form_with_headers(
                "/oauth2/token",
                &params,
                &[("authorization", &authorization)],
            )
            .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            response.json::<serde_json::Value>().await.unwrap()["error"],
            "invalid_client"
        );
    }
    let response = client.post_form("/oauth2/token", &params).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body: serde_json::Value = response.json().await.unwrap();
    let mut refresh_params = vec![
        ("grant_type", "refresh_token"),
        ("refresh_token", body["refresh_token"].as_str().unwrap()),
    ];
    let response = client.post_form("/oauth2/token", &refresh_params).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response.json::<serde_json::Value>().await.unwrap()["error"],
        "invalid_request"
    );
    refresh_params.push(("client_id", &client_id));
    let response = client.post_form("/oauth2/token", &refresh_params).await;
    assert_eq!(response.status(), StatusCode::OK);

    let response = client
        .post_form(
            "/oauth2/token",
            &[
                ("grant_type", "client_credentials"),
                ("client_id", &client_id),
            ],
        )
        .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response.json::<serde_json::Value>().await.unwrap()["error"],
        "invalid_client"
    );
}

async fn oauth_tokens(
    client: &TestClient,
    client_id: &str,
    username: &str,
    password: &str,
) -> serde_json::Value {
    let code = request_authorization_code(client, client_id, username, password).await;
    let response = client
        .post_form(
            "/oauth2/token",
            &[
                ("grant_type", "authorization_code"),
                ("code", &code),
                ("client_id", client_id),
                ("redirect_uri", "https://example.com/callback"),
            ],
        )
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    response.json().await.unwrap()
}

async fn assert_userinfo_invalid_token(client: &TestClient, token: &str) {
    let response = client.get_with_auth("/oauth2/userInfo", token).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response.headers()["www-authenticate"],
        "Bearer error=\"invalid_token\""
    );
    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["error"], "invalid_token");
    assert!(body.get("sub").is_none());
    assert!(body.get("email").is_none());
}

#[tokio::test]
async fn test_userinfo_rejects_ended_sessions() {
    for operation in [
        "GlobalSignOut",
        "AdminUserGlobalSignOut",
        "RevokeToken",
        "AdminDeleteUser",
    ] {
        let client = TestClient::new();
        let (pool_id, client_id, username, password) = setup_user_and_client(&client).await;
        let tokens = oauth_tokens(&client, &client_id, &username, &password).await;
        let access_token = tokens["access_token"].as_str().unwrap();
        assert_eq!(
            client
                .get_with_auth("/oauth2/userInfo", access_token)
                .await
                .status(),
            StatusCode::OK
        );
        let request = match operation {
            "GlobalSignOut" => {
                let auth = client
                    .cognito_request(
                        "InitiateAuth",
                        json!({
                            "ClientId": client_id,
                            "AuthFlow": "USER_PASSWORD_AUTH",
                            "AuthParameters": {"USERNAME": username, "PASSWORD": password}
                        }),
                    )
                    .await;
                json!({"AccessToken": auth["AuthenticationResult"]["AccessToken"]})
            }
            "RevokeToken" => json!({"ClientId": client_id, "Token": tokens["refresh_token"]}),
            _ => json!({"UserPoolId": pool_id, "Username": username}),
        };
        client.cognito_request(operation, request).await;
        assert_userinfo_invalid_token(&client, access_token).await;
    }
}

#[tokio::test]
async fn test_userinfo_requires_openid_scope() {
    let client = TestClient::new();
    let (_, client_id, username, password) = setup_user_and_client(&client).await;
    let response = client
        .cognito_request(
            "InitiateAuth",
            json!({
                "ClientId": client_id,
                "AuthFlow": "USER_PASSWORD_AUTH",
                "AuthParameters": {"USERNAME": username, "PASSWORD": password}
            }),
        )
        .await;
    let api_token = response["AuthenticationResult"]["AccessToken"]
        .as_str()
        .unwrap();
    assert_eq!(
        verify_access_token(api_token).unwrap().claims.scope,
        "aws.cognito.signin.user.admin"
    );
    assert_userinfo_invalid_token(&client, api_token).await;

    for (operation, request) in [
        (
            "InitiateAuth",
            json!({
                "ClientId": client_id,
                "AuthFlow": "REFRESH_TOKEN_AUTH",
                "AuthParameters": {"REFRESH_TOKEN": response["AuthenticationResult"]["RefreshToken"]}
            }),
        ),
        (
            "GetTokensFromRefreshToken",
            json!({
                "ClientId": client_id,
                "RefreshToken": response["AuthenticationResult"]["RefreshToken"]
            }),
        ),
    ] {
        let refreshed = client.cognito_request(operation, request).await;
        let token = refreshed["AuthenticationResult"]["AccessToken"]
            .as_str()
            .unwrap();
        assert_eq!(
            verify_access_token(token).unwrap().claims.scope,
            "aws.cognito.signin.user.admin"
        );
        assert_userinfo_invalid_token(&client, token).await;
    }

    let tokens = oauth_tokens(&client, &client_id, &username, &password).await;
    assert_userinfo_invalid_token(&client, tokens["id_token"].as_str().unwrap()).await;
    let authorization = format!("bEaReR   {}", tokens["access_token"].as_str().unwrap());
    let response = client
        .get_with_headers("/oauth2/userInfo", &[("authorization", &authorization)])
        .await;
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_userinfo_rejects_malformed_authorization() {
    let client = TestClient::new();
    for headers in [
        vec![],
        vec![("authorization", "Basic invalid")],
        vec![("authorization", "Bearer")],
        vec![
            ("authorization", "Bearer first"),
            ("authorization", "Bearer second"),
        ],
    ] {
        let response = client.get_with_headers("/oauth2/userInfo", &headers).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            response.json::<serde_json::Value>().await.unwrap()["error"],
            "invalid_request"
        );
    }
    assert_userinfo_invalid_token(&client, "malformed-jwt").await;
}

#[tokio::test]
async fn test_disabling_user_permanently_revokes_existing_sessions() {
    let client = TestClient::new();
    let (pool_id, client_id, username, password) = setup_user_and_client(&client).await;
    let first = oauth_tokens(&client, &client_id, &username, &password).await;
    let second = oauth_tokens(&client, &client_id, &username, &password).await;
    client
        .cognito_request(
            "AdminDisableUser",
            json!({"UserPoolId": pool_id, "Username": username}),
        )
        .await;

    for enabled in [false, true] {
        if enabled {
            client
                .cognito_request(
                    "AdminEnableUser",
                    json!({"UserPoolId": pool_id, "Username": username}),
                )
                .await;
        }
        for tokens in [&first, &second] {
            let access_token = tokens["access_token"].as_str().unwrap();
            assert_userinfo_invalid_token(&client, access_token).await;
            let (status, body) = client
                .request("GetUser", json!({"AccessToken": access_token}))
                .await;
            assert_eq!(status, StatusCode::UNAUTHORIZED);
            assert_eq!(body["__type"], "NotAuthorizedException");
            let (status, body) = client
                .request(
                    "InitiateAuth",
                    json!({
                        "ClientId": client_id,
                        "AuthFlow": "REFRESH_TOKEN_AUTH",
                        "AuthParameters": {"REFRESH_TOKEN": tokens["refresh_token"]}
                    }),
                )
                .await;
            assert_eq!(status, StatusCode::UNAUTHORIZED);
            assert_eq!(body["__type"], "NotAuthorizedException");
            let refresh = client
                .post_form(
                    "/oauth2/token",
                    &[
                        ("grant_type", "refresh_token"),
                        ("client_id", &client_id),
                        ("refresh_token", tokens["refresh_token"].as_str().unwrap()),
                    ],
                )
                .await;
            assert_eq!(refresh.status(), StatusCode::BAD_REQUEST);
            assert_eq!(
                refresh.json::<serde_json::Value>().await.unwrap()["error"],
                "invalid_grant"
            );
        }
    }
    // The revocation boundary uses millisecond timestamps.
    tokio::time::sleep(std::time::Duration::from_millis(2)).await;
    let fresh = oauth_tokens(&client, &client_id, &username, &password).await;
    let response = client
        .get_with_auth("/oauth2/userInfo", fresh["access_token"].as_str().unwrap())
        .await;
    assert_eq!(response.status(), StatusCode::OK);
}
