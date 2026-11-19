//! OAuth 2.0 endpoint tests

mod common;

use axum::http::StatusCode;
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD as BASE64_STANDARD, URL_SAFE_NO_PAD},
};
use cognitox::jwt::{verify_access_token, verify_id_token};
use hmac::{Hmac, Mac};
use serde_json::json;
use sha2::{Digest, Sha256};

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
                "ExplicitAuthFlows": ["ALLOW_USER_PASSWORD_AUTH", "ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_USER_SRP_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
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
                "ExplicitAuthFlows": ["ALLOW_USER_PASSWORD_AUTH", "ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_USER_SRP_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
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
async fn test_user_pool_openid_configuration_and_jwks() {
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
    assert_eq!(jwks["keys"][0]["alg"], "RS256");
}

#[tokio::test]
async fn test_user_pool_openid_configuration_and_jwks_reject_unknown_pool() {
    let client = TestClient::new();

    for path in [
        "/us-east-1_Missing/.well-known/openid-configuration",
        "/us-east-1_Missing/.well-known/jwks.json",
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
    assert_eq!(response.status(), StatusCode::FOUND);

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
    assert_eq!(claims.nonce, None);
}

#[tokio::test]
async fn test_authorization_code_flow_returns_nonce_in_id_token() {
    let client = TestClient::new();
    let (_, client_id, username, password) = setup_user_and_client(&client).await;

    let response = client
        .get(&format!(
            "/oauth2/authorize?response_type=code&client_id={client_id}&redirect_uri=https://example.com/callback&scope=openid&nonce=n-0S6_WzA2Mj&username={username}&password={}",
            urlencoding::encode(&password)
        ))
        .await;
    assert_eq!(response.status(), StatusCode::FOUND);
    let location = response.headers()["location"].to_str().unwrap();
    let code = reqwest::Url::parse(location)
        .unwrap()
        .query_pairs()
        .find(|(name, _)| name == "code")
        .unwrap()
        .1
        .into_owned();

    let token_response = client
        .post_form(
            "/oauth2/token",
            &[
                ("grant_type", "authorization_code"),
                ("code", &code),
                ("client_id", &client_id),
                ("redirect_uri", "https://example.com/callback"),
            ],
        )
        .await;
    assert_eq!(token_response.status(), StatusCode::OK);
    let token_body: serde_json::Value = token_response.json().await.unwrap();
    let claims = verify_id_token(token_body["id_token"].as_str().unwrap(), &client_id)
        .unwrap()
        .claims;
    assert_eq!(claims.nonce.as_deref(), Some("n-0S6_WzA2Mj"));

    // The nonce binds one authorization, so refreshed ID tokens leave it out.
    let refresh_response = client
        .post_form(
            "/oauth2/token",
            &[
                ("grant_type", "refresh_token"),
                (
                    "refresh_token",
                    token_body["refresh_token"].as_str().unwrap(),
                ),
                ("client_id", &client_id),
            ],
        )
        .await;
    assert_eq!(refresh_response.status(), StatusCode::OK);
    let refresh_body: serde_json::Value = refresh_response.json().await.unwrap();
    let refreshed_claims = verify_id_token(refresh_body["id_token"].as_str().unwrap(), &client_id)
        .unwrap()
        .claims;
    assert_eq!(refreshed_claims.nonce, None);
}

#[tokio::test]
async fn test_implicit_flow_returns_nonce_in_id_token() {
    let client = TestClient::new();
    let (_, client_id, username, password) = setup_user_and_client(&client).await;

    let response = client
        .get(&format!(
            "/oauth2/authorize?response_type=token&client_id={client_id}&redirect_uri=https://example.com/callback&scope=openid&nonce=n-0S6_WzA2Mj&username={username}&password={}",
            urlencoding::encode(&password)
        ))
        .await;
    assert_eq!(response.status(), StatusCode::FOUND);
    let location = response.headers()["location"].to_str().unwrap();
    let fragment = reqwest::Url::parse(location)
        .unwrap()
        .fragment()
        .unwrap()
        .to_string();
    let id_token = reqwest::Url::parse(&format!("https://example.com/?{fragment}"))
        .unwrap()
        .query_pairs()
        .find(|(name, _)| name == "id_token")
        .unwrap()
        .1
        .into_owned();
    let claims = verify_id_token(&id_token, &client_id).unwrap().claims;
    assert_eq!(claims.nonce.as_deref(), Some("n-0S6_WzA2Mj"));
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

    assert_eq!(response.status(), StatusCode::FOUND);
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
    assert_eq!(response.status(), StatusCode::FOUND);

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
    assert_eq!(response.status(), StatusCode::FOUND);

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
                "ExplicitAuthFlows": ["ALLOW_USER_PASSWORD_AUTH", "ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_USER_SRP_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
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
                "ExplicitAuthFlows": ["ALLOW_USER_PASSWORD_AUTH", "ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_USER_SRP_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
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

    assert_eq!(response.status(), StatusCode::FOUND);
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
                "ExplicitAuthFlows": ["ALLOW_USER_PASSWORD_AUTH", "ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_USER_SRP_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
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
                "ExplicitAuthFlows": ["ALLOW_USER_PASSWORD_AUTH", "ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_USER_SRP_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
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
                "ExplicitAuthFlows": ["ALLOW_USER_PASSWORD_AUTH", "ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_USER_SRP_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
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
                "ExplicitAuthFlows": ["ALLOW_USER_PASSWORD_AUTH", "ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_USER_SRP_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
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
    assert!(claims.iss.ends_with(&format!("/{pool_id}")));
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
    assert_eq!(response.status(), StatusCode::FOUND);
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
                "ExplicitAuthFlows": ["ALLOW_USER_PASSWORD_AUTH", "ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_USER_SRP_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
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
                "ExplicitAuthFlows": ["ALLOW_USER_PASSWORD_AUTH", "ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_USER_SRP_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
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
            assert_eq!(status, StatusCode::BAD_REQUEST);
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
            assert_eq!(status, StatusCode::BAD_REQUEST);
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

// =============================================================================
// Managed login parity
// =============================================================================

const CALLBACK: &str = "https://example.com/callback";

fn jwt_claims(token: &serde_json::Value) -> serde_json::Value {
    let payload = token.as_str().unwrap().split('.').nth(1).unwrap();
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).unwrap()).unwrap()
}

/// `at_hash` as OpenID Connect defines it, computed independently.
fn at_hash(access_token: &serde_json::Value) -> String {
    let digest = Sha256::digest(access_token.as_str().unwrap().as_bytes());
    URL_SAFE_NO_PAD.encode(&digest[..16])
}

/// Sign `testuser` in at the authorize endpoint. `scope: None` leaves the
/// parameter out.
async fn authorize_code(client: &TestClient, client_id: &str, scope: Option<&str>) -> String {
    let scope = scope
        .map(|scope| format!("&scope={}", urlencoding::encode(scope)))
        .unwrap_or_default();
    let response = client
        .get(&format!(
            "/oauth2/authorize?response_type=code&client_id={client_id}&redirect_uri={CALLBACK}{scope}&username=testuser&password={}",
            urlencoding::encode("Test123!")
        ))
        .await;
    assert_eq!(response.status(), StatusCode::FOUND);
    let location = response.headers()["location"].to_str().unwrap();
    reqwest::Url::parse(location)
        .unwrap()
        .query_pairs()
        .find(|(name, _)| name == "code")
        .unwrap()
        .1
        .into_owned()
}

async fn exchange_code(client: &TestClient, client_id: &str, code: &str) -> serde_json::Value {
    let response = client
        .post_form(
            "/oauth2/token",
            &[
                ("grant_type", "authorization_code"),
                ("code", code),
                ("client_id", client_id),
                ("redirect_uri", CALLBACK),
            ],
        )
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    response.json().await.unwrap()
}

async fn tokens_for_scope(client: &TestClient, client_id: &str, scope: &str) -> serde_json::Value {
    let code = authorize_code(client, client_id, Some(scope)).await;
    exchange_code(client, client_id, &code).await
}

async fn refresh(
    client: &TestClient,
    client_id: &str,
    refresh_token: &serde_json::Value,
    scope: Option<&str>,
) -> common::TestResponse {
    let mut form = vec![
        ("grant_type", "refresh_token"),
        ("client_id", client_id),
        ("refresh_token", refresh_token.as_str().unwrap()),
    ];
    if let Some(scope) = scope {
        form.push(("scope", scope));
    }
    client.post_form("/oauth2/token", &form).await
}

async fn expect_token_error(response: common::TestResponse, error: &str) {
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["error"], error, "{body}");
    assert!(body.get("access_token").is_none());
}

/// Another public OAuth client in the pool, with extra settings.
async fn create_oauth_client(
    client: &TestClient,
    pool_id: &str,
    settings: serde_json::Value,
) -> serde_json::Value {
    let mut request = json!({
        "UserPoolId": pool_id,
        "ClientName": "AnotherOAuthClient",
        "AllowedOAuthFlows": ["code", "implicit"],
        "AllowedOAuthScopes": ["openid", "email", "profile"],
        "AllowedOAuthFlowsUserPoolClient": true,
        "CallbackURLs": [CALLBACK],
    });
    request
        .as_object_mut()
        .unwrap()
        .extend(settings.as_object().unwrap().clone());
    let body = client
        .cognito_request("CreateUserPoolClient", request)
        .await;
    body["UserPoolClient"].clone()
}

async fn userinfo(client: &TestClient, access_token: &serde_json::Value) -> serde_json::Value {
    let response = client
        .get_with_auth("/oauth2/userInfo", access_token.as_str().unwrap())
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    response.json().await.unwrap()
}

#[tokio::test]
async fn test_oauth_tokens_of_one_sign_in_share_a_session() {
    let client = TestClient::new();
    let (_, client_id, _, _) = setup_user_and_client(&client).await;

    let tokens = tokens_for_scope(&client, &client_id, "openid email").await;
    let access = jwt_claims(&tokens["access_token"]);
    let id = jwt_claims(&tokens["id_token"]);

    // Tokens from the OAuth 2.0 endpoints are version 2 and carry the
    // granted scopes.
    assert_eq!(access["version"], 2);
    assert_eq!(access["scope"], "openid email");
    assert_eq!(access["token_use"], "access");
    for claim in ["origin_jti", "event_id", "auth_time"] {
        assert!(!access[claim].is_null(), "access token lacks {claim}");
        assert_eq!(access[claim], id[claim], "{claim} differs");
    }
    assert_ne!(access["jti"], id["jti"]);
    assert_eq!(id["at_hash"], at_hash(&tokens["access_token"]));
    assert_eq!(id["email"], "test@example.com");

    // A refresh keeps the sign-in, its scopes, and the refresh token.
    let response = refresh(&client, &client_id, &tokens["refresh_token"], None).await;
    assert_eq!(response.status(), StatusCode::OK);
    let refreshed: serde_json::Value = response.json().await.unwrap();
    assert!(refreshed.get("refresh_token").is_none());
    let refreshed_access = jwt_claims(&refreshed["access_token"]);
    let refreshed_id = jwt_claims(&refreshed["id_token"]);
    assert_eq!(refreshed_access["scope"], "openid email");
    assert_eq!(refreshed_access["version"], 2);
    assert_eq!(refreshed_access["origin_jti"], access["origin_jti"]);
    assert_eq!(refreshed_access["auth_time"], access["auth_time"]);
    assert_ne!(refreshed_access["jti"], access["jti"]);
    assert_eq!(refreshed_id["origin_jti"], access["origin_jti"]);
    assert_eq!(refreshed_id["at_hash"], at_hash(&refreshed["access_token"]));
    // The nonce belongs to the authorization, not to later refreshes.
    assert!(refreshed_id.get("nonce").is_none());
}

#[tokio::test]
async fn test_authorization_time_becomes_auth_time() {
    let client = TestClient::new();
    let (_, client_id, _, _) = setup_user_and_client(&client).await;

    // A code minted by a sign-in ten minutes ago.
    let tokens = tokens_for_scope(&client, &client_id, "openid").await;
    let user_id =
        uuid::Uuid::parse_str(jwt_claims(&tokens["id_token"])["sub"].as_str().unwrap()).unwrap();
    let signed_in_at = chrono::Utc::now().timestamp() - 600;
    client
        .storage()
        .save_authorization_code(cognitox::types::AuthorizationCode {
            code: "earlier-sign-in".to_string(),
            user_id,
            client_id: client_id.parse().unwrap(),
            redirect_uri: CALLBACK.to_string(),
            scope: vec!["openid".to_string()],
            nonce: None,
            code_challenge: None,
            code_challenge_method: None,
            expires_at: chrono::Utc::now() + chrono::Duration::minutes(1),
            auth_time: Some(signed_in_at),
        })
        .await;

    let tokens = exchange_code(&client, &client_id, "earlier-sign-in").await;
    assert_eq!(
        jwt_claims(&tokens["access_token"])["auth_time"],
        signed_in_at
    );
    assert_eq!(jwt_claims(&tokens["id_token"])["auth_time"], signed_in_at);
}

#[tokio::test]
async fn test_refresh_scope_can_narrow_but_not_widen() {
    let client = TestClient::new();
    let (_, client_id, _, _) = setup_user_and_client(&client).await;
    let tokens = tokens_for_scope(&client, &client_id, "openid email").await;

    let response = refresh(
        &client,
        &client_id,
        &tokens["refresh_token"],
        Some("openid"),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let narrowed: serde_json::Value = response.json().await.unwrap();
    assert_eq!(jwt_claims(&narrowed["access_token"])["scope"], "openid");

    // `profile` is allowed for the client but was not part of this grant.
    let response = refresh(
        &client,
        &client_id,
        &tokens["refresh_token"],
        Some("openid profile"),
    )
    .await;
    expect_token_error(response, "invalid_scope").await;

    // Narrowing one refresh does not shrink the grant.
    let response = refresh(&client, &client_id, &tokens["refresh_token"], None).await;
    let full: serde_json::Value = response.json().await.unwrap();
    assert_eq!(jwt_claims(&full["access_token"])["scope"], "openid email");
}

#[tokio::test]
async fn test_token_endpoint_refreshes_a_user_pools_api_sign_in() {
    let client = TestClient::new();
    let (_, client_id, username, password) = setup_user_and_client(&client).await;
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
    let api_tokens = &auth["AuthenticationResult"];

    let response = refresh(&client, &client_id, &api_tokens["RefreshToken"], None).await;
    assert_eq!(response.status(), StatusCode::OK);
    let refreshed: serde_json::Value = response.json().await.unwrap();
    let access = jwt_claims(&refreshed["access_token"]);
    // The sign-in never had OAuth scopes, and a refresh does not add any.
    assert_eq!(access["scope"], "aws.cognito.signin.user.admin");
    assert_eq!(
        access["origin_jti"],
        jwt_claims(&api_tokens["AccessToken"])["origin_jti"]
    );
    assert!(refreshed["id_token"].is_string());
}

#[tokio::test]
async fn test_refresh_token_rotation_replaces_the_refresh_token() {
    let client = TestClient::new();
    let (pool_id, _, _, _) = setup_user_and_client(&client).await;
    let rotating = create_oauth_client(
        &client,
        &pool_id,
        json!({"RefreshTokenRotation": {"Feature": "ENABLED", "RetryGracePeriodSeconds": 0}}),
    )
    .await;
    let client_id = rotating["ClientId"].as_str().unwrap();
    let tokens = tokens_for_scope(&client, client_id, "openid").await;

    let response = refresh(&client, client_id, &tokens["refresh_token"], None).await;
    assert_eq!(response.status(), StatusCode::OK);
    let rotated: serde_json::Value = response.json().await.unwrap();
    assert!(rotated["refresh_token"].is_string());
    assert_ne!(rotated["refresh_token"], tokens["refresh_token"]);

    // The presented token is spent; its replacement carries on.
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    let response = refresh(&client, client_id, &tokens["refresh_token"], None).await;
    expect_token_error(response, "invalid_grant").await;
    let response = refresh(&client, client_id, &rotated["refresh_token"], None).await;
    assert_eq!(response.status(), StatusCode::OK);
    let again: serde_json::Value = response.json().await.unwrap();
    assert_eq!(
        jwt_claims(&again["access_token"])["origin_jti"],
        jwt_claims(&tokens["access_token"])["origin_jti"]
    );
}

#[tokio::test]
async fn test_read_attributes_limit_id_token_and_userinfo() {
    let client = TestClient::new();
    let (pool_id, open_client_id, _, _) = setup_user_and_client(&client).await;
    client
        .cognito_request(
            "AdminUpdateUserAttributes",
            json!({
                "UserPoolId": pool_id,
                "Username": "testuser",
                "UserAttributes": [{"Name": "name", "Value": "Test User"}]
            }),
        )
        .await;
    let restricted = create_oauth_client(
        &client,
        &pool_id,
        json!({"ReadAttributes": ["email", "email_verified"]}),
    )
    .await;
    let restricted_id = restricted["ClientId"].as_str().unwrap();

    let tokens = tokens_for_scope(&client, restricted_id, "openid email profile").await;
    let id = jwt_claims(&tokens["id_token"]);
    assert_eq!(id["email"], "test@example.com");
    assert!(id.get("name").is_none());
    let info = userinfo(&client, &tokens["access_token"]).await;
    assert_eq!(info["email"], "test@example.com");
    assert!(info.get("name").is_none());

    // A client without ReadAttributes reads everything.
    let tokens = tokens_for_scope(&client, &open_client_id, "openid email profile").await;
    assert_eq!(jwt_claims(&tokens["id_token"])["name"], "Test User");
    assert_eq!(
        userinfo(&client, &tokens["access_token"]).await["name"],
        "Test User"
    );
}

#[tokio::test]
async fn test_token_endpoint_reports_grant_failures_as_invalid_grant() {
    let client = TestClient::new();
    let (pool_id, client_id, _, _) = setup_user_and_client(&client).await;
    // A code works once.
    let code = authorize_code(&client, &client_id, Some("openid")).await;
    let tokens = exchange_code(&client, &client_id, &code).await;
    let replay = client
        .post_form(
            "/oauth2/token",
            &[
                ("grant_type", "authorization_code"),
                ("code", &code),
                ("client_id", &client_id),
                ("redirect_uri", CALLBACK),
            ],
        )
        .await;
    expect_token_error(replay, "invalid_grant").await;

    // It is bound to the redirect URI of its authorization...
    let code = authorize_code(&client, &client_id, Some("openid")).await;
    let response = client
        .post_form(
            "/oauth2/token",
            &[
                ("grant_type", "authorization_code"),
                ("code", &code),
                ("client_id", &client_id),
                ("redirect_uri", "https://example.com/other"),
            ],
        )
        .await;
    expect_token_error(response, "invalid_grant").await;

    // ...and to the client it was issued to.
    let other = create_oauth_client(&client, &pool_id, json!({})).await;
    let code = authorize_code(&client, &client_id, Some("openid")).await;
    let response = client
        .post_form(
            "/oauth2/token",
            &[
                ("grant_type", "authorization_code"),
                ("code", &code),
                ("client_id", other["ClientId"].as_str().unwrap()),
                ("redirect_uri", CALLBACK),
            ],
        )
        .await;
    expect_token_error(response, "invalid_grant").await;

    // An expired code, and an expired refresh token.
    let user_id =
        uuid::Uuid::parse_str(jwt_claims(&tokens["id_token"])["sub"].as_str().unwrap()).unwrap();
    let expired = chrono::Utc::now() - chrono::Duration::seconds(1);
    client
        .storage()
        .save_authorization_code(cognitox::types::AuthorizationCode {
            code: "expired-code".to_string(),
            user_id,
            client_id: client_id.parse().unwrap(),
            redirect_uri: CALLBACK.to_string(),
            scope: vec!["openid".to_string()],
            nonce: None,
            code_challenge: None,
            code_challenge_method: None,
            expires_at: expired,
            auth_time: None,
        })
        .await;
    let response = client
        .post_form(
            "/oauth2/token",
            &[
                ("grant_type", "authorization_code"),
                ("code", "expired-code"),
                ("client_id", &client_id),
                ("redirect_uri", CALLBACK),
            ],
        )
        .await;
    expect_token_error(response, "invalid_grant").await;

    client
        .storage()
        .save_refresh_token(cognitox::types::RefreshToken {
            token: "expired-refresh-token".to_string(),
            user_id,
            client_id: client_id.parse().unwrap(),
            expires_at: expired,
            origin_jti: None,
            auth_time: None,
            scope: vec!["openid".to_string()],
        })
        .await;
    let response = refresh(&client, &client_id, &json!("expired-refresh-token"), None).await;
    expect_token_error(response, "invalid_grant").await;

    // A revoked refresh token.
    client
        .cognito_request(
            "RevokeToken",
            json!({"ClientId": client_id, "Token": tokens["refresh_token"]}),
        )
        .await;
    let response = refresh(&client, &client_id, &tokens["refresh_token"], None).await;
    expect_token_error(response, "invalid_grant").await;
}

#[tokio::test]
async fn test_pkce_verifier_mismatch_is_invalid_grant() {
    let client = TestClient::new();
    let (_, client_id, username, password) = setup_user_and_client(&client).await;
    let code_challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    let response = client
        .get(&format!(
            "/oauth2/authorize?response_type=code&client_id={client_id}&redirect_uri={CALLBACK}&scope=openid&code_challenge={code_challenge}&code_challenge_method=S256&username={username}&password={}",
            urlencoding::encode(&password)
        ))
        .await;
    let location = response.headers()["location"].to_str().unwrap();
    let code = location.split("code=").nth(1).unwrap();

    let response = client
        .post_form(
            "/oauth2/token",
            &[
                ("grant_type", "authorization_code"),
                ("code", code),
                ("client_id", &client_id),
                ("redirect_uri", CALLBACK),
                (
                    "code_verifier",
                    "not-the-verifier-the-challenge-was-made-from",
                ),
            ],
        )
        .await;
    expect_token_error(response, "invalid_grant").await;

    // Cognito supports S256 only.
    let response = client
        .get(&format!(
            "/oauth2/authorize?response_type=code&client_id={client_id}&redirect_uri={CALLBACK}&scope=openid&code_challenge={code_challenge}&code_challenge_method=plain"
        ))
        .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["error"], "invalid_request");
}

#[tokio::test]
async fn test_token_endpoint_rejects_missing_and_unknown_grant_types() {
    let client = TestClient::new();
    let (_, client_id, _, _) = setup_user_and_client(&client).await;

    let response = client
        .post_form("/oauth2/token", &[("client_id", &client_id)])
        .await;
    expect_token_error(response, "invalid_request").await;

    let response = client
        .post_form(
            "/oauth2/token",
            &[("grant_type", "password"), ("client_id", &client_id)],
        )
        .await;
    expect_token_error(response, "unsupported_grant_type").await;
}

#[tokio::test]
async fn test_authorize_never_redirects_to_an_unregistered_uri() {
    let client = TestClient::new();
    let (pool_id, client_id, username, password) = setup_user_and_client(&client).await;
    let credentials = format!(
        "username={username}&password={}",
        urlencoding::encode(&password)
    );

    // Even with valid credentials, an unregistered URI gets nothing.
    let response = client
        .get(&format!(
            "/oauth2/authorize?response_type=code&client_id={client_id}&redirect_uri=https://attacker.example/cb&scope=openid&{credentials}"
        ))
        .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(response.headers().get("location").is_none());
    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["error"], "redirect_mismatch");

    // An unknown client is not redirected either.
    let response = client
        .get(&format!(
            "/oauth2/authorize?response_type=code&client_id=unknownclient&redirect_uri={CALLBACK}&scope=openid&{credentials}"
        ))
        .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(response.headers().get("location").is_none());

    // A client that registered no callback URL has none to redirect to.
    let body = client
        .cognito_request(
            "CreateUserPoolClient",
            json!({
                "UserPoolId": pool_id,
                "ClientName": "NoCallbacks",
                "AllowedOAuthFlows": ["code"],
                "AllowedOAuthScopes": ["openid"],
                "AllowedOAuthFlowsUserPoolClient": true
            }),
        )
        .await;
    let response = client
        .get(&format!(
            "/oauth2/authorize?response_type=code&client_id={}&redirect_uri={CALLBACK}&scope=openid&{credentials}",
            body["UserPoolClient"]["ClientId"].as_str().unwrap()
        ))
        .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(response.headers().get("location").is_none());
    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["error"], "redirect_mismatch");
}

#[tokio::test]
async fn test_authorize_without_scope_grants_every_client_scope() {
    let client = TestClient::new();
    let (_, client_id, _, _) = setup_user_and_client(&client).await;

    let code = authorize_code(&client, &client_id, None).await;
    let tokens = exchange_code(&client, &client_id, &code).await;
    assert_eq!(
        jwt_claims(&tokens["access_token"])["scope"],
        "openid email profile"
    );
    assert!(tokens["id_token"].is_string());
}

/// The reason the authorize endpoint gives for refusing a sign-in.
async fn authorize_denial(
    client: &TestClient,
    client_id: &str,
    username: &str,
    password: &str,
) -> String {
    let response = client
        .get(&format!(
            "/oauth2/authorize?response_type=code&client_id={client_id}&redirect_uri={CALLBACK}&scope=openid&username={username}&password={}",
            urlencoding::encode(password)
        ))
        .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(response.headers().get("location").is_none());
    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["error"], "access_denied");
    body["error_description"].as_str().unwrap().to_string()
}

#[tokio::test]
async fn test_authorize_refuses_accounts_that_cannot_sign_in() {
    let client = TestClient::new();
    let (pool_id, client_id, _, _) = setup_user_and_client(&client).await;
    let authorize = |username, password| authorize_denial(&client, &client_id, username, password);

    assert_eq!(
        authorize("testuser", "Wrong123!").await,
        "Incorrect username or password."
    );
    assert_eq!(
        authorize("nobody", "Test123!").await,
        "Incorrect username or password."
    );

    // An unconfirmed account, with the wrong and with the right password.
    client
        .cognito_request(
            "SignUp",
            json!({"ClientId": client_id, "Username": "pending", "Password": "Test123!"}),
        )
        .await;
    assert_eq!(
        authorize("pending", "Wrong123!").await,
        "Incorrect username or password."
    );
    assert_eq!(
        authorize("pending", "Test123!").await,
        "User is not confirmed."
    );

    client
        .cognito_request(
            "AdminDisableUser",
            json!({"UserPoolId": pool_id, "Username": "testuser"}),
        )
        .await;
    assert_eq!(authorize("testuser", "Test123!").await, "User is disabled.");
}

#[tokio::test]
async fn test_implicit_flow_returns_tokens_of_one_session_in_the_fragment() {
    let client = TestClient::new();
    let (_, client_id, username, password) = setup_user_and_client(&client).await;

    let response = client
        .get(&format!(
            "/oauth2/authorize?response_type=token&client_id={client_id}&redirect_uri={CALLBACK}&scope=openid%20email&state=xyz&username={username}&password={}",
            urlencoding::encode(&password)
        ))
        .await;
    assert_eq!(response.status(), StatusCode::FOUND);
    let location = response.headers()["location"].to_str().unwrap();
    let url = reqwest::Url::parse(location).unwrap();
    assert!(url.query().is_none());
    let fragment: std::collections::HashMap<String, String> =
        reqwest::Url::parse(&format!("https://example.com/?{}", url.fragment().unwrap()))
            .unwrap()
            .query_pairs()
            .into_owned()
            .collect();

    assert_eq!(fragment["token_type"], "Bearer");
    assert_eq!(fragment["expires_in"], "3600");
    assert_eq!(fragment["state"], "xyz");
    // The implicit grant never hands out a refresh token.
    assert!(!fragment.contains_key("refresh_token"));
    let access = jwt_claims(&json!(fragment["access_token"]));
    let id = jwt_claims(&json!(fragment["id_token"]));
    assert_eq!(access["version"], 2);
    assert_eq!(access["origin_jti"], id["origin_jti"]);
    assert_eq!(id["at_hash"], at_hash(&json!(fragment["access_token"])));
}

#[tokio::test]
async fn test_openid_configuration_lists_cognitos_members() {
    let client = TestClient::new();
    let (pool_id, client_id, username, password) = setup_user_and_client(&client).await;

    let response = client
        .get(&format!("/{pool_id}/.well-known/openid-configuration"))
        .await;
    let discovery: serde_json::Value = response.json().await.unwrap();
    let issuer = discovery["issuer"].as_str().unwrap();
    let base = issuer.strip_suffix(&format!("/{pool_id}")).unwrap();

    assert_eq!(
        discovery,
        json!({
            "authorization_endpoint": format!("{base}/oauth2/authorize"),
            "end_session_endpoint": format!("{base}/logout"),
            "id_token_signing_alg_values_supported": ["RS256"],
            "issuer": issuer,
            "jwks_uri": format!("{issuer}/.well-known/jwks.json"),
            "response_types_supported": ["code", "token"],
            "revocation_endpoint": format!("{base}/oauth2/revoke"),
            "scopes_supported": ["openid", "email", "phone", "profile"],
            "subject_types_supported": ["public"],
            "token_endpoint": format!("{base}/oauth2/token"),
            "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
            "userinfo_endpoint": format!("{base}/oauth2/userInfo")
        })
    );

    // The key the tokens are signed with is the one the issuer publishes.
    let jwks: serde_json::Value = client
        .get(&format!("/{pool_id}/.well-known/jwks.json"))
        .await
        .json()
        .await
        .unwrap();
    let tokens = oauth_tokens(&client, &client_id, &username, &password).await;
    let header = tokens["id_token"]
        .as_str()
        .unwrap()
        .split('.')
        .next()
        .unwrap();
    let header: serde_json::Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(header).unwrap()).unwrap();
    assert_eq!(header["kid"], jwks["keys"][0]["kid"]);
    assert_eq!(jwt_claims(&tokens["id_token"])["iss"], issuer);
}

#[tokio::test]
async fn test_userinfo_returns_the_attributes_the_scopes_cover() {
    let client = TestClient::new();
    let (pool_id, _, _, _) = setup_user_and_client(&client).await;
    let all_scopes = create_oauth_client(
        &client,
        &pool_id,
        json!({"AllowedOAuthScopes": ["openid", "email", "phone", "profile"]}),
    )
    .await;
    let client_id = all_scopes["ClientId"].as_str().unwrap();
    client
        .cognito_request(
            "AdminUpdateUserAttributes",
            json!({
                "UserPoolId": pool_id,
                "Username": "testuser",
                "UserAttributes": [
                    {"Name": "name", "Value": "Test User"},
                    {"Name": "phone_number", "Value": "+15555550100"},
                    {"Name": "phone_number_verified", "Value": "true"}
                ]
            }),
        )
        .await;
    let sub =
        jwt_claims(&tokens_for_scope(&client, client_id, "openid").await["access_token"])["sub"]
            .clone();

    // With `openid` alone Cognito releases every attribute the app client
    // can read, in the ID token as well as from userInfo.
    let tokens = tokens_for_scope(&client, client_id, "openid").await;
    assert_eq!(
        userinfo(&client, &tokens["access_token"]).await,
        json!({
            "sub": sub,
            "username": "testuser",
            "email": "test@example.com",
            "email_verified": "false",
            "name": "Test User",
            "phone_number": "+15555550100",
            "phone_number_verified": "true"
        })
    );
    let id_token = jwt_claims(&tokens["id_token"]);
    assert_eq!(id_token["email"], "test@example.com");
    assert_eq!(id_token["name"], "Test User");
    assert_eq!(id_token["phone_number"], "+15555550100");

    // Asking for a standard scope narrows both to what the scopes cover.
    let tokens = tokens_for_scope(&client, client_id, "openid email").await;
    let id_token = jwt_claims(&tokens["id_token"]);
    assert_eq!(id_token["email"], "test@example.com");
    assert_eq!(id_token["email_verified"], false);
    assert!(id_token.get("name").is_none());
    assert!(id_token.get("phone_number").is_none());
    // The token response itself carries no `scope` member.
    assert!(tokens.get("scope").is_none());

    // The address was never verified, and userInfo says so, as a string.
    let tokens = tokens_for_scope(&client, client_id, "openid email").await;
    assert_eq!(
        userinfo(&client, &tokens["access_token"]).await,
        json!({
            "sub": sub,
            "username": "testuser",
            "email": "test@example.com",
            "email_verified": "false"
        })
    );

    let tokens = tokens_for_scope(&client, client_id, "openid phone").await;
    assert_eq!(
        userinfo(&client, &tokens["access_token"]).await,
        json!({
            "sub": sub,
            "username": "testuser",
            "phone_number": "+15555550100",
            "phone_number_verified": "true"
        })
    );

    let tokens = tokens_for_scope(&client, client_id, "openid profile").await;
    assert_eq!(
        userinfo(&client, &tokens["access_token"]).await,
        json!({"sub": sub, "username": "testuser", "name": "Test User"})
    );

    client
        .cognito_request(
            "AdminUpdateUserAttributes",
            json!({
                "UserPoolId": pool_id,
                "Username": "testuser",
                "UserAttributes": [{"Name": "email_verified", "Value": "true"}]
            }),
        )
        .await;
    let tokens = tokens_for_scope(&client, client_id, "openid email phone profile").await;
    let info = userinfo(&client, &tokens["access_token"]).await;
    assert_eq!(info["email_verified"], "true");
    assert_eq!(info["name"], "Test User");
    assert_eq!(info["phone_number"], "+15555550100");
    assert!(info.get("cognito:groups").is_none());
}

async fn revoke_token(
    client: &TestClient,
    token: &serde_json::Value,
    client_id: &str,
) -> common::TestResponse {
    client
        .post_form(
            "/oauth2/revoke",
            &[("token", token.as_str().unwrap()), ("client_id", client_id)],
        )
        .await
}

#[tokio::test]
async fn test_revoke_ends_the_sign_in_of_a_refresh_token() {
    let client = TestClient::new();
    let (pool_id, client_id, username, password) = setup_user_and_client(&client).await;
    let first = oauth_tokens(&client, &client_id, &username, &password).await;
    let second = oauth_tokens(&client, &client_id, &username, &password).await;

    let response = revoke_token(&client, &first["refresh_token"], &client_id).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(response.body_string().is_empty());

    // The refresh token and the access token of that sign-in are dead...
    let response = refresh(&client, &client_id, &first["refresh_token"], None).await;
    expect_token_error(response, "invalid_grant").await;
    assert_userinfo_invalid_token(&client, first["access_token"].as_str().unwrap()).await;
    // ...the user's other sign-in is not.
    userinfo(&client, &second["access_token"]).await;
    let response = refresh(&client, &client_id, &second["refresh_token"], None).await;
    assert_eq!(response.status(), StatusCode::OK);

    // Revoking again, or revoking a token that never existed, is a success.
    let response = revoke_token(&client, &first["refresh_token"], &client_id).await;
    assert_eq!(response.status(), StatusCode::OK);
    let response = revoke_token(&client, &json!("never-issued"), &client_id).await;
    assert_eq!(response.status(), StatusCode::OK);

    // Another client cannot revoke the token.
    let other = create_oauth_client(&client, &pool_id, json!({})).await;
    let response = revoke_token(
        &client,
        &second["refresh_token"],
        other["ClientId"].as_str().unwrap(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let response = refresh(&client, &client_id, &second["refresh_token"], None).await;
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_revoke_rejects_what_it_cannot_revoke() {
    let client = TestClient::new();
    let (pool_id, client_id, username, password) = setup_user_and_client(&client).await;
    let tokens = oauth_tokens(&client, &client_id, &username, &password).await;
    let error_of = |response: common::TestResponse| async move {
        let status = response.status();
        let body: serde_json::Value = response.json().await.unwrap();
        (status, body["error"].as_str().unwrap().to_string())
    };

    // Only refresh tokens can be revoked.
    for token in ["access_token", "id_token"] {
        let response = client
            .post_form(
                "/oauth2/revoke",
                &[
                    ("token", tokens[token].as_str().unwrap()),
                    ("client_id", &client_id),
                ],
            )
            .await;
        assert_eq!(
            error_of(response).await,
            (
                StatusCode::BAD_REQUEST,
                "unsupported_token_type".to_string()
            )
        );
    }

    let response = client
        .post_form("/oauth2/revoke", &[("client_id", &client_id)])
        .await;
    assert_eq!(
        error_of(response).await,
        (StatusCode::BAD_REQUEST, "invalid_request".to_string())
    );

    // A client with token revocation turned off.
    let no_revocation =
        create_oauth_client(&client, &pool_id, json!({"EnableTokenRevocation": false})).await;
    let no_revocation_id = no_revocation["ClientId"].as_str().unwrap();
    let its_tokens = oauth_tokens(&client, no_revocation_id, &username, &password).await;
    let response = client
        .post_form(
            "/oauth2/revoke",
            &[
                ("token", its_tokens["refresh_token"].as_str().unwrap()),
                ("client_id", no_revocation_id),
            ],
        )
        .await;
    assert_eq!(
        error_of(response).await,
        (StatusCode::BAD_REQUEST, "invalid_request".to_string())
    );

    // Bad client credentials are a 401 here.
    let confidential =
        create_oauth_client(&client, &pool_id, json!({"GenerateSecret": true})).await;
    let confidential_id = confidential["ClientId"].as_str().unwrap();
    let response = client
        .post_form_with_headers(
            "/oauth2/revoke",
            &[("token", "anything")],
            &[(
                "authorization",
                &basic_auth(confidential_id, "wrong-secret"),
            )],
        )
        .await;
    assert_eq!(
        error_of(response).await,
        (StatusCode::UNAUTHORIZED, "invalid_client".to_string())
    );
    let response = client
        .post_form_with_headers(
            "/oauth2/revoke",
            &[("token", "anything")],
            &[(
                "authorization",
                &basic_auth(
                    confidential_id,
                    confidential["ClientSecret"].as_str().unwrap(),
                ),
            )],
        )
        .await;
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_logout_with_redirect_uri_restarts_sign_in() {
    let client = TestClient::new();
    let (pool_id, client_id, _, _) = setup_user_and_client(&client).await;

    let response = client
        .get(&format!(
            "/logout?client_id={client_id}&redirect_uri={}&response_type=code&scope=openid&state=abc",
            urlencoding::encode(CALLBACK)
        ))
        .await;
    assert_eq!(response.status(), StatusCode::FOUND);
    let location = response.headers()["location"].to_str().unwrap();
    assert!(location.starts_with("/login?"));
    let query: std::collections::HashMap<String, String> =
        reqwest::Url::parse(&format!("https://example.com{location}"))
            .unwrap()
            .query_pairs()
            .into_owned()
            .collect();
    assert_eq!(query["client_id"], client_id);
    assert_eq!(query["redirect_uri"], CALLBACK);
    assert_eq!(query["response_type"], "code");
    assert_eq!(query["scope"], "openid");
    assert_eq!(query["state"], "abc");
    // The page it points to exists.
    assert_eq!(client.get(location).await.status(), StatusCode::OK);

    let error_of = |response: common::TestResponse| async move {
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(response.headers().get("location").is_none());
        let body: serde_json::Value = response.json().await.unwrap();
        body["error"].as_str().unwrap().to_string()
    };

    // The redirect URI has to be one of the client's callback URLs.
    let response = client
        .get(&format!(
            "/logout?client_id={client_id}&redirect_uri={}&response_type=code",
            urlencoding::encode("https://attacker.example/cb")
        ))
        .await;
    assert_eq!(error_of(response).await, "redirect_mismatch");

    // Neither form of the request.
    let response = client.get(&format!("/logout?client_id={client_id}")).await;
    assert_eq!(error_of(response).await, "invalid_request");
    let response = client
        .get(&format!(
            "/logout?client_id={client_id}&redirect_uri={}",
            urlencoding::encode(CALLBACK)
        ))
        .await;
    assert_eq!(error_of(response).await, "invalid_request");
    let response = client.get("/logout?logout_uri=https://example.com/").await;
    assert_eq!(error_of(response).await, "invalid_request");

    // A client that registered no sign-out URL has none to return to.
    let response = client
        .get(&format!(
            "/logout?client_id={client_id}&logout_uri={}",
            urlencoding::encode("https://example.com/signed-out")
        ))
        .await;
    assert_eq!(error_of(response).await, "invalid_request");

    // The other pool client is unaffected by this one's settings.
    let with_logout = create_oauth_client(
        &client,
        &pool_id,
        json!({"LogoutURLs": ["https://example.com/signed-out"]}),
    )
    .await;
    let response = client
        .get(&format!(
            "/logout?client_id={}&logout_uri={}",
            with_logout["ClientId"].as_str().unwrap(),
            urlencoding::encode("https://example.com/signed-out")
        ))
        .await;
    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(
        response.headers()["location"],
        "https://example.com/signed-out"
    );
}

#[tokio::test]
async fn test_client_credentials_without_scope_grants_every_client_scope() {
    let client = TestClient::new();
    let (_, pool_body) = client
        .request("CreateUserPool", json!({ "PoolName": "MachinePool" }))
        .await;
    let pool_id = pool_body["UserPool"]["Id"].as_str().unwrap();
    let machine = client
        .cognito_request(
            "CreateUserPoolClient",
            json!({
                "UserPoolId": pool_id,
                "ClientName": "MachineClient",
                "GenerateSecret": true,
                "AllowedOAuthFlows": ["client_credentials"],
                "AllowedOAuthScopes": ["api/read", "api/write"],
                "AllowedOAuthFlowsUserPoolClient": true
            }),
        )
        .await;
    let client_id = machine["UserPoolClient"]["ClientId"].as_str().unwrap();
    let client_secret = machine["UserPoolClient"]["ClientSecret"].as_str().unwrap();

    let response = client
        .post_form_with_headers(
            "/oauth2/token",
            &[("grant_type", "client_credentials")],
            &[("authorization", &basic_auth(client_id, client_secret))],
        )
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body: serde_json::Value = response.json().await.unwrap();
    assert!(body.get("refresh_token").is_none());
    assert!(body.get("id_token").is_none());

    let claims = jwt_claims(&body["access_token"]);
    assert_eq!(claims["scope"], "api/read api/write");
    assert_eq!(claims["sub"], client_id);
    assert_eq!(claims["client_id"], client_id);
    assert_eq!(claims["version"], 2);
    assert_eq!(claims["token_use"], "access");
    // No user stands behind the token.
    assert!(claims.get("username").is_none());

    let response = client
        .post_form_with_headers(
            "/oauth2/token",
            &[("grant_type", "client_credentials"), ("scope", "api/admin")],
            &[("authorization", &basic_auth(client_id, client_secret))],
        )
        .await;
    expect_token_error(response, "invalid_scope").await;
}

#[tokio::test]
async fn test_code_grant_requires_the_redirect_uri() {
    let client = TestClient::new();
    let (_, client_id, username, password) = setup_user_and_client(&client).await;

    // Leaving the redirect URI out is a malformed request...
    let code = request_authorization_code(&client, &client_id, &username, &password).await;
    let response = client
        .post_form(
            "/oauth2/token",
            &[
                ("grant_type", "authorization_code"),
                ("code", &code),
                ("client_id", &client_id),
            ],
        )
        .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response.json::<serde_json::Value>().await.unwrap()["error"],
        "invalid_request"
    );

    // ...and one the code was not issued for does not redeem it.
    let code = request_authorization_code(&client, &client_id, &username, &password).await;
    let response = client
        .post_form(
            "/oauth2/token",
            &[
                ("grant_type", "authorization_code"),
                ("code", &code),
                ("client_id", &client_id),
                ("redirect_uri", "https://example.com/other"),
            ],
        )
        .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response.json::<serde_json::Value>().await.unwrap()["error"],
        "invalid_grant"
    );
}
