//! OAuth 2.0 endpoint tests

mod common;

use axum::http::StatusCode;
use serde_json::json;

use common::TestClient;

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

async fn authorize_code_via_login(
    client: &TestClient,
    client_id: &str,
    username: &str,
    password: &str,
    scope: &str,
    code_challenge: Option<&str>,
    code_challenge_method: Option<&str>,
) -> String {
    let mut auth_url = format!(
        "/oauth2/authorize?response_type=code&client_id={}&redirect_uri={}&scope={}",
        client_id, "https://example.com/callback", scope
    );
    if let Some(challenge) = code_challenge {
        auth_url.push_str(&format!("&code_challenge={challenge}"));
    }
    if let Some(method) = code_challenge_method {
        auth_url.push_str(&format!("&code_challenge_method={method}"));
    }

    let response = client.get(&auth_url).await;
    assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
    let location = response
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(location.starts_with("/login?"));

    let mut form_fields = vec![
        ("username".to_string(), username.to_string()),
        ("password".to_string(), password.to_string()),
        ("response_type".to_string(), "code".to_string()),
        ("client_id".to_string(), client_id.to_string()),
        (
            "redirect_uri".to_string(),
            "https://example.com/callback".to_string(),
        ),
        ("scope".to_string(), scope.replace("%20", " ")),
    ];
    if let Some(challenge) = code_challenge {
        form_fields.push(("code_challenge".to_string(), challenge.to_string()));
    }
    if let Some(method) = code_challenge_method {
        form_fields.push(("code_challenge_method".to_string(), method.to_string()));
    }

    let form_refs: Vec<(&str, &str)> = form_fields
        .iter()
        .map(|(name, value)| (name.as_str(), value.as_str()))
        .collect();
    let login_response = client.post_form("/login", &form_refs).await;
    assert_eq!(login_response.status(), StatusCode::SEE_OTHER);

    let login_location = login_response
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(login_location.starts_with("https://example.com/callback"));

    login_location
        .split("code=")
        .nth(1)
        .unwrap()
        .split('&')
        .next()
        .unwrap()
        .to_string()
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

    let code = authorize_code_via_login(
        &client,
        &client_id,
        &username,
        &password,
        "openid%20email",
        None,
        None,
    )
    .await;

    // Exchange code for tokens
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
    assert!(token_body["access_token"].as_str().is_some());
    assert!(token_body["id_token"].as_str().is_some());
    assert!(token_body["refresh_token"].as_str().is_some());
    assert_eq!(token_body["token_type"], "Bearer");
}

#[tokio::test]
async fn test_authorization_code_flow_with_pkce() {
    let client = TestClient::new();
    let (_, client_id, username, password) = setup_user_and_client(&client).await;

    // Generate PKCE code verifier and challenge
    let code_verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    // S256 hash of code_verifier
    let code_challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    let code = authorize_code_via_login(
        &client,
        &client_id,
        &username,
        &password,
        "openid",
        Some(code_challenge),
        Some("S256"),
    )
    .await;

    // Exchange code for tokens with code_verifier
    let token_response = client
        .post_form(
            "/oauth2/token",
            &[
                ("grant_type", "authorization_code"),
                ("code", &code),
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

    let code = authorize_code_via_login(
        &client, &client_id, &username, &password, "openid", None, None,
    )
    .await;

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
async fn test_userinfo_endpoint() {
    let client = TestClient::new();
    let (_, client_id, username, password) = setup_user_and_client(&client).await;

    let code = authorize_code_via_login(
        &client,
        &client_id,
        &username,
        &password,
        "openid%20email",
        None,
        None,
    )
    .await;

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

#[tokio::test]
async fn test_client_credentials_returns_jwt_access_token() {
    let client = TestClient::new();

    let (_, pool_body) = client
        .request("CreateUserPool", json!({ "PoolName": "MachinePool" }))
        .await;
    let pool_id = pool_body["UserPool"]["Id"].as_str().unwrap();

    let (_, client_body) = client
        .request(
            "CreateUserPoolClient",
            json!({
                "UserPoolId": pool_id,
                "ClientName": "MachineClient",
                "AllowedOAuthFlows": ["client_credentials"],
                "AllowedOAuthScopes": ["openid"],
                "AllowedOAuthFlowsUserPoolClient": true,
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

    let response = client
        .post_form(
            "/oauth2/token",
            &[
                ("grant_type", "client_credentials"),
                ("client_id", &client_id),
                ("client_secret", &client_secret),
                ("scope", "openid"),
            ],
        )
        .await;

    assert_eq!(response.status(), StatusCode::OK);

    let body: serde_json::Value = response.json().await.unwrap();
    let access_token = body["access_token"].as_str().unwrap();
    assert_eq!(access_token.split('.').count(), 3);
}
