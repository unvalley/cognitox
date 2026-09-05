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
                "AllowedOAuthFlowsUserPoolClient": true,
                "AllowedOAuthFlows": ["code"],
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
                "AllowedOAuthFlowsUserPoolClient": true,
                "AllowedOAuthFlows": ["code"],
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
                "AllowedOAuthFlowsUserPoolClient": true,
                "AllowedOAuthFlows": ["code"],
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
                "AllowedOAuthFlowsUserPoolClient": true,
                "AllowedOAuthFlows": ["code"],
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

/// Helper: create a pool + confirmed user + client, returning (client_id, username, password).
async fn setup_login_fixture(client: &TestClient) -> (String, String, String) {
    let (_, pool_body) = client
        .request("CreateUserPool", json!({ "PoolName": "test-pool" }))
        .await;
    let user_pool_id = pool_body["UserPool"]["Id"].as_str().unwrap().to_string();

    let (_, client_body) = client
        .request(
            "CreateUserPoolClient",
            json!({
                "UserPoolId": user_pool_id,
                "ClientName": "test-client",
                "AllowedOAuthFlowsUserPoolClient": true,
                "AllowedOAuthFlows": ["code"],
                "CallbackURLs": ["https://example.com/callback"]
            }),
        )
        .await;
    let client_id = client_body["UserPoolClient"]["ClientId"]
        .as_str()
        .unwrap()
        .to_string();

    let username = "alice".to_string();
    let password = "Passw0rd!".to_string();
    client
        .request(
            "AdminCreateUser",
            json!({
                "UserPoolId": user_pool_id,
                "Username": username,
                "MessageAction": "SUPPRESS"
            }),
        )
        .await;
    client
        .request(
            "AdminSetUserPassword",
            json!({
                "UserPoolId": user_pool_id,
                "Username": username,
                "Password": password,
                "Permanent": true
            }),
        )
        .await;

    (client_id, username, password)
}

#[tokio::test]
async fn test_login_submit_rejects_unregistered_redirect_uri() {
    let client = TestClient::new();
    let (client_id, username, password) = setup_login_fixture(&client).await;

    // Attacker-controlled redirect_uri that is NOT in the client's CallbackURLs.
    let response = client
        .post_form(
            "/login",
            &[
                ("response_type", "code"),
                ("client_id", &client_id),
                ("redirect_uri", "https://attacker.example/callback"),
                ("scope", "openid"),
                ("username", &username),
                ("password", &password),
            ],
        )
        .await;

    // Must not issue a code / redirect to the attacker; re-renders the login
    // page (200, no Location redirect) with an error instead.
    assert_eq!(response.status(), StatusCode::OK);
    assert!(response.headers().get("location").is_none());
    let body = response.body_string();
    assert!(body.contains("Invalid redirect_uri"));
}

#[tokio::test]
async fn test_login_submit_allows_registered_redirect_uri() {
    let client = TestClient::new();
    let (client_id, username, password) = setup_login_fixture(&client).await;

    let response = client
        .post_form(
            "/login",
            &[
                ("response_type", "code"),
                ("client_id", &client_id),
                ("redirect_uri", "https://example.com/callback"),
                ("scope", "openid"),
                ("username", &username),
                ("password", &password),
            ],
        )
        .await;

    // Successful login redirects to the registered callback with an authorization code.
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let location = response
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(location.starts_with("https://example.com/callback?code="));
}

#[tokio::test]
async fn test_login_page_escapes_reflected_params() {
    let client = TestClient::new();
    let (client_id, _, _) = setup_login_fixture(&client).await;

    // A malicious `state` param must be HTML-escaped, not reflected as live markup.
    let response = client
        .get(&format!(
            "/login?response_type=code&client_id={}&redirect_uri=https://example.com/callback&scope=openid&state=%22%3E%3Cscript%3Ealert(1)%3C/script%3E",
            client_id
        ))
        .await;

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.body_string();
    assert!(
        !body.contains("<script>alert(1)</script>"),
        "reflected state was not escaped"
    );
    assert!(body.contains("&lt;script&gt;"));
}

#[tokio::test]
async fn test_login_submit_enforces_client_oauth_policy() {
    let client = TestClient::new();
    let (_, pool_body) = client
        .request("CreateUserPool", json!({ "PoolName": "test-pool" }))
        .await;
    let user_pool_id = pool_body["UserPool"]["Id"].as_str().unwrap().to_string();

    // Client with OAuth flows disabled entirely.
    let (_, client_body) = client
        .request(
            "CreateUserPoolClient",
            json!({
                "UserPoolId": user_pool_id,
                "ClientName": "no-oauth"
            }),
        )
        .await;
    let client_id = client_body["UserPoolClient"]["ClientId"]
        .as_str()
        .unwrap()
        .to_string();

    client
        .request(
            "AdminCreateUser",
            json!({ "UserPoolId": user_pool_id, "Username": "bob", "MessageAction": "SUPPRESS" }),
        )
        .await;
    client
        .request(
            "AdminSetUserPassword",
            json!({
                "UserPoolId": user_pool_id,
                "Username": "bob",
                "Password": "Passw0rd!",
                "Permanent": true
            }),
        )
        .await;

    let response = client
        .post_form(
            "/login",
            &[
                ("response_type", "code"),
                ("client_id", &client_id),
                ("redirect_uri", "https://example.com/callback"),
                ("scope", "openid"),
                ("username", "bob"),
                ("password", "Passw0rd!"),
            ],
        )
        .await;
    // /oauth2/authorize would refuse this client, so the Hosted UI must too.
    assert_eq!(response.status(), StatusCode::OK);
    assert!(response.headers().get("location").is_none());
    assert!(
        response
            .body_string()
            .contains("OAuth flows are not enabled for this client")
    );

    // Enable the code flow; a scope outside AllowedOAuthScopes is still refused.
    client
        .request(
            "UpdateUserPoolClient",
            json!({
                "UserPoolId": user_pool_id,
                "ClientId": client_id,
                "AllowedOAuthFlowsUserPoolClient": true,
                "AllowedOAuthFlows": ["code"],
                "AllowedOAuthScopes": ["email"],
                "CallbackURLs": ["https://example.com/callback"]
            }),
        )
        .await;
    let response = client
        .post_form(
            "/login",
            &[
                ("response_type", "code"),
                ("client_id", &client_id),
                ("redirect_uri", "https://example.com/callback"),
                ("scope", "openid profile"),
                ("username", "bob"),
                ("password", "Passw0rd!"),
            ],
        )
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(response.headers().get("location").is_none());
    assert!(
        response
            .body_string()
            .contains("is not allowed for this client")
    );
}

#[tokio::test]
async fn test_login_submit_checks_password_before_confirmation_status() {
    let client = TestClient::new();
    let (client_id, _, _) = setup_login_fixture(&client).await;

    // Unconfirmed user via SignUp.
    client
        .request(
            "SignUp",
            json!({
                "ClientId": client_id,
                "Username": "carol",
                "Password": "Passw0rd!",
                "UserAttributes": [{ "Name": "email", "Value": "carol@example.com" }]
            }),
        )
        .await;

    // Wrong password must not reveal the unconfirmed state via a /confirm redirect.
    let response = client
        .post_form(
            "/login",
            &[
                ("response_type", "code"),
                ("client_id", &client_id),
                ("redirect_uri", "https://example.com/callback"),
                ("scope", "openid"),
                ("username", "carol"),
                ("password", "wrong-password"),
            ],
        )
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(response.headers().get("location").is_none());
    assert!(
        response
            .body_string()
            .contains("Invalid username or password")
    );

    // Correct password for an unconfirmed user goes to the confirmation page.
    let response = client
        .post_form(
            "/login",
            &[
                ("response_type", "code"),
                ("client_id", &client_id),
                ("redirect_uri", "https://example.com/callback"),
                ("scope", "openid"),
                ("username", "carol"),
                ("password", "Passw0rd!"),
            ],
        )
        .await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let location = response
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(location.starts_with("/confirm?"));
}
