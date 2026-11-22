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
                "ExplicitAuthFlows": ["ALLOW_USER_PASSWORD_AUTH", "ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_USER_SRP_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
                "ClientName": "test-client",
                "AllowedOAuthFlowsUserPoolClient": true,
                "AllowedOAuthFlows": ["code"],
                "AllowedOAuthScopes": ["openid", "email"],
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
                "ExplicitAuthFlows": ["ALLOW_USER_PASSWORD_AUTH", "ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_USER_SRP_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
                "ClientName": "test-client",
                "AllowedOAuthFlowsUserPoolClient": true,
                "AllowedOAuthFlows": ["code"],
                "AllowedOAuthScopes": ["openid", "email"],
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
                "ExplicitAuthFlows": ["ALLOW_USER_PASSWORD_AUTH", "ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_USER_SRP_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
                "ClientName": "test-client",
                "AllowedOAuthFlowsUserPoolClient": true,
                "AllowedOAuthFlows": ["code"],
                "AllowedOAuthScopes": ["openid", "email"],
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
                "ExplicitAuthFlows": ["ALLOW_USER_PASSWORD_AUTH", "ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_USER_SRP_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
                "ClientName": "test-client",
                "AllowedOAuthFlowsUserPoolClient": true,
                "AllowedOAuthFlows": ["code"],
                "AllowedOAuthScopes": ["openid", "email"],
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
                "ExplicitAuthFlows": ["ALLOW_USER_PASSWORD_AUTH", "ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_USER_SRP_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
                "ClientName": "test-client",
                "AllowedOAuthFlowsUserPoolClient": true,
                "AllowedOAuthFlows": ["code"],
                "AllowedOAuthScopes": ["openid", "email"],
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
    assert_eq!(response.status(), StatusCode::FOUND);
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

// =============================================================================
// Managed login follows the user pool's rules
// =============================================================================

const CALLBACK: &str = "https://example.com/callback";

struct Hosted {
    client: TestClient,
    pool_id: String,
    client_id: String,
}

impl Hosted {
    /// A pool that verifies email addresses and a public client for the
    /// authorization code grant.
    async fn new(pool_settings: serde_json::Value) -> Self {
        let client = TestClient::new();
        let mut pool_request = json!({
            "PoolName": "hosted-pool",
            "AutoVerifiedAttributes": ["email"],
        });
        pool_request
            .as_object_mut()
            .unwrap()
            .extend(pool_settings.as_object().unwrap().clone());
        let pool = client.cognito_request("CreateUserPool", pool_request).await;
        let pool_id = pool["UserPool"]["Id"].as_str().unwrap().to_string();

        let app_client = client
            .cognito_request(
                "CreateUserPoolClient",
                json!({
                    "UserPoolId": pool_id,
                    "ClientName": "hosted-client",
                    "AllowedOAuthFlowsUserPoolClient": true,
                    "AllowedOAuthFlows": ["code"],
                    "AllowedOAuthScopes": ["openid", "email"],
                    "CallbackURLs": [CALLBACK]
                }),
            )
            .await;
        let client_id = app_client["UserPoolClient"]["ClientId"]
            .as_str()
            .unwrap()
            .to_string();

        Self {
            client,
            pool_id,
            client_id,
        }
    }

    /// Post one of the forms with the authorization request it carries.
    async fn post(&self, path: &str, fields: &[(&str, &str)]) -> common::TestResponse {
        let mut form = vec![
            ("response_type", "code"),
            ("client_id", self.client_id.as_str()),
            ("redirect_uri", CALLBACK),
            ("scope", "openid email"),
            ("state", "st4te"),
        ];
        form.extend_from_slice(fields);
        self.client.post_form(path, &form).await
    }

    async fn login(&self, username: &str, password: &str) -> common::TestResponse {
        self.post("/login", &[("username", username), ("password", password)])
            .await
    }

    async fn signup(&self, username: &str, password: &str, confirm: &str) -> common::TestResponse {
        let email = format!("{username}@example.com");
        self.post(
            "/signup",
            &[
                ("username", username),
                ("email", &email),
                ("password", password),
                ("password_confirm", confirm),
            ],
        )
        .await
    }

    async fn new_password(
        &self,
        session: &str,
        password: &str,
        confirm: &str,
    ) -> common::TestResponse {
        self.post(
            "/new-password",
            &[
                ("session", session),
                ("new_password", password),
                ("new_password_confirm", confirm),
            ],
        )
        .await
    }

    async fn reset_password(
        &self,
        username: &str,
        code: &str,
        password: &str,
    ) -> common::TestResponse {
        self.post(
            "/reset-password",
            &[
                ("username", username),
                ("code", code),
                ("new_password", password),
                ("new_password_confirm", password),
            ],
        )
        .await
    }

    async fn admin_get_user(&self, username: &str) -> serde_json::Value {
        self.client
            .cognito_request(
                "AdminGetUser",
                json!({"UserPoolId": self.pool_id, "Username": username}),
            )
            .await
    }

    /// The code the emulator "sent" to the user.
    async fn sent_code(&self, username: &str) -> String {
        let user = self.admin_get_user(username).await;
        let sub = attribute(&user, "sub").unwrap();
        self.client
            .storage()
            .get_confirmation_code(&uuid::Uuid::parse_str(&sub).unwrap())
            .await
            .unwrap()
            .code
    }

    /// Exchange the code a successful sign-in redirected with.
    async fn tokens_from(&self, response: &common::TestResponse) -> serde_json::Value {
        let query = location_query(response);
        assert_eq!(query["state"], "st4te");
        let token_response = self
            .client
            .post_form(
                "/oauth2/token",
                &[
                    ("grant_type", "authorization_code"),
                    ("code", &query["code"]),
                    ("client_id", &self.client_id),
                    ("redirect_uri", CALLBACK),
                ],
            )
            .await;
        assert_eq!(token_response.status(), StatusCode::OK);
        token_response.json().await.unwrap()
    }
}

fn attribute(user: &serde_json::Value, name: &str) -> Option<String> {
    user["UserAttributes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|attribute| attribute["Name"] == name)
        .map(|attribute| attribute["Value"].as_str().unwrap().to_string())
}

fn location(response: &common::TestResponse) -> String {
    assert_eq!(response.status(), StatusCode::FOUND);
    response.headers()["location"].to_str().unwrap().to_string()
}

fn location_query(response: &common::TestResponse) -> std::collections::HashMap<String, String> {
    let location = location(response);
    let absolute = if location.starts_with('/') {
        format!("https://emulator.invalid{location}")
    } else {
        location
    };
    reqwest::Url::parse(&absolute)
        .unwrap()
        .query_pairs()
        .into_owned()
        .collect()
}

/// A page re-rendered with an error rather than a redirect.
fn page_error(response: &common::TestResponse, message: &str) {
    assert_eq!(response.status(), StatusCode::OK);
    assert!(response.headers().get("location").is_none());
    let body = response.body_string();
    assert!(body.contains(message), "{message:?} not shown in:\n{body}");
}

fn jwt_claims(token: &serde_json::Value) -> serde_json::Value {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    let payload = token.as_str().unwrap().split('.').nth(1).unwrap();
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).unwrap()).unwrap()
}

#[tokio::test]
async fn test_signup_confirm_and_sign_in_through_the_pages() {
    let hosted = Hosted::new(json!({})).await;

    // The pool's password policy applies to the form.
    let response = hosted.signup("alice", "password", "password").await;
    page_error(
        &response,
        "Password did not conform with policy: Password must have uppercase characters",
    );
    let response = hosted.signup("alice", "Passw0rd!", "Passw0rd?").await;
    page_error(&response, "Passwords do not match");
    let (status, _) = hosted
        .client
        .request(
            "AdminGetUser",
            json!({"UserPoolId": hosted.pool_id, "Username": "alice"}),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a refused sign-up left a user"
    );

    let response = hosted.signup("alice", "Passw0rd!", "Passw0rd!").await;
    assert!(location(&response).starts_with("/confirm?"));
    assert_eq!(location_query(&response)["username"], "alice");
    let response = hosted.signup("alice", "Passw0rd!", "Passw0rd!").await;
    page_error(&response, "User already exists");

    // The account waits for its code, with the address unverified.
    let user = hosted.admin_get_user("alice").await;
    assert_eq!(user["UserStatus"], "UNCONFIRMED");
    assert_eq!(
        attribute(&user, "email").as_deref(),
        Some("alice@example.com")
    );
    assert_eq!(attribute(&user, "email_verified").as_deref(), Some("false"));
    let code = hosted.sent_code("alice").await;
    assert_eq!(code.len(), 6);
    assert!(code.chars().all(|ch| ch.is_ascii_digit()));

    // The right password does not get an unconfirmed user in...
    let response = hosted.login("alice", "Passw0rd!").await;
    assert!(location(&response).starts_with("/confirm?"));
    // ...and the wrong one says nothing about the account.
    let response = hosted.login("alice", "Wr0ng-password!").await;
    page_error(&response, "Incorrect username or password.");

    let wrong_code = if code == "000000" { "000001" } else { "000000" };
    let response = hosted
        .post("/confirm", &[("username", "alice"), ("code", wrong_code)])
        .await;
    page_error(
        &response,
        "Invalid verification code provided, please try again.",
    );
    let response = hosted
        .post("/confirm", &[("username", "alice"), ("code", &code)])
        .await;
    assert!(location(&response).starts_with("/login?"));

    // Returning the code confirmed the account and verified the address.
    let user = hosted.admin_get_user("alice").await;
    assert_eq!(user["UserStatus"], "CONFIRMED");
    assert_eq!(attribute(&user, "email_verified").as_deref(), Some("true"));
    let response = hosted
        .post("/confirm", &[("username", "alice"), ("code", &code)])
        .await;
    page_error(
        &response,
        "User cannot be confirmed. Current status is CONFIRMED",
    );

    let response = hosted.login("alice", "Passw0rd!").await;
    assert!(location(&response).starts_with(&format!("{CALLBACK}?code=")));
    let tokens = hosted.tokens_from(&response).await;
    let id = jwt_claims(&tokens["id_token"]);
    assert_eq!(id["cognito:username"], "alice");
    assert_eq!(id["email_verified"], true);
    assert_eq!(jwt_claims(&tokens["access_token"])["scope"], "openid email");
}

#[tokio::test]
async fn test_signup_is_refused_when_only_admins_create_users() {
    let hosted =
        Hosted::new(json!({"AdminCreateUserConfig": {"AllowAdminCreateUserOnly": true}})).await;

    let response = hosted
        .post(
            "/signup",
            &[
                ("username", "alice"),
                ("email", "alice@example.com"),
                ("password", "Passw0rd!"),
                ("password_confirm", "Passw0rd!"),
            ],
        )
        .await;
    page_error(&response, "SignUp is not permitted for this user pool");
}

#[tokio::test]
async fn test_login_reports_failures_the_way_cognito_does() {
    let hosted = Hosted::new(json!({})).await;
    hosted
        .client
        .cognito_request(
            "AdminCreateUser",
            json!({"UserPoolId": hosted.pool_id, "Username": "bob", "MessageAction": "SUPPRESS"}),
        )
        .await;
    hosted
        .client
        .cognito_request(
            "AdminSetUserPassword",
            json!({
                "UserPoolId": hosted.pool_id,
                "Username": "bob",
                "Password": "Passw0rd!",
                "Permanent": true
            }),
        )
        .await;

    let response = hosted.login("bob", "Wr0ng-password!").await;
    page_error(&response, "Incorrect username or password.");
    let response = hosted.login("nobody", "Passw0rd!").await;
    page_error(&response, "Incorrect username or password.");

    // The request itself is checked like one to the authorize endpoint.
    let response = hosted
        .client
        .post_form(
            "/login",
            &[
                ("response_type", "code"),
                ("client_id", &hosted.client_id),
                ("redirect_uri", CALLBACK),
                ("scope", "openid profile"),
                ("username", "bob"),
                ("password", "Passw0rd!"),
            ],
        )
        .await;
    page_error(&response, "is not allowed for this client");
    let response = hosted
        .client
        .post_form(
            "/login",
            &[
                ("response_type", "token"),
                ("client_id", &hosted.client_id),
                ("redirect_uri", CALLBACK),
                ("username", "bob"),
                ("password", "Passw0rd!"),
            ],
        )
        .await;
    page_error(&response, "Implicit flow not allowed for this client");

    // Without `scope`, the sign-in is for every scope the client allows.
    let response = hosted
        .client
        .post_form(
            "/login",
            &[
                ("response_type", "code"),
                ("client_id", &hosted.client_id),
                ("redirect_uri", CALLBACK),
                ("state", "st4te"),
                ("username", "bob"),
                ("password", "Passw0rd!"),
            ],
        )
        .await;
    let tokens = hosted.tokens_from(&response).await;
    assert_eq!(jwt_claims(&tokens["access_token"])["scope"], "openid email");

    hosted
        .client
        .cognito_request(
            "AdminDisableUser",
            json!({"UserPoolId": hosted.pool_id, "Username": "bob"}),
        )
        .await;
    let response = hosted.login("bob", "Passw0rd!").await;
    page_error(&response, "User is disabled.");
}

#[tokio::test]
async fn test_temporary_password_leads_to_a_new_password_step() {
    let hosted = Hosted::new(json!({})).await;
    hosted
        .client
        .cognito_request(
            "AdminCreateUser",
            json!({
                "UserPoolId": hosted.pool_id,
                "Username": "carol",
                "TemporaryPassword": "TempPass123!",
                "MessageAction": "SUPPRESS"
            }),
        )
        .await;

    // The temporary password does not sign the user in.
    let response = hosted.login("carol", "TempPass123!").await;
    let next = location(&response);
    assert!(next.starts_with("/new-password?"), "{next}");
    let session = location_query(&response)["session"].clone();
    let page = hosted.client.get(&next).await;
    assert_eq!(page.status(), StatusCode::OK);
    assert!(page.body_string().contains("Change Password"));

    let response = hosted
        .new_password("made-up-session", "NewPassw0rd!", "NewPassw0rd!")
        .await;
    page_error(&response, "Invalid session for the user.");
    let response = hosted
        .new_password(&session, "NewPassw0rd!", "OtherPassw0rd!")
        .await;
    page_error(&response, "Passwords do not match");
    let response = hosted.new_password(&session, "short", "short").await;
    page_error(
        &response,
        "Password did not conform with policy: Password not long enough",
    );
    assert_eq!(
        hosted.admin_get_user("carol").await["UserStatus"],
        "FORCE_CHANGE_PASSWORD"
    );

    // Choosing a password finishes the sign-in that started at /login.
    let response = hosted
        .new_password(&session, "NewPassw0rd!", "NewPassw0rd!")
        .await;
    assert!(location(&response).starts_with(&format!("{CALLBACK}?code=")));
    let tokens = hosted.tokens_from(&response).await;
    assert_eq!(jwt_claims(&tokens["id_token"])["cognito:username"], "carol");
    assert_eq!(
        hosted.admin_get_user("carol").await["UserStatus"],
        "CONFIRMED"
    );

    // The session is spent, the temporary password gone, the new one works.
    let response = hosted
        .new_password(&session, "AnotherPassw0rd!", "AnotherPassw0rd!")
        .await;
    page_error(&response, "Invalid session for the user.");
    let response = hosted.login("carol", "TempPass123!").await;
    page_error(&response, "Incorrect username or password.");
    let response = hosted.login("carol", "NewPassw0rd!").await;
    assert!(location(&response).starts_with(&format!("{CALLBACK}?code=")));
}

#[tokio::test]
async fn test_reset_password_enforces_the_code_and_the_policy() {
    let hosted = Hosted::new(json!({})).await;
    hosted
        .client
        .cognito_request(
            "AdminCreateUser",
            json!({
                "UserPoolId": hosted.pool_id,
                "Username": "dave",
                "MessageAction": "SUPPRESS",
                "UserAttributes": [
                    {"Name": "email", "Value": "dave@example.com"},
                    {"Name": "email_verified", "Value": "true"}
                ]
            }),
        )
        .await;

    // A user who still has a temporary password gets no reset code.
    let response = hosted
        .post("/forgot-password", &[("username", "dave")])
        .await;
    assert!(location(&response).starts_with("/reset-password?"));
    let dave = hosted.admin_get_user("dave").await;
    let sub = uuid::Uuid::parse_str(&attribute(&dave, "sub").unwrap()).unwrap();
    assert!(
        hosted
            .client
            .storage()
            .get_confirmation_code(&sub)
            .await
            .is_none()
    );

    hosted
        .client
        .cognito_request(
            "AdminSetUserPassword",
            json!({
                "UserPoolId": hosted.pool_id,
                "Username": "dave",
                "Password": "Passw0rd!",
                "Permanent": true
            }),
        )
        .await;

    let response = hosted
        .post("/forgot-password", &[("username", "dave")])
        .await;
    assert!(location(&response).starts_with("/reset-password?"));
    assert_eq!(location_query(&response)["username"], "dave");
    // An unknown user is sent on the same way.
    let response = hosted
        .post("/forgot-password", &[("username", "nobody")])
        .await;
    assert!(location(&response).starts_with("/reset-password?"));

    let code = hosted.sent_code("dave").await;
    assert_eq!(code.len(), 6);
    assert!(code.chars().all(|ch| ch.is_ascii_digit()));
    let wrong_code = if code == "000000" { "000001" } else { "000000" };

    let response = hosted
        .reset_password("dave", wrong_code, "NewPassw0rd!")
        .await;
    page_error(
        &response,
        "Invalid verification code provided, please try again.",
    );
    let response = hosted.reset_password("nobody", &code, "NewPassw0rd!").await;
    page_error(
        &response,
        "Invalid code provided, please request a code again.",
    );
    let response = hosted.reset_password("dave", &code, "newpassword").await;
    page_error(
        &response,
        "Password did not conform with policy: Password must have uppercase characters",
    );
    // None of that changed the password.
    let response = hosted.login("dave", "Passw0rd!").await;
    assert!(location(&response).starts_with(&format!("{CALLBACK}?code=")));

    let response = hosted.reset_password("dave", &code, "NewPassw0rd!").await;
    assert!(location(&response).starts_with("/login?"));
    let response = hosted.login("dave", "Passw0rd!").await;
    page_error(&response, "Incorrect username or password.");
    let response = hosted.login("dave", "NewPassw0rd!").await;
    assert!(location(&response).starts_with(&format!("{CALLBACK}?code=")));

    // The code worked once.
    let response = hosted.reset_password("dave", &code, "ThirdPassw0rd!").await;
    page_error(
        &response,
        "Invalid code provided, please request a code again.",
    );
}

// ==================== MFA ====================

const MFA_PASSWORD: &str = "Passw0rd!";

/// The code an authenticator app shows for a secret key (RFC 6238), offset
/// by a number of 30-second steps.
fn totp(secret: &str, step_offset: i64) -> String {
    use hmac::{Hmac, Mac};

    let mut bits = 0u32;
    let mut bit_count = 0;
    let mut key = Vec::new();
    for ch in secret.bytes() {
        let value = match ch {
            b'A'..=b'Z' => ch - b'A',
            b'2'..=b'7' => ch - b'2' + 26,
            _ => panic!("not a base32 secret: {secret}"),
        };
        bits = (bits << 5) | u32::from(value);
        bit_count += 5;
        if bit_count >= 8 {
            bit_count -= 8;
            key.push((bits >> bit_count) as u8);
            bits &= (1 << bit_count) - 1;
        }
    }

    let counter = (chrono::Utc::now().timestamp() / 30 + step_offset) as u64;
    let mut mac = Hmac::<sha1::Sha1>::new_from_slice(&key).unwrap();
    mac.update(&counter.to_be_bytes());
    let digest = mac.finalize().into_bytes();
    let offset = (digest[19] & 0x0f) as usize;
    let binary = u32::from_be_bytes(digest[offset..offset + 4].try_into().unwrap()) & 0x7fff_ffff;
    format!("{:06}", binary % 1_000_000)
}

/// A well-formed code no authenticator app would show right now.
fn wrong_totp(secret: &str) -> String {
    let accepted: Vec<String> = (-2..=2).map(|step| totp(secret, step)).collect();
    ["000000", "111111", "222222", "333333", "444444", "555555"]
        .into_iter()
        .find(|code| !accepted.iter().any(|accepted| accepted == code))
        .unwrap()
        .to_string()
}

impl Hosted {
    async fn set_pool_mfa(&self, settings: serde_json::Value) {
        let mut request = json!({"UserPoolId": self.pool_id});
        request
            .as_object_mut()
            .unwrap()
            .extend(settings.as_object().unwrap().clone());
        self.client
            .cognito_request("SetUserPoolMfaConfig", request)
            .await;
    }

    /// A confirmed user with a permanent password.
    async fn permanent_user(&self, username: &str, attributes: serde_json::Value) {
        self.client
            .cognito_request(
                "AdminCreateUser",
                json!({
                    "UserPoolId": self.pool_id,
                    "Username": username,
                    "UserAttributes": attributes,
                    "MessageAction": "SUPPRESS"
                }),
            )
            .await;
        self.client
            .cognito_request(
                "AdminSetUserPassword",
                json!({
                    "UserPoolId": self.pool_id,
                    "Username": username,
                    "Password": MFA_PASSWORD,
                    "Permanent": true
                }),
            )
            .await;
    }

    /// Sign in with the password and follow the redirect to the MFA page.
    /// Returns the session and the page.
    async fn login_to_mfa(&self, username: &str) -> (String, String) {
        let response = self.login(username, MFA_PASSWORD).await;
        self.mfa_page(&response).await
    }

    async fn mfa_page(&self, response: &common::TestResponse) -> (String, String) {
        let next = location(response);
        assert!(next.starts_with("/mfa?"), "{next}");
        let session = location_query(response)["session"].clone();
        let page = self.client.get(&next).await;
        assert_eq!(page.status(), StatusCode::OK);
        (session, page.body_string())
    }

    async fn mfa_code(&self, session: &str, code: &str) -> common::TestResponse {
        self.post("/mfa", &[("session", session), ("code", code)])
            .await
    }

    /// The code the emulator "sent" for an MFA challenge.
    async fn sent_mfa_code(&self, session: &str) -> String {
        self.client
            .storage()
            .get_auth_challenge_session(session)
            .await
            .unwrap()
            .code
            .unwrap()
    }

    fn signed_in(&self, response: &common::TestResponse) {
        let next = location(response);
        assert!(next.starts_with(&format!("{CALLBACK}?code=")), "{next}");
    }
}

#[tokio::test]
async fn test_required_mfa_registers_an_authenticator_app_and_asks_for_it() {
    let hosted = Hosted::new(json!({})).await;
    hosted
        .set_pool_mfa(json!({
            "MfaConfiguration": "ON",
            "SoftwareTokenMfaConfiguration": {"Enabled": true}
        }))
        .await;
    hosted.permanent_user("alice", json!([])).await;

    // The password alone does not sign the user in: without a factor, the
    // page has them register an authenticator app.
    let (session, page) = hosted.login_to_mfa("alice").await;
    assert!(page.contains("Set up an authenticator app"), "{page}");
    let (_, secret) = hosted
        .client
        .storage()
        .get_software_token_session(&session)
        .await
        .unwrap();
    assert!(page.contains(&secret), "{page}");

    let response = hosted.mfa_code("made-up-session", &totp(&secret, 0)).await;
    page_error(&response, "Invalid session for the user.");
    // A wrong code leaves the page, and its secret key, for another try.
    let response = hosted.mfa_code(&session, &wrong_totp(&secret)).await;
    page_error(&response, "Code mismatch");
    assert!(response.body_string().contains(&secret));

    let response = hosted.mfa_code(&session, &totp(&secret, 0)).await;
    hosted.signed_in(&response);
    let tokens = hosted.tokens_from(&response).await;
    assert_eq!(jwt_claims(&tokens["id_token"])["cognito:username"], "alice");
    assert_eq!(
        hosted.admin_get_user("alice").await["UserMFASettingList"],
        json!(["SOFTWARE_TOKEN_MFA"])
    );

    // The spent session is of no further use.
    let response = hosted.mfa_code(&session, &totp(&secret, 0)).await;
    page_error(&response, "Invalid session for the user.");

    // From now on the app's code follows the password.
    let (session, page) = hosted.login_to_mfa("alice").await;
    assert!(
        page.contains("Enter the code from your authenticator app"),
        "{page}"
    );
    assert!(!page.contains(&secret));
    let response = hosted.mfa_code(&session, &wrong_totp(&secret)).await;
    page_error(&response, "Invalid code received for user");
    assert!(response.body_string().contains("Verify your identity"));
    let response = hosted.mfa_code(&session, &totp(&secret, 0)).await;
    hosted.signed_in(&response);

    // Three wrong codes end the session; the user starts over.
    let (session, _) = hosted.login_to_mfa("alice").await;
    for _ in 0..3 {
        let response = hosted.mfa_code(&session, &wrong_totp(&secret)).await;
        page_error(&response, "Invalid code received for user");
    }
    let response = hosted.mfa_code(&session, &totp(&secret, 0)).await;
    page_error(&response, "Invalid session for the user.");
    assert!(response.body_string().contains("action=\"/login\""));
}

#[tokio::test]
async fn test_sent_codes_and_the_choice_between_factors() {
    let hosted = Hosted::new(json!({})).await;
    hosted
        .set_pool_mfa(json!({
            "MfaConfiguration": "OPTIONAL",
            "SoftwareTokenMfaConfiguration": {"Enabled": true},
            "SmsMfaConfiguration": {
                "SmsConfiguration": {"SnsCallerArn": "arn:aws:iam::000000000000:role/sms"}
            }
        }))
        .await;
    hosted
        .permanent_user(
            "bob",
            json!([{"Name": "phone_number", "Value": "+15555550100"}]),
        )
        .await;

    // MFA is optional and bob has no factor: the password is enough.
    let response = hosted.login("bob", MFA_PASSWORD).await;
    hosted.signed_in(&response);

    let set_mfa = |settings: serde_json::Value| {
        let mut request = json!({"UserPoolId": hosted.pool_id, "Username": "bob"});
        request
            .as_object_mut()
            .unwrap()
            .extend(settings.as_object().unwrap().clone());
        hosted
            .client
            .cognito_request("AdminSetUserMFAPreference", request)
    };
    set_mfa(json!({"SMSMfaSettings": {"Enabled": true}})).await;

    // With SMS as the only factor, the code goes to the phone number.
    let (session, page) = hosted.login_to_mfa("bob").await;
    assert!(page.contains("We sent a code to +*******0100"), "{page}");
    let code = hosted.sent_mfa_code(&session).await;
    let wrong = if code == "000000" { "000001" } else { "000000" };
    let response = hosted.mfa_code(&session, wrong).await;
    page_error(&response, "Invalid code received for user");
    let response = hosted.mfa_code(&session, &code).await;
    hosted.signed_in(&response);

    // The session belongs to the app client that started the sign-in.
    let (session, _) = hosted.login_to_mfa("bob").await;
    let code = hosted.sent_mfa_code(&session).await;
    let other = hosted
        .client
        .cognito_request(
            "CreateUserPoolClient",
            json!({
                "UserPoolId": hosted.pool_id,
                "ClientName": "other-client",
                "AllowedOAuthFlowsUserPoolClient": true,
                "AllowedOAuthFlows": ["code"],
                "AllowedOAuthScopes": ["openid"],
                "CallbackURLs": [CALLBACK]
            }),
        )
        .await;
    let response = hosted
        .client
        .post_form(
            "/mfa",
            &[
                ("response_type", "code"),
                (
                    "client_id",
                    other["UserPoolClient"]["ClientId"].as_str().unwrap(),
                ),
                ("redirect_uri", CALLBACK),
                ("session", &session),
                ("code", &code),
            ],
        )
        .await;
    page_error(&response, "Invalid session for the user.");
    let response = hosted.mfa_code(&session, &code).await;
    hosted.signed_in(&response);

    // A second factor and no preference: the user chooses.
    hosted
        .permanent_user(
            "carol",
            json!([
                {"Name": "phone_number", "Value": "+15555550111"},
                {"Name": "email", "Value": "carol@example.com"},
                {"Name": "email_verified", "Value": "true"}
            ]),
        )
        .await;
    hosted
        .set_pool_mfa(json!({
            "EmailMfaConfiguration": {"Message": "Your code is {####}", "Subject": "Code"}
        }))
        .await;
    hosted
        .client
        .cognito_request(
            "AdminSetUserMFAPreference",
            json!({
                "UserPoolId": hosted.pool_id,
                "Username": "carol",
                "SMSMfaSettings": {"Enabled": true},
                "EmailMfaSettings": {"Enabled": true}
            }),
        )
        .await;
    let (session, page) = hosted.login_to_mfa("carol").await;
    assert!(page.contains("Choose a verification method"), "{page}");
    assert!(page.contains("value=\"SMS_MFA\""));
    assert!(page.contains("value=\"EMAIL_OTP\""));
    assert!(!page.contains("value=\"SOFTWARE_TOKEN_MFA\""));

    let response = hosted
        .post(
            "/mfa",
            &[("session", &session), ("answer", "SOFTWARE_TOKEN_MFA")],
        )
        .await;
    page_error(
        &response,
        "Invalid ANSWER SOFTWARE_TOKEN_MFA for SELECT_MFA_TYPE",
    );
    let response = hosted
        .post("/mfa", &[("session", &session), ("answer", "EMAIL_OTP")])
        .await;
    let (session, page) = hosted.mfa_page(&response).await;
    assert!(page.contains("We sent a code to c***@e***"), "{page}");
    let code = hosted.sent_mfa_code(&session).await;
    assert_eq!(code.len(), 8);
    let response = hosted.mfa_code(&session, &code).await;
    hosted.signed_in(&response);
}

#[tokio::test]
async fn test_mfa_follows_a_new_password_and_needs_no_client_secret() {
    let hosted = Hosted::new(json!({})).await;
    hosted
        .set_pool_mfa(json!({
            "MfaConfiguration": "ON",
            "SoftwareTokenMfaConfiguration": {"Enabled": true}
        }))
        .await;
    hosted
        .client
        .cognito_request(
            "AdminCreateUser",
            json!({
                "UserPoolId": hosted.pool_id,
                "Username": "dave",
                "TemporaryPassword": "TempPass123!",
                "MessageAction": "SUPPRESS"
            }),
        )
        .await;

    // Temporary password, then the new one, then MFA.
    let response = hosted.login("dave", "TempPass123!").await;
    assert!(location(&response).starts_with("/new-password?"));
    let session = location_query(&response)["session"].clone();
    let response = hosted
        .new_password(&session, MFA_PASSWORD, MFA_PASSWORD)
        .await;
    let (session, page) = hosted.mfa_page(&response).await;
    assert!(page.contains("Set up an authenticator app"), "{page}");
    let (_, secret) = hosted
        .client
        .storage()
        .get_software_token_session(&session)
        .await
        .unwrap();
    let response = hosted.mfa_code(&session, &totp(&secret, 0)).await;
    hosted.signed_in(&response);

    // The browser never holds a client secret, so the pages of a
    // confidential app client answer the challenge without its hash.
    let confidential = hosted
        .client
        .cognito_request(
            "CreateUserPoolClient",
            json!({
                "UserPoolId": hosted.pool_id,
                "ClientName": "confidential-client",
                "GenerateSecret": true,
                "AllowedOAuthFlowsUserPoolClient": true,
                "AllowedOAuthFlows": ["code"],
                "AllowedOAuthScopes": ["openid"],
                "CallbackURLs": [CALLBACK]
            }),
        )
        .await;
    let client_id = confidential["UserPoolClient"]["ClientId"].as_str().unwrap();
    let request = [
        ("response_type", "code"),
        ("client_id", client_id),
        ("redirect_uri", CALLBACK),
    ];
    let mut form = request.to_vec();
    form.extend([("username", "dave"), ("password", MFA_PASSWORD)]);
    let response = hosted.client.post_form("/login", &form).await;
    let session = location_query(&response)["session"].clone();
    assert!(location(&response).starts_with("/mfa?"));
    let code = totp(&secret, 0);
    let mut form = request.to_vec();
    form.extend([("session", session.as_str()), ("code", code.as_str())]);
    let response = hosted.client.post_form("/mfa", &form).await;
    hosted.signed_in(&response);
}

#[tokio::test]
async fn test_required_email_mfa_sends_a_code_to_the_users_address() {
    let hosted = Hosted::new(json!({})).await;
    hosted
        .set_pool_mfa(json!({
            "MfaConfiguration": "ON",
            "EmailMfaConfiguration": {"Message": "Your code is {####}", "Subject": "Code"}
        }))
        .await;
    hosted
        .permanent_user(
            "erin",
            json!([
                {"Name": "email", "Value": "erin@example.com"},
                {"Name": "email_verified", "Value": "true"}
            ]),
        )
        .await;

    // An email address is all that email MFA needs; there is nothing to
    // set up first.
    let (session, page) = hosted.login_to_mfa("erin").await;
    assert!(page.contains("We sent a code to e***@e***"), "{page}");
    let response = hosted
        .mfa_code(&session, &hosted.sent_mfa_code(&session).await)
        .await;
    hosted.signed_in(&response);
}

#[tokio::test]
async fn test_challenge_sessions_are_answered_where_they_were_issued() {
    let hosted = Hosted::new(json!({
        "Policies": {"SignInPolicy": {"AllowedFirstAuthFactors": ["PASSWORD", "EMAIL_OTP"]}}
    }))
    .await;
    hosted
        .set_pool_mfa(json!({
            "MfaConfiguration": "OPTIONAL",
            "SmsMfaConfiguration": {
                "SmsConfiguration": {"SnsCallerArn": "arn:aws:iam::000000000000:role/sms"}
            }
        }))
        .await;
    // An app client for both the API and the pages.
    let app_client = hosted
        .client
        .cognito_request(
            "CreateUserPoolClient",
            json!({
                "UserPoolId": hosted.pool_id,
                "ClientName": "both",
                "ExplicitAuthFlows": [
                    "ALLOW_USER_PASSWORD_AUTH",
                    "ALLOW_USER_AUTH",
                    "ALLOW_REFRESH_TOKEN_AUTH"
                ],
                "AllowedOAuthFlowsUserPoolClient": true,
                "AllowedOAuthFlows": ["code"],
                "AllowedOAuthScopes": ["openid"],
                "CallbackURLs": [CALLBACK]
            }),
        )
        .await;
    let client_id = app_client["UserPoolClient"]["ClientId"].as_str().unwrap();
    let http = &hosted.client;
    let post = |path: &'static str, fields: Vec<(&'static str, String)>| {
        let mut form = vec![
            ("response_type", "code".to_string()),
            ("client_id", client_id.to_string()),
            ("redirect_uri", CALLBACK.to_string()),
        ];
        form.extend(fields);
        async move {
            let form: Vec<(&str, &str)> = form
                .iter()
                .map(|(name, value)| (*name, value.as_str()))
                .collect();
            http.post_form(path, &form).await
        }
    };
    let initiate = |flow: &'static str, parameters: serde_json::Value| {
        hosted.client.cognito_request(
            "InitiateAuth",
            json!({"ClientId": client_id, "AuthFlow": flow, "AuthParameters": parameters}),
        )
    };

    hosted
        .permanent_user(
            "frank",
            json!([
                {"Name": "email", "Value": "frank@example.com"},
                {"Name": "email_verified", "Value": "true"}
            ]),
        )
        .await;

    // A one-time code that signs in through the API without a password is
    // not a way to an authorization code.
    let challenge = initiate(
        "USER_AUTH",
        json!({"USERNAME": "frank", "PREFERRED_CHALLENGE": "EMAIL_OTP"}),
    )
    .await;
    assert_eq!(challenge["ChallengeName"], "EMAIL_OTP");
    let session = challenge["Session"].as_str().unwrap().to_string();
    let code = hosted.sent_mfa_code(&session).await;
    let response = post("/mfa", vec![("session", session), ("code", code)]).await;
    page_error(&response, "Invalid session for the user.");

    // Nor does the page finish the MFA challenge of an API sign-in.
    hosted
        .permanent_user(
            "grace",
            json!([{"Name": "phone_number", "Value": "+15555550122"}]),
        )
        .await;
    hosted
        .client
        .cognito_request(
            "AdminSetUserMFAPreference",
            json!({
                "UserPoolId": hosted.pool_id,
                "Username": "grace",
                "SMSMfaSettings": {"Enabled": true}
            }),
        )
        .await;
    let challenge = initiate(
        "USER_PASSWORD_AUTH",
        json!({"USERNAME": "grace", "PASSWORD": MFA_PASSWORD}),
    )
    .await;
    assert_eq!(challenge["ChallengeName"], "SMS_MFA");
    let api_session = challenge["Session"].as_str().unwrap().to_string();
    let code = hosted.sent_mfa_code(&api_session).await;
    let response = post(
        "/mfa",
        vec![("session", api_session.clone()), ("code", code.clone())],
    )
    .await;
    page_error(&response, "Invalid session for the user.");

    // The other way around, a session of the pages is no use to the API,
    // which would answer it with tokens of its own scope.
    let response = post(
        "/login",
        vec![
            ("username", "grace".to_string()),
            ("password", MFA_PASSWORD.to_string()),
        ],
    )
    .await;
    assert!(location(&response).starts_with("/mfa?"));
    let page_session = location_query(&response)["session"].clone();
    let page_code = hosted.sent_mfa_code(&page_session).await;
    let (status, body) = hosted
        .client
        .request(
            "RespondToAuthChallenge",
            json!({
                "ClientId": client_id,
                "ChallengeName": "SMS_MFA",
                "Session": page_session,
                "ChallengeResponses": {"USERNAME": "grace", "SMS_MFA_CODE": page_code}
            }),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["message"], "Invalid session for the user.");

    // Each is still good where it came from.
    let response = post("/mfa", vec![("session", page_session), ("code", page_code)]).await;
    hosted.signed_in(&response);
    let tokens = hosted
        .client
        .cognito_request(
            "RespondToAuthChallenge",
            json!({
                "ClientId": client_id,
                "ChallengeName": "SMS_MFA",
                "Session": api_session,
                "ChallengeResponses": {"USERNAME": "grace", "SMS_MFA_CODE": code}
            }),
        )
        .await;
    assert!(tokens["AuthenticationResult"]["AccessToken"].is_string());
}

#[tokio::test]
async fn test_mfa_page_is_not_cached_and_its_session_expires() {
    let hosted = Hosted::new(json!({})).await;
    hosted
        .set_pool_mfa(json!({
            "MfaConfiguration": "ON",
            "EmailMfaConfiguration": {"Message": "Your code is {####}", "Subject": "Code"}
        }))
        .await;
    hosted
        .permanent_user(
            "heidi",
            json!([
                {"Name": "email", "Value": "heidi@example.com"},
                {"Name": "email_verified", "Value": "true"}
            ]),
        )
        .await;

    let response = hosted.login("heidi", MFA_PASSWORD).await;
    let next = location(&response);
    let session = location_query(&response)["session"].clone();
    let page = hosted.client.get(&next).await;
    assert_eq!(page.headers()["cache-control"], "no-store");

    // What the page reflects is escaped.
    let response = hosted
        .post(
            "/mfa",
            &[
                ("session", "\"><script>alert(1)</script>"),
                ("code", "000000"),
            ],
        )
        .await;
    assert!(!response.body_string().contains("<script>alert(1)"));

    let code = hosted.sent_mfa_code(&session).await;
    hosted
        .client
        .storage()
        .update_auth_challenge_session(&session, |pending| {
            pending.expires_at = chrono::Utc::now() - chrono::Duration::seconds(1);
        })
        .await
        .unwrap();
    let page = hosted.client.get(&next).await;
    page_error(&page, "Invalid session for the user.");
    assert!(page.body_string().contains("action=\"/login\""));
    let response = hosted.mfa_code(&session, &code).await;
    page_error(&response, "Invalid session for the user.");
}
