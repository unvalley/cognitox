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
