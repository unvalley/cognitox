//! Hosted UI - Cognito Managed Login UI emulation
//!
//! Provides web pages for user authentication flows including:
//! - Login
//! - Sign up
//! - Forgot password
//! - Confirmation code entry

use axum::{
    Form,
    extract::{Query, State},
    http::StatusCode,
    response::{Html, IntoResponse, Redirect, Response},
};
use chrono::{Duration, Utc};
use serde::Deserialize;
use tera::{Context, Tera};
use uuid::Uuid;

use crate::{
    action::user::helpers::{
        generate_confirmation_code, hash_password, normalize_confirmation_code, verify_password,
    },
    storage::Storage,
    types::{
        AuthorizationCode, ClientId, ConfirmationCode, ManagedLoginBranding, User, UserPoolId,
        UserStatus,
    },
};

/// Common OAuth parameters passed through the UI flow
#[derive(Debug, Clone, Deserialize)]
pub struct OAuthParams {
    pub response_type: String,
    pub client_id: String,
    pub redirect_uri: String,
    #[serde(default)]
    pub scope: Option<String>,
    #[serde(default)]
    pub state: Option<String>,
    #[serde(default)]
    pub nonce: Option<String>,
    #[serde(default)]
    pub code_challenge: Option<String>,
    #[serde(default)]
    pub code_challenge_method: Option<String>,
}

/// Login form data
#[derive(Debug, Deserialize)]
pub struct LoginForm {
    pub username: String,
    pub password: String,
    #[serde(flatten)]
    pub oauth: OAuthParams,
}

/// Signup form data
#[derive(Debug, Deserialize)]
pub struct SignupForm {
    pub username: String,
    pub email: String,
    pub password: String,
    pub password_confirm: String,
    #[serde(flatten)]
    pub oauth: OAuthParams,
}

/// Confirmation form data
#[derive(Debug, Deserialize)]
pub struct ConfirmForm {
    pub username: String,
    pub code: String,
    #[serde(flatten)]
    pub oauth: OAuthParams,
}

/// Forgot password form data
#[derive(Debug, Deserialize)]
pub struct ForgotPasswordForm {
    pub username: String,
    #[serde(flatten)]
    pub oauth: OAuthParams,
}

/// Reset password form data
#[derive(Debug, Deserialize)]
pub struct ResetPasswordForm {
    pub username: String,
    pub code: String,
    pub new_password: String,
    pub new_password_confirm: String,
    #[serde(flatten)]
    pub oauth: OAuthParams,
}

/// Branding context for templates
#[derive(Debug, Default)]
struct BrandingContext {
    page_title: String,
    sign_in_header: String,
    sign_in_subheader: String,
    background_color: String,
    primary_color: String,
    text_color: String,
    button_color: String,
    button_text_color: String,
    logo_url: Option<String>,
    css_url: Option<String>,
}

fn default_branding_context() -> BrandingContext {
    BrandingContext {
        page_title: "Sign In".to_string(),
        sign_in_header: "Welcome".to_string(),
        sign_in_subheader: "Sign in to continue".to_string(),
        background_color: "#f5f5f5".to_string(),
        primary_color: "#007bff".to_string(),
        text_color: "#333333".to_string(),
        button_color: "#007bff".to_string(),
        button_text_color: "#ffffff".to_string(),
        logo_url: None,
        css_url: None,
    }
}

fn apply_branding(ctx: &mut BrandingContext, branding: &ManagedLoginBranding) {
    if let Some(settings) = &branding.settings {
        if let Some(title) = &settings.page_title {
            ctx.page_title = title.clone();
        }
        if let Some(header) = &settings.sign_in_header {
            ctx.sign_in_header = header.clone();
        }
        if let Some(subheader) = &settings.sign_in_subheader {
            ctx.sign_in_subheader = subheader.clone();
        }
        if let Some(colors) = &settings.colors {
            if let Some(c) = &colors.background_color {
                ctx.background_color = c.clone();
            }
            if let Some(c) = &colors.primary_color {
                ctx.primary_color = c.clone();
            }
            if let Some(c) = &colors.text_color {
                ctx.text_color = c.clone();
            }
            if let Some(c) = &colors.button_color {
                ctx.button_color = c.clone();
            }
            if let Some(c) = &colors.button_text_color {
                ctx.button_text_color = c.clone();
            }
        }
    }
    if let Some(assets) = &branding.assets {
        ctx.logo_url = assets.logo_url.clone();
        ctx.css_url = assets.css_url.clone();
    }
}

/// Get branding for a client or user pool
async fn get_branding(storage: &Storage, client_id: &str) -> BrandingContext {
    let mut ctx = default_branding_context();

    // Parse client_id string to ClientId
    let parsed_client_id = match ClientId::new(client_id) {
        Ok(id) => id,
        Err(_) => return ctx, // Return default branding if client_id is invalid
    };

    let branding = if let Some(client_branding) = storage
        .get_managed_login_branding_by_client(&parsed_client_id)
        .await
    {
        Some(client_branding)
    } else if let Some(client) = storage.get_user_pool_client(&parsed_client_id).await {
        storage
            .get_managed_login_branding_by_user_pool(&client.user_pool_id)
            .await
    } else {
        None
    };

    if let Some(branding) = branding {
        apply_branding(&mut ctx, &branding);
    }

    ctx
}

/// Create Tera context with branding and OAuth params
fn create_template_context(branding: &BrandingContext, oauth: &OAuthParams) -> Context {
    let mut ctx = Context::new();

    // Branding
    ctx.insert("page_title", &branding.page_title);
    ctx.insert("sign_in_header", &branding.sign_in_header);
    ctx.insert("sign_in_subheader", &branding.sign_in_subheader);
    ctx.insert("background_color", &branding.background_color);
    ctx.insert("primary_color", &branding.primary_color);
    ctx.insert("text_color", &branding.text_color);
    ctx.insert("button_color", &branding.button_color);
    ctx.insert("button_text_color", &branding.button_text_color);
    ctx.insert("logo_url", &branding.logo_url);
    ctx.insert("css_url", &branding.css_url);

    // OAuth params
    ctx.insert("response_type", &oauth.response_type);
    ctx.insert("client_id", &oauth.client_id);
    ctx.insert("redirect_uri", &oauth.redirect_uri);
    ctx.insert("scope", &oauth.scope.as_deref().unwrap_or("openid"));
    ctx.insert("state", &oauth.state);
    ctx.insert("nonce", &oauth.nonce);
    ctx.insert("code_challenge", &oauth.code_challenge);
    ctx.insert("code_challenge_method", &oauth.code_challenge_method);

    ctx
}

/// Base HTML template
const BASE_TEMPLATE: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ page_title }}</title>
    {% if css_url %}
    <link rel="stylesheet" href="{{ css_url }}">
    {% endif %}
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background-color: {{ background_color }};
            color: {{ text_color }};
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
            padding: 20px;
        }
        .container {
            background: white;
            border-radius: 8px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            padding: 40px;
            width: 100%;
            max-width: 400px;
        }
        .logo {
            text-align: center;
            margin-bottom: 24px;
        }
        .logo img {
            max-width: 150px;
            max-height: 60px;
        }
        h1 {
            font-size: 24px;
            font-weight: 600;
            text-align: center;
            margin-bottom: 8px;
            color: {{ text_color }};
        }
        .subheader {
            text-align: center;
            color: #666;
            margin-bottom: 24px;
            font-size: 14px;
        }
        .form-group {
            margin-bottom: 16px;
        }
        label {
            display: block;
            margin-bottom: 6px;
            font-size: 14px;
            font-weight: 500;
            color: {{ text_color }};
        }
        input[type="text"],
        input[type="email"],
        input[type="password"] {
            width: 100%;
            padding: 12px;
            border: 1px solid #ddd;
            border-radius: 4px;
            font-size: 16px;
            transition: border-color 0.2s;
        }
        input:focus {
            outline: none;
            border-color: {{ primary_color }};
        }
        .btn {
            width: 100%;
            padding: 12px;
            border: none;
            border-radius: 4px;
            font-size: 16px;
            font-weight: 500;
            cursor: pointer;
            transition: opacity 0.2s;
        }
        .btn:hover {
            opacity: 0.9;
        }
        .btn-primary {
            background-color: {{ button_color }};
            color: {{ button_text_color }};
        }
        .btn-link {
            background: none;
            color: {{ primary_color }};
            text-decoration: underline;
            padding: 8px;
            font-size: 14px;
        }
        .error {
            background-color: #fee;
            border: 1px solid #fcc;
            color: #c00;
            padding: 12px;
            border-radius: 4px;
            margin-bottom: 16px;
            font-size: 14px;
        }
        .success {
            background-color: #efe;
            border: 1px solid #cfc;
            color: #060;
            padding: 12px;
            border-radius: 4px;
            margin-bottom: 16px;
            font-size: 14px;
        }
        .links {
            margin-top: 24px;
            text-align: center;
        }
        .links a {
            color: {{ primary_color }};
            text-decoration: none;
            font-size: 14px;
        }
        .links a:hover {
            text-decoration: underline;
        }
        .divider {
            margin: 16px 0;
            text-align: center;
            color: #999;
            font-size: 12px;
        }
        input[type="hidden"] { display: none; }
    </style>
</head>
<body>
    <div class="container">
        {% if logo_url %}
        <div class="logo">
            <img src="{{ logo_url }}" alt="Logo">
        </div>
        {% endif %}
        {% block content %}{% endblock %}
    </div>
</body>
</html>"#;

/// Login page template
const LOGIN_TEMPLATE: &str = r#"{% extends "base" %}
{% block content %}
<h1>{{ sign_in_header }}</h1>
<p class="subheader">{{ sign_in_subheader }}</p>

{% if error %}
<div class="error">{{ error }}</div>
{% endif %}

<form method="POST" action="/login">
    <input type="hidden" name="response_type" value="{{ response_type }}">
    <input type="hidden" name="client_id" value="{{ client_id }}">
    <input type="hidden" name="redirect_uri" value="{{ redirect_uri }}">
    <input type="hidden" name="scope" value="{{ scope }}">
    {% if state %}<input type="hidden" name="state" value="{{ state }}">{% endif %}
    {% if nonce %}<input type="hidden" name="nonce" value="{{ nonce }}">{% endif %}
    {% if code_challenge %}<input type="hidden" name="code_challenge" value="{{ code_challenge }}">{% endif %}
    {% if code_challenge_method %}<input type="hidden" name="code_challenge_method" value="{{ code_challenge_method }}">{% endif %}

    <div class="form-group">
        <label for="username">Username</label>
        <input type="text" id="username" name="username" required autofocus>
    </div>

    <div class="form-group">
        <label for="password">Password</label>
        <input type="password" id="password" name="password" required>
    </div>

    <button type="submit" class="btn btn-primary">Sign In</button>
</form>

<div class="links">
    <a href="/forgot-password?{{ oauth_query }}">Forgot password?</a>
    <div class="divider">or</div>
    <a href="/signup?{{ oauth_query }}">Create an account</a>
</div>
{% endblock %}"#;

/// Signup page template
const SIGNUP_TEMPLATE: &str = r#"{% extends "base" %}
{% block content %}
<h1>Create Account</h1>
<p class="subheader">Sign up for a new account</p>

{% if error %}
<div class="error">{{ error }}</div>
{% endif %}

<form method="POST" action="/signup">
    <input type="hidden" name="response_type" value="{{ response_type }}">
    <input type="hidden" name="client_id" value="{{ client_id }}">
    <input type="hidden" name="redirect_uri" value="{{ redirect_uri }}">
    <input type="hidden" name="scope" value="{{ scope }}">
    {% if state %}<input type="hidden" name="state" value="{{ state }}">{% endif %}
    {% if nonce %}<input type="hidden" name="nonce" value="{{ nonce }}">{% endif %}
    {% if code_challenge %}<input type="hidden" name="code_challenge" value="{{ code_challenge }}">{% endif %}
    {% if code_challenge_method %}<input type="hidden" name="code_challenge_method" value="{{ code_challenge_method }}">{% endif %}

    <div class="form-group">
        <label for="username">Username</label>
        <input type="text" id="username" name="username" required autofocus>
    </div>

    <div class="form-group">
        <label for="email">Email</label>
        <input type="email" id="email" name="email" required>
    </div>

    <div class="form-group">
        <label for="password">Password</label>
        <input type="password" id="password" name="password" required minlength="8">
    </div>

    <div class="form-group">
        <label for="password_confirm">Confirm Password</label>
        <input type="password" id="password_confirm" name="password_confirm" required minlength="8">
    </div>

    <button type="submit" class="btn btn-primary">Sign Up</button>
</form>

<div class="links">
    <a href="/login?{{ oauth_query }}">Already have an account? Sign in</a>
</div>
{% endblock %}"#;

/// Confirmation page template
const CONFIRM_TEMPLATE: &str = r#"{% extends "base" %}
{% block content %}
<h1>Confirm Your Account</h1>
<p class="subheader">Enter the confirmation code sent to your email</p>

{% if error %}
<div class="error">{{ error }}</div>
{% endif %}

{% if success %}
<div class="success">{{ success }}</div>
{% endif %}

<form method="POST" action="/confirm">
    <input type="hidden" name="response_type" value="{{ response_type }}">
    <input type="hidden" name="client_id" value="{{ client_id }}">
    <input type="hidden" name="redirect_uri" value="{{ redirect_uri }}">
    <input type="hidden" name="scope" value="{{ scope }}">
    {% if state %}<input type="hidden" name="state" value="{{ state }}">{% endif %}
    {% if nonce %}<input type="hidden" name="nonce" value="{{ nonce }}">{% endif %}
    {% if code_challenge %}<input type="hidden" name="code_challenge" value="{{ code_challenge }}">{% endif %}
    {% if code_challenge_method %}<input type="hidden" name="code_challenge_method" value="{{ code_challenge_method }}">{% endif %}
    <input type="hidden" name="username" value="{{ username }}">

    <div class="form-group">
        <label for="code">Confirmation Code</label>
        <input type="text" id="code" name="code" required autofocus placeholder="Enter 6-digit code">
    </div>

    <button type="submit" class="btn btn-primary">Confirm</button>
</form>

<div class="links">
    <a href="/login?{{ oauth_query }}">Back to Sign In</a>
</div>
{% endblock %}"#;

/// Forgot password page template
const FORGOT_PASSWORD_TEMPLATE: &str = r#"{% extends "base" %}
{% block content %}
<h1>Reset Password</h1>
<p class="subheader">Enter your username to receive a reset code</p>

{% if error %}
<div class="error">{{ error }}</div>
{% endif %}

<form method="POST" action="/forgot-password">
    <input type="hidden" name="response_type" value="{{ response_type }}">
    <input type="hidden" name="client_id" value="{{ client_id }}">
    <input type="hidden" name="redirect_uri" value="{{ redirect_uri }}">
    <input type="hidden" name="scope" value="{{ scope }}">
    {% if state %}<input type="hidden" name="state" value="{{ state }}">{% endif %}
    {% if nonce %}<input type="hidden" name="nonce" value="{{ nonce }}">{% endif %}
    {% if code_challenge %}<input type="hidden" name="code_challenge" value="{{ code_challenge }}">{% endif %}
    {% if code_challenge_method %}<input type="hidden" name="code_challenge_method" value="{{ code_challenge_method }}">{% endif %}

    <div class="form-group">
        <label for="username">Username</label>
        <input type="text" id="username" name="username" required autofocus>
    </div>

    <button type="submit" class="btn btn-primary">Send Reset Code</button>
</form>

<div class="links">
    <a href="/login?{{ oauth_query }}">Back to Sign In</a>
</div>
{% endblock %}"#;

/// Reset password page template
const RESET_PASSWORD_TEMPLATE: &str = r#"{% extends "base" %}
{% block content %}
<h1>Set New Password</h1>
<p class="subheader">Enter the code sent to your email and your new password</p>

{% if error %}
<div class="error">{{ error }}</div>
{% endif %}

<form method="POST" action="/reset-password">
    <input type="hidden" name="response_type" value="{{ response_type }}">
    <input type="hidden" name="client_id" value="{{ client_id }}">
    <input type="hidden" name="redirect_uri" value="{{ redirect_uri }}">
    <input type="hidden" name="scope" value="{{ scope }}">
    {% if state %}<input type="hidden" name="state" value="{{ state }}">{% endif %}
    {% if nonce %}<input type="hidden" name="nonce" value="{{ nonce }}">{% endif %}
    {% if code_challenge %}<input type="hidden" name="code_challenge" value="{{ code_challenge }}">{% endif %}
    {% if code_challenge_method %}<input type="hidden" name="code_challenge_method" value="{{ code_challenge_method }}">{% endif %}
    <input type="hidden" name="username" value="{{ username }}">

    <div class="form-group">
        <label for="code">Reset Code</label>
        <input type="text" id="code" name="code" required autofocus placeholder="Enter 6-digit code">
    </div>

    <div class="form-group">
        <label for="new_password">New Password</label>
        <input type="password" id="new_password" name="new_password" required minlength="8">
    </div>

    <div class="form-group">
        <label for="new_password_confirm">Confirm New Password</label>
        <input type="password" id="new_password_confirm" name="new_password_confirm" required minlength="8">
    </div>

    <button type="submit" class="btn btn-primary">Reset Password</button>
</form>

<div class="links">
    <a href="/login?{{ oauth_query }}">Back to Sign In</a>
</div>
{% endblock %}"#;

/// Initialize Tera templates
fn create_tera() -> Tera {
    let mut tera = Tera::default();
    tera.add_raw_template("base", BASE_TEMPLATE)
        .expect("invalid base template");
    tera.add_raw_template("login", LOGIN_TEMPLATE)
        .expect("invalid login template");
    tera.add_raw_template("signup", SIGNUP_TEMPLATE)
        .expect("invalid signup template");
    tera.add_raw_template("confirm", CONFIRM_TEMPLATE)
        .expect("invalid confirm template");
    tera.add_raw_template("forgot_password", FORGOT_PASSWORD_TEMPLATE)
        .expect("invalid forgot_password template");
    tera.add_raw_template("reset_password", RESET_PASSWORD_TEMPLATE)
        .expect("invalid reset_password template");
    tera
}

async fn get_user_by_username_or_email(
    storage: &Storage,
    user_pool_id: &UserPoolId,
    username_or_email: &str,
) -> Option<User> {
    if let Some(user) = storage
        .get_user_by_username(user_pool_id, username_or_email)
        .await
    {
        return Some(user);
    }

    storage
        .list_users(user_pool_id)
        .await
        .into_iter()
        .find(|user| user.email.as_deref() == Some(username_or_email))
}

/// Build OAuth query string for links
fn build_oauth_query(oauth: &OAuthParams) -> String {
    let mut params = vec![
        format!(
            "response_type={}",
            urlencoding::encode(&oauth.response_type)
        ),
        format!("client_id={}", urlencoding::encode(&oauth.client_id)),
        format!("redirect_uri={}", urlencoding::encode(&oauth.redirect_uri)),
        format!(
            "scope={}",
            urlencoding::encode(oauth.scope.as_deref().unwrap_or("openid"))
        ),
    ];

    if let Some(state) = &oauth.state {
        params.push(format!("state={}", urlencoding::encode(state)));
    }
    if let Some(nonce) = &oauth.nonce {
        params.push(format!("nonce={}", urlencoding::encode(nonce)));
    }
    if let Some(challenge) = &oauth.code_challenge {
        params.push(format!("code_challenge={}", urlencoding::encode(challenge)));
    }
    if let Some(method) = &oauth.code_challenge_method {
        params.push(format!(
            "code_challenge_method={}",
            urlencoding::encode(method)
        ));
    }

    params.join("&")
}

/// Render a template with error handling
fn render_template(tera: &Tera, template: &str, ctx: &Context) -> Response {
    match tera.render(template, ctx) {
        Ok(html) => Html(html).into_response(),
        Err(e) => {
            tracing::error!("Template error: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Template rendering error",
            )
                .into_response()
        }
    }
}

// ==================== Route Handlers ====================

/// GET /login - Login page
pub async fn login_page(
    State(storage): State<Storage>,
    Query(oauth): Query<OAuthParams>,
) -> Response {
    let branding = get_branding(&storage, &oauth.client_id).await;
    let tera = create_tera();
    let mut ctx = create_template_context(&branding, &oauth);
    ctx.insert("oauth_query", &build_oauth_query(&oauth));
    ctx.insert("error", &None::<String>);

    render_template(&tera, "login", &ctx)
}

/// POST /login - Process login
pub async fn login_submit(State(storage): State<Storage>, Form(form): Form<LoginForm>) -> Response {
    let branding = get_branding(&storage, &form.oauth.client_id).await;
    let tera = create_tera();

    // Parse client_id
    let parsed_client_id = match ClientId::new(&form.oauth.client_id) {
        Ok(id) => id,
        Err(_) => {
            let mut ctx = create_template_context(&branding, &form.oauth);
            ctx.insert("oauth_query", &build_oauth_query(&form.oauth));
            ctx.insert("error", &Some("Invalid client".to_string()));
            return render_template(&tera, "login", &ctx);
        }
    };

    // Validate client
    let client = match storage.get_user_pool_client(&parsed_client_id).await {
        Some(c) => c,
        None => {
            let mut ctx = create_template_context(&branding, &form.oauth);
            ctx.insert("oauth_query", &build_oauth_query(&form.oauth));
            ctx.insert("error", &Some("Invalid client".to_string()));
            return render_template(&tera, "login", &ctx);
        }
    };

    // Find user
    let user =
        match get_user_by_username_or_email(&storage, &client.user_pool_id, &form.username).await {
            Some(u) => u,
            None => {
                let mut ctx = create_template_context(&branding, &form.oauth);
                ctx.insert("oauth_query", &build_oauth_query(&form.oauth));
                ctx.insert("error", &Some("Invalid username or password".to_string()));
                return render_template(&tera, "login", &ctx);
            }
        };

    // Check if user is enabled
    if !user.enabled {
        let mut ctx = create_template_context(&branding, &form.oauth);
        ctx.insert("oauth_query", &build_oauth_query(&form.oauth));
        ctx.insert("error", &Some("This account has been disabled".to_string()));
        return render_template(&tera, "login", &ctx);
    }

    // Check user status
    if user.user_status != UserStatus::Confirmed {
        // Redirect to confirmation page
        let query = build_oauth_query(&form.oauth);
        let redirect_url = format!(
            "/confirm?{}&username={}",
            query,
            urlencoding::encode(&form.username)
        );
        return Redirect::to(&redirect_url).into_response();
    }

    // Verify password
    if !verify_password(&form.password, &user.password_hash) {
        let mut ctx = create_template_context(&branding, &form.oauth);
        ctx.insert("oauth_query", &build_oauth_query(&form.oauth));
        ctx.insert("error", &Some("Invalid username or password".to_string()));
        return render_template(&tera, "login", &ctx);
    }

    // Generate authorization code and redirect
    let scopes: Vec<String> = form
        .oauth
        .scope
        .as_deref()
        .unwrap_or("openid")
        .split_whitespace()
        .map(String::from)
        .collect();

    let code = Uuid::new_v4().to_string();
    let auth_code = AuthorizationCode {
        code: code.clone(),
        user_id: user.id,
        client_id: parsed_client_id,
        redirect_uri: form.oauth.redirect_uri.clone(),
        scope: scopes,
        nonce: form.oauth.nonce.clone(),
        code_challenge: form.oauth.code_challenge.clone(),
        code_challenge_method: form.oauth.code_challenge_method.clone(),
        expires_at: Utc::now() + Duration::minutes(5),
    };
    storage.save_authorization_code(auth_code).await;

    // Build redirect URL
    let mut redirect_url = form.oauth.redirect_uri.clone();
    redirect_url.push_str(if redirect_url.contains('?') { "&" } else { "?" });
    redirect_url.push_str(&format!("code={}", code));
    if let Some(state) = &form.oauth.state {
        redirect_url.push_str(&format!("&state={}", urlencoding::encode(state)));
    }

    Redirect::to(&redirect_url).into_response()
}

/// GET /signup - Signup page
pub async fn signup_page(
    State(storage): State<Storage>,
    Query(oauth): Query<OAuthParams>,
) -> Response {
    let branding = get_branding(&storage, &oauth.client_id).await;
    let tera = create_tera();
    let mut ctx = create_template_context(&branding, &oauth);
    ctx.insert("oauth_query", &build_oauth_query(&oauth));
    ctx.insert("error", &None::<String>);

    render_template(&tera, "signup", &ctx)
}

/// POST /signup - Process signup
pub async fn signup_submit(
    State(storage): State<Storage>,
    Form(form): Form<SignupForm>,
) -> Response {
    let branding = get_branding(&storage, &form.oauth.client_id).await;
    let tera = create_tera();

    // Parse client_id
    let parsed_client_id = match ClientId::new(&form.oauth.client_id) {
        Ok(id) => id,
        Err(_) => {
            let mut ctx = create_template_context(&branding, &form.oauth);
            ctx.insert("oauth_query", &build_oauth_query(&form.oauth));
            ctx.insert("error", &Some("Invalid client".to_string()));
            return render_template(&tera, "signup", &ctx);
        }
    };

    // Validate passwords match
    if form.password != form.password_confirm {
        let mut ctx = create_template_context(&branding, &form.oauth);
        ctx.insert("oauth_query", &build_oauth_query(&form.oauth));
        ctx.insert("error", &Some("Passwords do not match".to_string()));
        return render_template(&tera, "signup", &ctx);
    }

    // Validate client
    let client = match storage.get_user_pool_client(&parsed_client_id).await {
        Some(c) => c,
        None => {
            let mut ctx = create_template_context(&branding, &form.oauth);
            ctx.insert("oauth_query", &build_oauth_query(&form.oauth));
            ctx.insert("error", &Some("Invalid client".to_string()));
            return render_template(&tera, "signup", &ctx);
        }
    };

    // Check if user already exists
    if storage
        .get_user_by_username(&client.user_pool_id, &form.username)
        .await
        .is_some()
    {
        let mut ctx = create_template_context(&branding, &form.oauth);
        ctx.insert("oauth_query", &build_oauth_query(&form.oauth));
        ctx.insert("error", &Some("Username already exists".to_string()));
        return render_template(&tera, "signup", &ctx);
    }

    // Create user
    let now = Utc::now();
    let user_id = Uuid::new_v4();
    let code = generate_confirmation_code();

    let password_hash = match hash_password(&form.password) {
        Ok(hash) => hash,
        Err(e) => {
            tracing::error!("Failed to hash password: {}", e);
            let mut ctx = create_template_context(&branding, &form.oauth);
            ctx.insert("oauth_query", &build_oauth_query(&form.oauth));
            ctx.insert("error", &Some("Internal error".to_string()));
            return render_template(&tera, "signup", &ctx);
        }
    };

    let user = User {
        id: user_id,
        user_pool_id: client.user_pool_id.clone(),
        username: form.username.clone(),
        password_hash,
        email: Some(form.email.clone()),
        phone_number: None,
        user_status: UserStatus::Unconfirmed,
        enabled: true,
        attributes: vec![],
        creation_date: now,
        last_modified_date: now,
    };

    storage.create_user(user).await;

    // Save confirmation code separately
    let confirmation = ConfirmationCode {
        user_id,
        attribute_name: None,
        code: code.clone(),
        expires_at: now + Duration::hours(24),
    };
    storage.save_confirmation_code(confirmation).await;

    // Log confirmation code for development
    tracing::info!(
        "User {} created. Confirmation code: {}",
        form.username,
        code
    );

    // Redirect to confirmation page
    let query = build_oauth_query(&form.oauth);
    let redirect_url = format!(
        "/confirm?{}&username={}",
        query,
        urlencoding::encode(&form.username)
    );
    Redirect::to(&redirect_url).into_response()
}

/// Query params for confirmation page
#[derive(Debug, Deserialize)]
pub struct ConfirmPageQuery {
    pub username: String,
    #[serde(flatten)]
    pub oauth: OAuthParams,
}

/// GET /confirm - Confirmation page
pub async fn confirm_page(
    State(storage): State<Storage>,
    Query(query): Query<ConfirmPageQuery>,
) -> Response {
    let branding = get_branding(&storage, &query.oauth.client_id).await;
    let tera = create_tera();
    let mut ctx = create_template_context(&branding, &query.oauth);
    ctx.insert("oauth_query", &build_oauth_query(&query.oauth));
    ctx.insert("username", &query.username);
    ctx.insert("error", &None::<String>);
    ctx.insert("success", &None::<String>);

    render_template(&tera, "confirm", &ctx)
}

/// POST /confirm - Process confirmation
pub async fn confirm_submit(
    State(storage): State<Storage>,
    Form(form): Form<ConfirmForm>,
) -> Response {
    let branding = get_branding(&storage, &form.oauth.client_id).await;
    let tera = create_tera();

    // Parse client_id
    let parsed_client_id = match ClientId::new(&form.oauth.client_id) {
        Ok(id) => id,
        Err(_) => {
            let mut ctx = create_template_context(&branding, &form.oauth);
            ctx.insert("oauth_query", &build_oauth_query(&form.oauth));
            ctx.insert("username", &form.username);
            ctx.insert("error", &Some("Invalid client".to_string()));
            ctx.insert("success", &None::<String>);
            return render_template(&tera, "confirm", &ctx);
        }
    };

    // Validate client
    let client = match storage.get_user_pool_client(&parsed_client_id).await {
        Some(c) => c,
        None => {
            let mut ctx = create_template_context(&branding, &form.oauth);
            ctx.insert("oauth_query", &build_oauth_query(&form.oauth));
            ctx.insert("username", &form.username);
            ctx.insert("error", &Some("Invalid client".to_string()));
            ctx.insert("success", &None::<String>);
            return render_template(&tera, "confirm", &ctx);
        }
    };

    // Find user
    let user = match storage
        .get_user_by_username(&client.user_pool_id, &form.username)
        .await
    {
        Some(u) => u,
        None => {
            let mut ctx = create_template_context(&branding, &form.oauth);
            ctx.insert("oauth_query", &build_oauth_query(&form.oauth));
            ctx.insert("username", &form.username);
            ctx.insert("error", &Some("User not found".to_string()));
            ctx.insert("success", &None::<String>);
            return render_template(&tera, "confirm", &ctx);
        }
    };

    // Verify confirmation code (normalize to ignore dashes and case)
    let stored_code = storage.get_confirmation_code(&user.id).await;
    let code_valid = stored_code.as_ref().is_some_and(|c| {
        normalize_confirmation_code(&c.code) == normalize_confirmation_code(&form.code)
            && c.expires_at > Utc::now()
    });

    if !code_valid {
        let mut ctx = create_template_context(&branding, &form.oauth);
        ctx.insert("oauth_query", &build_oauth_query(&form.oauth));
        ctx.insert("username", &form.username);
        ctx.insert("error", &Some("Invalid confirmation code".to_string()));
        ctx.insert("success", &None::<String>);
        return render_template(&tera, "confirm", &ctx);
    }

    // Confirm user (this also removes the confirmation code)
    storage.confirm_user(&user.id).await;

    // Redirect to login with success message
    let query = build_oauth_query(&form.oauth);
    let redirect_url = format!("/login?{}", query);
    Redirect::to(&redirect_url).into_response()
}

/// GET /forgot-password - Forgot password page
pub async fn forgot_password_page(
    State(storage): State<Storage>,
    Query(oauth): Query<OAuthParams>,
) -> Response {
    let branding = get_branding(&storage, &oauth.client_id).await;
    let tera = create_tera();
    let mut ctx = create_template_context(&branding, &oauth);
    ctx.insert("oauth_query", &build_oauth_query(&oauth));
    ctx.insert("error", &None::<String>);

    render_template(&tera, "forgot_password", &ctx)
}

/// POST /forgot-password - Process forgot password
pub async fn forgot_password_submit(
    State(storage): State<Storage>,
    Form(form): Form<ForgotPasswordForm>,
) -> Response {
    let branding = get_branding(&storage, &form.oauth.client_id).await;
    let tera = create_tera();

    // Parse client_id
    let parsed_client_id = match ClientId::new(&form.oauth.client_id) {
        Ok(id) => id,
        Err(_) => {
            let mut ctx = create_template_context(&branding, &form.oauth);
            ctx.insert("oauth_query", &build_oauth_query(&form.oauth));
            ctx.insert("error", &Some("Invalid client".to_string()));
            return render_template(&tera, "forgot_password", &ctx);
        }
    };

    // Validate client
    let client = match storage.get_user_pool_client(&parsed_client_id).await {
        Some(c) => c,
        None => {
            let mut ctx = create_template_context(&branding, &form.oauth);
            ctx.insert("oauth_query", &build_oauth_query(&form.oauth));
            ctx.insert("error", &Some("Invalid client".to_string()));
            return render_template(&tera, "forgot_password", &ctx);
        }
    };

    // Find user (we don't reveal if user exists or not for security)
    if let Some(user) = storage
        .get_user_by_username(&client.user_pool_id, &form.username)
        .await
    {
        // Generate reset code
        let reset_code = generate_confirmation_code();
        let confirmation = ConfirmationCode {
            user_id: user.id,
            attribute_name: None,
            code: reset_code.clone(),
            expires_at: Utc::now() + Duration::hours(1),
        };
        storage.save_confirmation_code(confirmation).await;

        // Log reset code for development
        tracing::info!(
            "Password reset requested for {}. Code: {}",
            form.username,
            reset_code
        );
    }

    // Always redirect to reset page (don't reveal if user exists)
    let query = build_oauth_query(&form.oauth);
    let redirect_url = format!(
        "/reset-password?{}&username={}",
        query,
        urlencoding::encode(&form.username)
    );
    Redirect::to(&redirect_url).into_response()
}

/// Query params for reset password page
#[derive(Debug, Deserialize)]
pub struct ResetPasswordPageQuery {
    pub username: String,
    #[serde(flatten)]
    pub oauth: OAuthParams,
}

/// GET /reset-password - Reset password page
pub async fn reset_password_page(
    State(storage): State<Storage>,
    Query(query): Query<ResetPasswordPageQuery>,
) -> Response {
    let branding = get_branding(&storage, &query.oauth.client_id).await;
    let tera = create_tera();
    let mut ctx = create_template_context(&branding, &query.oauth);
    ctx.insert("oauth_query", &build_oauth_query(&query.oauth));
    ctx.insert("username", &query.username);
    ctx.insert("error", &None::<String>);

    render_template(&tera, "reset_password", &ctx)
}

/// POST /reset-password - Process password reset
pub async fn reset_password_submit(
    State(storage): State<Storage>,
    Form(form): Form<ResetPasswordForm>,
) -> Response {
    let branding = get_branding(&storage, &form.oauth.client_id).await;
    let tera = create_tera();

    // Parse client_id
    let parsed_client_id = match ClientId::new(&form.oauth.client_id) {
        Ok(id) => id,
        Err(_) => {
            let mut ctx = create_template_context(&branding, &form.oauth);
            ctx.insert("oauth_query", &build_oauth_query(&form.oauth));
            ctx.insert("username", &form.username);
            ctx.insert("error", &Some("Invalid client".to_string()));
            return render_template(&tera, "reset_password", &ctx);
        }
    };

    // Validate passwords match
    if form.new_password != form.new_password_confirm {
        let mut ctx = create_template_context(&branding, &form.oauth);
        ctx.insert("oauth_query", &build_oauth_query(&form.oauth));
        ctx.insert("username", &form.username);
        ctx.insert("error", &Some("Passwords do not match".to_string()));
        return render_template(&tera, "reset_password", &ctx);
    }

    // Validate client
    let client = match storage.get_user_pool_client(&parsed_client_id).await {
        Some(c) => c,
        None => {
            let mut ctx = create_template_context(&branding, &form.oauth);
            ctx.insert("oauth_query", &build_oauth_query(&form.oauth));
            ctx.insert("username", &form.username);
            ctx.insert("error", &Some("Invalid client".to_string()));
            return render_template(&tera, "reset_password", &ctx);
        }
    };

    // Find user
    let user = match storage
        .get_user_by_username(&client.user_pool_id, &form.username)
        .await
    {
        Some(u) => u,
        None => {
            let mut ctx = create_template_context(&branding, &form.oauth);
            ctx.insert("oauth_query", &build_oauth_query(&form.oauth));
            ctx.insert("username", &form.username);
            ctx.insert("error", &Some("Invalid reset code".to_string()));
            return render_template(&tera, "reset_password", &ctx);
        }
    };

    // Verify reset code (normalize to ignore dashes and case)
    let stored_code = storage.get_confirmation_code(&user.id).await;
    let code_valid = stored_code.as_ref().is_some_and(|c| {
        normalize_confirmation_code(&c.code) == normalize_confirmation_code(&form.code)
            && c.expires_at > Utc::now()
    });

    if !code_valid {
        let mut ctx = create_template_context(&branding, &form.oauth);
        ctx.insert("oauth_query", &build_oauth_query(&form.oauth));
        ctx.insert("username", &form.username);
        ctx.insert("error", &Some("Invalid reset code".to_string()));
        return render_template(&tera, "reset_password", &ctx);
    }

    // Update password
    let password_hash = match hash_password(&form.new_password) {
        Ok(hash) => hash,
        Err(e) => {
            tracing::error!("Failed to hash password: {}", e);
            let mut ctx = create_template_context(&branding, &form.oauth);
            ctx.insert("oauth_query", &build_oauth_query(&form.oauth));
            ctx.insert("username", &form.username);
            ctx.insert("error", &Some("Internal error".to_string()));
            return render_template(&tera, "reset_password", &ctx);
        }
    };
    storage.set_user_password(&user.id, &password_hash).await;

    // Clear confirmation code
    storage.delete_confirmation_code(&user.id).await;

    // Redirect to login
    let query = build_oauth_query(&form.oauth);
    let redirect_url = format!("/login?{}", query);
    Redirect::to(&redirect_url).into_response()
}
