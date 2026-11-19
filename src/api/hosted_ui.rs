//! Hosted UI - Cognito Managed Login UI emulation
//!
//! Provides web pages for user authentication flows including:
//! - Login
//! - Sign up
//! - Forgot password
//! - Confirmation code entry
//! - The MFA step of a sign-in

use axum::{
    Form,
    extract::{Query, State},
    http::{HeaderValue, StatusCode, header},
    response::{Html, IntoResponse, Response},
};
use chrono::{Duration, Utc};
use std::collections::HashMap;

use super::oauth2::AuthorizationRequest;
use crate::types::UsernameAttribute;
use serde::Deserialize;
use tera::{Context, Tera};
use uuid::Uuid;

use super::oauth2::{
    AuthorizationParams, SignIn, check_credentials, complete_authorization, redirect_found,
    validate_authorization_request,
};
use crate::{
    action::user::{
        associate_software_token::associate_with_session,
        auth_flow::{
            AuthApi, AuthContext, Challenge, INVALID_SESSION, SECOND_FACTOR_CHALLENGES,
            SecondFactorAnswer, answer_second_factor, new_session_token, second_factor,
        },
        helpers::{
            EMAIL_OTP_FACTOR, SMS_MFA_FACTOR, SOFTWARE_TOKEN_MFA_FACTOR, confirmation_attribute,
            generate_confirmation_code, mask_email, mask_phone_number, normalize_confirmation_code,
            recovery_delivery, set_user_password, upsert_user_attribute,
        },
        verify_software_token::verify_with_session,
    },
    error::{AppError, OAuthError},
    storage::Storage,
    types::{
        AutoVerifiedAttribute, ChallengeType, ClientId, ConfirmationCode, ManagedLoginBranding,
        PendingAuthChallenge, User, UserPool, UserPoolClient, UserStatus,
    },
    validation::{validate_email, validate_password_against_policy, validate_username},
};

/// Default `AuthSessionValidity`, in minutes.
const DEFAULT_SESSION_MINUTES: i64 = 3;

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
    ctx.insert("scope", &oauth.scope);
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
        .secret {
            display: block;
            padding: 12px;
            border: 1px solid #ddd;
            border-radius: 4px;
            background: #f8f8f8;
            font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
            font-size: 14px;
            word-break: break-all;
            user-select: all;
        }
        .choice {
            display: flex;
            align-items: center;
            gap: 8px;
            padding: 10px 12px;
            border: 1px solid #ddd;
            border-radius: 4px;
            margin-bottom: 8px;
            cursor: pointer;
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
    {% if scope %}<input type="hidden" name="scope" value="{{ scope }}">{% endif %}
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
    {% if scope %}<input type="hidden" name="scope" value="{{ scope }}">{% endif %}
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
        <input type="password" id="password" name="password" required>
    </div>

    <div class="form-group">
        <label for="password_confirm">Confirm Password</label>
        <input type="password" id="password_confirm" name="password_confirm" required>
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
    {% if scope %}<input type="hidden" name="scope" value="{{ scope }}">{% endif %}
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
    {% if scope %}<input type="hidden" name="scope" value="{{ scope }}">{% endif %}
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
    {% if scope %}<input type="hidden" name="scope" value="{{ scope }}">{% endif %}
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
        <input type="password" id="new_password" name="new_password" required>
    </div>

    <div class="form-group">
        <label for="new_password_confirm">Confirm New Password</label>
        <input type="password" id="new_password_confirm" name="new_password_confirm" required>
    </div>

    <button type="submit" class="btn btn-primary">Reset Password</button>
</form>

<div class="links">
    <a href="/login?{{ oauth_query }}">Back to Sign In</a>
</div>
{% endblock %}"#;

/// Set-new-password page template, for a user signing in with a temporary
/// password.
const NEW_PASSWORD_TEMPLATE: &str = r#"{% extends "base" %}
{% block content %}
<h1>Change Password</h1>
<p class="subheader">Your password is temporary. Choose a new one to continue</p>

{% if error %}
<div class="error">{{ error }}</div>
{% endif %}

<form method="POST" action="/new-password">
    <input type="hidden" name="response_type" value="{{ response_type }}">
    <input type="hidden" name="client_id" value="{{ client_id }}">
    <input type="hidden" name="redirect_uri" value="{{ redirect_uri }}">
    {% if scope %}<input type="hidden" name="scope" value="{{ scope }}">{% endif %}
    {% if state %}<input type="hidden" name="state" value="{{ state }}">{% endif %}
    {% if nonce %}<input type="hidden" name="nonce" value="{{ nonce }}">{% endif %}
    {% if code_challenge %}<input type="hidden" name="code_challenge" value="{{ code_challenge }}">{% endif %}
    {% if code_challenge_method %}<input type="hidden" name="code_challenge_method" value="{{ code_challenge_method }}">{% endif %}
    <input type="hidden" name="session" value="{{ session }}">

    <div class="form-group">
        <label for="new_password">New Password</label>
        <input type="password" id="new_password" name="new_password" required autofocus>
    </div>

    <div class="form-group">
        <label for="new_password_confirm">Confirm New Password</label>
        <input type="password" id="new_password_confirm" name="new_password_confirm" required>
    </div>

    <button type="submit" class="btn btn-primary">Change Password</button>
</form>

<div class="links">
    <a href="/login?{{ oauth_query }}">Back to Sign In</a>
</div>
{% endblock %}"#;

/// MFA page template. One page serves every challenge that can follow the
/// password: a code from an authenticator app, a code that was sent, the
/// choice between factors, and the registration of an authenticator app.
const MFA_TEMPLATE: &str = r#"{% extends "base" %}
{% block content %}
{% if challenge == "SELECT_MFA_TYPE" %}
<h1>Choose a verification method</h1>
<p class="subheader">Select how you want to verify your identity</p>
{% elif challenge == "MFA_SETUP" %}
<h1>Set up an authenticator app</h1>
<p class="subheader">Add this secret key to your authenticator app, then enter the code it shows</p>
{% else %}
<h1>Verify your identity</h1>
<p class="subheader">{% if destination %}We sent a code to {{ destination }}{% else %}Enter the code from your authenticator app{% endif %}</p>
{% endif %}

{% if error %}
<div class="error">{{ error }}</div>
{% endif %}

<form method="POST" action="/mfa">
    <input type="hidden" name="response_type" value="{{ response_type }}">
    <input type="hidden" name="client_id" value="{{ client_id }}">
    <input type="hidden" name="redirect_uri" value="{{ redirect_uri }}">
    {% if scope %}<input type="hidden" name="scope" value="{{ scope }}">{% endif %}
    {% if state %}<input type="hidden" name="state" value="{{ state }}">{% endif %}
    {% if nonce %}<input type="hidden" name="nonce" value="{{ nonce }}">{% endif %}
    {% if code_challenge %}<input type="hidden" name="code_challenge" value="{{ code_challenge }}">{% endif %}
    {% if code_challenge_method %}<input type="hidden" name="code_challenge_method" value="{{ code_challenge_method }}">{% endif %}
    <input type="hidden" name="session" value="{{ session }}">

    {% if challenge == "SELECT_MFA_TYPE" %}
    <div class="form-group">
        {% if software_token_mfa %}<label class="choice"><input type="radio" name="answer" value="SOFTWARE_TOKEN_MFA" required> Authenticator app</label>{% endif %}
        {% if sms_mfa %}<label class="choice"><input type="radio" name="answer" value="SMS_MFA" required> Text message (SMS)</label>{% endif %}
        {% if email_otp %}<label class="choice"><input type="radio" name="answer" value="EMAIL_OTP" required> Email message</label>{% endif %}
    </div>

    <button type="submit" class="btn btn-primary">Continue</button>
    {% else %}
    {% if secret %}
    <div class="form-group">
        <label>Secret key</label>
        <code class="secret">{{ secret }}</code>
    </div>
    {% endif %}

    <div class="form-group">
        <label for="code">Code</label>
        <input type="text" id="code" name="code" inputmode="numeric" autocomplete="one-time-code" required autofocus>
    </div>

    <button type="submit" class="btn btn-primary">Sign In</button>
    {% endif %}
</form>

<div class="links">
    <a href="/login?{{ oauth_query }}">Back to Sign In</a>
</div>
{% endblock %}"#;

const TEMPLATES: &[(&str, &str)] = &[
    ("base", BASE_TEMPLATE),
    ("login", LOGIN_TEMPLATE),
    ("signup", SIGNUP_TEMPLATE),
    ("confirm", CONFIRM_TEMPLATE),
    ("forgot_password", FORGOT_PASSWORD_TEMPLATE),
    ("reset_password", RESET_PASSWORD_TEMPLATE),
    ("new_password", NEW_PASSWORD_TEMPLATE),
    ("mfa", MFA_TEMPLATE),
];

/// Initialize Tera templates
fn create_tera() -> Tera {
    let mut tera = Tera::default();
    for (name, template) in TEMPLATES {
        tera.add_raw_template(name, template)
            .unwrap_or_else(|error| panic!("invalid {name} template: {error}"));
    }
    // Tera only autoescapes templates whose name ends in .html/.htm/.xml by
    // default. These templates are registered under bare names, so enable
    // escaping explicitly to prevent reflected XSS from user-supplied OAuth
    // params (state, redirect_uri, username, ...) interpolated into markup.
    tera.autoescape_on(TEMPLATES.iter().map(|(name, _)| *name).collect());
    tera
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
    ];

    // A request without `scope` stays without one: it stands for every
    // scope the app client allows.
    if let Some(scope) = oauth.scope.as_deref().filter(|scope| !scope.is_empty()) {
        params.push(format!("scope={}", urlencoding::encode(scope)));
    }
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

/// Render one of the pages, with the values its form carries along.
async fn render_page(
    storage: &Storage,
    oauth: &OAuthParams,
    template: &str,
    fields: &[(&str, &str)],
    error: Option<&str>,
) -> Response {
    let branding = get_branding(storage, &oauth.client_id).await;
    let mut ctx = create_template_context(&branding, oauth);
    ctx.insert("oauth_query", &build_oauth_query(oauth));
    ctx.insert("error", &error);
    ctx.insert("success", &None::<String>);
    for (name, value) in fields {
        ctx.insert(*name, value);
    }

    match create_tera().render(template, &ctx) {
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

fn authorization_params(oauth: &OAuthParams) -> AuthorizationParams<'_> {
    AuthorizationParams {
        client_id: &oauth.client_id,
        response_type: &oauth.response_type,
        redirect_uri: &oauth.redirect_uri,
        scope: oauth.scope.as_deref(),
        state: oauth.state.as_deref(),
        nonce: oauth.nonce.as_deref(),
        code_challenge: oauth.code_challenge.as_deref(),
        code_challenge_method: oauth.code_challenge_method.as_deref(),
    }
}

/// What to show for a request the OAuth layer refused.
fn describe(error: OAuthError) -> String {
    error.error_description.unwrap_or(error.error)
}

/// The app client and user pool a form belongs to.
async fn client_and_pool(storage: &Storage, client_id: &str) -> Option<(UserPoolClient, UserPool)> {
    let client_id = ClientId::new(client_id).ok()?;
    let client = storage.get_user_pool_client(&client_id).await?;
    let pool = storage.get_user_pool(&client.user_pool_id).await?;
    Some((client, pool))
}

/// A link to another page of the flow, keeping the authorization request.
fn page_url(path: &str, oauth: &OAuthParams, extra: &[(&str, &str)]) -> String {
    let mut url = format!("{path}?{}", build_oauth_query(oauth));
    for (name, value) in extra {
        url.push_str(&format!("&{name}={}", urlencoding::encode(value)));
    }
    url
}

const INVALID_CODE: &str = "Invalid verification code provided, please try again.";
const EXPIRED_CODE: &str = "Invalid code provided, please request a code again.";

/// Check a submitted code against the pending one, with Cognito's messages.
fn check_code(pending: Option<&ConfirmationCode>, submitted: &str) -> Result<(), &'static str> {
    let pending = pending.ok_or(EXPIRED_CODE)?;
    if normalize_confirmation_code(&pending.code) != normalize_confirmation_code(submitted) {
        return Err(INVALID_CODE);
    }
    if pending.expires_at < Utc::now() {
        return Err(EXPIRED_CODE);
    }
    Ok(())
}

// ==================== Route Handlers ====================

/// GET /login - Login page
pub async fn login_page(
    State(storage): State<Storage>,
    Query(oauth): Query<OAuthParams>,
) -> Response {
    render_page(&storage, &oauth, "login", &[], None).await
}

/// POST /login - Process login
pub async fn login_submit(State(storage): State<Storage>, Form(form): Form<LoginForm>) -> Response {
    // The request is validated before anything is authenticated or minted:
    // an unregistered redirect_uri must never receive a code.
    let request = match validate_authorization_request(&storage, &authorization_params(&form.oauth))
        .await
    {
        Ok(request) => request,
        Err(error) => {
            return render_page(&storage, &form.oauth, "login", &[], Some(&describe(error))).await;
        }
    };

    let user = match check_credentials(&storage, &request.pool, &form.username, &form.password)
        .await
    {
        Ok(SignIn::Complete(user)) => user,
        Ok(SignIn::ConfirmationRequired(user)) => {
            let url = page_url("/confirm", &form.oauth, &[("username", &user.username)]);
            return redirect_found(&url);
        }
        Ok(SignIn::PasswordResetRequired) => {
            return redirect_found(&page_url("/forgot-password", &form.oauth, &[]));
        }
        Ok(SignIn::NewPasswordRequired(user)) => {
            // The password was right, but it is temporary. The session
            // carries that proof to the set-new-password step.
            let session = new_session_token();
            let validity = request
                .client
                .auth_session_validity
                .map_or(DEFAULT_SESSION_MINUTES, i64::from);
            storage
                .save_auth_challenge_session(PendingAuthChallenge {
                    session: session.clone(),
                    challenge_name: ChallengeType::NewPasswordRequired,
                    user_id: user.id,
                    client_id: request.client.client_id.clone(),
                    user_pool_id: request.pool.id.clone(),
                    expires_at: Utc::now() + Duration::minutes(validity),
                    srp: None,
                    code: None,
                    choices: Vec::new(),
                    mfa_setup_complete: false,
                    failed_attempts: 0,
                    user_auth: false,
                    managed_login: true,
                })
                .await;
            let url = page_url("/new-password", &form.oauth, &[("session", &session)]);
            return redirect_found(&url);
        }
        Err(error) => {
            return render_page(&storage, &form.oauth, "login", &[], Some(error.message())).await;
        }
    };

    match after_password(&storage, &request, &form.oauth, &user).await {
        Ok(redirect_url) => redirect_found(&redirect_url),
        Err(error) => {
            render_page(&storage, &form.oauth, "login", &[], Some(&describe(error))).await
        }
    }
}

/// Query params for the set-new-password page
#[derive(Debug, Deserialize)]
pub struct NewPasswordPageQuery {
    pub session: String,
    #[serde(flatten)]
    pub oauth: OAuthParams,
}

/// Set-new-password form data
#[derive(Debug, Deserialize)]
pub struct NewPasswordForm {
    pub session: String,
    pub new_password: String,
    pub new_password_confirm: String,
    #[serde(flatten)]
    pub oauth: OAuthParams,
}

/// GET /new-password - Set-new-password page
pub async fn new_password_page(
    State(storage): State<Storage>,
    Query(query): Query<NewPasswordPageQuery>,
) -> Response {
    let fields = [("session", query.session.as_str())];
    render_page(&storage, &query.oauth, "new_password", &fields, None).await
}

/// POST /new-password - Replace a temporary password and finish signing in
pub async fn new_password_submit(
    State(storage): State<Storage>,
    Form(form): Form<NewPasswordForm>,
) -> Response {
    let fields = [("session", form.session.as_str())];
    let request = match validate_authorization_request(&storage, &authorization_params(&form.oauth))
        .await
    {
        Ok(request) => request,
        Err(error) => {
            return render_page(&storage, &form.oauth, "login", &[], Some(&describe(error))).await;
        }
    };

    // Without a live session the user has to sign in again.
    let pending = storage
        .get_auth_challenge_session(&form.session)
        .await
        .filter(|pending| {
            pending.challenge_name == ChallengeType::NewPasswordRequired
                && pending.managed_login
                && pending.client_id == request.client.client_id
                && pending.expires_at >= Utc::now()
        });
    let user = match &pending {
        Some(pending) => storage.get_user(&pending.user_id).await,
        None => None,
    }
    .filter(|user| user.enabled && user.user_status == UserStatus::ForceChangePassword);
    let Some(mut user) = user else {
        let error = "Invalid session for the user.";
        return render_page(&storage, &form.oauth, "login", &[], Some(error)).await;
    };

    if form.new_password != form.new_password_confirm {
        let error = "Passwords do not match";
        return render_page(&storage, &form.oauth, "new_password", &fields, Some(error)).await;
    }
    if let Err(error) = validate_password_against_policy(&request.pool, &form.new_password)
        .and_then(|()| set_user_password(&mut user, &form.new_password))
    {
        let error = error.to_string();
        return render_page(&storage, &form.oauth, "new_password", &fields, Some(&error)).await;
    }

    user.user_status = UserStatus::Confirmed;
    user.last_modified_date = Utc::now();
    let Some(user) = storage.update_user(user).await else {
        let error = "Invalid session for the user.";
        return render_page(&storage, &form.oauth, "login", &[], Some(error)).await;
    };
    storage.delete_auth_challenge_session(&form.session).await;

    // The new password is set; MFA comes next for a user who needs it.
    match after_password(&storage, &request, &form.oauth, &user).await {
        Ok(redirect_url) => redirect_found(&redirect_url),
        Err(error) => {
            render_page(&storage, &form.oauth, "login", &[], Some(&describe(error))).await
        }
    }
}

// ==================== MFA ====================

fn managed_login<'a>(storage: &'a Storage, request: &'a AuthorizationRequest) -> AuthContext<'a> {
    AuthContext {
        storage,
        pool: &request.pool,
        client: &request.client,
        api: AuthApi::ManagedLogin,
    }
}

fn access_denied(error: AppError) -> OAuthError {
    OAuthError {
        error: "access_denied".to_string(),
        error_description: Some(error.to_string()),
    }
}

/// Where a sign-in goes once its password is accepted: to the MFA page when
/// the user or the user pool calls for a second factor, otherwise to the
/// app's callback.
pub(crate) async fn after_password(
    storage: &Storage,
    request: &AuthorizationRequest,
    oauth: &OAuthParams,
    user: &User,
) -> Result<String, OAuthError> {
    let challenge = second_factor(&managed_login(storage, request), user)
        .await
        .map_err(access_denied)?;
    match challenge {
        Some(challenge) => mfa_page_url(storage, oauth, challenge).await,
        None => complete_authorization(storage, request, user).await,
    }
}

/// The URL of the MFA page for a challenge.
async fn mfa_page_url(
    storage: &Storage,
    oauth: &OAuthParams,
    challenge: Challenge,
) -> Result<String, OAuthError> {
    // A user who has to register a factor sets up an authenticator app,
    // by the steps the API offers: the secret key is handed out under a
    // new session.
    let session = if challenge.name == ChallengeType::MfaSetup {
        let (_, session) = associate_with_session(storage, &challenge.session, true)
            .await
            .map_err(access_denied)?;
        session
    } else {
        challenge.session
    };
    Ok(page_url("/mfa", oauth, &[("session", &session)]))
}

/// The MFA challenge a session these pages issued for this app client is
/// waiting on, and the user it belongs to.
async fn pending_mfa(
    storage: &Storage,
    oauth: &OAuthParams,
    session: &str,
) -> Option<(PendingAuthChallenge, User)> {
    let pending = storage
        .get_auth_challenge_session(session)
        .await
        .filter(|pending| {
            pending.managed_login
                && pending.client_id.as_str() == oauth.client_id
                && pending.expires_at >= Utc::now()
                && SECOND_FACTOR_CHALLENGES.contains(&pending.challenge_name)
        })?;
    let user = storage
        .get_user(&pending.user_id)
        .await
        .filter(|user| user.enabled)?;
    Some((pending, user))
}

/// Render the MFA page for the challenge a session is waiting on. Without
/// a live session the user starts over at the sign-in page.
async fn render_mfa(
    storage: &Storage,
    oauth: &OAuthParams,
    session: &str,
    error: Option<&str>,
) -> Response {
    let Some((pending, user)) = pending_mfa(storage, oauth, session).await else {
        let error = error.unwrap_or(INVALID_SESSION);
        return render_page(storage, oauth, "login", &[], Some(error)).await;
    };

    let mut fields = vec![
        ("session", session.to_string()),
        ("challenge", pending.challenge_name.as_str().to_string()),
    ];
    match pending.challenge_name {
        ChallengeType::SmsMfa => {
            let phone_number = user.phone_number.as_deref().unwrap_or_default();
            fields.push(("destination", mask_phone_number(phone_number)));
        }
        ChallengeType::EmailOtp => {
            let email = user.email.as_deref().unwrap_or_default();
            fields.push(("destination", mask_email(email)));
        }
        ChallengeType::SelectMfaType => {
            for (factor, field) in [
                (SOFTWARE_TOKEN_MFA_FACTOR, "software_token_mfa"),
                (SMS_MFA_FACTOR, "sms_mfa"),
                (EMAIL_OTP_FACTOR, "email_otp"),
            ] {
                if pending.choices.iter().any(|choice| choice == factor) {
                    fields.push((field, "true".to_string()));
                }
            }
        }
        ChallengeType::MfaSetup => {
            if let Some((_, secret)) = storage.get_software_token_session(session).await {
                fields.push(("secret", secret));
            }
        }
        _ => {}
    }

    let fields: Vec<(&str, &str)> = fields
        .iter()
        .map(|(name, value)| (*name, value.as_str()))
        .collect();
    // The page shows a secret key and its URL carries the session.
    let mut response = render_page(storage, oauth, "mfa", &fields, error).await;
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

/// Query params for the MFA page
#[derive(Debug, Deserialize)]
pub struct MfaPageQuery {
    pub session: String,
    #[serde(flatten)]
    pub oauth: OAuthParams,
}

/// MFA form data: a code, or the choice of a factor
#[derive(Debug, Deserialize)]
pub struct MfaForm {
    pub session: String,
    #[serde(default)]
    pub code: Option<String>,
    #[serde(default)]
    pub answer: Option<String>,
    #[serde(flatten)]
    pub oauth: OAuthParams,
}

/// GET /mfa - MFA page
pub async fn mfa_page(
    State(storage): State<Storage>,
    Query(query): Query<MfaPageQuery>,
) -> Response {
    render_mfa(&storage, &query.oauth, &query.session, None).await
}

/// POST /mfa - Answer the MFA challenge and finish signing in
pub async fn mfa_submit(State(storage): State<Storage>, Form(form): Form<MfaForm>) -> Response {
    let request = match validate_authorization_request(&storage, &authorization_params(&form.oauth))
        .await
    {
        Ok(request) => request,
        Err(error) => {
            return render_page(&storage, &form.oauth, "login", &[], Some(&describe(error))).await;
        }
    };
    let Some((pending, _)) = pending_mfa(&storage, &form.oauth, &form.session).await else {
        return render_page(&storage, &form.oauth, "login", &[], Some(INVALID_SESSION)).await;
    };

    let code = form.code.as_deref().unwrap_or_default().trim();
    let mut session = form.session.clone();
    let mut responses = HashMap::new();
    match pending.challenge_name {
        ChallengeType::MfaSetup => {
            // Verifying the first code registers the authenticator app
            // and continues the challenge under a new session.
            match verify_with_session(&storage, &form.session, code, true).await {
                Ok(next_session) => session = next_session,
                Err(error) => {
                    let error = error.to_string();
                    return render_mfa(&storage, &form.oauth, &form.session, Some(&error)).await;
                }
            }
        }
        ChallengeType::SelectMfaType => {
            let answer = form.answer.clone().unwrap_or_default();
            responses.insert("ANSWER".to_string(), answer);
        }
        ChallengeType::SoftwareTokenMfa => {
            responses.insert("SOFTWARE_TOKEN_MFA_CODE".to_string(), code.to_string());
        }
        ChallengeType::SmsMfa => {
            responses.insert("SMS_MFA_CODE".to_string(), code.to_string());
        }
        _ => {
            responses.insert("EMAIL_OTP_CODE".to_string(), code.to_string());
        }
    }

    let ctx = managed_login(&storage, &request);
    let redirect_url = match answer_second_factor(&ctx, &session, &responses).await {
        Ok(SecondFactorAnswer::Verified(user)) => {
            complete_authorization(&storage, &request, &user).await
        }
        Ok(SecondFactorAnswer::Next(challenge)) => {
            mfa_page_url(&storage, &form.oauth, challenge).await
        }
        // A wrong answer leaves the session for another try, until its
        // attempts run out.
        Err(error) => {
            let error = error.to_string();
            return render_mfa(&storage, &form.oauth, &form.session, Some(&error)).await;
        }
    };
    match redirect_url {
        Ok(redirect_url) => redirect_found(&redirect_url),
        Err(error) => {
            render_page(&storage, &form.oauth, "login", &[], Some(&describe(error))).await
        }
    }
}

/// GET /signup - Signup page
pub async fn signup_page(
    State(storage): State<Storage>,
    Query(oauth): Query<OAuthParams>,
) -> Response {
    render_page(&storage, &oauth, "signup", &[], None).await
}

/// POST /signup - Process signup
///
/// Applies the rules `SignUp` does: the pool has to allow self-registration,
/// the password has to satisfy the pool's policy, and the email address
/// starts out unverified.
pub async fn signup_submit(
    State(storage): State<Storage>,
    Form(form): Form<SignupForm>,
) -> Response {
    let Some((client, pool)) = client_and_pool(&storage, &form.oauth.client_id).await else {
        return render_page(&storage, &form.oauth, "signup", &[], Some("Invalid client")).await;
    };

    let refusal = if pool
        .admin_create_user_config
        .as_ref()
        .and_then(|config| config.allow_admin_create_user_only)
        == Some(true)
    {
        Some("SignUp is not permitted for this user pool".to_string())
    } else if form.password != form.password_confirm {
        Some("Passwords do not match".to_string())
    } else {
        validate_username(&form.username)
            .and_then(|()| validate_email(&form.email))
            .and_then(|()| validate_password_against_policy(&pool, &form.password))
            .err()
            .map(|error| error.to_string())
    };
    if let Some(error) = refusal {
        return render_page(&storage, &form.oauth, "signup", &[], Some(&error)).await;
    }

    let now = Utc::now();
    let user_id = Uuid::new_v4();
    let mut user = User {
        id: user_id,
        user_pool_id: client.user_pool_id.clone(),
        username: form.username.clone(),
        password_hash: String::new(),
        email: Some(form.email.clone()),
        phone_number: None,
        user_status: UserStatus::Unconfirmed,
        enabled: true,
        attributes: Vec::new(),
        creation_date: now,
        last_modified_date: now,
        srp_salt: None,
        srp_verifier: None,
        password_set_at: None,
    };
    upsert_user_attribute(&mut user.attributes, "email", Some(form.email.clone()));
    upsert_user_attribute(
        &mut user.attributes,
        "email_verified",
        Some("false".to_string()),
    );
    if let Err(e) = set_user_password(&mut user, &form.password) {
        tracing::error!("Failed to hash password: {}", e);
        return render_page(&storage, &form.oauth, "signup", &[], Some("Internal error")).await;
    }

    // An address users sign in with can belong to one user only.
    let email_signs_in = pool
        .username_attributes
        .as_deref()
        .unwrap_or_default()
        .contains(&UsernameAttribute::Email);
    if email_signs_in
        && storage
            .sign_in_value_taken(&client.user_pool_id, "email", &form.email, &user_id, false)
            .await
    {
        let error = "An account with the given email already exists.";
        return render_page(&storage, &form.oauth, "signup", &[], Some(error)).await;
    }

    if storage
        .get_user_by_username(&client.user_pool_id, &form.username)
        .await
        .is_some()
        || storage.try_create_user(user).await.is_none()
    {
        let error = "User already exists";
        return render_page(&storage, &form.oauth, "signup", &[], Some(error)).await;
    }

    let code = generate_confirmation_code();
    storage
        .save_confirmation_code(ConfirmationCode {
            user_id,
            attribute_name: None,
            code: code.clone(),
            expires_at: now + Duration::hours(24),
        })
        .await;

    // Log confirmation code for development
    tracing::debug!(
        "User {} created. Confirmation code: {}",
        form.username,
        code
    );

    let url = page_url("/confirm", &form.oauth, &[("username", &form.username)]);
    redirect_found(&url)
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
    let fields = [("username", query.username.as_str())];
    render_page(&storage, &query.oauth, "confirm", &fields, None).await
}

/// POST /confirm - Process confirmation
pub async fn confirm_submit(
    State(storage): State<Storage>,
    Form(form): Form<ConfirmForm>,
) -> Response {
    match confirm_user(&storage, &form).await {
        Ok(()) => redirect_found(&page_url("/login", &form.oauth, &[])),
        Err(error) => {
            let fields = [("username", form.username.as_str())];
            render_page(&storage, &form.oauth, "confirm", &fields, Some(error)).await
        }
    }
}

/// Confirm a sign-up with the code the user returned, as `ConfirmSignUp`
/// does.
async fn confirm_user(storage: &Storage, form: &ConfirmForm) -> Result<(), &'static str> {
    let (client, pool) = client_and_pool(storage, &form.oauth.client_id)
        .await
        .ok_or("Invalid client")?;
    let mut user = storage
        .get_user_by_username(&client.user_pool_id, &form.username)
        .await
        .ok_or("User does not exist.")?;
    if user.user_status != UserStatus::Unconfirmed {
        return Err("User cannot be confirmed. Current status is CONFIRMED");
    }

    let pending = storage.get_confirmation_code(&user.id).await;
    check_code(pending.as_ref(), &form.code)?;

    // Returning the code proves control of the address it was sent to.
    if let Some(attribute) = confirmation_attribute(&pool, &user) {
        let verified_attribute = match attribute {
            AutoVerifiedAttribute::Email => "email_verified",
            AutoVerifiedAttribute::PhoneNumber => "phone_number_verified",
        };
        upsert_user_attribute(
            &mut user.attributes,
            verified_attribute,
            Some("true".to_string()),
        );
    }
    user.user_status = UserStatus::Confirmed;
    user.last_modified_date = Utc::now();
    let user_id = user.id;
    storage.update_user(user).await;
    storage.delete_confirmation_code(&user_id).await;
    Ok(())
}

/// GET /forgot-password - Forgot password page
pub async fn forgot_password_page(
    State(storage): State<Storage>,
    Query(oauth): Query<OAuthParams>,
) -> Response {
    render_page(&storage, &oauth, "forgot_password", &[], None).await
}

/// POST /forgot-password - Process forgot password
pub async fn forgot_password_submit(
    State(storage): State<Storage>,
    Form(form): Form<ForgotPasswordForm>,
) -> Response {
    let Some((client, pool)) = client_and_pool(&storage, &form.oauth.client_id).await else {
        let error = Some("Invalid client");
        return render_page(&storage, &form.oauth, "forgot_password", &[], error).await;
    };

    // A code only goes out under the conditions ForgotPassword applies: an
    // enabled user with a password of their own and a verified address or
    // number to send it to. The page does not reveal which of these failed,
    // nor whether the user exists.
    let user = storage
        .get_user_by_username(&client.user_pool_id, &form.username)
        .await
        .filter(|user| user.enabled && user.user_status != UserStatus::ForceChangePassword);
    let deliverable = match &user {
        Some(user) => {
            let mfa_factors = storage.list_user_auth_factors(&user.id).await;
            recovery_delivery(&pool, user, &mfa_factors, true).is_ok()
        }
        None => false,
    };
    if let Some(user) = user.filter(|_| deliverable) {
        let reset_code = generate_confirmation_code();
        storage
            .save_confirmation_code(ConfirmationCode {
                user_id: user.id,
                attribute_name: None,
                code: reset_code.clone(),
                expires_at: Utc::now() + Duration::hours(1),
            })
            .await;

        // Log reset code for development
        tracing::debug!(
            "Password reset requested for {}. Code: {}",
            form.username,
            reset_code
        );
    }

    // Always redirect to reset page (don't reveal if user exists)
    let url = page_url(
        "/reset-password",
        &form.oauth,
        &[("username", &form.username)],
    );
    redirect_found(&url)
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
    let fields = [("username", query.username.as_str())];
    render_page(&storage, &query.oauth, "reset_password", &fields, None).await
}

/// POST /reset-password - Process password reset
pub async fn reset_password_submit(
    State(storage): State<Storage>,
    Form(form): Form<ResetPasswordForm>,
) -> Response {
    match reset_password(&storage, &form).await {
        Ok(()) => redirect_found(&page_url("/login", &form.oauth, &[])),
        Err(error) => {
            let fields = [("username", form.username.as_str())];
            render_page(
                &storage,
                &form.oauth,
                "reset_password",
                &fields,
                Some(&error),
            )
            .await
        }
    }
}

/// Set a new password with a reset code, as `ConfirmForgotPassword` does.
async fn reset_password(storage: &Storage, form: &ResetPasswordForm) -> Result<(), String> {
    let (client, pool) = client_and_pool(storage, &form.oauth.client_id)
        .await
        .ok_or("Invalid client")?;
    if form.new_password != form.new_password_confirm {
        return Err("Passwords do not match".to_string());
    }

    // An unknown user gets the answer a missing code gets.
    let mut user = storage
        .get_user_by_username(&client.user_pool_id, &form.username)
        .await
        .ok_or(EXPIRED_CODE)?;
    let pending = storage.get_confirmation_code(&user.id).await;
    check_code(pending.as_ref(), &form.code)?;

    validate_password_against_policy(&pool, &form.new_password)
        .and_then(|()| set_user_password(&mut user, &form.new_password))
        .map_err(|error| error.to_string())?;
    // Choosing a password is what an administrator's reset asks for.
    if user.user_status == UserStatus::ResetRequired {
        user.user_status = UserStatus::Confirmed;
    }
    user.last_modified_date = Utc::now();
    let user_id = user.id;
    storage.update_user(user).await;
    storage.delete_confirmation_code(&user_id).await;
    Ok(())
}
