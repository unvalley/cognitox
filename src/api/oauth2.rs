//! OAuth 2.0 / OpenID Connect endpoints
//!
//! Implements the OAuth 2.0 Authorization Framework and OpenID Connect Core 1.0
//! compatible endpoints for Cognito Hosted UI emulation.

use axum::{
    Form, Json,
    extract::{Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Redirect, Response},
};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD as BASE64_STANDARD, URL_SAFE_NO_PAD},
};
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{
    error::OAuthError,
    jwt::{
        generate_access_token, generate_client_credentials_access_token, generate_id_token,
        issuer_base_url, resolve_access_token_expiry, resolve_id_token_expiry,
        resolve_refresh_token_expiry,
    },
    storage::Storage,
    types::{
        AuthorizationCode, ClientId, OAuthFlow, RefreshToken, User, UserPoolClient, UserPoolId,
        UserStatus,
    },
};

use super::super::action::user::helpers::{verify_and_extract_active_user_id, verify_password};

/// Authorization endpoint query parameters
#[derive(Debug, Deserialize)]
pub struct AuthorizeParams {
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
    // For direct login (non-interactive for testing)
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
}

/// Token endpoint request body
#[derive(Debug, Deserialize)]
pub struct TokenRequest {
    pub grant_type: String,
    #[serde(default)]
    pub code: Option<String>,
    #[serde(default)]
    pub redirect_uri: Option<String>,
    #[serde(default)]
    pub client_id: Option<String>,
    #[serde(default)]
    pub client_secret: Option<String>,
    #[serde(default)]
    pub refresh_token: Option<String>,
    #[serde(default)]
    pub code_verifier: Option<String>,
    #[serde(default)]
    pub scope: Option<String>,
}

/// Logout endpoint query parameters
#[derive(Debug, Deserialize)]
pub struct LogoutParams {
    pub client_id: String,
    #[serde(default)]
    pub logout_uri: Option<String>,
    #[serde(default)]
    pub redirect_uri: Option<String>,
}

/// Token response
#[derive(Debug, Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
}

fn prefers_json_redirect(headers: &HeaderMap) -> bool {
    headers
        .get("x-requested-with")
        .and_then(|value| value.to_str().ok())
        .map(|value| value.eq_ignore_ascii_case("XMLHttpRequest"))
        .unwrap_or(false)
        || headers
            .get(header::ACCEPT)
            .and_then(|value| value.to_str().ok())
            .map(|value| value.contains("application/json"))
            .unwrap_or(false)
}

fn parse_scopes(raw: Option<&str>, default: &str) -> Vec<String> {
    raw.unwrap_or(default)
        .split_whitespace()
        .map(String::from)
        .collect()
}

/// A registered callback list restricts `redirect_uri`; an empty list keeps
/// the emulator lenient (any URI). Without this check a crafted link could
/// exfiltrate a usable authorization code after the victim signs in.
fn is_redirect_uri_allowed(callback_urls: &[String], redirect_uri: &str) -> bool {
    callback_urls.is_empty() || callback_urls.iter().any(|u| u == redirect_uri)
}

/// Resolve the scopes for an authorization request. Like Cognito, an omitted
/// `scope` means every scope configured on the client; a client with no
/// configured scopes falls back to `openid` and accepts any request.
fn resolve_requested_scopes(
    client: &UserPoolClient,
    raw: Option<&str>,
) -> Result<Vec<String>, OAuthError> {
    let scopes = match raw.map(str::trim) {
        Some(raw) if !raw.is_empty() => parse_scopes(Some(raw), ""),
        _ if client.allowed_oauth_scopes.is_empty() => vec!["openid".to_string()],
        _ => client.allowed_oauth_scopes.clone(),
    };
    if !client.allowed_oauth_scopes.is_empty() {
        validate_requested_scopes(&client.allowed_oauth_scopes, &scopes)?;
    }
    Ok(scopes)
}

/// Client-policy checks shared by `/oauth2/authorize` and the Hosted UI login
/// form, so both entry points issue grants under the same rules. Returns the
/// effective scopes.
pub(crate) fn validate_authorize_request(
    client: &UserPoolClient,
    response_type: &str,
    redirect_uri: &str,
    requested_scope: Option<&str>,
) -> Result<Vec<String>, OAuthError> {
    if !is_redirect_uri_allowed(&client.callback_urls, redirect_uri) {
        return Err(OAuthError {
            error: "invalid_request".to_string(),
            error_description: Some("Invalid redirect_uri".to_string()),
        });
    }

    if !client.allowed_oauth_flows_user_pool_client {
        return Err(OAuthError {
            error: "unauthorized_client".to_string(),
            error_description: Some("OAuth flows are not enabled for this client".to_string()),
        });
    }

    let (required_flow, flow_label) = match response_type {
        "code" => (OAuthFlow::Code, "Code"),
        "token" => (OAuthFlow::Implicit, "Implicit"),
        other => {
            return Err(OAuthError {
                error: "unsupported_response_type".to_string(),
                error_description: Some(format!("Response type '{other}' is not supported")),
            });
        }
    };
    if !client.allowed_oauth_flows.contains(&required_flow) {
        return Err(OAuthError {
            error: "unauthorized_client".to_string(),
            error_description: Some(format!("{flow_label} flow not allowed for this client")),
        });
    }

    resolve_requested_scopes(client, requested_scope)
}

/// Client credentials passed via HTTP Basic auth (RFC 6749 §2.3.1), the
/// method most OAuth libraries use by default for the token endpoint.
fn parse_basic_client_auth(headers: &HeaderMap) -> Result<Option<(String, String)>, OAuthError> {
    let Some(encoded) = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Basic "))
    else {
        return Ok(None);
    };

    let invalid = || OAuthError {
        error: "invalid_client".to_string(),
        error_description: Some("Malformed Basic authorization header".to_string()),
    };
    let decoded = BASE64_STANDARD
        .decode(encoded.trim())
        .map_err(|_| invalid())?;
    let credentials = String::from_utf8(decoded).map_err(|_| invalid())?;
    let (client_id, client_secret) = credentials.split_once(':').ok_or_else(invalid)?;

    let decode = |value: &str| {
        urlencoding::decode(value)
            .map(|v| v.into_owned())
            .unwrap_or_else(|_| value.to_string())
    };
    Ok(Some((decode(client_id), decode(client_secret))))
}

fn validate_requested_scopes(
    allowed_scopes: &[String],
    requested_scopes: &[String],
) -> Result<(), OAuthError> {
    if let Some(scope) = requested_scopes
        .iter()
        .find(|scope| !allowed_scopes.contains(scope))
    {
        return Err(OAuthError {
            error: "invalid_scope".to_string(),
            error_description: Some(format!("Scope '{scope}' is not allowed for this client")),
        });
    }
    Ok(())
}

fn append_query_param(target: &mut String, name: &str, value: &str) {
    target.push_str(if target.contains('?') { "&" } else { "?" });
    target.push_str(name);
    target.push('=');
    target.push_str(&urlencoding::encode(value));
}

fn append_fragment_param(target: &mut String, name: &str, value: &str) {
    target.push_str(if target.contains('#') { "&" } else { "#" });
    target.push_str(name);
    target.push('=');
    target.push_str(&urlencoding::encode(value));
}

fn html_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

pub(crate) async fn get_user_by_username_or_email(
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

/// GET /oauth2/authorize - Authorization endpoint
///
/// For testing purposes, this endpoint can directly authenticate users
/// if username and password are provided as query parameters.
/// In production, this would redirect to a login page.
pub async fn authorize(
    State(storage): State<Storage>,
    headers: HeaderMap,
    Query(params): Query<AuthorizeParams>,
) -> Result<impl IntoResponse, OAuthError> {
    // Parse and validate client_id
    let parsed_client_id = ClientId::new(&params.client_id).map_err(|_| OAuthError {
        error: "invalid_client".to_string(),
        error_description: Some("Invalid client ID format".to_string()),
    })?;

    // Validate client
    let client = storage
        .get_user_pool_client(&parsed_client_id)
        .await
        .ok_or_else(|| OAuthError {
            error: "invalid_client".to_string(),
            error_description: Some("Client not found".to_string()),
        })?;

    // Redirect URI, enabled flows, response type and scopes.
    let scopes = validate_authorize_request(
        &client,
        &params.response_type,
        &params.redirect_uri,
        params.scope.as_deref(),
    )?;

    match params.response_type.as_str() {
        "code" => {
            // For testing: direct authentication if credentials provided
            if let (Some(username), Some(password)) = (&params.username, &params.password) {
                let user = get_user_by_username_or_email(&storage, &client.user_pool_id, username)
                    .await
                    .ok_or_else(|| OAuthError {
                        error: "access_denied".to_string(),
                        error_description: Some("Invalid credentials".to_string()),
                    })?;

                // Check if user is enabled
                if !user.enabled {
                    return Err(OAuthError {
                        error: "access_denied".to_string(),
                        error_description: Some("User is disabled".to_string()),
                    });
                }

                if user.user_status != UserStatus::Confirmed {
                    return Err(OAuthError {
                        error: "access_denied".to_string(),
                        error_description: Some("User not confirmed".to_string()),
                    });
                }

                if !verify_password(password, &user.password_hash) {
                    return Err(OAuthError {
                        error: "access_denied".to_string(),
                        error_description: Some("Invalid credentials".to_string()),
                    });
                }

                // Generate authorization code
                let code = Uuid::new_v4().to_string();
                let auth_code = AuthorizationCode {
                    code: code.clone(),
                    user_id: user.id,
                    client_id: parsed_client_id.clone(),
                    redirect_uri: params.redirect_uri.clone(),
                    scope: scopes,
                    nonce: params.nonce.clone(),
                    code_challenge: params.code_challenge.clone(),
                    code_challenge_method: params.code_challenge_method.clone(),
                    expires_at: Utc::now() + Duration::minutes(5),
                };
                storage.save_authorization_code(auth_code).await;

                let mut redirect_url = params.redirect_uri.clone();
                append_query_param(&mut redirect_url, "code", &code);
                if let Some(state) = &params.state {
                    append_query_param(&mut redirect_url, "state", state);
                }

                if prefers_json_redirect(&headers) {
                    return Ok(Json(json!({ "redirectUrl": redirect_url })).into_response());
                }

                return Ok(Redirect::temporary(&redirect_url).into_response());
            }

            // Without credentials, return login page HTML (simplified)
            let login_html = generate_login_html(&params);
            Ok((
                StatusCode::OK,
                [(header::CONTENT_TYPE, "text/html")],
                login_html,
            )
                .into_response())
        }
        "token" => {
            // Implicit Flow (legacy, not recommended)
            // For implicit flow with direct auth
            if let (Some(username), Some(password)) = (&params.username, &params.password) {
                let user = get_user_by_username_or_email(&storage, &client.user_pool_id, username)
                    .await
                    .ok_or_else(|| OAuthError {
                        error: "access_denied".to_string(),
                        error_description: Some("Invalid credentials".to_string()),
                    })?;

                // Check if user is enabled
                if !user.enabled {
                    return Err(OAuthError {
                        error: "access_denied".to_string(),
                        error_description: Some("User is disabled".to_string()),
                    });
                }

                if !verify_password(password, &user.password_hash) {
                    return Err(OAuthError {
                        error: "access_denied".to_string(),
                        error_description: Some("Invalid credentials".to_string()),
                    });
                }

                if user.user_status != UserStatus::Confirmed {
                    return Err(OAuthError {
                        error: "access_denied".to_string(),
                        error_description: Some("User not confirmed".to_string()),
                    });
                }

                let groups = storage.get_groups_for_user(&user.id).await;

                let access_expiry = resolve_access_token_expiry(&client);
                let id_expiry = resolve_id_token_expiry(&client);

                let access_token = generate_access_token(
                    &user,
                    &params.client_id,
                    &client.user_pool_id,
                    &groups,
                    &scopes,
                    access_expiry,
                )
                .map_err(|e| OAuthError {
                    error: "server_error".to_string(),
                    error_description: Some(e),
                })?;

                let mut redirect_url = params.redirect_uri.clone();
                append_fragment_param(&mut redirect_url, "access_token", &access_token);
                append_fragment_param(&mut redirect_url, "token_type", "Bearer");
                append_fragment_param(
                    &mut redirect_url,
                    "expires_in",
                    &access_expiry.num_seconds().to_string(),
                );

                if scopes.contains(&"openid".to_string()) {
                    let id_token = generate_id_token(
                        &user,
                        &params.client_id,
                        &client.user_pool_id,
                        &groups,
                        params.nonce.as_deref(),
                        id_expiry,
                    )
                    .map_err(|e| OAuthError {
                        error: "server_error".to_string(),
                        error_description: Some(e),
                    })?;
                    append_fragment_param(&mut redirect_url, "id_token", &id_token);
                }

                if let Some(state) = &params.state {
                    append_fragment_param(&mut redirect_url, "state", state);
                }

                return Ok(Redirect::temporary(&redirect_url).into_response());
            }

            let login_html = generate_login_html(&params);
            Ok((
                StatusCode::OK,
                [(header::CONTENT_TYPE, "text/html")],
                login_html,
            )
                .into_response())
        }
        _ => Err(OAuthError {
            error: "unsupported_response_type".to_string(),
            error_description: Some(format!(
                "Response type '{}' is not supported",
                params.response_type
            )),
        }),
    }
}

/// POST /oauth2/token - Token endpoint
pub async fn token(
    State(storage): State<Storage>,
    headers: HeaderMap,
    Form(mut req): Form<TokenRequest>,
) -> Result<Json<TokenResponse>, OAuthError> {
    if let Some((client_id, client_secret)) = parse_basic_client_auth(&headers)? {
        req.client_id.get_or_insert(client_id);
        req.client_secret.get_or_insert(client_secret);
    }

    match req.grant_type.as_str() {
        "authorization_code" => {
            let code = req.code.as_ref().ok_or_else(|| OAuthError {
                error: "invalid_request".to_string(),
                error_description: Some("Missing code parameter".to_string()),
            })?;

            let client_id_str = req.client_id.as_ref().ok_or_else(|| OAuthError {
                error: "invalid_request".to_string(),
                error_description: Some("Missing client_id parameter".to_string()),
            })?;

            // Parse client_id
            let client_id = ClientId::new(client_id_str).map_err(|_| OAuthError {
                error: "invalid_client".to_string(),
                error_description: Some("Invalid client ID format".to_string()),
            })?;

            // Get and validate authorization code
            let auth_code = storage
                .delete_authorization_code(code)
                .await
                .ok_or_else(|| OAuthError {
                    error: "invalid_grant".to_string(),
                    error_description: Some("Invalid or expired authorization code".to_string()),
                })?;

            // Check expiration
            if auth_code.expires_at < Utc::now() {
                return Err(OAuthError {
                    error: "invalid_grant".to_string(),
                    error_description: Some("Authorization code expired".to_string()),
                });
            }

            // Validate client_id
            if auth_code.client_id != client_id {
                return Err(OAuthError {
                    error: "invalid_grant".to_string(),
                    error_description: Some("Client ID mismatch".to_string()),
                });
            }

            // Validate redirect_uri
            if let Some(redirect_uri) = &req.redirect_uri
                && redirect_uri != &auth_code.redirect_uri
            {
                return Err(OAuthError {
                    error: "invalid_grant".to_string(),
                    error_description: Some("Redirect URI mismatch".to_string()),
                });
            }

            // Validate PKCE if code_challenge was provided
            if let Some(code_challenge) = &auth_code.code_challenge {
                let code_verifier = req.code_verifier.as_ref().ok_or_else(|| OAuthError {
                    error: "invalid_request".to_string(),
                    error_description: Some("Missing code_verifier parameter".to_string()),
                })?;

                let method = auth_code.code_challenge_method.as_deref().unwrap_or("S256");

                let computed_challenge = match method {
                    "S256" => {
                        let mut hasher = Sha256::new();
                        hasher.update(code_verifier.as_bytes());
                        URL_SAFE_NO_PAD.encode(hasher.finalize())
                    }
                    "plain" => code_verifier.clone(),
                    _ => {
                        return Err(OAuthError {
                            error: "invalid_request".to_string(),
                            error_description: Some(
                                "Unsupported code_challenge_method".to_string(),
                            ),
                        });
                    }
                };

                if &computed_challenge != code_challenge {
                    return Err(OAuthError {
                        error: "invalid_grant".to_string(),
                        error_description: Some("Code verifier mismatch".to_string()),
                    });
                }
            }

            // Get client and user
            let client = storage
                .get_user_pool_client(&client_id)
                .await
                .ok_or_else(|| OAuthError {
                    error: "invalid_client".to_string(),
                    error_description: Some("Client not found".to_string()),
                })?;

            // Validate client secret if required
            if client.client_secret.is_some() {
                let provided_secret = req.client_secret.as_ref().ok_or_else(|| OAuthError {
                    error: "invalid_client".to_string(),
                    error_description: Some("Client secret required".to_string()),
                })?;

                if client.client_secret.as_ref() != Some(provided_secret) {
                    return Err(OAuthError {
                        error: "invalid_client".to_string(),
                        error_description: Some("Invalid client secret".to_string()),
                    });
                }
            }

            let user = storage
                .get_user(&auth_code.user_id)
                .await
                .ok_or_else(|| OAuthError {
                    error: "invalid_grant".to_string(),
                    error_description: Some("User not found".to_string()),
                })?;

            // The user may have been disabled during the code's lifetime.
            if !user.enabled {
                return Err(OAuthError {
                    error: "invalid_grant".to_string(),
                    error_description: Some("User is disabled".to_string()),
                });
            }

            let groups = storage.get_groups_for_user(&user.id).await;

            let access_expiry = resolve_access_token_expiry(&client);
            let id_expiry = resolve_id_token_expiry(&client);
            let refresh_expiry = resolve_refresh_token_expiry(&client);

            // Generate tokens
            let access_token = generate_access_token(
                &user,
                client_id.as_str(),
                &client.user_pool_id,
                &groups,
                &auth_code.scope,
                access_expiry,
            )
            .map_err(|e| OAuthError {
                error: "server_error".to_string(),
                error_description: Some(e),
            })?;

            let id_token = if auth_code.scope.contains(&"openid".to_string()) {
                Some(
                    generate_id_token(
                        &user,
                        client_id.as_str(),
                        &client.user_pool_id,
                        &groups,
                        auth_code.nonce.as_deref(),
                        id_expiry,
                    )
                    .map_err(|e| OAuthError {
                        error: "server_error".to_string(),
                        error_description: Some(e),
                    })?,
                )
            } else {
                None
            };

            // Generate refresh token
            let refresh_token_str = Uuid::new_v4().to_string();
            let refresh = RefreshToken {
                token: refresh_token_str.clone(),
                user_id: user.id,
                client_id: client_id.clone(),
                expires_at: Utc::now() + refresh_expiry,
            };
            storage.save_refresh_token(refresh).await;

            Ok(Json(TokenResponse {
                access_token,
                token_type: "Bearer".to_string(),
                expires_in: access_expiry.num_seconds(),
                refresh_token: Some(refresh_token_str),
                id_token,
                scope: Some(auth_code.scope.join(" ")),
            }))
        }
        "refresh_token" => {
            let refresh_token = req.refresh_token.as_ref().ok_or_else(|| OAuthError {
                error: "invalid_request".to_string(),
                error_description: Some("Missing refresh_token parameter".to_string()),
            })?;

            let stored_token = storage
                .get_refresh_token(refresh_token)
                .await
                .ok_or_else(|| OAuthError {
                    error: "invalid_grant".to_string(),
                    error_description: Some("Invalid refresh token".to_string()),
                })?;

            if stored_token.expires_at < Utc::now() {
                return Err(OAuthError {
                    error: "invalid_grant".to_string(),
                    error_description: Some("Refresh token expired".to_string()),
                });
            }

            if let Some(requested_client_id) = req.client_id.as_deref() {
                let requested_client_id =
                    ClientId::new(requested_client_id).map_err(|_| OAuthError {
                        error: "invalid_client".to_string(),
                        error_description: Some("Invalid client ID format".to_string()),
                    })?;

                if requested_client_id != stored_token.client_id {
                    return Err(OAuthError {
                        error: "invalid_grant".to_string(),
                        error_description: Some("Client ID mismatch".to_string()),
                    });
                }
            }

            let client = storage
                .get_user_pool_client(&stored_token.client_id)
                .await
                .ok_or_else(|| OAuthError {
                    error: "invalid_client".to_string(),
                    error_description: Some("Client not found".to_string()),
                })?;

            if client.client_secret.is_some() {
                let provided_secret = req.client_secret.as_ref().ok_or_else(|| OAuthError {
                    error: "invalid_client".to_string(),
                    error_description: Some("Client secret required".to_string()),
                })?;

                if client.client_secret.as_ref() != Some(provided_secret) {
                    return Err(OAuthError {
                        error: "invalid_client".to_string(),
                        error_description: Some("Invalid client secret".to_string()),
                    });
                }
            }

            let user = storage
                .get_user(&stored_token.user_id)
                .await
                .ok_or_else(|| OAuthError {
                    error: "invalid_grant".to_string(),
                    error_description: Some("User not found".to_string()),
                })?;

            if !user.enabled {
                return Err(OAuthError {
                    error: "invalid_grant".to_string(),
                    error_description: Some("User is disabled".to_string()),
                });
            }

            let groups = storage.get_groups_for_user(&user.id).await;
            let scopes = parse_scopes(req.scope.as_deref(), "openid");
            validate_requested_scopes(&client.allowed_oauth_scopes, &scopes)?;

            let access_expiry = resolve_access_token_expiry(&client);
            let id_expiry = resolve_id_token_expiry(&client);

            let access_token = generate_access_token(
                &user,
                stored_token.client_id.as_str(),
                &client.user_pool_id,
                &groups,
                &scopes,
                access_expiry,
            )
            .map_err(|e| OAuthError {
                error: "server_error".to_string(),
                error_description: Some(e),
            })?;

            let id_token = if scopes.contains(&"openid".to_string()) {
                Some(
                    generate_id_token(
                        &user,
                        stored_token.client_id.as_str(),
                        &client.user_pool_id,
                        &groups,
                        None,
                        id_expiry,
                    )
                    .map_err(|e| OAuthError {
                        error: "server_error".to_string(),
                        error_description: Some(e),
                    })?,
                )
            } else {
                None
            };

            Ok(Json(TokenResponse {
                access_token,
                token_type: "Bearer".to_string(),
                expires_in: access_expiry.num_seconds(),
                refresh_token: None, // Don't issue new refresh token
                id_token,
                scope: Some(scopes.join(" ")),
            }))
        }
        "client_credentials" => {
            let client_id_str = req.client_id.as_ref().ok_or_else(|| OAuthError {
                error: "invalid_request".to_string(),
                error_description: Some("Missing client_id".to_string()),
            })?;

            // Parse client_id
            let client_id = ClientId::new(client_id_str).map_err(|_| OAuthError {
                error: "invalid_client".to_string(),
                error_description: Some("Invalid client ID format".to_string()),
            })?;

            let client_secret = req.client_secret.as_ref().ok_or_else(|| OAuthError {
                error: "invalid_request".to_string(),
                error_description: Some("Missing client_secret".to_string()),
            })?;

            let client = storage
                .get_user_pool_client(&client_id)
                .await
                .ok_or_else(|| OAuthError {
                    error: "invalid_client".to_string(),
                    error_description: Some("Client not found".to_string()),
                })?;

            if client.client_secret.as_ref() != Some(client_secret) {
                return Err(OAuthError {
                    error: "invalid_client".to_string(),
                    error_description: Some("Invalid client credentials".to_string()),
                });
            }

            if !client.allowed_oauth_flows_user_pool_client {
                return Err(OAuthError {
                    error: "unauthorized_client".to_string(),
                    error_description: Some(
                        "OAuth flows are not enabled for this client".to_string(),
                    ),
                });
            }

            if !client
                .allowed_oauth_flows
                .contains(&OAuthFlow::ClientCredentials)
            {
                return Err(OAuthError {
                    error: "unauthorized_client".to_string(),
                    error_description: Some(
                        "Client credentials flow not allowed for this client".to_string(),
                    ),
                });
            }

            // Omitted scope means every scope configured on the client.
            let scopes = match req.scope.as_deref().map(str::trim) {
                Some(raw) if !raw.is_empty() => parse_scopes(Some(raw), ""),
                _ => client.allowed_oauth_scopes.clone(),
            };
            validate_requested_scopes(&client.allowed_oauth_scopes, &scopes)?;

            let access_expiry = resolve_access_token_expiry(&client);

            let access_token =
                generate_client_credentials_access_token(&client_id, &scopes, access_expiry)
                    .map_err(|e| OAuthError {
                        error: "server_error".to_string(),
                        error_description: Some(e),
                    })?;

            Ok(Json(TokenResponse {
                access_token,
                token_type: "Bearer".to_string(),
                expires_in: access_expiry.num_seconds(),
                refresh_token: None,
                id_token: None,
                scope: if scopes.is_empty() {
                    None
                } else {
                    Some(scopes.join(" "))
                },
            }))
        }
        _ => Err(OAuthError {
            error: "unsupported_grant_type".to_string(),
            error_description: Some(format!("Grant type '{}' is not supported", req.grant_type)),
        }),
    }
}

/// UserInfo response
#[derive(Debug, Serialize)]
pub struct UserInfoResponse {
    pub sub: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_verified: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phone_number: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phone_number_verified: Option<bool>,
    pub username: String,
    #[serde(rename = "cognito:groups", skip_serializing_if = "Vec::is_empty")]
    pub groups: Vec<String>,
}

/// Bearer-token failure per RFC 6750 §3: `401` plus a `WWW-Authenticate`
/// challenge, which is what SDKs key their token-refresh logic on.
fn invalid_token_response(description: impl Into<String>) -> Response {
    let description = description.into();
    let mut response = OAuthError {
        error: "invalid_token".to_string(),
        error_description: Some(description.clone()),
    }
    .into_response();
    *response.status_mut() = StatusCode::UNAUTHORIZED;
    let challenge = format!(
        "Bearer error=\"invalid_token\", error_description=\"{}\"",
        description.replace('"', "'")
    );
    if let Ok(value) = HeaderValue::from_str(&challenge) {
        response
            .headers_mut()
            .insert(header::WWW_AUTHENTICATE, value);
    }
    response
}

/// GET /oauth2/userInfo - UserInfo endpoint
pub async fn userinfo(
    State(storage): State<Storage>,
    headers: HeaderMap,
) -> Result<Json<UserInfoResponse>, Response> {
    // Extract Bearer token from Authorization header
    let auth_header = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| invalid_token_response("Missing Authorization header"))?;

    let token = auth_header
        .strip_prefix("Bearer ")
        .ok_or_else(|| invalid_token_response("Invalid Authorization header format"))?;

    // Same checks as the cognito-idp handlers: signature, expiry and
    // revocation via GlobalSignOut / AdminUserGlobalSignOut.
    let user_id = verify_and_extract_active_user_id(&storage, token)
        .await
        .map_err(invalid_token_response)?;

    let user = storage
        .get_user(&user_id)
        .await
        .ok_or_else(|| invalid_token_response("User not found"))?;

    let groups = storage.get_groups_for_user(&user_id).await;

    Ok(Json(UserInfoResponse {
        sub: user.id.to_string(),
        email_verified: user.email_verified(),
        phone_number_verified: user.phone_number_verified(),
        email: user.email,
        phone_number: user.phone_number,
        username: user.username,
        groups,
    }))
}

/// GET /logout - Hosted UI logout endpoint
pub async fn logout(
    State(storage): State<Storage>,
    Query(params): Query<LogoutParams>,
) -> Result<impl IntoResponse, OAuthError> {
    let parsed_client_id = ClientId::new(&params.client_id).map_err(|_| OAuthError {
        error: "invalid_client".to_string(),
        error_description: Some("Invalid client ID format".to_string()),
    })?;

    let client = storage
        .get_user_pool_client(&parsed_client_id)
        .await
        .ok_or_else(|| OAuthError {
            error: "invalid_client".to_string(),
            error_description: Some("Client not found".to_string()),
        })?;

    let redirect_target = params
        .logout_uri
        .as_deref()
        .or(params.redirect_uri.as_deref())
        .ok_or_else(|| OAuthError {
            error: "invalid_request".to_string(),
            error_description: Some("Missing logout_uri parameter".to_string()),
        })?;

    if !client.logout_urls.is_empty()
        && !client.logout_urls.iter().any(|url| url == redirect_target)
    {
        return Err(OAuthError {
            error: "invalid_request".to_string(),
            error_description: Some("Invalid logout_uri".to_string()),
        });
    }

    Ok(Redirect::to(redirect_target))
}

/// GET /.well-known/openid-configuration - OpenID Connect Discovery
pub async fn openid_configuration() -> Json<Value> {
    let base_url = issuer_base_url();

    Json(json!({
        "issuer": base_url.clone(),
        "authorization_endpoint": format!("{}/oauth2/authorize", base_url),
        "token_endpoint": format!("{}/oauth2/token", base_url),
        "userinfo_endpoint": format!("{}/oauth2/userInfo", base_url),
        "jwks_uri": format!("{}/.well-known/jwks.json", base_url),
        "response_types_supported": ["code", "token"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "scopes_supported": ["openid", "email", "phone", "profile", "aws.cognito.signin.user.admin"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
        "claims_supported": [
            "sub", "aud", "email", "email_verified", "exp", "iat", "iss",
            "phone_number", "phone_number_verified", "cognito:username", "cognito:groups"
        ],
        "code_challenge_methods_supported": ["S256", "plain"],
        "grant_types_supported": ["authorization_code", "refresh_token", "client_credentials"]
    }))
}

/// Generate a simple login HTML page
fn generate_login_html(params: &AuthorizeParams) -> String {
    let state_input = params
        .state
        .as_ref()
        .map(|s| {
            format!(
                r#"<input type="hidden" name="state" value="{}">"#,
                html_escape(s)
            )
        })
        .unwrap_or_default();
    let nonce_input = params
        .nonce
        .as_ref()
        .map(|s| {
            format!(
                r#"<input type="hidden" name="nonce" value="{}">"#,
                html_escape(s)
            )
        })
        .unwrap_or_default();
    let code_challenge_input = params
        .code_challenge
        .as_ref()
        .map(|s| {
            format!(
                r#"<input type="hidden" name="code_challenge" value="{}"><input type="hidden" name="code_challenge_method" value="{}">"#,
                html_escape(s),
                html_escape(params.code_challenge_method.as_deref().unwrap_or("S256"))
            )
        })
        .unwrap_or_default();

    format!(
        r#"<!DOCTYPE html>
<html>
<head>
    <title>Sign In - Cognito Emulator</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
               display: flex; justify-content: center; align-items: center; height: 100vh;
               margin: 0; background: #f5f5f5; }}
        .container {{ background: white; padding: 40px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); width: 300px; }}
        h1 {{ margin: 0 0 20px; font-size: 24px; text-align: center; }}
        input {{ width: 100%; padding: 12px; margin: 8px 0; border: 1px solid #ddd; border-radius: 4px; box-sizing: border-box; }}
        button {{ width: 100%; padding: 12px; background: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 16px; }}
        button:hover {{ background: #0056b3; }}
        .error {{ color: #dc3545; text-align: center; margin-top: 10px; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Sign In</h1>
        <form method="GET" action="/oauth2/authorize">
            <input type="hidden" name="response_type" value="{}">
            <input type="hidden" name="client_id" value="{}">
            <input type="hidden" name="redirect_uri" value="{}">
            <input type="hidden" name="scope" value="{}">
            {}
            {}
            {}
            <input type="text" name="username" placeholder="Username" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit">Sign In</button>
        </form>
    </div>
</body>
</html>"#,
        html_escape(&params.response_type),
        html_escape(&params.client_id),
        html_escape(&params.redirect_uri),
        html_escape(params.scope.as_deref().unwrap_or("openid")),
        state_input,
        nonce_input,
        code_challenge_input,
    )
}
