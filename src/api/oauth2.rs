//! OAuth 2.0 / OpenID Connect endpoints
//!
//! The endpoints of a Cognito managed login domain: `/oauth2/authorize`,
//! `/oauth2/token`, `/oauth2/userInfo`, `/oauth2/revoke`, `/logout`, and
//! OpenID Connect discovery.

use axum::{
    Form, Json,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{
    action::user::{
        auth_flow::{group_claims, new_session_token},
        helpers::{store_srp_verifier, verify_password},
    },
    error::OAuthError,
    jwt::{
        AccessTokenRequest, IdTokenRequest, TokenSession, attribute_in_scopes,
        generate_client_credentials_access_token, get_jwks, issue_access_token, issue_id_token,
        issuer_base_url, resolve_access_token_expiry, resolve_id_token_expiry,
        resolve_refresh_token_expiry, user_pool_issuer, verify_access_token,
    },
    storage::Storage,
    types::{
        AuthorizationCode, ClientId, MfaConfiguration, OAuthFlow, RefreshToken,
        RefreshTokenRotationFeature, User, UserPool, UserPoolClient, UserPoolId, UserStatus,
    },
};

/// `TemporaryPasswordValidityDays` when the user pool sets none.
const DEFAULT_TEMPORARY_PASSWORD_DAYS: i64 = 7;

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
    #[serde(default)]
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

/// Revocation endpoint request body
#[derive(Debug, Deserialize)]
pub struct RevokeRequest {
    #[serde(default)]
    pub token: Option<String>,
    #[serde(default)]
    pub client_id: Option<String>,
    #[serde(default)]
    pub client_secret: Option<String>,
}

/// Logout endpoint query parameters
#[derive(Debug, Deserialize)]
pub struct LogoutParams {
    #[serde(default)]
    pub client_id: Option<String>,
    #[serde(default)]
    pub logout_uri: Option<String>,
    #[serde(default)]
    pub redirect_uri: Option<String>,
    #[serde(default)]
    pub response_type: Option<String>,
    #[serde(default)]
    pub scope: Option<String>,
    #[serde(default)]
    pub state: Option<String>,
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
}

fn oauth_error(error: &str, description: impl Into<String>) -> OAuthError {
    OAuthError {
        error: error.to_string(),
        error_description: Some(description.into()),
    }
}

fn server_error(description: String) -> OAuthError {
    oauth_error("server_error", description)
}

/// `302 Found`, the redirect Cognito's endpoints answer with.
pub(crate) fn redirect_found(location: &str) -> Response {
    (
        StatusCode::FOUND,
        [(header::LOCATION, location.to_string())],
    )
        .into_response()
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

fn parse_scopes(raw: &str) -> Vec<String> {
    raw.split_whitespace().map(String::from).collect()
}

fn validate_requested_scopes(
    allowed_scopes: &[String],
    requested_scopes: &[String],
) -> Result<(), OAuthError> {
    if let Some(scope) = requested_scopes
        .iter()
        .find(|scope| !allowed_scopes.contains(scope))
    {
        return Err(oauth_error(
            "invalid_scope",
            format!("Scope '{scope}' is not allowed for this client"),
        ));
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

/// The parameters of an authorization request as they arrive, from the
/// authorize endpoint or from a managed login form.
pub(crate) struct AuthorizationParams<'a> {
    pub client_id: &'a str,
    pub response_type: &'a str,
    pub redirect_uri: &'a str,
    pub scope: Option<&'a str>,
    pub state: Option<&'a str>,
    pub nonce: Option<&'a str>,
    pub code_challenge: Option<&'a str>,
    pub code_challenge_method: Option<&'a str>,
}

/// An authorization request that passed validation against its app client.
pub(crate) struct AuthorizationRequest {
    pub client: UserPoolClient,
    pub pool: UserPool,
    /// `response_type=token` rather than `code`.
    pub implicit: bool,
    pub redirect_uri: String,
    pub scopes: Vec<String>,
    pub state: Option<String>,
    pub nonce: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
}

/// Validate an authorization request.
///
/// The client and the redirect URI are checked first: until both are known
/// to be good, nothing may be sent to the `redirect_uri` the request names.
pub(crate) async fn validate_authorization_request(
    storage: &Storage,
    params: &AuthorizationParams<'_>,
) -> Result<AuthorizationRequest, OAuthError> {
    let client_id = ClientId::new(params.client_id)
        .map_err(|_| oauth_error("invalid_client", "Invalid client ID format"))?;
    let client = storage
        .get_user_pool_client(&client_id)
        .await
        .ok_or_else(|| oauth_error("invalid_client", "Client not found"))?;

    if !client.allowed_oauth_flows_user_pool_client {
        return Err(oauth_error(
            "unauthorized_client",
            "OAuth flows are not enabled for this client",
        ));
    }

    // Cognito redirects only to a URL registered as a callback URL; a client
    // that registered none has nowhere to send a user.
    if !client
        .callback_urls
        .iter()
        .any(|url| url == params.redirect_uri)
    {
        return Err(oauth_error("redirect_mismatch", "Invalid redirect_uri"));
    }

    let pool = storage
        .get_user_pool(&client.user_pool_id)
        .await
        .ok_or_else(|| oauth_error("invalid_client", "Client not found"))?;

    let implicit = match params.response_type {
        "code" => {
            if !client.allowed_oauth_flows.contains(&OAuthFlow::Code) {
                return Err(oauth_error(
                    "unauthorized_client",
                    "Code flow not allowed for this client",
                ));
            }
            false
        }
        "token" => {
            if !client.allowed_oauth_flows.contains(&OAuthFlow::Implicit) {
                return Err(oauth_error(
                    "unauthorized_client",
                    "Implicit flow not allowed for this client",
                ));
            }
            true
        }
        other => {
            return Err(oauth_error(
                "unsupported_response_type",
                format!("Response type '{other}' is not supported"),
            ));
        }
    };

    // A request without `scope` gets every scope the client is allowed.
    let scopes = match params.scope.map(parse_scopes) {
        Some(scopes) if !scopes.is_empty() => {
            validate_requested_scopes(&client.allowed_oauth_scopes, &scopes)?;
            scopes
        }
        _ => client.allowed_oauth_scopes.clone(),
    };
    // Tokens without a scope would read as user pools API tokens.
    if scopes.is_empty() {
        return Err(oauth_error(
            "invalid_scope",
            "The app client allows no OAuth scopes",
        ));
    }

    // S256 is the only PKCE method Cognito supports.
    if let Some(method) = params.code_challenge_method
        && method != "S256"
    {
        return Err(oauth_error(
            "invalid_request",
            "Unsupported code_challenge_method",
        ));
    }

    Ok(AuthorizationRequest {
        client,
        pool,
        implicit,
        redirect_uri: params.redirect_uri.to_string(),
        scopes,
        state: params.state.map(str::to_string),
        nonce: params.nonce.map(str::to_string),
        code_challenge: params.code_challenge.map(str::to_string),
        code_challenge_method: params.code_challenge_method.map(str::to_string),
    })
}

/// Where a correct password leaves a managed login sign-in.
pub(crate) enum SignIn {
    /// The user may be signed in.
    Complete(User),
    /// The password is temporary; the user has to choose a new one first.
    NewPasswordRequired(User),
    /// The account still awaits its confirmation code.
    ConfirmationRequired(User),
    /// An administrator reset the password; the user has to pick a new one
    /// through the forgot-password flow.
    PasswordResetRequired,
}

/// Why managed login refused a username and password.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SignInError {
    IncorrectCredentials,
    Disabled,
    TemporaryPasswordExpired,
    /// The sign-in needs an MFA challenge the hosted pages cannot present.
    MfaUnsupported,
}

impl SignInError {
    /// The message Cognito shows for the failure.
    pub(crate) fn message(self) -> &'static str {
        match self {
            Self::IncorrectCredentials => "Incorrect username or password.",
            Self::Disabled => "User is disabled.",
            Self::TemporaryPasswordExpired => {
                "Temporary password has expired and must be reset by an administrator."
            }
            Self::MfaUnsupported => {
                "This sign-in requires MFA, which the cognitox hosted pages do not support yet. Sign in through the user pools API."
            }
        }
    }
}

fn temporary_password_expired(pool: &UserPool, user: &User) -> bool {
    let days = pool
        .policies
        .as_ref()
        .and_then(|policies| policies.password_policy.as_ref())
        .and_then(|policy| policy.temporary_password_validity_days)
        .map_or(DEFAULT_TEMPORARY_PASSWORD_DAYS, i64::from);
    user.password_set_at
        .is_some_and(|set_at| set_at + Duration::days(days) < Utc::now())
}

/// Check a username and password the way the user pools API does: a
/// disabled user is refused outright, the account state only matters once
/// the password is known to be right.
pub(crate) async fn check_credentials(
    storage: &Storage,
    pool: &UserPool,
    username: &str,
    password: &str,
) -> Result<SignIn, SignInError> {
    // The same names the user pools API accepts: the username, the sub, a
    // sign-in attribute, or a verified alias.
    let user = storage
        .get_user_by_username(&pool.id, username)
        .await
        .ok_or(SignInError::IncorrectCredentials)?;
    if !user.enabled {
        return Err(SignInError::Disabled);
    }
    if !verify_password(password, &user.password_hash) {
        return Err(SignInError::IncorrectCredentials);
    }

    // A user from a snapshot that predates SRP support: now that the
    // password is known, derive its verifier.
    let user = if user.srp_verifier.is_none() {
        let mut user = user;
        store_srp_verifier(&mut user, password);
        storage.update_user(user.clone()).await.unwrap_or(user)
    } else {
        user
    };

    match user.user_status {
        UserStatus::Unconfirmed => Ok(SignIn::ConfirmationRequired(user)),
        UserStatus::ResetRequired => Ok(SignIn::PasswordResetRequired),
        UserStatus::ForceChangePassword => {
            if temporary_password_expired(pool, &user) {
                Err(SignInError::TemporaryPasswordExpired)
            } else {
                Ok(SignIn::NewPasswordRequired(user))
            }
        }
        _ if requires_mfa(storage, pool, &user).await => Err(SignInError::MfaUnsupported),
        _ => Ok(SignIn::Complete(user)),
    }
}

/// Whether Cognito would follow the password with an MFA challenge: the
/// user has a factor enabled, or the user pool requires one.
///
/// The hosted pages have no MFA step yet. Signing such a user in with the
/// password alone would hand out tokens Cognito would not, so the hosted
/// sign-in refuses instead.
pub(crate) async fn requires_mfa(storage: &Storage, pool: &UserPool, user: &User) -> bool {
    pool.mfa_configuration == Some(MfaConfiguration::On)
        || !storage.list_user_auth_factors(&user.id).await.is_empty()
}

/// Tokens issued to a user through the OAuth 2.0 endpoints.
struct UserTokens {
    access_token: String,
    id_token: Option<String>,
    expires_in: i64,
}

/// Issue the access token, and with `openid` the ID token, of one sign-in.
///
/// An empty scope list is a refresh token that came from the user pools
/// API: its tokens keep that API's scope and include an ID token.
async fn issue_user_tokens(
    storage: &Storage,
    client: &UserPoolClient,
    user: &User,
    scopes: &[String],
    session: &TokenSession,
    nonce: Option<&str>,
) -> Result<UserTokens, OAuthError> {
    let groups = group_claims(storage, user).await;
    let access_expiry = resolve_access_token_expiry(client);

    let access_token = issue_access_token(&AccessTokenRequest {
        user,
        client_id: client.client_id.as_str(),
        user_pool_id: &client.user_pool_id,
        groups: &groups,
        session,
        scopes,
        oauth: true,
        expiry: access_expiry,
    })
    .map_err(server_error)?;

    let id_token = if scopes.is_empty() || scopes.iter().any(|scope| scope == "openid") {
        Some(
            issue_id_token(&IdTokenRequest {
                user,
                client_id: client.client_id.as_str(),
                user_pool_id: &client.user_pool_id,
                groups: &groups,
                session,
                nonce,
                access_token: Some(&access_token),
                readable_attributes: &client.read_attributes,
                oauth_scopes: Some(scopes),
                expiry: resolve_id_token_expiry(client),
            })
            .map_err(server_error)?,
        )
    } else {
        None
    };

    Ok(UserTokens {
        access_token,
        id_token,
        expires_in: access_expiry.num_seconds(),
    })
}

/// Finish an authorization for an authenticated user and return the URL to
/// send the browser to: the callback with a `code`, or for the implicit
/// grant with the tokens in the fragment.
pub(crate) async fn complete_authorization(
    storage: &Storage,
    request: &AuthorizationRequest,
    user: &User,
) -> Result<String, OAuthError> {
    let mut redirect_url = request.redirect_uri.clone();

    if request.implicit {
        let session = TokenSession::new(request.client.enable_token_revocation);
        let tokens = issue_user_tokens(
            storage,
            &request.client,
            user,
            &request.scopes,
            &session,
            request.nonce.as_deref(),
        )
        .await?;

        if let Some(id_token) = &tokens.id_token {
            append_fragment_param(&mut redirect_url, "id_token", id_token);
        }
        append_fragment_param(&mut redirect_url, "access_token", &tokens.access_token);
        append_fragment_param(
            &mut redirect_url,
            "expires_in",
            &tokens.expires_in.to_string(),
        );
        append_fragment_param(&mut redirect_url, "token_type", "Bearer");
        if let Some(state) = &request.state {
            append_fragment_param(&mut redirect_url, "state", state);
        }
        return Ok(redirect_url);
    }

    let now = Utc::now();
    let code = Uuid::new_v4().to_string();
    storage
        .save_authorization_code(AuthorizationCode {
            code: code.clone(),
            user_id: user.id,
            client_id: request.client.client_id.clone(),
            redirect_uri: request.redirect_uri.clone(),
            scope: request.scopes.clone(),
            nonce: request.nonce.clone(),
            code_challenge: request.code_challenge.clone(),
            code_challenge_method: request.code_challenge_method.clone(),
            expires_at: now + Duration::minutes(5),
            auth_time: Some(now.timestamp()),
        })
        .await;

    append_query_param(&mut redirect_url, "code", &code);
    if let Some(state) = &request.state {
        append_query_param(&mut redirect_url, "state", state);
    }
    Ok(redirect_url)
}

/// GET /oauth2/authorize - Authorization endpoint
///
/// Shows the sign-in page. As a convenience for tests and the bundled UI, a
/// request that carries `username` and `password` is authenticated directly.
pub async fn authorize(
    State(storage): State<Storage>,
    headers: HeaderMap,
    Query(params): Query<AuthorizeParams>,
) -> Result<Response, OAuthError> {
    let request = validate_authorization_request(
        &storage,
        &AuthorizationParams {
            client_id: &params.client_id,
            response_type: &params.response_type,
            redirect_uri: &params.redirect_uri,
            scope: params.scope.as_deref(),
            state: params.state.as_deref(),
            nonce: params.nonce.as_deref(),
            code_challenge: params.code_challenge.as_deref(),
            code_challenge_method: params.code_challenge_method.as_deref(),
        },
    )
    .await?;

    let (Some(username), Some(password)) = (&params.username, &params.password) else {
        return Ok((
            StatusCode::OK,
            [(header::CONTENT_TYPE, "text/html")],
            generate_login_html(&params),
        )
            .into_response());
    };

    let user = match check_credentials(&storage, &request.pool, username, password).await {
        Ok(SignIn::Complete(user)) => user,
        Ok(SignIn::ConfirmationRequired(_)) => {
            return Err(oauth_error("access_denied", "User is not confirmed."));
        }
        Ok(SignIn::PasswordResetRequired) => {
            return Err(oauth_error(
                "access_denied",
                "Password reset required for the user",
            ));
        }
        Ok(SignIn::NewPasswordRequired(_)) => {
            return Err(oauth_error(
                "access_denied",
                "The user has a temporary password; sign in through /login to set a new one",
            ));
        }
        Err(error) => return Err(oauth_error("access_denied", error.message())),
    };

    let redirect_url = complete_authorization(&storage, &request, &user).await?;
    if !request.implicit && prefers_json_redirect(&headers) {
        return Ok(Json(json!({ "redirectUrl": redirect_url })).into_response());
    }
    Ok(redirect_found(&redirect_url))
}

fn invalid_client() -> OAuthError {
    oauth_error("invalid_client", "Invalid client credentials")
}

fn decode_basic_credential(value: &str) -> Result<String, OAuthError> {
    // RFC 6749 section 2.3.1 uses form encoding inside the Basic credentials.
    urlencoding::decode(&value.replace('+', " "))
        .map(|decoded| decoded.into_owned())
        .map_err(|_| invalid_client())
}

/// Authenticate the client of a token or revocation request, by
/// `client_secret_basic` or `client_secret_post`; a public client only
/// names itself.
async fn authenticate_client(
    storage: &Storage,
    headers: &HeaderMap,
    form_client_id: Option<&str>,
    form_client_secret: Option<&str>,
) -> Result<UserPoolClient, OAuthError> {
    let mut authorization_headers = headers.get_all(header::AUTHORIZATION).iter();
    let authorization = authorization_headers.next();
    if authorization_headers.next().is_some() {
        return Err(oauth_error(
            "invalid_request",
            "Multiple Authorization headers are not allowed",
        ));
    }

    let (client_id, client_secret) = if let Some(authorization) = authorization {
        let (scheme, encoded) = authorization
            .to_str()
            .ok()
            .and_then(|value| value.split_once(' '))
            .ok_or_else(invalid_client)?;
        if !scheme.eq_ignore_ascii_case("Basic") {
            return Err(invalid_client());
        }
        let decoded = STANDARD
            .decode(encoded.trim_start_matches(' '))
            .map_err(|_| invalid_client())?;
        let decoded = String::from_utf8(decoded).map_err(|_| invalid_client())?;
        let (client_id, secret) = decoded.split_once(':').ok_or_else(invalid_client)?;
        let client_id = decode_basic_credential(client_id)?;
        let secret = decode_basic_credential(secret)?;

        // A redundant client_id is permitted, but it must identify the same client.
        if form_client_secret.is_some() || form_client_id.is_some_and(|id| id != client_id) {
            return Err(oauth_error(
                "invalid_request",
                "Conflicting or multiple client authentication methods",
            ));
        }
        (client_id, Some(secret))
    } else {
        let client_id = form_client_id
            .ok_or_else(|| oauth_error("invalid_request", "Missing client_id parameter"))?;
        (
            client_id.to_string(),
            form_client_secret.map(str::to_string),
        )
    };

    let client_id = ClientId::new(&client_id).map_err(|_| invalid_client())?;
    let client = storage
        .get_user_pool_client(&client_id)
        .await
        .ok_or_else(invalid_client)?;
    if client.client_secret != client_secret {
        return Err(invalid_client());
    }
    Ok(client)
}

fn invalid_grant(description: &str) -> OAuthError {
    oauth_error("invalid_grant", description)
}

/// POST /oauth2/token - Token endpoint
pub async fn token(
    State(storage): State<Storage>,
    headers: HeaderMap,
    Form(req): Form<TokenRequest>,
) -> Result<Json<TokenResponse>, OAuthError> {
    let authenticate = || {
        authenticate_client(
            &storage,
            &headers,
            req.client_id.as_deref(),
            req.client_secret.as_deref(),
        )
    };

    match req.grant_type.as_str() {
        "" => Err(oauth_error(
            "invalid_request",
            "Missing grant_type parameter",
        )),
        "authorization_code" => {
            let code = req
                .code
                .as_ref()
                .ok_or_else(|| oauth_error("invalid_request", "Missing code parameter"))?;

            // Authenticate before consuming the one-time authorization code.
            let client = authenticate().await?;

            // The code is single use: taking it out of storage is what makes
            // a replay fail.
            let auth_code = storage
                .delete_authorization_code(code)
                .await
                .ok_or_else(|| invalid_grant("Invalid or expired authorization code"))?;

            if auth_code.expires_at < Utc::now() {
                return Err(invalid_grant("Authorization code expired"));
            }
            if auth_code.client_id != client.client_id {
                return Err(invalid_grant("Client ID mismatch"));
            }
            // The token request has to repeat the redirect URI the code
            // was issued for.
            if req.redirect_uri.as_ref() != Some(&auth_code.redirect_uri) {
                return Err(match req.redirect_uri {
                    Some(_) => invalid_grant("Redirect URI mismatch"),
                    None => oauth_error("invalid_request", "Missing redirect_uri parameter"),
                });
            }

            // Validate PKCE if code_challenge was provided
            if let Some(code_challenge) = &auth_code.code_challenge {
                let code_verifier = req.code_verifier.as_ref().ok_or_else(|| {
                    oauth_error("invalid_request", "Missing code_verifier parameter")
                })?;
                let computed_challenge =
                    URL_SAFE_NO_PAD.encode(Sha256::digest(code_verifier.as_bytes()));
                if &computed_challenge != code_challenge {
                    return Err(invalid_grant("Code verifier mismatch"));
                }
            }

            let user = storage
                .get_user(&auth_code.user_id)
                .await
                .ok_or_else(|| invalid_grant("User not found"))?;
            if !user.enabled {
                return Err(invalid_grant("User is disabled"));
            }

            // The tokens date from the sign-in at the authorize endpoint.
            let mut session = TokenSession::new(client.enable_token_revocation);
            if let Some(auth_time) = auth_code.auth_time {
                session.auth_time = auth_time;
            }
            let tokens = issue_user_tokens(
                &storage,
                &client,
                &user,
                &auth_code.scope,
                &session,
                auth_code.nonce.as_deref(),
            )
            .await?;

            let refresh_token = new_session_token();
            storage
                .save_refresh_token(RefreshToken {
                    token: refresh_token.clone(),
                    user_id: user.id,
                    client_id: client.client_id.clone(),
                    expires_at: Utc::now() + resolve_refresh_token_expiry(&client),
                    origin_jti: session.origin_jti.clone(),
                    auth_time: Some(session.auth_time),
                    scope: auth_code.scope.clone(),
                })
                .await;

            Ok(Json(TokenResponse {
                access_token: tokens.access_token,
                token_type: "Bearer".to_string(),
                expires_in: tokens.expires_in,
                refresh_token: Some(refresh_token),
                id_token: tokens.id_token,
            }))
        }
        "refresh_token" => {
            let refresh_token = req
                .refresh_token
                .as_ref()
                .ok_or_else(|| oauth_error("invalid_request", "Missing refresh_token parameter"))?;

            let client = authenticate().await?;

            // A revoked token is gone from storage, like one never issued.
            let stored_token = storage
                .get_refresh_token(refresh_token)
                .await
                .ok_or_else(|| invalid_grant("Invalid refresh token"))?;

            if stored_token.expires_at < Utc::now() {
                return Err(invalid_grant("Refresh token expired"));
            }
            if client.client_id != stored_token.client_id {
                return Err(invalid_grant("Client ID mismatch"));
            }

            let user = storage
                .get_user(&stored_token.user_id)
                .await
                .ok_or_else(|| invalid_grant("User not found"))?;
            if !user.enabled {
                return Err(invalid_grant("User is disabled"));
            }

            // The new tokens carry the scopes of the original grant. A
            // `scope` parameter can ask for fewer, never for more.
            let scopes = match req.scope.as_deref().map(parse_scopes) {
                Some(requested) if !requested.is_empty() => {
                    validate_requested_scopes(&stored_token.scope, &requested)?;
                    requested
                }
                _ => stored_token.scope.clone(),
            };

            let session =
                TokenSession::resumed(stored_token.origin_jti.clone(), stored_token.auth_time);
            let tokens =
                issue_user_tokens(&storage, &client, &user, &scopes, &session, None).await?;

            // With refresh token rotation every exchange hands out a new
            // refresh token, and the presented one stops working once the
            // grace period ends. Without it the refresh token stays as is.
            let rotation = client
                .refresh_token_rotation
                .as_ref()
                .filter(|rotation| rotation.feature == Some(RefreshTokenRotationFeature::Enabled));
            let rotated = match rotation {
                Some(rotation) => {
                    let replacement = new_session_token();
                    storage
                        .save_refresh_token(RefreshToken {
                            token: replacement.clone(),
                            ..stored_token.clone()
                        })
                        .await;
                    let retired_at = Utc::now()
                        + Duration::seconds(i64::from(
                            rotation.retry_grace_period_seconds.unwrap_or(0),
                        ));
                    if retired_at < stored_token.expires_at {
                        storage
                            .save_refresh_token(RefreshToken {
                                expires_at: retired_at,
                                ..stored_token.clone()
                            })
                            .await;
                    }
                    Some(replacement)
                }
                None => None,
            };

            Ok(Json(TokenResponse {
                access_token: tokens.access_token,
                token_type: "Bearer".to_string(),
                expires_in: tokens.expires_in,
                refresh_token: rotated,
                id_token: tokens.id_token,
            }))
        }
        "client_credentials" => {
            let client = authenticate().await?;
            if client.client_secret.is_none() {
                return Err(invalid_client());
            }

            if !client.allowed_oauth_flows_user_pool_client {
                return Err(oauth_error(
                    "unauthorized_client",
                    "OAuth flows are not enabled for this client",
                ));
            }

            if !client
                .allowed_oauth_flows
                .contains(&OAuthFlow::ClientCredentials)
            {
                return Err(oauth_error(
                    "unauthorized_client",
                    "Client credentials flow not allowed for this client",
                ));
            }

            // A request without `scope` gets every scope the client is
            // allowed.
            let scopes = match req.scope.as_deref().map(parse_scopes) {
                Some(scopes) if !scopes.is_empty() => {
                    validate_requested_scopes(&client.allowed_oauth_scopes, &scopes)?;
                    scopes
                }
                _ => client.allowed_oauth_scopes.clone(),
            };

            let access_expiry = resolve_access_token_expiry(&client);

            let access_token = generate_client_credentials_access_token(
                &client.client_id,
                &client.user_pool_id,
                &scopes,
                access_expiry,
            )
            .map_err(server_error)?;

            Ok(Json(TokenResponse {
                access_token,
                token_type: "Bearer".to_string(),
                expires_in: access_expiry.num_seconds(),
                refresh_token: None,
                id_token: None,
            }))
        }
        other => Err(oauth_error(
            "unsupported_grant_type",
            format!("Grant type '{other}' is not supported"),
        )),
    }
}

/// Whether a token is a JWT, as access and ID tokens are and refresh tokens
/// are not.
fn is_jwt(token: &str) -> bool {
    let mut parts = token.split('.');
    let header = parts.next().unwrap_or_default();
    parts.count() == 2
        && URL_SAFE_NO_PAD
            .decode(header)
            .ok()
            .and_then(|header| serde_json::from_slice::<Value>(&header).ok())
            .is_some_and(|header| header.get("alg").is_some())
}

fn oauth_error_response(status: StatusCode, error: &str, description: &str) -> Response {
    (
        status,
        Json(json!({ "error": error, "error_description": description })),
    )
        .into_response()
}

/// POST /oauth2/revoke - Token revocation endpoint (RFC 7009)
///
/// Revokes a refresh token together with the access and ID tokens of the
/// same sign-in. As Cognito does, it answers 200 for a token that is
/// unknown or already revoked.
pub async fn revoke(
    State(storage): State<Storage>,
    headers: HeaderMap,
    Form(req): Form<RevokeRequest>,
) -> Response {
    let client = match authenticate_client(
        &storage,
        &headers,
        req.client_id.as_deref(),
        req.client_secret.as_deref(),
    )
    .await
    {
        Ok(client) => client,
        // Unlike the token endpoint, revocation reports bad client
        // credentials with 401.
        Err(error) if error.error == "invalid_client" => {
            return oauth_error_response(
                StatusCode::UNAUTHORIZED,
                "invalid_client",
                "Invalid client credentials",
            );
        }
        Err(error) => return error.into_response(),
    };

    let Some(token) = req.token.as_deref().filter(|token| !token.is_empty()) else {
        return oauth_error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Missing token parameter",
        );
    };
    if !client.enable_token_revocation {
        return oauth_error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Token revocation is not enabled for this client",
        );
    }
    if is_jwt(token) {
        return oauth_error_response(
            StatusCode::BAD_REQUEST,
            "unsupported_token_type",
            "Only refresh tokens can be revoked",
        );
    }

    // Only the client a token was issued to can revoke it.
    if let Some(stored) = storage.get_refresh_token(token).await
        && stored.client_id == client.client_id
    {
        storage.delete_refresh_token(token).await;
        // Tokens issued before the emulator recorded `origin_jti` can only
        // be voided for the whole user.
        if stored.origin_jti.is_none() {
            storage
                .invalidate_access_tokens_for_user(&stored.user_id)
                .await;
        }
    }

    StatusCode::OK.into_response()
}

/// Attributes that are never returned as claims of their own.
const INTERNAL_ATTRIBUTES: &[&str] = &["sub", "preferred_mfa_setting"];

/// GET /oauth2/userInfo - UserInfo endpoint
///
/// Returns `sub`, `username`, and the user attributes the access token's
/// scopes cover. Like Cognito, every attribute is a string, including
/// `email_verified` and `phone_number_verified`.
pub async fn userinfo(
    State(storage): State<Storage>,
    headers: axum::http::HeaderMap,
) -> Result<Json<Value>, OAuthError> {
    // Multiple credentials must not be resolved by silently selecting one.
    if headers.get_all(header::AUTHORIZATION).iter().count() > 1 {
        return Err(oauth_error(
            "invalid_request",
            "Multiple Authorization headers are not allowed",
        ));
    }
    let auth_header = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| oauth_error("invalid_request", "Missing Authorization header"))?;

    let token = auth_header
        .split_once(' ')
        .filter(|(scheme, _)| scheme.eq_ignore_ascii_case("Bearer"))
        .map(|(_, token)| token.trim_start_matches(' '))
        .ok_or_else(|| oauth_error("invalid_request", "Invalid Authorization header format"))?;

    // Verify token
    let token_data = verify_access_token(token).map_err(|e| oauth_error("invalid_token", e))?;
    let claims = token_data.claims;
    let has_scope = |scope: &str| {
        claims
            .scope
            .split_whitespace()
            .any(|granted| granted == scope)
    };

    if claims.token_use != "access" || !has_scope("openid") {
        return Err(oauth_error(
            "invalid_token",
            "An access token with openid scope is required",
        ));
    }

    let user_id = uuid::Uuid::parse_str(&claims.sub)
        .map_err(|_| oauth_error("invalid_token", "Invalid user ID in token"))?;

    let user = storage
        .get_user(&user_id)
        .await
        .ok_or_else(|| oauth_error("invalid_token", "User not found"))?;

    if !user.enabled
        || storage
            .is_access_token_revoked(
                &user_id,
                claims.iat,
                claims.cognitox_iat_ms,
                claims.origin_jti.as_deref(),
            )
            .await
    {
        return Err(oauth_error(
            "invalid_token",
            "Access token has been revoked or the user is disabled",
        ));
    }

    // Attributes outside the app client's ReadAttributes stay hidden.
    let readable_attributes = match ClientId::new(&claims.client_id) {
        Ok(client_id) => storage
            .get_user_pool_client(&client_id)
            .await
            .map(|client| client.read_attributes)
            .unwrap_or_default(),
        Err(_) => Vec::new(),
    };
    let readable = |name: &str| {
        readable_attributes.is_empty()
            || readable_attributes
                .iter()
                .any(|attribute| attribute == name)
    };
    let granted_scopes: Vec<String> = claims
        .scope
        .split_whitespace()
        .map(str::to_string)
        .collect();
    let in_scope = |name: &str| attribute_in_scopes(name, &granted_scopes);

    let mut body = Map::new();
    body.insert("sub".to_string(), json!(user.id.to_string()));
    for attribute in &user.attributes {
        let name = attribute.name.as_str();
        if INTERNAL_ATTRIBUTES.contains(&name) || !in_scope(name) || !readable(name) {
            continue;
        }
        if let Some(value) = &attribute.value {
            body.insert(name.to_string(), json!(value));
        }
    }
    // The address and number live on the user record; an unverified one is
    // reported as such even when the attribute was never written.
    for (value, name, verified_name) in [
        (&user.email, "email", "email_verified"),
        (&user.phone_number, "phone_number", "phone_number_verified"),
    ] {
        let Some(value) = value else {
            body.remove(name);
            body.remove(verified_name);
            continue;
        };
        if in_scope(name) && readable(name) {
            body.insert(name.to_string(), json!(value));
        }
        if in_scope(verified_name) && readable(verified_name) {
            body.entry(verified_name.to_string())
                .or_insert_with(|| json!("false"));
        }
    }
    body.insert("username".to_string(), json!(user.username));

    Ok(Json(Value::Object(body)))
}

/// GET /logout - Managed login sign-out endpoint
///
/// Takes `client_id` and either `logout_uri`, one of the client's sign-out
/// URLs to return to, or `redirect_uri` with `response_type`, which sends
/// the user back to the sign-in page for a new authorization.
pub async fn logout(
    State(storage): State<Storage>,
    Query(params): Query<LogoutParams>,
) -> Result<Response, OAuthError> {
    let client_id = params
        .client_id
        .as_deref()
        .ok_or_else(|| oauth_error("invalid_request", "Missing client_id parameter"))?;
    let parsed_client_id = ClientId::new(client_id)
        .map_err(|_| oauth_error("invalid_client", "Invalid client ID format"))?;

    let client = storage
        .get_user_pool_client(&parsed_client_id)
        .await
        .ok_or_else(|| oauth_error("invalid_client", "Client not found"))?;

    if let Some(logout_uri) = params.logout_uri.as_deref() {
        if !client.logout_urls.iter().any(|url| url == logout_uri) {
            return Err(oauth_error("invalid_request", "Invalid logout_uri"));
        }
        return Ok(redirect_found(logout_uri));
    }

    let (Some(redirect_uri), Some(response_type)) = (
        params.redirect_uri.as_deref(),
        params.response_type.as_deref(),
    ) else {
        return Err(oauth_error(
            "invalid_request",
            "Missing logout_uri, or redirect_uri and response_type",
        ));
    };
    if !client.callback_urls.iter().any(|url| url == redirect_uri) {
        return Err(oauth_error("redirect_mismatch", "Invalid redirect_uri"));
    }

    let mut login_url = "/login".to_string();
    append_query_param(&mut login_url, "client_id", client_id);
    append_query_param(&mut login_url, "redirect_uri", redirect_uri);
    append_query_param(&mut login_url, "response_type", response_type);
    if let Some(scope) = &params.scope {
        append_query_param(&mut login_url, "scope", scope);
    }
    if let Some(state) = &params.state {
        append_query_param(&mut login_url, "state", state);
    }
    Ok(redirect_found(&login_url))
}

/// GET /.well-known/openid-configuration - OpenID Connect Discovery
pub async fn openid_configuration(_headers: axum::http::HeaderMap) -> Json<Value> {
    Json(openid_configuration_document(issuer_base_url()))
}

/// GET /{user_pool_id}/.well-known/openid-configuration - OpenID Connect Discovery for a user pool
///
/// Cognito serves discovery under the user pool issuer, so OIDC clients can derive it from `iss`.
pub async fn user_pool_openid_configuration(
    State(storage): State<Storage>,
    Path(user_pool_id): Path<String>,
) -> Result<Json<Value>, UserPoolNotFound> {
    let user_pool_id = find_user_pool_id(&storage, &user_pool_id).await?;
    Ok(Json(openid_configuration_document(user_pool_issuer(
        &user_pool_id,
    ))))
}

/// GET /{user_pool_id}/.well-known/jwks.json - JWKS for a user pool
pub async fn user_pool_jwks(
    State(storage): State<Storage>,
    Path(user_pool_id): Path<String>,
) -> Result<Json<Value>, UserPoolNotFound> {
    find_user_pool_id(&storage, &user_pool_id).await?;
    Ok(Json(get_jwks()))
}

/// 404 for a user pool path whose pool does not exist
pub struct UserPoolNotFound(String);

impl IntoResponse for UserPoolNotFound {
    fn into_response(self) -> Response {
        let message = format!("User pool {} does not exist.", self.0);
        (StatusCode::NOT_FOUND, Json(json!({ "message": message }))).into_response()
    }
}

async fn find_user_pool_id(storage: &Storage, raw: &str) -> Result<UserPoolId, UserPoolNotFound> {
    let not_found = || UserPoolNotFound(raw.to_string());
    let user_pool_id = UserPoolId::new(raw).map_err(|_| not_found())?;
    storage
        .get_user_pool(&user_pool_id)
        .await
        .ok_or_else(not_found)?;
    Ok(user_pool_id)
}

/// The discovery document, with the members Cognito publishes. The issuer
/// and keys belong to the user pool; the endpoints are the managed login
/// domain's, which here is the emulator's base URL.
fn openid_configuration_document(issuer: String) -> Value {
    let base_url = issuer_base_url();

    json!({
        "authorization_endpoint": format!("{base_url}/oauth2/authorize"),
        "end_session_endpoint": format!("{base_url}/logout"),
        "id_token_signing_alg_values_supported": ["RS256"],
        "issuer": issuer,
        "jwks_uri": format!("{issuer}/.well-known/jwks.json"),
        "response_types_supported": ["code", "token"],
        "revocation_endpoint": format!("{base_url}/oauth2/revoke"),
        "scopes_supported": ["openid", "email", "phone", "profile"],
        "subject_types_supported": ["public"],
        "token_endpoint": format!("{base_url}/oauth2/token"),
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
        "userinfo_endpoint": format!("{base_url}/oauth2/userInfo")
    })
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
        html_escape(params.scope.as_deref().unwrap_or_default()),
        state_input,
        nonce_input,
        code_challenge_input,
    )
}
