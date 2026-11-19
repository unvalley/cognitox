//! JWT token generation and validation
//!
//! Generates RS256 signed JWT tokens compatible with AWS Cognito format.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{Duration, Utc};
use jsonwebtoken::{
    Algorithm, DecodingKey, EncodingKey, Header, TokenData, Validation, decode, encode,
};
use rsa::pkcs1::{
    DecodeRsaPrivateKey, DecodeRsaPublicKey, EncodeRsaPrivateKey, EncodeRsaPublicKey,
};
use rsa::pkcs8::LineEnding;
use rsa::traits::PublicKeyParts;
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fs, sync::OnceLock};

use crate::types::{ClientId, TokenValidityUnit, User, UserPoolClient, UserPoolId};

/// Global JWT key pair (generated once at startup)
static JWT_KEYS: OnceLock<JwtKeys> = OnceLock::new();
static JWT_ISSUER_BASE_URL: OnceLock<String> = OnceLock::new();
const DEFAULT_ISSUER_BASE_URL: &str = "http://localhost:9229";

/// RSA key pair for JWT signing
pub struct JwtKeys {
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
    key_id: String,
    public_key_n: String,
    public_key_e: String,
}

impl JwtKeys {
    fn from_rsa_keys(
        private_key: RsaPrivateKey,
        public_key: RsaPublicKey,
        key_id: String,
    ) -> Result<Self, String> {
        let private_pem = private_key
            .to_pkcs1_pem(LineEnding::LF)
            .map_err(|e| format!("Failed to encode private key: {e}"))?;
        let public_pem = public_key
            .to_pkcs1_pem(LineEnding::LF)
            .map_err(|e| format!("Failed to encode public key: {e}"))?;

        let encoding_key = EncodingKey::from_rsa_pem(private_pem.as_bytes())
            .map_err(|e| format!("Invalid private key PEM: {e}"))?;
        let decoding_key = DecodingKey::from_rsa_pem(public_pem.as_bytes())
            .map_err(|e| format!("Invalid public key PEM: {e}"))?;

        let n_bytes = public_key.n().to_bytes_be();
        let e_bytes = public_key.e().to_bytes_be();

        Ok(Self {
            encoding_key,
            decoding_key,
            key_id,
            public_key_n: URL_SAFE_NO_PAD.encode(&n_bytes),
            public_key_e: URL_SAFE_NO_PAD.encode(&e_bytes),
        })
    }

    fn load_pem_from_env(direct_var: &str, path_var: &str) -> Result<Option<String>, String> {
        if let Ok(pem) = std::env::var(direct_var) {
            return Ok(Some(pem));
        }
        if let Ok(path) = std::env::var(path_var) {
            let pem = fs::read_to_string(&path)
                .map_err(|e| format!("Failed to read {path_var} ({path}): {e}"))?;
            return Ok(Some(pem));
        }
        Ok(None)
    }

    fn from_env() -> Result<Option<Self>, String> {
        let private_pem = Self::load_pem_from_env(
            "COGNITOX_JWT_PRIVATE_KEY_PEM",
            "COGNITOX_JWT_PRIVATE_KEY_PATH",
        )?;
        let public_pem = Self::load_pem_from_env(
            "COGNITOX_JWT_PUBLIC_KEY_PEM",
            "COGNITOX_JWT_PUBLIC_KEY_PATH",
        )?;

        if private_pem.is_none() && public_pem.is_none() {
            return Ok(None);
        }

        let private_pem = private_pem.ok_or_else(|| {
            "JWT private key is required when configuring external JWT keys".to_string()
        })?;
        let private_key = RsaPrivateKey::from_pkcs1_pem(&private_pem)
            .map_err(|e| format!("Failed to parse configured private key: {e}"))?;

        let public_key = if let Some(public_pem) = public_pem {
            RsaPublicKey::from_pkcs1_pem(&public_pem)
                .map_err(|e| format!("Failed to parse configured public key: {e}"))?
        } else {
            RsaPublicKey::from(&private_key)
        };

        let key_id = std::env::var("COGNITOX_JWT_KEY_ID")
            .unwrap_or_else(|_| uuid::Uuid::new_v4().to_string());

        Self::from_rsa_keys(private_key, public_key, key_id).map(Some)
    }

    /// Generate a new RSA key pair
    fn generate() -> Self {
        let mut rng = rand::thread_rng();

        // Generate 2048-bit RSA key
        let private_key =
            RsaPrivateKey::new(&mut rng, 2048).expect("Failed to generate RSA key pair");
        let public_key = RsaPublicKey::from(&private_key);
        let key_id = uuid::Uuid::new_v4().to_string();

        Self::from_rsa_keys(private_key, public_key, key_id)
            .expect("Failed to create JWT keys from generated RSA key pair")
    }
}

/// Get or initialize the global JWT keys
pub fn get_jwt_keys() -> &'static JwtKeys {
    JWT_KEYS.get_or_init(|| {
        JwtKeys::from_env()
            .unwrap_or_else(|e| panic!("Failed to load configured JWT keys: {e}"))
            .unwrap_or_else(JwtKeys::generate)
    })
}

fn normalize_issuer_base_url(value: impl Into<String>) -> String {
    value.into().trim_end_matches('/').to_string()
}

/// Override the issuer base URL used in generated tokens and discovery metadata.
pub fn set_issuer_base_url(value: impl Into<String>) -> Result<(), String> {
    JWT_ISSUER_BASE_URL
        .set(normalize_issuer_base_url(value))
        .map_err(|_| "JWT issuer base URL has already been initialized".to_string())
}

/// Return the issuer base URL used for generated OIDC tokens.
pub fn issuer_base_url() -> String {
    JWT_ISSUER_BASE_URL
        .get()
        .cloned()
        .or_else(|| std::env::var("COGNITOX_ISSUER_BASE_URL").ok())
        .map(normalize_issuer_base_url)
        .unwrap_or_else(|| DEFAULT_ISSUER_BASE_URL.to_string())
}

/// Return the `iss` claim for tokens issued by a user pool.
///
/// Mirrors Cognito, whose issuer is `https://cognito-idp.<region>.amazonaws.com/<user pool id>`.
pub fn user_pool_issuer(user_pool_id: &UserPoolId) -> String {
    format!("{}/{}", issuer_base_url(), user_pool_id)
}

/// Claims for ID Token
#[derive(Debug, Serialize, Deserialize)]
pub struct IdTokenClaims {
    // Standard claims
    pub sub: String,
    pub aud: String,
    pub iss: String,
    pub iat: i64,
    pub exp: i64,
    pub auth_time: i64,
    pub token_use: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub jti: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub origin_jti: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub event_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub nonce: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub at_hash: Option<String>,

    // Cognito-specific claims
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub email_verified: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub phone_number: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub phone_number_verified: Option<bool>,
    #[serde(rename = "cognito:username")]
    pub cognito_username: String,
    #[serde(
        rename = "cognito:groups",
        skip_serializing_if = "Vec::is_empty",
        default
    )]
    pub cognito_groups: Vec<String>,
    #[serde(
        rename = "cognito:roles",
        skip_serializing_if = "Vec::is_empty",
        default
    )]
    pub cognito_roles: Vec<String>,
    #[serde(
        rename = "cognito:preferred_role",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub cognito_preferred_role: Option<String>,

    /// The user's remaining attributes (`name`, `custom:*`, ...), which
    /// Cognito copies into the ID token as string claims.
    #[serde(flatten)]
    pub attributes: BTreeMap<String, serde_json::Value>,
}

/// Claims for Access Token
#[derive(Debug, Serialize, Deserialize)]
pub struct AccessTokenClaims {
    // Standard claims
    pub sub: String,
    pub iss: String,
    pub iat: i64,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub cognitox_iat_ms: Option<i64>,
    pub exp: i64,
    pub auth_time: i64,
    pub token_use: String,
    pub client_id: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub jti: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub origin_jti: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub event_id: Option<String>,
    /// `2` on tokens issued through the OAuth 2.0 endpoints.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub version: Option<u8>,

    // Cognito-specific claims
    #[serde(
        rename = "cognito:groups",
        skip_serializing_if = "Vec::is_empty",
        default
    )]
    pub cognito_groups: Vec<String>,
    pub scope: String,
    /// Absent on client credentials tokens, which have no user.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub username: Option<String>,
}

/// The sign-in a set of tokens descends from.
///
/// Tokens obtained with a refresh token keep the `auth_time` and
/// `origin_jti` of the authentication that produced that refresh token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenSession {
    /// Identifies the originating authentication; present when the app
    /// client has token revocation enabled.
    pub origin_jti: Option<String>,
    pub event_id: String,
    pub auth_time: i64,
}

impl TokenSession {
    /// A session for an authentication happening now.
    pub fn new(token_revocation_enabled: bool) -> Self {
        Self {
            origin_jti: token_revocation_enabled.then(|| uuid::Uuid::new_v4().to_string()),
            event_id: uuid::Uuid::new_v4().to_string(),
            auth_time: Utc::now().timestamp(),
        }
    }

    /// A session for tokens derived from an earlier authentication.
    pub fn resumed(origin_jti: Option<String>, auth_time: Option<i64>) -> Self {
        Self {
            origin_jti,
            event_id: uuid::Uuid::new_v4().to_string(),
            auth_time: auth_time.unwrap_or_else(|| Utc::now().timestamp()),
        }
    }
}

/// Group membership as the tokens present it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GroupClaims {
    /// `cognito:groups`
    pub groups: Vec<String>,
    /// `cognito:roles`: the IAM role of each group that has one.
    pub roles: Vec<String>,
    /// `cognito:preferred_role`: the role of the group with the lowest
    /// precedence value.
    pub preferred_role: Option<String>,
}

impl GroupClaims {
    pub fn from_names(groups: &[String]) -> Self {
        Self {
            groups: groups.to_vec(),
            ..Self::default()
        }
    }

    /// Order groups the way Cognito does and derive the role claims.
    pub fn from_groups(mut groups: Vec<crate::types::Group>) -> Self {
        groups.sort_by(|left, right| {
            let precedence = |group: &crate::types::Group| group.precedence.unwrap_or(i32::MAX);
            precedence(left)
                .cmp(&precedence(right))
                .then_with(|| left.group_name.cmp(&right.group_name))
        });
        let roles: Vec<String> = groups
            .iter()
            .filter_map(|group| group.role_arn.clone())
            .collect();
        let preferred_role = groups
            .iter()
            .find(|group| group.precedence.is_some())
            .and_then(|group| group.role_arn.clone())
            .or_else(|| (roles.len() == 1).then(|| roles[0].clone()));
        Self {
            groups: groups.into_iter().map(|group| group.group_name).collect(),
            roles,
            preferred_role,
        }
    }
}

/// Attributes that never become ID token claims of their own.
const NON_CLAIM_ATTRIBUTES: &[&str] = &[
    "sub",
    "email",
    "email_verified",
    "phone_number",
    "phone_number_verified",
    // Emulator bookkeeping stored next to the real attributes.
    "preferred_mfa_setting",
];

fn attribute_is_true(user: &User, name: &str) -> bool {
    user.attributes
        .iter()
        .any(|attribute| attribute.name == name && attribute.value.as_deref() == Some("true"))
}

fn sign<T: Serialize>(claims: &T, what: &str) -> Result<String, String> {
    let keys = get_jwt_keys();
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(keys.key_id.clone());
    // Cognito's JOSE header carries only `kid` and `alg`.
    header.typ = None;

    encode(&header, claims, &keys.encoding_key).map_err(|e| format!("Failed to encode {what}: {e}"))
}

/// `at_hash`: the left half of the access token's SHA-256, base64url encoded.
pub fn access_token_hash(access_token: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(access_token.as_bytes());
    URL_SAFE_NO_PAD.encode(&digest[..digest.len() / 2])
}

/// Everything that goes into an ID token.
pub struct IdTokenRequest<'a> {
    pub user: &'a User,
    pub client_id: &'a str,
    pub user_pool_id: &'a UserPoolId,
    pub groups: &'a GroupClaims,
    pub session: &'a TokenSession,
    /// The value the client sent to the authorize endpoint. Like Cognito,
    /// only tokens issued for that authorization carry it.
    pub nonce: Option<&'a str>,
    /// The access token issued alongside, for `at_hash` (OAuth 2.0 only).
    pub access_token: Option<&'a str>,
    /// The app client's `ReadAttributes`; empty means every attribute.
    pub readable_attributes: &'a [String],
    /// The OAuth scopes granted with the token, which bound the attributes
    /// it releases (see [`attribute_in_scopes`]). `None` for user pools API
    /// authentication, which is not scoped.
    pub oauth_scopes: Option<&'a [String]>,
    pub expiry: Duration,
}

/// Whether the granted OpenID Connect scopes release a user attribute.
///
/// With `openid` alone Cognito releases every attribute the app client can
/// read. Once `email`, `phone`, or `profile` is requested, each attribute
/// needs its scope: `email` covers the address and its verification flag,
/// `phone` likewise, and `profile` everything else.
pub fn attribute_in_scopes(name: &str, scopes: &[String]) -> bool {
    let granted = |scope: &str| scopes.iter().any(|granted| granted == scope);
    if !(granted("email") || granted("phone") || granted("profile")) {
        return true;
    }
    match name {
        "email" | "email_verified" => granted("email"),
        "phone_number" | "phone_number_verified" => granted("phone"),
        _ => granted("profile"),
    }
}

/// Generate an ID token.
pub fn issue_id_token(request: &IdTokenRequest<'_>) -> Result<String, String> {
    let user = request.user;
    let now = Utc::now();
    let readable = |name: &str| {
        (request.readable_attributes.is_empty()
            || request
                .readable_attributes
                .iter()
                .any(|attribute| attribute == name))
            && request
                .oauth_scopes
                .is_none_or(|scopes| attribute_in_scopes(name, scopes))
    };

    let email = user.email.clone().filter(|_| readable("email"));
    let phone_number = user
        .phone_number
        .clone()
        .filter(|_| readable("phone_number"));
    let attributes = user
        .attributes
        .iter()
        .filter(|attribute| {
            !NON_CLAIM_ATTRIBUTES.contains(&attribute.name.as_str()) && readable(&attribute.name)
        })
        .filter_map(|attribute| {
            let value = attribute.value.clone()?;
            Some((attribute.name.clone(), serde_json::Value::String(value)))
        })
        .collect();

    let claims = IdTokenClaims {
        sub: user.id.to_string(),
        aud: request.client_id.to_string(),
        iss: user_pool_issuer(request.user_pool_id),
        iat: now.timestamp(),
        exp: (now + request.expiry).timestamp(),
        auth_time: request.session.auth_time,
        token_use: "id".to_string(),
        jti: Some(uuid::Uuid::new_v4().to_string()),
        origin_jti: request.session.origin_jti.clone(),
        event_id: Some(request.session.event_id.clone()),
        nonce: request.nonce.map(str::to_string),
        at_hash: request.access_token.map(access_token_hash),
        email_verified: (email.is_some() && readable("email_verified"))
            .then(|| attribute_is_true(user, "email_verified")),
        email,
        phone_number_verified: (phone_number.is_some() && readable("phone_number_verified"))
            .then(|| attribute_is_true(user, "phone_number_verified")),
        phone_number,
        cognito_username: user.username.clone(),
        cognito_groups: request.groups.groups.clone(),
        cognito_roles: request.groups.roles.clone(),
        cognito_preferred_role: request.groups.preferred_role.clone(),
        attributes,
    };

    sign(&claims, "ID token")
}

/// Everything that goes into a user's access token.
pub struct AccessTokenRequest<'a> {
    pub user: &'a User,
    pub client_id: &'a str,
    pub user_pool_id: &'a UserPoolId,
    pub groups: &'a GroupClaims,
    pub session: &'a TokenSession,
    /// Empty for user pools API authentication, which grants only
    /// `aws.cognito.signin.user.admin`.
    pub scopes: &'a [String],
    /// Whether the OAuth 2.0 endpoints issue the token.
    pub oauth: bool,
    pub expiry: Duration,
}

/// Generate an access token for a user.
pub fn issue_access_token(request: &AccessTokenRequest<'_>) -> Result<String, String> {
    let now = Utc::now();
    let scope = if request.scopes.is_empty() {
        "aws.cognito.signin.user.admin".to_string()
    } else {
        request.scopes.join(" ")
    };

    let claims = AccessTokenClaims {
        sub: request.user.id.to_string(),
        iss: user_pool_issuer(request.user_pool_id),
        iat: now.timestamp(),
        cognitox_iat_ms: Some(now.timestamp_millis()),
        exp: (now + request.expiry).timestamp(),
        auth_time: request.session.auth_time,
        token_use: "access".to_string(),
        client_id: request.client_id.to_string(),
        jti: Some(uuid::Uuid::new_v4().to_string()),
        origin_jti: request.session.origin_jti.clone(),
        event_id: Some(request.session.event_id.clone()),
        version: request.oauth.then_some(2),
        cognito_groups: request.groups.groups.clone(),
        scope,
        username: Some(request.user.username.clone()),
    };

    sign(&claims, "access token")
}

/// Generate ID Token
///
/// `nonce` is the value the client sent to the authorize endpoint. Like
/// Cognito, only tokens issued for that authorization carry it.
pub fn generate_id_token(
    user: &User,
    client_id: &str,
    user_pool_id: &UserPoolId,
    groups: &[String],
    nonce: Option<&str>,
    expiry: Duration,
) -> Result<String, String> {
    issue_id_token(&IdTokenRequest {
        user,
        client_id,
        user_pool_id,
        groups: &GroupClaims::from_names(groups),
        session: &TokenSession::new(true),
        nonce,
        access_token: None,
        readable_attributes: &[],
        oauth_scopes: None,
        expiry,
    })
}

/// Generate Access Token
pub fn generate_access_token(
    user: &User,
    client_id: &str,
    user_pool_id: &UserPoolId,
    groups: &[String],
    scopes: &[String],
    expiry: Duration,
) -> Result<String, String> {
    issue_access_token(&AccessTokenRequest {
        user,
        client_id,
        user_pool_id,
        groups: &GroupClaims::from_names(groups),
        session: &TokenSession::new(true),
        scopes,
        oauth: false,
        expiry,
    })
}

/// Generate an OAuth client credentials access token.
///
/// Like Cognito's, it has the app client as its subject and carries no
/// `username`.
pub fn generate_client_credentials_access_token(
    client_id: &ClientId,
    user_pool_id: &UserPoolId,
    scopes: &[String],
    expiry: Duration,
) -> Result<String, String> {
    let now = Utc::now();
    let client_id = client_id.as_str();

    let claims = AccessTokenClaims {
        sub: client_id.to_string(),
        iss: user_pool_issuer(user_pool_id),
        iat: now.timestamp(),
        cognitox_iat_ms: Some(now.timestamp_millis()),
        exp: (now + expiry).timestamp(),
        auth_time: now.timestamp(),
        token_use: "access".to_string(),
        client_id: client_id.to_string(),
        jti: Some(uuid::Uuid::new_v4().to_string()),
        origin_jti: None,
        event_id: None,
        version: Some(2),
        cognito_groups: Vec::new(),
        scope: scopes.join(" "),
        username: None,
    };

    sign(&claims, "client credentials access token")
}

/// Why an access token was rejected.
#[derive(Debug)]
pub enum AccessTokenError {
    /// The signature is valid but `exp` has passed.
    Expired,
    Invalid(String),
}

impl std::fmt::Display for AccessTokenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Expired => write!(f, "Token validation failed: ExpiredSignature"),
            Self::Invalid(reason) => write!(f, "Token validation failed: {reason}"),
        }
    }
}

/// Verify and decode an access token, telling an expired token apart from an
/// otherwise invalid one.
pub fn decode_access_token(token: &str) -> Result<TokenData<AccessTokenClaims>, AccessTokenError> {
    let keys = get_jwt_keys();

    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_required_spec_claims(&["sub", "iss", "exp", "iat"]);
    validation.validate_exp = true;
    // Cognito allows no clock skew on its own tokens.
    validation.leeway = 0;
    // Don't validate audience for access tokens (they use client_id instead)
    validation.validate_aud = false;

    decode::<AccessTokenClaims>(token, &keys.decoding_key, &validation).map_err(|e| {
        match e.kind() {
            jsonwebtoken::errors::ErrorKind::ExpiredSignature => AccessTokenError::Expired,
            _ => AccessTokenError::Invalid(e.to_string()),
        }
    })
}

/// Verify and decode an access token
pub fn verify_access_token(token: &str) -> Result<TokenData<AccessTokenClaims>, String> {
    decode_access_token(token).map_err(|e| e.to_string())
}

/// Verify and decode an ID token
pub fn verify_id_token(token: &str, client_id: &str) -> Result<TokenData<IdTokenClaims>, String> {
    let keys = get_jwt_keys();

    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_required_spec_claims(&["sub", "iss", "exp", "iat", "aud"]);
    validation.set_audience(&[client_id]);
    validation.validate_exp = true;

    decode::<IdTokenClaims>(token, &keys.decoding_key, &validation)
        .map_err(|e| format!("Token validation failed: {}", e))
}

/// Get JWKS (JSON Web Key Set) for public key distribution
pub fn get_jwks() -> serde_json::Value {
    let keys = get_jwt_keys();

    serde_json::json!({
        "keys": [{
            "kty": "RSA",
            "alg": "RS256",
            "use": "sig",
            "kid": keys.key_id,
            "n": keys.public_key_n,
            "e": keys.public_key_e,
        }]
    })
}

/// Extract user ID from access token without full validation
/// (for backward compatibility, but prefer verify_access_token)
pub fn extract_user_id_from_token(token: &str) -> Option<uuid::Uuid> {
    // Try to decode without signature verification first (for quick extraction)
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return None;
    }

    let payload = URL_SAFE_NO_PAD.decode(parts[1]).ok()?;
    let claims: serde_json::Value = serde_json::from_slice(&payload).ok()?;
    let sub = claims.get("sub")?.as_str()?;
    uuid::Uuid::parse_str(sub).ok()
}

fn resolve_duration(
    value: Option<i32>,
    unit: Option<TokenValidityUnit>,
    default: Duration,
) -> Duration {
    match value {
        Some(v) => {
            let v = v as i64;
            match unit {
                Some(TokenValidityUnit::Seconds) => Duration::seconds(v),
                Some(TokenValidityUnit::Minutes) => Duration::minutes(v),
                Some(TokenValidityUnit::Hours) => Duration::hours(v),
                Some(TokenValidityUnit::Days) => Duration::days(v),
                _ => default,
            }
        }
        None => default,
    }
}

/// Resolve access token validity duration from UserPoolClient config.
/// AWS default: 1 hour, default unit: hours.
pub fn resolve_access_token_expiry(client: &UserPoolClient) -> Duration {
    let default = Duration::hours(1);
    let unit = client
        .token_validity_units
        .as_ref()
        .and_then(|u| u.access_token)
        .unwrap_or(TokenValidityUnit::Hours);
    resolve_duration(client.access_token_validity, Some(unit), default)
}

/// Resolve ID token validity duration from UserPoolClient config.
/// AWS default: 1 hour, default unit: hours.
pub fn resolve_id_token_expiry(client: &UserPoolClient) -> Duration {
    let default = Duration::hours(1);
    let unit = client
        .token_validity_units
        .as_ref()
        .and_then(|u| u.id_token)
        .unwrap_or(TokenValidityUnit::Hours);
    resolve_duration(client.id_token_validity, Some(unit), default)
}

/// Resolve refresh token validity duration from UserPoolClient config.
/// AWS default: 30 days, default unit: days.
pub fn resolve_refresh_token_expiry(client: &UserPoolClient) -> Duration {
    let default = Duration::days(30);
    let unit = client
        .token_validity_units
        .as_ref()
        .and_then(|u| u.refresh_token)
        .unwrap_or(TokenValidityUnit::Days);
    resolve_duration(client.refresh_token_validity, Some(unit), default)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jwt_generation_and_verification() {
        let user_pool_id = UserPoolId::new("local_test123").unwrap();
        let user = User {
            id: uuid::Uuid::new_v4(),
            user_pool_id: user_pool_id.clone(),
            username: "testuser".to_string(),
            email: Some("test@example.com".to_string()),
            phone_number: None,
            password_hash: "hash".to_string(),
            enabled: true,
            user_status: crate::types::UserStatus::Confirmed,
            attributes: vec![],
            creation_date: Utc::now(),
            last_modified_date: Utc::now(),
            srp_salt: None,
            srp_verifier: None,
            password_set_at: None,
        };

        let client_id = "test_client_id";
        let groups = vec!["admin".to_string()];

        let access_token = generate_access_token(
            &user,
            client_id,
            &user_pool_id,
            &groups,
            &[],
            Duration::hours(1),
        )
        .expect("Failed to generate access token");
        let id_token = generate_id_token(
            &user,
            client_id,
            &user_pool_id,
            &groups,
            None,
            Duration::hours(1),
        )
        .expect("Failed to generate ID token");

        // Verify tokens
        let access_result = verify_access_token(&access_token);
        assert!(access_result.is_ok());
        let access_claims = access_result.unwrap().claims;
        assert_eq!(access_claims.sub, user.id.to_string());
        assert_eq!(access_claims.token_use, "access");
        assert_eq!(access_claims.iss, user_pool_issuer(&user_pool_id));

        let id_result = verify_id_token(&id_token, client_id);
        assert!(id_result.is_ok());
        let id_claims = id_result.unwrap().claims;
        assert_eq!(id_claims.sub, user.id.to_string());
        assert_eq!(id_claims.token_use, "id");
        assert_eq!(id_claims.email, Some("test@example.com".to_string()));
        assert_eq!(id_claims.iss, user_pool_issuer(&user_pool_id));
    }

    #[test]
    fn test_jwks_format() {
        let jwks = get_jwks();
        assert!(jwks["keys"].is_array());
        assert_eq!(jwks["keys"][0]["kty"], "RSA");
        assert_eq!(jwks["keys"][0]["alg"], "RS256");
    }
}
