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
use sha2::{Digest, Sha256};
use std::{fs, sync::OnceLock};

use crate::types::{ClientId, TokenValidityUnit, User, UserPoolClient, UserPoolId};

/// Global JWT key pair (configured, restored, or generated once at startup)
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
    /// Build signing keys. Without an explicit `key_id`, the RFC 7638 JWK
    /// thumbprint is used so the `kid` stays stable for the same key pair.
    fn from_rsa_keys(
        private_key: RsaPrivateKey,
        public_key: RsaPublicKey,
        key_id: Option<String>,
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

        let public_key_n = URL_SAFE_NO_PAD.encode(public_key.n().to_bytes_be());
        let public_key_e = URL_SAFE_NO_PAD.encode(public_key.e().to_bytes_be());
        let key_id = key_id.unwrap_or_else(|| rsa_jwk_thumbprint(&public_key_n, &public_key_e));

        Ok(Self {
            encoding_key,
            decoding_key,
            key_id,
            public_key_n,
            public_key_e,
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

        let key_id = std::env::var("COGNITOX_JWT_KEY_ID").ok();

        Self::from_rsa_keys(private_key, public_key, key_id).map(Some)
    }

    /// Restore the key pair from a persisted PKCS#1 PEM, or generate a new one.
    /// Returns the keys together with the private key PEM to persist.
    fn restore_or_generate(
        persisted_private_key_pem: Option<&str>,
    ) -> Result<(Self, String), String> {
        let private_key = match persisted_private_key_pem {
            Some(pem) => RsaPrivateKey::from_pkcs1_pem(pem)
                .map_err(|e| format!("Failed to parse persisted JWT private key: {e}"))?,
            None => generate_private_key(),
        };
        let private_pem = private_key
            .to_pkcs1_pem(LineEnding::LF)
            .map_err(|e| format!("Failed to encode private key: {e}"))?
            .to_string();
        let public_key = RsaPublicKey::from(&private_key);

        Ok((
            Self::from_rsa_keys(private_key, public_key, None)?,
            private_pem,
        ))
    }

    /// Generate a new RSA key pair
    fn generate() -> Self {
        let private_key = generate_private_key();
        let public_key = RsaPublicKey::from(&private_key);

        Self::from_rsa_keys(private_key, public_key, None)
            .expect("Failed to create JWT keys from generated RSA key pair")
    }
}

fn generate_private_key() -> RsaPrivateKey {
    let mut rng = rand::thread_rng();
    RsaPrivateKey::new(&mut rng, 2048).expect("Failed to generate RSA key pair")
}

/// RFC 7638 JWK thumbprint of an RSA public key.
fn rsa_jwk_thumbprint(n: &str, e: &str) -> String {
    let canonical = format!(r#"{{"e":"{e}","kty":"RSA","n":"{n}"}}"#);
    URL_SAFE_NO_PAD.encode(Sha256::digest(canonical.as_bytes()))
}

/// Initialize the global JWT keys at startup.
///
/// Keys configured through `COGNITOX_JWT_*` take precedence. Otherwise the key
/// restored from persisted state is reused, or a new one is generated, so that
/// tokens stay verifiable across restarts. Returns the private key PEM to
/// persist, or `None` when the key is configured externally.
pub fn init_jwt_keys(persisted_private_key_pem: Option<&str>) -> Result<Option<String>, String> {
    let (keys, private_pem) = match JwtKeys::from_env()? {
        Some(keys) => (keys, None),
        None => {
            let (keys, pem) = JwtKeys::restore_or_generate(persisted_private_key_pem)?;
            (keys, Some(pem))
        }
    };
    JWT_KEYS
        .set(keys)
        .map_err(|_| "JWT keys have already been initialized".to_string())?;
    Ok(private_pem)
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

/// Return the `iss` claim for tokens of a user pool, mirroring Cognito's
/// `https://cognito-idp.<region>.amazonaws.com/<user-pool-id>` format.
pub fn issuer_for_user_pool(user_pool_id: &UserPoolId) -> String {
    format!("{}/{}", issuer_base_url(), user_pool_id)
}

/// Identifiers shared by the tokens issued for one authentication.
#[derive(Debug, Clone)]
pub struct TokenOrigin {
    origin_jti: String,
    event_id: String,
}

impl TokenOrigin {
    /// Origin for tokens issued without a refresh token.
    pub fn new() -> Self {
        Self {
            origin_jti: uuid::Uuid::new_v4().to_string(),
            event_id: uuid::Uuid::new_v4().to_string(),
        }
    }

    /// Origin bound to a refresh token, so `origin_jti` stays the same for all
    /// tokens obtained with it, as in Cognito.
    pub fn for_refresh_token(refresh_token: &str) -> Self {
        let digest = Sha256::digest(refresh_token.as_bytes());
        let mut bytes = [0u8; 16];
        bytes.copy_from_slice(&digest[..16]);
        Self {
            origin_jti: uuid::Builder::from_random_bytes(bytes)
                .into_uuid()
                .to_string(),
            event_id: uuid::Uuid::new_v4().to_string(),
        }
    }
}

impl Default for TokenOrigin {
    fn default() -> Self {
        Self::new()
    }
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
    #[serde(default)]
    pub jti: String,
    #[serde(default)]
    pub origin_jti: String,
    #[serde(default)]
    pub event_id: String,

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
    #[serde(default)]
    pub version: u32,
    #[serde(default)]
    pub jti: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub origin_jti: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub event_id: Option<String>,

    // Cognito-specific claims
    #[serde(
        rename = "cognito:groups",
        skip_serializing_if = "Vec::is_empty",
        default
    )]
    pub cognito_groups: Vec<String>,
    pub scope: String,
    pub username: String,
}

/// Cognito access token format version.
const ACCESS_TOKEN_VERSION: u32 = 2;

/// Generate ID Token
pub fn generate_id_token(
    user: &User,
    client_id: &str,
    user_pool_id: &UserPoolId,
    groups: &[String],
    origin: &TokenOrigin,
    expiry: Duration,
) -> Result<String, String> {
    let keys = get_jwt_keys();
    let now = Utc::now();
    let auth_time = now.timestamp();

    let claims = IdTokenClaims {
        sub: user.id.to_string(),
        aud: client_id.to_string(),
        iss: issuer_for_user_pool(user_pool_id),
        iat: now.timestamp(),
        exp: (now + expiry).timestamp(),
        auth_time,
        token_use: "id".to_string(),
        jti: uuid::Uuid::new_v4().to_string(),
        origin_jti: origin.origin_jti.clone(),
        event_id: origin.event_id.clone(),
        email: user.email.clone(),
        email_verified: user.email.as_ref().map(|_| true),
        phone_number: user.phone_number.clone(),
        phone_number_verified: user.phone_number.as_ref().map(|_| true),
        cognito_username: user.username.clone(),
        cognito_groups: groups.to_vec(),
    };

    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(keys.key_id.clone());

    encode(&header, &claims, &keys.encoding_key)
        .map_err(|e| format!("Failed to encode ID token: {}", e))
}

/// Generate Access Token
pub fn generate_access_token(
    user: &User,
    client_id: &str,
    user_pool_id: &UserPoolId,
    groups: &[String],
    scopes: &[String],
    origin: &TokenOrigin,
    expiry: Duration,
) -> Result<String, String> {
    let keys = get_jwt_keys();
    let now = Utc::now();
    let auth_time = now.timestamp();

    let scope = if scopes.is_empty() {
        "aws.cognito.signin.user.admin".to_string()
    } else {
        scopes.join(" ")
    };

    let claims = AccessTokenClaims {
        sub: user.id.to_string(),
        iss: issuer_for_user_pool(user_pool_id),
        iat: now.timestamp(),
        cognitox_iat_ms: Some(now.timestamp_millis()),
        exp: (now + expiry).timestamp(),
        auth_time,
        token_use: "access".to_string(),
        client_id: client_id.to_string(),
        version: ACCESS_TOKEN_VERSION,
        jti: uuid::Uuid::new_v4().to_string(),
        origin_jti: Some(origin.origin_jti.clone()),
        event_id: Some(origin.event_id.clone()),
        cognito_groups: groups.to_vec(),
        scope,
        username: user.username.clone(),
    };

    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(keys.key_id.clone());

    encode(&header, &claims, &keys.encoding_key)
        .map_err(|e| format!("Failed to encode access token: {}", e))
}

/// Generate an OAuth client credentials access token.
pub fn generate_client_credentials_access_token(
    client_id: &ClientId,
    user_pool_id: &UserPoolId,
    scopes: &[String],
    expiry: Duration,
) -> Result<String, String> {
    let keys = get_jwt_keys();
    let now = Utc::now();
    let client_id = client_id.as_str();

    let claims = AccessTokenClaims {
        sub: client_id.to_string(),
        iss: issuer_for_user_pool(user_pool_id),
        iat: now.timestamp(),
        cognitox_iat_ms: Some(now.timestamp_millis()),
        exp: (now + expiry).timestamp(),
        auth_time: now.timestamp(),
        token_use: "access".to_string(),
        client_id: client_id.to_string(),
        version: ACCESS_TOKEN_VERSION,
        jti: uuid::Uuid::new_v4().to_string(),
        origin_jti: None,
        event_id: None,
        cognito_groups: Vec::new(),
        scope: scopes.join(" "),
        username: client_id.to_string(),
    };

    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(keys.key_id.clone());

    encode(&header, &claims, &keys.encoding_key)
        .map_err(|e| format!("Failed to encode client credentials access token: {e}"))
}

/// Verify and decode an access token
pub fn verify_access_token(token: &str) -> Result<TokenData<AccessTokenClaims>, String> {
    let keys = get_jwt_keys();

    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_required_spec_claims(&["sub", "iss", "exp", "iat"]);
    validation.validate_exp = true;
    // Don't validate audience for access tokens (they use client_id instead)
    validation.validate_aud = false;

    decode::<AccessTokenClaims>(token, &keys.decoding_key, &validation)
        .map_err(|e| format!("Token validation failed: {}", e))
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
        };

        let client_id = "test_client_id";
        let groups = vec!["admin".to_string()];

        let origin = TokenOrigin::new();
        let access_token = generate_access_token(
            &user,
            client_id,
            &user_pool_id,
            &groups,
            &[],
            &origin,
            Duration::hours(1),
        )
        .expect("Failed to generate access token");
        let id_token = generate_id_token(
            &user,
            client_id,
            &user_pool_id,
            &groups,
            &origin,
            Duration::hours(1),
        )
        .expect("Failed to generate ID token");

        // Verify tokens
        let access_result = verify_access_token(&access_token);
        assert!(access_result.is_ok());
        let access_claims = access_result.unwrap().claims;
        assert_eq!(access_claims.sub, user.id.to_string());
        assert_eq!(access_claims.token_use, "access");
        assert_eq!(access_claims.iss, issuer_for_user_pool(&user_pool_id));
        assert_eq!(access_claims.version, ACCESS_TOKEN_VERSION);
        assert!(!access_claims.jti.is_empty());

        let id_result = verify_id_token(&id_token, client_id);
        assert!(id_result.is_ok());
        let id_claims = id_result.unwrap().claims;
        assert_eq!(id_claims.sub, user.id.to_string());
        assert_eq!(id_claims.token_use, "id");
        assert_eq!(id_claims.email, Some("test@example.com".to_string()));
        assert_eq!(id_claims.iss, access_claims.iss);
        assert_ne!(id_claims.jti, access_claims.jti);
        assert_eq!(
            Some(&id_claims.origin_jti),
            access_claims.origin_jti.as_ref()
        );
        assert_eq!(Some(&id_claims.event_id), access_claims.event_id.as_ref());
    }

    #[test]
    fn test_token_origin_is_stable_per_refresh_token() {
        let first = TokenOrigin::for_refresh_token("refresh-a");
        let second = TokenOrigin::for_refresh_token("refresh-a");
        assert_eq!(first.origin_jti, second.origin_jti);
        assert_ne!(first.event_id, second.event_id);
        assert!(uuid::Uuid::parse_str(&first.origin_jti).is_ok());
        assert_ne!(
            first.origin_jti,
            TokenOrigin::for_refresh_token("refresh-b").origin_jti
        );
    }

    #[test]
    fn test_rsa_jwk_thumbprint_matches_rfc7638_example() {
        let n = "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw";
        assert_eq!(
            rsa_jwk_thumbprint(n, "AQAB"),
            "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
        );
    }

    #[test]
    fn test_restored_key_keeps_key_id_and_verifies_existing_tokens() {
        let (generated, pem) = JwtKeys::restore_or_generate(None).unwrap();
        let (restored, restored_pem) = JwtKeys::restore_or_generate(Some(&pem)).unwrap();
        assert_eq!(restored_pem, pem);
        assert_eq!(restored.key_id, generated.key_id);
        assert_eq!(restored.public_key_n, generated.public_key_n);

        let token = encode(
            &Header::new(Algorithm::RS256),
            &serde_json::json!({ "sub": "s", "iss": "i", "iat": 0, "exp": i64::MAX }),
            &generated.encoding_key,
        )
        .unwrap();
        let validation = Validation::new(Algorithm::RS256);
        assert!(decode::<serde_json::Value>(&token, &restored.decoding_key, &validation).is_ok());
    }

    #[test]
    fn test_restore_rejects_invalid_persisted_key() {
        assert!(JwtKeys::restore_or_generate(Some("not a pem")).is_err());
    }

    #[test]
    fn test_jwks_format() {
        let jwks = get_jwks();
        assert!(jwks["keys"].is_array());
        assert_eq!(jwks["keys"][0]["kty"], "RSA");
        assert_eq!(jwks["keys"][0]["alg"], "RS256");
    }
}
