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
use std::{fs, sync::OnceLock};

use crate::types::{User, UserPoolClient, UserPoolId};

/// Global JWT key pair (generated once at startup)
static JWT_KEYS: OnceLock<JwtKeys> = OnceLock::new();

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
    pub exp: i64,
    pub auth_time: i64,
    pub token_use: String,
    pub client_id: String,

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

/// Generate ID Token
pub fn generate_id_token(
    user: &User,
    client_id: &str,
    user_pool_id: &UserPoolId,
    groups: &[String],
    expiry: Duration,
) -> Result<String, String> {
    let keys = get_jwt_keys();
    let now = Utc::now();
    let auth_time = now.timestamp();

    let claims = IdTokenClaims {
        sub: user.id.to_string(),
        aud: client_id.to_string(),
        iss: format!("https://cognito-idp.local.amazonaws.com/{}", user_pool_id),
        iat: now.timestamp(),
        exp: (now + expiry).timestamp(),
        auth_time,
        token_use: "id".to_string(),
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
        iss: format!("https://cognito-idp.local.amazonaws.com/{}", user_pool_id),
        iat: now.timestamp(),
        exp: (now + expiry).timestamp(),
        auth_time,
        token_use: "access".to_string(),
        client_id: client_id.to_string(),
        cognito_groups: groups.to_vec(),
        scope,
        username: user.username.clone(),
    };

    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(keys.key_id.clone());

    encode(&header, &claims, &keys.encoding_key)
        .map_err(|e| format!("Failed to encode access token: {}", e))
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

fn resolve_duration(value: Option<i32>, unit: Option<&str>, default: Duration) -> Duration {
    match value {
        Some(v) => {
            let v = v as i64;
            match unit {
                Some("seconds") => Duration::seconds(v),
                Some("minutes") => Duration::minutes(v),
                Some("hours") => Duration::hours(v),
                Some("days") => Duration::days(v),
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
        .and_then(|u| u.access_token.as_deref())
        .unwrap_or("hours");
    resolve_duration(client.access_token_validity, Some(unit), default)
}

/// Resolve ID token validity duration from UserPoolClient config.
/// AWS default: 1 hour, default unit: hours.
pub fn resolve_id_token_expiry(client: &UserPoolClient) -> Duration {
    let default = Duration::hours(1);
    let unit = client
        .token_validity_units
        .as_ref()
        .and_then(|u| u.id_token.as_deref())
        .unwrap_or("hours");
    resolve_duration(client.id_token_validity, Some(unit), default)
}

/// Resolve refresh token validity duration from UserPoolClient config.
/// AWS default: 30 days, default unit: days.
pub fn resolve_refresh_token_expiry(client: &UserPoolClient) -> Duration {
    let default = Duration::days(30);
    let unit = client
        .token_validity_units
        .as_ref()
        .and_then(|u| u.refresh_token.as_deref())
        .unwrap_or("days");
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

        let access_token = generate_access_token(
            &user,
            client_id,
            &user_pool_id,
            &groups,
            &[],
            Duration::hours(1),
        )
        .expect("Failed to generate access token");
        let id_token =
            generate_id_token(&user, client_id, &user_pool_id, &groups, Duration::hours(1))
                .expect("Failed to generate ID token");

        // Verify tokens
        let access_result = verify_access_token(&access_token);
        assert!(access_result.is_ok());
        let access_claims = access_result.unwrap().claims;
        assert_eq!(access_claims.sub, user.id.to_string());
        assert_eq!(access_claims.token_use, "access");

        let id_result = verify_id_token(&id_token, client_id);
        assert!(id_result.is_ok());
        let id_claims = id_result.unwrap().claims;
        assert_eq!(id_claims.sub, user.id.to_string());
        assert_eq!(id_claims.token_use, "id");
        assert_eq!(id_claims.email, Some("test@example.com".to_string()));
    }

    #[test]
    fn test_jwks_format() {
        let jwks = get_jwks();
        assert!(jwks["keys"].is_array());
        assert_eq!(jwks["keys"][0]["kty"], "RSA");
        assert_eq!(jwks["keys"][0]["alg"], "RS256");
    }
}
