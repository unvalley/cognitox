//! Shared helper functions for user domain

use serde_json::{Value, json};
use std::sync::OnceLock;
use uuid::Uuid;

use crate::{
    jwt,
    types::{Device, User},
};

/// Default bcrypt cost factor (4 for fast testing, use 12+ in production)
const DEFAULT_BCRYPT_COST: u32 = 4;
const MIN_BCRYPT_COST: u32 = 4;
const MAX_BCRYPT_COST: u32 = 31;
static BCRYPT_COST: OnceLock<u32> = OnceLock::new();

fn configured_bcrypt_cost() -> u32 {
    *BCRYPT_COST.get_or_init(|| {
        std::env::var("COGNITOX_BCRYPT_COST")
            .ok()
            .and_then(|value| value.parse::<u32>().ok())
            .filter(|cost| (MIN_BCRYPT_COST..=MAX_BCRYPT_COST).contains(cost))
            .unwrap_or(DEFAULT_BCRYPT_COST)
    })
}

/// Generate a secure confirmation code
/// Uses 20 alphanumeric characters for high entropy (~119 bits)
/// Format: XXXX-XXXX-XXXX-XXXX-XXXX for readability
pub fn generate_confirmation_code() -> String {
    use rand::Rng;
    const CHARSET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789"; // Excludes confusing chars: 0/O, 1/I/L
    let mut rng = rand::thread_rng();

    let code: String = (0..20)
        .map(|_| {
            let idx = rng.gen_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect();

    // Format as XXXX-XXXX-XXXX-XXXX-XXXX for readability
    format!(
        "{}-{}-{}-{}-{}",
        &code[0..4],
        &code[4..8],
        &code[8..12],
        &code[12..16],
        &code[16..20]
    )
}

/// Normalize a confirmation code by removing dashes and converting to uppercase
pub fn normalize_confirmation_code(code: &str) -> String {
    code.chars()
        .filter(|c| c.is_alphanumeric())
        .collect::<String>()
        .to_uppercase()
}

/// Hash password using bcrypt with automatic salt generation
pub fn hash_password(password: &str) -> Result<String, String> {
    bcrypt::hash(password, configured_bcrypt_cost())
        .map_err(|e| format!("Failed to hash password: {}", e))
}

/// Verify password against bcrypt hash
pub fn verify_password(password: &str, hash: &str) -> bool {
    bcrypt::verify(password, hash).unwrap_or(false)
}

pub fn mask_email(email: &str) -> String {
    if let Some((local, domain)) = email.split_once('@') {
        if local.len() > 2 {
            format!("{}***@{}", &local[..2], domain)
        } else {
            format!("***@{}", domain)
        }
    } else {
        "***".to_string()
    }
}

/// Verify access token signature and extract user ID
/// Returns the user ID if the token is valid, or an error message if validation fails
pub fn verify_and_extract_user_id(token: &str) -> Result<Uuid, String> {
    let token_data = jwt::verify_access_token(token)?;
    Uuid::parse_str(&token_data.claims.sub).map_err(|e| format!("Invalid user ID in token: {}", e))
}

/// Build device response payload in Cognito-compatible shape.
pub fn build_device_response(device: &Device) -> Value {
    let mut value = json!({
        "DeviceKey": device.device_key,
        "DeviceAttributes": device.device_attributes,
        "DeviceCreateDate": device.device_create_date.timestamp(),
        "DeviceLastModifiedDate": device.device_last_modified_date.timestamp(),
        "DeviceLastAuthenticatedDate": device.device_last_authenticated_date.timestamp()
    });

    if let Some(status) = &device.device_remembered_status {
        value["DeviceRememberedStatus"] = json!(status);
    }

    value
}

pub fn build_user_attributes(user: &User) -> Vec<Value> {
    let mut attributes = user.attributes.clone();

    let ensure_attribute =
        |attributes: &mut Vec<crate::types::UserAttribute>, name: &str, value: Option<String>| {
            if let Some(value) = value {
                if let Some(attribute) = attributes
                    .iter_mut()
                    .find(|attribute| attribute.name == name)
                {
                    attribute.value = Some(value);
                } else {
                    attributes.push(crate::types::UserAttribute {
                        name: name.to_string(),
                        value: Some(value),
                    });
                }
            }
        };

    ensure_attribute(&mut attributes, "sub", Some(user.id.to_string()));
    ensure_attribute(&mut attributes, "email", user.email.clone());
    ensure_attribute(&mut attributes, "phone_number", user.phone_number.clone());

    attributes
        .into_iter()
        .map(|attribute| {
            json!({
                "Name": attribute.name,
                "Value": attribute.value
            })
        })
        .collect()
}

pub fn preferred_mfa_setting(user: &User, factors: &[String]) -> Option<String> {
    if let Some(email) = user
        .attributes
        .iter()
        .find(|attr| attr.name == "preferred_mfa_setting")
        .and_then(|attr| attr.value.clone())
    {
        return Some(email);
    }

    factors.first().cloned()
}

pub fn build_mfa_options(_user: &User) -> Vec<Value> {
    Vec::new()
}
