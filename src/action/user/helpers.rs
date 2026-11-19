//! Shared helper functions for user domain

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use hmac::{Hmac, Mac};
use serde_json::{Value, json};
use sha2::Sha256;
use std::sync::OnceLock;
use uuid::Uuid;

use crate::{
    error::AppError,
    jwt, srp,
    storage::Storage,
    types::{AutoVerifiedAttribute, Device, User, UserAttribute, UserPool, UserPoolClient},
};

pub const SOFTWARE_TOKEN_MFA_FACTOR: &str = "SOFTWARE_TOKEN_MFA";
pub const SMS_MFA_FACTOR: &str = "SMS_MFA";
pub const EMAIL_OTP_FACTOR: &str = "EMAIL_OTP";

/// Default bcrypt cost factor (4 for fast testing, use 12+ in production)
const DEFAULT_BCRYPT_COST: u32 = 4;
const MIN_BCRYPT_COST: u32 = 4;
const MAX_BCRYPT_COST: u32 = 31;
static BCRYPT_COST: OnceLock<u32> = OnceLock::new();
type HmacSha256 = Hmac<Sha256>;

fn configured_bcrypt_cost() -> u32 {
    *BCRYPT_COST.get_or_init(|| {
        std::env::var("COGNITOX_BCRYPT_COST")
            .ok()
            .and_then(|value| value.parse::<u32>().ok())
            .filter(|cost| (MIN_BCRYPT_COST..=MAX_BCRYPT_COST).contains(cost))
            .unwrap_or(DEFAULT_BCRYPT_COST)
    })
}

/// Generate a confirmation code.
///
/// Cognito sends six-digit numeric codes for sign-up confirmation, attribute
/// verification, and password reset.
pub fn generate_confirmation_code() -> String {
    generate_numeric_code()
}

/// A six-digit one-time code, the form Cognito sends by email and SMS.
pub fn generate_numeric_code() -> String {
    use rand::Rng;
    format!("{:06}", rand::thread_rng().gen_range(0..1_000_000))
}

/// Normalize a confirmation code by removing dashes and converting to uppercase
pub fn normalize_confirmation_code(code: &str) -> String {
    code.chars()
        .filter(|c| c.is_alphanumeric())
        .collect::<String>()
        .to_uppercase()
}

/// Hash password using bcrypt with automatic salt generation
pub fn hash_password(password: &str) -> std::result::Result<String, String> {
    bcrypt::hash(password, configured_bcrypt_cost())
        .map_err(|e| format!("Failed to hash password: {}", e))
}

/// Store a new password on a user.
///
/// Keeps a bcrypt hash for the flows that present the password in clear and
/// an SRP verifier for `USER_SRP_AUTH`, as Cognito does.
pub fn set_user_password(user: &mut User, password: &str) -> crate::error::Result<()> {
    user.password_hash = hash_password(password).map_err(AppError::Internal)?;
    store_srp_verifier(user, password);
    user.password_set_at = Some(chrono::Utc::now());
    Ok(())
}

/// Derive and store the SRP verifier for a password known to be the user's.
pub fn store_srp_verifier(user: &mut User, password: &str) {
    let verifier = srp::generate_verifier(user.user_pool_id.as_str(), &user.username, password);
    user.srp_salt = Some(verifier.salt);
    user.srp_verifier = Some(verifier.verifier);
}

/// Verify password against bcrypt hash
pub fn verify_password(password: &str, hash: &str) -> bool {
    bcrypt::verify(password, hash).unwrap_or(false)
}

/// Mask an email address the way Cognito does in `Destination`:
/// `alice@example.com` becomes `a***@e***`.
pub fn mask_email(email: &str) -> String {
    let initial = |part: &str| part.chars().next().map(String::from).unwrap_or_default();
    match email.split_once('@') {
        Some((local, domain)) => format!("{}***@{}***", initial(local), initial(domain)),
        None => "***".to_string(),
    }
}

/// Mask a phone number the way Cognito does in `Destination`:
/// `+15555550100` becomes `+*******0100`.
pub fn mask_phone_number(phone_number: &str) -> String {
    let digits: String = phone_number
        .chars()
        .filter(|c| c.is_ascii_digit())
        .collect();
    if digits.len() >= 4 {
        format!(
            "+{}{}",
            "*".repeat(digits.len() - 4),
            &digits[digits.len() - 4..]
        )
    } else {
        "***".to_string()
    }
}

pub fn find_user_attribute_value(attributes: &[UserAttribute], name: &str) -> Option<String> {
    attributes
        .iter()
        .find(|attribute| attribute.name == name)
        .and_then(|attribute| attribute.value.clone())
}

pub fn build_code_delivery_details(
    email: Option<&str>,
    phone_number: Option<&str>,
) -> Option<Value> {
    if let Some(email) = email {
        return Some(json!({
            "Destination": mask_email(email),
            "DeliveryMedium": "EMAIL",
            "AttributeName": "email"
        }));
    }

    phone_number.map(|phone_number| {
        json!({
            "Destination": mask_phone_number(phone_number),
            "DeliveryMedium": "SMS",
            "AttributeName": "phone_number"
        })
    })
}

/// Where a sign-up confirmation code goes: the attribute the user pool
/// verifies automatically. Cognito texts the code when it verifies both.
/// `None` when the pool verifies nothing the user has.
pub fn confirmation_attribute(pool: &UserPool, user: &User) -> Option<AutoVerifiedAttribute> {
    let auto_verified = pool.auto_verified_attributes.as_deref().unwrap_or_default();
    if auto_verified.contains(&AutoVerifiedAttribute::PhoneNumber) && user.phone_number.is_some() {
        Some(AutoVerifiedAttribute::PhoneNumber)
    } else if auto_verified.contains(&AutoVerifiedAttribute::Email) && user.email.is_some() {
        Some(AutoVerifiedAttribute::Email)
    } else {
        None
    }
}

/// `CodeDeliveryDetails` for a sign-up confirmation code.
pub fn confirmation_delivery(pool: &UserPool, user: &User) -> Option<Value> {
    match confirmation_attribute(pool, user)? {
        AutoVerifiedAttribute::Email => build_code_delivery_details(user.email.as_deref(), None),
        AutoVerifiedAttribute::PhoneNumber => {
            build_code_delivery_details(None, user.phone_number.as_deref())
        }
    }
}

pub fn require_code_delivery_details(user: &User) -> crate::error::Result<Value> {
    build_code_delivery_details(user.email.as_deref(), user.phone_number.as_deref()).ok_or_else(
        || {
            AppError::InvalidParameter(
                "User does not have an email or phone_number attribute".to_string(),
            )
        },
    )
}

pub(crate) fn calculate_secret_hash(
    client_id: &str,
    client_secret: &str,
    username: &str,
) -> std::result::Result<String, String> {
    let mut mac = HmacSha256::new_from_slice(client_secret.as_bytes())
        .map_err(|e| format!("Failed to initialize secret hash: {e}"))?;
    mac.update(username.as_bytes());
    mac.update(client_id.as_bytes());
    Ok(BASE64_STANDARD.encode(mac.finalize().into_bytes()))
}

pub fn verify_secret_hash(
    client: &UserPoolClient,
    username: &str,
    provided_secret_hash: Option<&str>,
) -> crate::error::Result<()> {
    let Some(client_secret) = client.client_secret.as_deref() else {
        return Ok(());
    };

    let provided_secret_hash = provided_secret_hash.ok_or_else(|| {
        AppError::NotAuthorized("Unable to verify secret hash for client".to_string())
    })?;
    let expected_secret_hash =
        calculate_secret_hash(client.client_id.as_str(), client_secret, username)
            .map_err(AppError::Internal)?;

    if provided_secret_hash != expected_secret_hash {
        return Err(AppError::NotAuthorized(
            "Unable to verify secret hash for client".to_string(),
        ));
    }

    Ok(())
}

/// Scope every access token issued by the user pools API carries, and the
/// one Cognito requires for token-authorized user pools API operations.
pub const USER_ADMIN_SCOPE: &str = "aws.cognito.signin.user.admin";

/// Authorize a token-authenticated user pools API call the way Cognito does:
/// the access token must be valid, unexpired, not revoked, and carry the
/// `aws.cognito.signin.user.admin` scope.
pub async fn verify_and_extract_active_user_id(
    storage: &Storage,
    token: &str,
) -> crate::error::Result<Uuid> {
    let token_data = jwt::decode_access_token(token).map_err(|e| match e {
        jwt::AccessTokenError::Expired => AppError::AccessTokenExpired,
        jwt::AccessTokenError::Invalid(_) => AppError::InvalidAccessToken,
    })?;
    let user_id =
        Uuid::parse_str(&token_data.claims.sub).map_err(|_| AppError::InvalidAccessToken)?;
    if storage
        .is_access_token_revoked(
            &user_id,
            token_data.claims.iat,
            token_data.claims.cognitox_iat_ms,
            token_data.claims.origin_jti.as_deref(),
        )
        .await
    {
        return Err(AppError::AccessTokenRevoked);
    }
    if !token_data
        .claims
        .scope
        .split_whitespace()
        .any(|scope| scope == USER_ADMIN_SCOPE)
    {
        return Err(AppError::NotAuthorized(
            "Access Token does not have required scopes".to_string(),
        ));
    }
    Ok(user_id)
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

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct UserAttributeUpdateSummary {
    pub email_updated: bool,
    pub phone_updated: bool,
    pub email_verified_explicit: bool,
    pub phone_verified_explicit: bool,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct UserAttributeDeletionSummary {
    pub email_deleted: bool,
    pub phone_deleted: bool,
    pub preferred_mfa_setting: Option<String>,
}

fn set_or_remove_user_attribute(
    attributes: &mut Vec<UserAttribute>,
    name: &str,
    value: Option<String>,
) {
    match value {
        Some(value) => upsert_user_attribute(attributes, name, Some(value)),
        None => remove_user_attribute(attributes, name),
    }
}

pub fn sync_user_profile_attributes(user: &mut User) {
    user.email = find_user_attribute_value(&user.attributes, "email");
    user.phone_number = find_user_attribute_value(&user.attributes, "phone_number");
}

pub fn build_user_attributes(user: &User) -> Vec<Value> {
    let mut attributes = user.attributes.clone();
    set_or_remove_user_attribute(&mut attributes, "sub", Some(user.id.to_string()));
    set_or_remove_user_attribute(&mut attributes, "email", user.email.clone());
    set_or_remove_user_attribute(&mut attributes, "phone_number", user.phone_number.clone());

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

pub fn upsert_user_attribute(
    attributes: &mut Vec<UserAttribute>,
    name: &str,
    value: Option<String>,
) {
    if let Some(attribute) = attributes
        .iter_mut()
        .find(|attribute| attribute.name == name)
    {
        attribute.value = value;
    } else {
        attributes.push(UserAttribute {
            name: name.to_string(),
            value,
        });
    }
}

pub fn remove_user_attribute(attributes: &mut Vec<UserAttribute>, name: &str) {
    attributes.retain(|attribute| attribute.name != name);
}

pub fn apply_user_attribute_updates(
    user: &mut User,
    updates: impl IntoIterator<Item = UserAttribute>,
) -> UserAttributeUpdateSummary {
    let mut summary = UserAttributeUpdateSummary::default();

    for attribute in updates {
        match attribute.name.as_str() {
            "email" => summary.email_updated = true,
            "phone_number" => summary.phone_updated = true,
            "email_verified" => summary.email_verified_explicit = true,
            "phone_number_verified" => summary.phone_verified_explicit = true,
            _ => {}
        }

        upsert_user_attribute(&mut user.attributes, &attribute.name, attribute.value);
    }

    sync_user_profile_attributes(user);
    summary
}

pub fn apply_user_attribute_deletions(
    user: &mut User,
    attribute_names: &[String],
) -> UserAttributeDeletionSummary {
    let preferred_mfa_setting = user
        .attributes
        .iter()
        .find(|attr| attr.name == "preferred_mfa_setting")
        .and_then(|attr| attr.value.clone());

    for attr_name in attribute_names {
        remove_user_attribute(&mut user.attributes, attr_name);
    }

    let email_deleted = attribute_names.iter().any(|name| name == "email");
    let phone_deleted = attribute_names.iter().any(|name| name == "phone_number");

    if email_deleted {
        remove_user_attribute(&mut user.attributes, "email_verified");
        if preferred_mfa_setting.as_deref() == Some(EMAIL_OTP_FACTOR) {
            remove_user_attribute(&mut user.attributes, "preferred_mfa_setting");
        }
    }

    if phone_deleted {
        remove_user_attribute(&mut user.attributes, "phone_number_verified");
        if preferred_mfa_setting.as_deref() == Some(SMS_MFA_FACTOR) {
            remove_user_attribute(&mut user.attributes, "preferred_mfa_setting");
        }
    }

    sync_user_profile_attributes(user);

    UserAttributeDeletionSummary {
        email_deleted,
        phone_deleted,
        preferred_mfa_setting,
    }
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

pub fn build_mfa_options(user: &User, factors: &[String]) -> Vec<Value> {
    if factors.iter().any(|factor| factor == SMS_MFA_FACTOR) && user.phone_number.is_some() {
        return vec![json!({
            "AttributeName": "phone_number",
            "DeliveryMedium": "SMS"
        })];
    }

    Vec::new()
}
