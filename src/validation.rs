//! Input validation functions for AWS Cognito API compliance
//!
//! Provides validation for usernames, passwords, emails, and URLs
//! to match AWS Cognito's validation rules.

use crate::error::{AppError, Result};
use crate::types::{
    AccountRecoverySetting, AdminCreateUserConfig, AnalyticsConfiguration, DeviceConfiguration,
    EmailConfiguration, EmailMfaConfiguration, ExplicitAuthFlow, InviteMessageTemplate,
    MfaConfiguration, OAuthFlow, PasswordPolicy, RefreshTokenRotationType, SchemaAttributeType,
    SmsConfiguration, SmsMfaConfiguration, SoftwareTokenMfaConfiguration, TokenValidityUnit,
    UserAttributeUpdateSettingsType, UserPool, UserPoolAddOns, UserPoolId, UserPoolPolicies,
    VerificationMessageTemplate, WebAuthnConfiguration,
};

/// `PasswordPolicy.MinimumLength` of a user pool created without a policy.
const DEFAULT_MIN_PASSWORD_LENGTH: i32 = 8;

/// `PasswordPolicy.TemporaryPasswordValidityDays` when unset.
const DEFAULT_TEMPORARY_PASSWORD_VALIDITY_DAYS: i32 = 7;

/// Maximum password length
const MAX_PASSWORD_LENGTH: usize = 256;

/// Maximum username length
const MAX_USERNAME_LENGTH: usize = 128;

/// Maximum confirmation/reset code length
const MAX_CODE_LENGTH: usize = 2048;

/// Validate a `Username` member against Cognito's shape constraints:
/// 1 to 128 characters of letters, marks, symbols, numbers, and punctuation.
pub fn validate_username(username: &str) -> Result<()> {
    let violation = |constraint: &str| {
        Err(AppError::InvalidParameter(format!(
            "1 validation error detected: Value '{username}' at 'username' failed to satisfy constraint: {constraint}"
        )))
    };

    if username.is_empty() {
        return violation("Member must have length greater than or equal to 1");
    }

    if username.chars().count() > MAX_USERNAME_LENGTH {
        return violation(&format!(
            "Member must have length less than or equal to {MAX_USERNAME_LENGTH}"
        ));
    }

    if username
        .chars()
        .any(|ch| ch.is_whitespace() || ch.is_control())
    {
        return violation(
            "Member must satisfy regular expression pattern: [\\p{L}\\p{M}\\p{S}\\p{N}\\p{P}]+",
        );
    }

    Ok(())
}

/// Cognito's password policy for a user pool created without one.
pub fn default_password_policy() -> PasswordPolicy {
    PasswordPolicy {
        minimum_length: Some(DEFAULT_MIN_PASSWORD_LENGTH),
        password_history_size: None,
        require_lowercase: Some(true),
        require_numbers: Some(true),
        require_symbols: Some(true),
        require_uppercase: Some(true),
        temporary_password_validity_days: Some(DEFAULT_TEMPORARY_PASSWORD_VALIDITY_DAYS),
    }
}

/// Characters Cognito counts as symbols for `RequireSymbols`.
const PASSWORD_SYMBOLS: &str = "^$*.[]{}()?\"!@#%&/\\,><':;|_~`=+- ";

/// The shape constraint on every password member: no leading or trailing
/// whitespace, at most 256 characters.
fn validate_password_shape(password: &str) -> Result<()> {
    let length = password.chars().count();
    if length > MAX_PASSWORD_LENGTH {
        return Err(AppError::InvalidParameter(format!(
            "1 validation error detected: Value at 'password' failed to satisfy constraint: Member must have length less than or equal to {MAX_PASSWORD_LENGTH}"
        )));
    }
    let edge_is_whitespace = password.chars().next().is_none_or(char::is_whitespace)
        || password.chars().next_back().is_none_or(char::is_whitespace);
    if edge_is_whitespace {
        return Err(AppError::InvalidParameter(
            "1 validation error detected: Value at 'password' failed to satisfy constraint: Member must satisfy regular expression pattern: ^[\\S]+.*[\\S]+$"
                .to_string(),
        ));
    }
    Ok(())
}

/// Enforce a user pool's `PasswordPolicy` on a new password.
///
/// A pool without a stored policy is held to Cognito's default.
pub fn validate_password_against_policy(pool: &UserPool, password: &str) -> Result<()> {
    validate_password_shape(password)?;

    let default_policy = default_password_policy();
    let policy = pool
        .policies
        .as_ref()
        .and_then(|policies| policies.password_policy.as_ref())
        .unwrap_or(&default_policy);

    let violation = |requirement: &str| {
        Err(AppError::InvalidPassword(format!(
            "Password did not conform with policy: {requirement}"
        )))
    };

    let minimum_length = policy
        .minimum_length
        .unwrap_or(DEFAULT_MIN_PASSWORD_LENGTH)
        .max(0) as usize;
    if password.chars().count() < minimum_length {
        return violation("Password not long enough");
    }
    if policy.require_uppercase == Some(true) && !password.chars().any(char::is_uppercase) {
        return violation("Password must have uppercase characters");
    }
    if policy.require_lowercase == Some(true) && !password.chars().any(char::is_lowercase) {
        return violation("Password must have lowercase characters");
    }
    if policy.require_numbers == Some(true) && !password.chars().any(|ch| ch.is_ascii_digit()) {
        return violation("Password must have numeric characters");
    }
    if policy.require_symbols == Some(true)
        && !password.chars().any(|ch| PASSWORD_SYMBOLS.contains(ch))
    {
        return violation("Password must have symbol characters");
    }

    Ok(())
}

/// A temporary password that satisfies the user pool's policy, for
/// `AdminCreateUser` and `AdminResetUserPassword` calls that supply none.
pub fn generate_temporary_password(pool: &UserPool) -> String {
    use rand::{Rng, seq::SliceRandom};

    const UPPER: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ";
    const LOWER: &[u8] = b"abcdefghijkmnopqrstuvwxyz";
    const DIGITS: &[u8] = b"23456789";
    const SYMBOLS: &[u8] = b"!@#$%^&*";

    let minimum_length = pool
        .policies
        .as_ref()
        .and_then(|policies| policies.password_policy.as_ref())
        .and_then(|policy| policy.minimum_length)
        .unwrap_or(DEFAULT_MIN_PASSWORD_LENGTH)
        .max(0) as usize;

    let mut rng = rand::thread_rng();
    let mut pick = |set: &[u8]| set[rng.gen_range(0..set.len())] as char;
    let mut password = vec![pick(UPPER), pick(LOWER), pick(DIGITS), pick(SYMBOLS)];
    while password.len() < minimum_length.max(8) {
        let set = [UPPER, LOWER, DIGITS][password.len() % 3];
        password.push(pick(set));
    }
    password.shuffle(&mut rand::thread_rng());
    password.into_iter().collect()
}

/// Validate email format (basic validation)
pub fn validate_email(email: &str) -> Result<()> {
    let trimmed = email.trim();

    if trimmed.is_empty() {
        return Err(AppError::InvalidParameter(
            "Email cannot be empty".to_string(),
        ));
    }

    // Basic email format check: must contain @ and have parts before and after
    let parts: Vec<&str> = trimmed.split('@').collect();
    if parts.len() != 2 {
        return Err(AppError::InvalidParameter(
            "Invalid email format".to_string(),
        ));
    }

    let (local, domain) = (parts[0], parts[1]);

    if local.is_empty() || domain.is_empty() {
        return Err(AppError::InvalidParameter(
            "Invalid email format".to_string(),
        ));
    }

    // Domain must contain at least one dot
    if !domain.contains('.') {
        return Err(AppError::InvalidParameter(
            "Invalid email format".to_string(),
        ));
    }

    // Domain parts must not be empty
    let domain_parts: Vec<&str> = domain.split('.').collect();
    if domain_parts.iter().any(|p| p.is_empty()) {
        return Err(AppError::InvalidParameter(
            "Invalid email format".to_string(),
        ));
    }

    Ok(())
}

pub fn validate_phone_number(phone_number: &str) -> Result<()> {
    let trimmed = phone_number.trim();

    if trimmed.is_empty() {
        return Err(AppError::InvalidParameter(
            "Phone number cannot be empty".to_string(),
        ));
    }

    if !trimmed.starts_with('+') {
        return Err(AppError::InvalidParameter(
            "Phone number must be in E.164 format".to_string(),
        ));
    }

    let digits = &trimmed[1..];
    if digits.is_empty() || digits.len() > 15 || !digits.chars().all(|ch| ch.is_ascii_digit()) {
        return Err(AppError::InvalidParameter(
            "Phone number must be in E.164 format".to_string(),
        ));
    }

    Ok(())
}

pub fn validate_confirmation_code(code: &str) -> Result<()> {
    let trimmed = code.trim();

    if trimmed.is_empty() {
        return Err(AppError::InvalidParameter(
            "Confirmation code cannot be empty".to_string(),
        ));
    }

    if trimmed.len() > MAX_CODE_LENGTH {
        return Err(AppError::InvalidParameter(format!(
            "Confirmation code cannot exceed {} characters",
            MAX_CODE_LENGTH
        )));
    }

    Ok(())
}

/// Validate callback URL format
pub fn validate_callback_url(url: &str) -> Result<()> {
    let trimmed = url.trim();

    if trimmed.is_empty() {
        return Err(AppError::InvalidParameter(
            "Callback URL cannot be empty".to_string(),
        ));
    }

    if trimmed.contains('#') {
        return Err(AppError::InvalidParameter(
            "Callback URL must not contain a fragment".to_string(),
        ));
    }

    if !trimmed.contains("://") {
        return Err(AppError::InvalidParameter(
            "Callback URL must include a URI scheme".to_string(),
        ));
    }

    let scheme = trimmed.split("://").next().unwrap_or("");
    if scheme.is_empty()
        || !scheme
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
    {
        return Err(AppError::InvalidParameter(
            "Callback URL contains an invalid URI scheme".to_string(),
        ));
    }

    if matches!(scheme, "ftp" | "file") {
        return Err(AppError::InvalidParameter(
            "Callback URL uses an unsupported URI scheme".to_string(),
        ));
    }

    // For HTTP URLs, AWS only allows localhost in development scenarios.
    if trimmed.starts_with("http://") {
        let host_part = trimmed.trim_start_matches("http://");
        let host = host_part.split('/').next().unwrap_or("");
        let host_without_port = host.split(':').next().unwrap_or("");

        // Allow HTTP only for localhost
        if host_without_port != "localhost" && host_without_port != "127.0.0.1" {
            // In emulator mode, we're more lenient - just warn
            // In production AWS, this would be an error
            tracing::warn!("HTTP callback URL used for non-localhost: {}", url);
        }
    }

    Ok(())
}

/// Validate pool name is not empty
/// A constraint violation in the words of the Cognito front end.
///
/// `member` is the path Cognito reports, in lower camel case
/// (`policies.passwordPolicy.minimumLength`).
fn constraint_violation(value: impl std::fmt::Display, member: &str, constraint: &str) -> AppError {
    AppError::InvalidParameter(format!(
        "1 validation error detected: Value '{value}' at '{member}' failed to satisfy constraint: {constraint}"
    ))
}

/// Hold a string member to its length range, counted in characters.
fn validate_member_length(member: &str, value: &str, min: usize, max: usize) -> Result<()> {
    let length = value.chars().count();
    if length < min {
        return Err(constraint_violation(
            value,
            member,
            &format!("Member must have length greater than or equal to {min}"),
        ));
    }
    if length > max {
        return Err(constraint_violation(
            value,
            member,
            &format!("Member must have length less than or equal to {max}"),
        ));
    }
    Ok(())
}

/// Hold an integer member to its range.
fn validate_member_range(member: &str, value: i32, min: i32, max: i32) -> Result<()> {
    if value < min {
        return Err(constraint_violation(
            value,
            member,
            &format!("Member must have value greater than or equal to {min}"),
        ));
    }
    if value > max {
        return Err(constraint_violation(
            value,
            member,
            &format!("Member must have value less than or equal to {max}"),
        ));
    }
    Ok(())
}

/// The pattern of `PoolName` and `ClientName`.
const RESOURCE_NAME_PATTERN: &str = r"[\w\s+=,.@-]+";

/// A pool or app client name: 1 to 128 characters of `[\w\s+=,.@-]`.
///
/// A name of nothing but whitespace is refused as well, which is stricter
/// than the pattern alone.
fn validate_resource_name(member: &str, name: &str) -> Result<()> {
    validate_member_length(member, name, 1, 128)?;

    let matches_pattern = name
        .chars()
        .all(|c| c.is_alphanumeric() || c.is_whitespace() || "_+=,.@-".contains(c));
    if !matches_pattern || name.trim().is_empty() {
        return Err(constraint_violation(
            name,
            member,
            &format!("Member must satisfy regular expression pattern: {RESOURCE_NAME_PATTERN}"),
        ));
    }

    Ok(())
}

/// Validate a user pool name
pub fn validate_pool_name(name: &str) -> Result<()> {
    validate_resource_name("poolName", name)
}

/// Validate an app client name
pub fn validate_client_name(name: &str) -> Result<()> {
    validate_resource_name("clientName", name)
}

fn validate_string_length(field: &str, value: &str, min: usize, max: usize) -> Result<()> {
    let len = value.chars().count();
    if len < min || len > max {
        return Err(AppError::InvalidParameter(format!(
            "{field} must be between {min} and {max} characters"
        )));
    }
    Ok(())
}

fn validate_contains(field: &str, value: &str, needle: &str) -> Result<()> {
    if !value.contains(needle) {
        return Err(AppError::InvalidParameter(format!(
            "{field} must contain {needle}"
        )));
    }
    Ok(())
}

fn validate_duration_seconds(field: &str, seconds: i64, min: i64, max: i64) -> Result<()> {
    if seconds < min || seconds > max {
        return Err(AppError::InvalidParameter(format!(
            "{field} is out of range"
        )));
    }
    Ok(())
}

pub fn validate_user_pool_policies(policies: &UserPoolPolicies) -> Result<()> {
    if let Some(password_policy) = &policies.password_policy {
        if let Some(minimum_length) = password_policy.minimum_length {
            validate_member_range(
                "policies.passwordPolicy.minimumLength",
                minimum_length,
                6,
                99,
            )?;
        }

        if let Some(password_history_size) = password_policy.password_history_size {
            validate_member_range(
                "policies.passwordPolicy.passwordHistorySize",
                password_history_size,
                0,
                24,
            )?;
        }

        if let Some(days) = password_policy.temporary_password_validity_days {
            validate_member_range(
                "policies.passwordPolicy.temporaryPasswordValidityDays",
                days,
                0,
                365,
            )?;
        }
    }

    Ok(())
}

pub fn validate_verification_message_template(
    template: &VerificationMessageTemplate,
) -> Result<()> {
    if template.email_message.is_some() && template.email_message_by_link.is_some() {
        return Err(AppError::InvalidParameter(
            "VerificationMessageTemplate cannot include both EmailMessage and EmailMessageByLink"
                .to_string(),
        ));
    }

    if let Some(message) = &template.email_message {
        validate_string_length(
            "VerificationMessageTemplate.EmailMessage",
            message,
            6,
            20_000,
        )?;
        validate_contains(
            "VerificationMessageTemplate.EmailMessage",
            message,
            "{####}",
        )?;
    }

    if let Some(message) = &template.email_message_by_link {
        validate_string_length(
            "VerificationMessageTemplate.EmailMessageByLink",
            message,
            6,
            20_000,
        )?;
        validate_contains(
            "VerificationMessageTemplate.EmailMessageByLink",
            message,
            "{##",
        )?;
        validate_contains(
            "VerificationMessageTemplate.EmailMessageByLink",
            message,
            "##}",
        )?;
    }

    if let Some(subject) = &template.email_subject {
        validate_string_length("VerificationMessageTemplate.EmailSubject", subject, 1, 140)?;
    }

    if let Some(subject) = &template.email_subject_by_link {
        validate_string_length(
            "VerificationMessageTemplate.EmailSubjectByLink",
            subject,
            1,
            140,
        )?;
    }

    if let Some(message) = &template.sms_message {
        validate_string_length("VerificationMessageTemplate.SmsMessage", message, 6, 140)?;
        validate_contains("VerificationMessageTemplate.SmsMessage", message, "{####}")?;
    }

    Ok(())
}

pub fn validate_code_delivery_message(field: &str, value: &str, max: usize) -> Result<()> {
    validate_string_length(field, value, 6, max)?;
    validate_contains(field, value, "{####}")
}

pub fn validate_subject(field: &str, value: &str) -> Result<()> {
    validate_string_length(field, value, 1, 140)
}

pub fn validate_account_recovery_setting(setting: &AccountRecoverySetting) -> Result<()> {
    let Some(mechanisms) = setting.recovery_mechanisms.as_ref() else {
        return Ok(());
    };

    if mechanisms.is_empty() {
        return Err(AppError::InvalidParameter(
            "AccountRecoverySetting.RecoveryMechanisms cannot be empty".to_string(),
        ));
    }

    if mechanisms.len() > 3 {
        return Err(AppError::InvalidParameter(
            "AccountRecoverySetting.RecoveryMechanisms cannot contain more than 3 entries"
                .to_string(),
        ));
    }

    let mut seen_priorities = std::collections::HashSet::new();
    for mechanism in mechanisms {
        if let Some(priority) = mechanism.priority {
            if priority <= 0 {
                return Err(AppError::InvalidParameter(
                    "AccountRecoverySetting.RecoveryMechanisms.Priority must be positive"
                        .to_string(),
                ));
            }
            if !seen_priorities.insert(priority) {
                return Err(AppError::InvalidParameter(
                    "AccountRecoverySetting.RecoveryMechanisms.Priority must be unique".to_string(),
                ));
            }
        }
    }

    Ok(())
}

fn validate_invite_message_template(template: &InviteMessageTemplate) -> Result<()> {
    if let Some(message) = &template.email_message {
        validate_code_delivery_message(
            "AdminCreateUserConfig.InviteMessageTemplate.EmailMessage",
            message,
            20_000,
        )?;
    }
    if let Some(subject) = &template.email_subject {
        validate_subject(
            "AdminCreateUserConfig.InviteMessageTemplate.EmailSubject",
            subject,
        )?;
    }
    if let Some(message) = &template.sms_message {
        validate_code_delivery_message(
            "AdminCreateUserConfig.InviteMessageTemplate.SMSMessage",
            message,
            140,
        )?;
    }
    Ok(())
}

pub fn validate_admin_create_user_config(config: &AdminCreateUserConfig) -> Result<()> {
    if let Some(template) = &config.invite_message_template {
        validate_invite_message_template(template)?;
    }

    if let Some(days) = config.unused_account_validity_days
        && !(0..=365).contains(&days)
    {
        return Err(AppError::InvalidParameter(
            "AdminCreateUserConfig.UnusedAccountValidityDays must be between 0 and 365".to_string(),
        ));
    }

    Ok(())
}

pub fn validate_device_configuration(_config: &DeviceConfiguration) -> Result<()> {
    Ok(())
}

pub fn validate_sms_configuration(config: &SmsConfiguration, field: &str) -> Result<()> {
    if let Some(region) = &config.sns_region {
        validate_string_length(&format!("{field}.SnsRegion"), region, 1, 32)?;
    }

    if let Some(external_id) = &config.external_id {
        validate_string_length(&format!("{field}.ExternalId"), external_id, 1, 128)?;
    }

    Ok(())
}

pub fn validate_email_configuration(config: &EmailConfiguration) -> Result<()> {
    if let Some(reply_to_email_address) = &config.reply_to_email_address {
        validate_email(reply_to_email_address)?;
    }

    if let Some(configuration_set) = &config.configuration_set {
        validate_string_length(
            "EmailConfiguration.ConfigurationSet",
            configuration_set,
            1,
            64,
        )?;
    }

    Ok(())
}

fn validate_numeric_constraint(field: &str, value: &str) -> Result<()> {
    value.parse::<i64>().map_err(|_| {
        AppError::InvalidParameter(format!("{field} must be a valid integer string"))
    })?;
    Ok(())
}

pub fn validate_schema_attributes(schema_attributes: &[SchemaAttributeType]) -> Result<()> {
    for attribute in schema_attributes {
        validate_string_length("Schema.Name", &attribute.name, 1, 64)?;

        if let Some(constraints) = &attribute.string_attribute_constraints {
            if let Some(min) = &constraints.min_length {
                validate_numeric_constraint("Schema.StringAttributeConstraints.MinLength", min)?;
            }
            if let Some(max) = &constraints.max_length {
                validate_numeric_constraint("Schema.StringAttributeConstraints.MaxLength", max)?;
            }
            if let (Some(min), Some(max)) = (&constraints.min_length, &constraints.max_length)
                && min.parse::<i64>().ok() > max.parse::<i64>().ok()
            {
                return Err(AppError::InvalidParameter(
                    "Schema.StringAttributeConstraints MinLength cannot exceed MaxLength"
                        .to_string(),
                ));
            }
        }

        if let Some(constraints) = &attribute.number_attribute_constraints {
            if let Some(min) = &constraints.min_value {
                validate_numeric_constraint("Schema.NumberAttributeConstraints.MinValue", min)?;
            }
            if let Some(max) = &constraints.max_value {
                validate_numeric_constraint("Schema.NumberAttributeConstraints.MaxValue", max)?;
            }
            if let (Some(min), Some(max)) = (&constraints.min_value, &constraints.max_value)
                && min.parse::<i64>().ok() > max.parse::<i64>().ok()
            {
                return Err(AppError::InvalidParameter(
                    "Schema.NumberAttributeConstraints MinValue cannot exceed MaxValue".to_string(),
                ));
            }
        }
    }

    Ok(())
}

pub fn validate_user_attribute_update_settings(
    settings: &UserAttributeUpdateSettingsType,
) -> Result<()> {
    if let Some(attributes) = &settings.attributes_require_verification_before_update
        && attributes.is_empty()
    {
        return Err(AppError::InvalidParameter(
            "UserAttributeUpdateSettings.AttributesRequireVerificationBeforeUpdate cannot be empty"
                .to_string(),
        ));
    }

    Ok(())
}

pub fn validate_user_pool_add_ons(_add_ons: &UserPoolAddOns) -> Result<()> {
    Ok(())
}

pub fn validate_oauth_client_configuration(
    allowed_oauth_flows_user_pool_client: bool,
    allowed_oauth_flows: &[OAuthFlow],
    callback_urls: &[String],
    logout_urls: &[String],
    default_redirect_uri: Option<&str>,
    generate_secret: bool,
) -> Result<()> {
    let uses_oauth_features = !allowed_oauth_flows.is_empty()
        || !callback_urls.is_empty()
        || !logout_urls.is_empty()
        || default_redirect_uri.is_some();

    if uses_oauth_features && !allowed_oauth_flows_user_pool_client {
        return Err(AppError::InvalidParameter(
            "AllowedOAuthFlowsUserPoolClient must be true when OAuth settings are provided"
                .to_string(),
        ));
    }

    for url in callback_urls {
        validate_callback_url(url)?;
    }
    for url in logout_urls {
        validate_callback_url(url)?;
    }

    if let Some(default_redirect_uri) = default_redirect_uri {
        validate_callback_url(default_redirect_uri)?;
        if !callback_urls.is_empty() && !callback_urls.iter().any(|url| url == default_redirect_uri)
        {
            return Err(AppError::InvalidParameter(
                "DefaultRedirectURI must match one of the CallbackURLs".to_string(),
            ));
        }
    }

    if allowed_oauth_flows.contains(&OAuthFlow::ClientCredentials) {
        if allowed_oauth_flows.len() > 1 {
            return Err(AppError::InvalidParameter(
                "client_credentials must be the only AllowedOAuthFlows value".to_string(),
            ));
        }
        if !generate_secret {
            return Err(AppError::InvalidParameter(
                "GenerateSecret must be true when client_credentials is enabled".to_string(),
            ));
        }
    }

    Ok(())
}

pub fn validate_pool_mfa_configuration(
    mfa_configuration: Option<MfaConfiguration>,
    sms_mfa_configuration: Option<&SmsMfaConfiguration>,
    software_token_mfa_configuration: Option<&SoftwareTokenMfaConfiguration>,
    email_mfa_configuration: Option<&EmailMfaConfiguration>,
    webauthn_configuration: Option<&WebAuthnConfiguration>,
) -> Result<()> {
    if let Some(sms) = sms_mfa_configuration
        && let Some(message) = &sms.sms_authentication_message
    {
        validate_code_delivery_message(
            "SmsMfaConfiguration.SmsAuthenticationMessage",
            message,
            140,
        )?;
    }

    if let Some(email) = email_mfa_configuration {
        if let Some(message) = &email.message {
            validate_code_delivery_message("EmailMfaConfiguration.Message", message, 20_000)?;
        }
        if let Some(subject) = &email.subject {
            validate_subject("EmailMfaConfiguration.Subject", subject)?;
        }
    }

    if let Some(webauthn) = webauthn_configuration
        && let Some(relying_party_id) = &webauthn.relying_party_id
        && relying_party_id.trim().is_empty()
    {
        return Err(AppError::InvalidParameter(
            "WebAuthnConfiguration.RelyingPartyId cannot be empty".to_string(),
        ));
    }

    if matches!(mfa_configuration, Some(MfaConfiguration::On)) {
        let has_enabled_factor = sms_mfa_configuration.is_some()
            || software_token_mfa_configuration
                .and_then(|config| config.enabled)
                .unwrap_or(false)
            || email_mfa_configuration.is_some();

        if !has_enabled_factor {
            return Err(AppError::InvalidParameter(
                "MfaConfiguration ON requires at least one MFA configuration".to_string(),
            ));
        }
    }

    Ok(())
}

pub fn validate_explicit_auth_flows(flows: &[ExplicitAuthFlow]) -> Result<()> {
    let has_legacy = flows.iter().any(|flow| flow.is_legacy());
    let has_allow = flows.iter().any(|flow| !flow.is_legacy());
    if has_legacy && has_allow {
        return Err(AppError::InvalidParameter(
            "Legacy ExplicitAuthFlows values cannot be combined with ALLOW_* values".to_string(),
        ));
    }
    Ok(())
}

pub fn validate_token_validities(
    access_token_validity: Option<i32>,
    id_token_validity: Option<i32>,
    refresh_token_validity: Option<i32>,
    access_token_unit: Option<TokenValidityUnit>,
    id_token_unit: Option<TokenValidityUnit>,
    refresh_token_unit: Option<TokenValidityUnit>,
) -> Result<()> {
    if let Some(validity) = access_token_validity {
        let seconds = i64::from(validity)
            * access_token_unit
                .unwrap_or(TokenValidityUnit::Hours)
                .seconds_multiplier();
        validate_duration_seconds("AccessTokenValidity", seconds, 300, 86_400)?;
    }

    if let Some(validity) = id_token_validity {
        let seconds = i64::from(validity)
            * id_token_unit
                .unwrap_or(TokenValidityUnit::Hours)
                .seconds_multiplier();
        validate_duration_seconds("IdTokenValidity", seconds, 300, 86_400)?;
    }

    if let Some(validity) = refresh_token_validity {
        let seconds = i64::from(validity)
            * refresh_token_unit
                .unwrap_or(TokenValidityUnit::Days)
                .seconds_multiplier();
        validate_duration_seconds("RefreshTokenValidity", seconds, 3_600, 315_360_000)?;
    }

    Ok(())
}

/// A group name: 1 to 128 letters, marks, symbols, numbers, and punctuation.
/// Whitespace is not part of the pattern.
pub fn validate_group_name(name: &str) -> Result<()> {
    validate_member_length("groupName", name, 1, 128)?;

    if name.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(constraint_violation(
            name,
            "groupName",
            r"Member must satisfy regular expression pattern: [\p{L}\p{M}\p{S}\p{N}\p{P}]+",
        ));
    }

    Ok(())
}

/// The optional members of CreateGroup and UpdateGroup.
pub fn validate_group_settings(
    description: Option<&str>,
    role_arn: Option<&str>,
    precedence: Option<i32>,
) -> Result<()> {
    if let Some(description) = description {
        validate_member_length("description", description, 0, 2048)?;
    }
    if let Some(role_arn) = role_arn {
        validate_member_length("roleArn", role_arn, 20, 2048)?;
    }
    if let Some(precedence) = precedence {
        validate_member_range("precedence", precedence, 0, i32::MAX)?;
    }
    Ok(())
}

/// Parse and validate a UserPoolId from a string
///
/// Returns InvalidParameter error if the format is invalid
pub fn parse_user_pool_id(value: &str) -> Result<UserPoolId> {
    UserPoolId::new(value).map_err(|e| AppError::InvalidParameter(e.to_string()))
}

pub fn validate_client_attribute_names(field: &str, attributes: &[String]) -> Result<()> {
    for attribute in attributes {
        let trimmed = attribute.trim();
        if trimmed.is_empty() {
            return Err(AppError::InvalidParameter(format!(
                "{field} cannot contain empty attribute names"
            )));
        }
        validate_string_length(field, trimmed, 1, 2048)?;
    }

    Ok(())
}

pub fn validate_analytics_configuration(config: &AnalyticsConfiguration) -> Result<()> {
    if let Some(application_id) = &config.application_id {
        validate_string_length(
            "AnalyticsConfiguration.ApplicationId",
            application_id,
            1,
            128,
        )?;
    }
    if let Some(application_arn) = &config.application_arn {
        validate_string_length(
            "AnalyticsConfiguration.ApplicationArn",
            application_arn,
            1,
            2048,
        )?;
    }
    if let Some(external_id) = &config.external_id {
        validate_string_length("AnalyticsConfiguration.ExternalId", external_id, 1, 128)?;
    }
    if let Some(role_arn) = &config.role_arn {
        validate_string_length("AnalyticsConfiguration.RoleArn", role_arn, 1, 2048)?;
    }

    Ok(())
}

pub fn validate_auth_session_validity(value: i32) -> Result<()> {
    validate_member_range("authSessionValidity", value, 3, 15)
}

pub fn validate_refresh_token_rotation(config: &RefreshTokenRotationType) -> Result<()> {
    if let Some(seconds) = config.retry_grace_period_seconds {
        validate_member_range(
            "refreshTokenRotation.retryGracePeriodSeconds",
            seconds,
            0,
            60,
        )?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_username_valid() {
        assert!(validate_username("testuser").is_ok());
        assert!(validate_username("user123").is_ok());
        assert!(validate_username("user_name").is_ok());
    }

    #[test]
    fn test_validate_username_empty() {
        assert!(validate_username("").is_err());
        assert!(validate_username("   ").is_err());
    }

    #[test]
    fn test_validate_username_with_spaces() {
        assert!(validate_username("user name").is_err());
    }

    fn pool_with_policy(policy: Option<PasswordPolicy>) -> UserPool {
        let mut pool = UserPool::new_for_test(UserPoolId::new("us-east-1_Test").unwrap());
        pool.policies = policy.map(|password_policy| UserPoolPolicies {
            password_policy: Some(password_policy),
            sign_in_policy: None,
        });
        pool
    }

    fn policy_violation(pool: &UserPool, password: &str) -> String {
        match validate_password_against_policy(pool, password) {
            Err(AppError::InvalidPassword(message)) => message,
            other => panic!("expected InvalidPasswordException, got {other:?}"),
        }
    }

    #[test]
    fn test_default_password_policy_is_cognitos() {
        let pool = pool_with_policy(None);
        assert!(validate_password_against_policy(&pool, "Password123!").is_ok());
        assert_eq!(
            policy_violation(&pool, "Pw1!"),
            "Password did not conform with policy: Password not long enough"
        );
        assert_eq!(
            policy_violation(&pool, "password123!"),
            "Password did not conform with policy: Password must have uppercase characters"
        );
        assert_eq!(
            policy_violation(&pool, "PASSWORD123!"),
            "Password did not conform with policy: Password must have lowercase characters"
        );
        assert_eq!(
            policy_violation(&pool, "Password!!!!"),
            "Password did not conform with policy: Password must have numeric characters"
        );
        assert_eq!(
            policy_violation(&pool, "Password1234"),
            "Password did not conform with policy: Password must have symbol characters"
        );
    }

    #[test]
    fn test_password_policy_of_the_pool_is_enforced() {
        let pool = pool_with_policy(Some(PasswordPolicy {
            minimum_length: Some(6),
            password_history_size: None,
            require_lowercase: Some(false),
            require_numbers: Some(false),
            require_symbols: None,
            require_uppercase: Some(false),
            temporary_password_validity_days: None,
        }));
        assert!(validate_password_against_policy(&pool, "secret").is_ok());
        assert_eq!(
            policy_violation(&pool, "short"),
            "Password did not conform with policy: Password not long enough"
        );
    }

    #[test]
    fn test_password_shape_is_a_validation_error() {
        let pool = pool_with_policy(None);
        for password in ["", " Password123!", "Password123! "] {
            assert!(matches!(
                validate_password_against_policy(&pool, password),
                Err(AppError::InvalidParameter(message)) if message.contains("^[\\S]+.*[\\S]+$")
            ));
        }
        assert!(matches!(
            validate_password_against_policy(&pool, &"Aa1!".repeat(65)),
            Err(AppError::InvalidParameter(message))
                if message.contains("length less than or equal to 256")
        ));
    }

    #[test]
    fn test_generated_temporary_password_satisfies_the_policy() {
        let default_pool = pool_with_policy(None);
        let long_pool = pool_with_policy(Some(PasswordPolicy {
            minimum_length: Some(24),
            ..default_password_policy()
        }));
        for pool in [&default_pool, &long_pool] {
            for _ in 0..20 {
                let password = generate_temporary_password(pool);
                assert!(validate_password_against_policy(pool, &password).is_ok());
            }
        }
    }

    #[test]
    fn test_validate_email_valid() {
        assert!(validate_email("user@example.com").is_ok());
        assert!(validate_email("user.name@example.co.uk").is_ok());
    }

    #[test]
    fn test_validate_email_invalid() {
        assert!(validate_email("notanemail").is_err());
        assert!(validate_email("user@").is_err());
        assert!(validate_email("@example.com").is_err());
        assert!(validate_email("user@example").is_err());
        assert!(validate_email("").is_err());
    }

    #[test]
    fn test_validate_callback_url_valid() {
        assert!(validate_callback_url("https://example.com/callback").is_ok());
        assert!(validate_callback_url("http://localhost:3000/callback").is_ok());
        assert!(validate_callback_url("http://127.0.0.1:3000/callback").is_ok());
    }

    #[test]
    fn test_validate_callback_url_invalid() {
        assert!(validate_callback_url("").is_err());
        assert!(validate_callback_url("not-a-url").is_err());
        assert!(validate_callback_url("ftp://example.com").is_err());
    }

    fn violation(result: Result<()>) -> String {
        match result {
            Err(AppError::InvalidParameter(message)) => message,
            other => panic!("expected InvalidParameterException, got {other:?}"),
        }
    }

    #[test]
    fn test_pool_and_client_names_follow_cognitos_constraints() {
        assert!(validate_pool_name("My pool+test=1,2.3@x-y_z").is_ok());
        assert!(validate_client_name("web client").is_ok());

        assert_eq!(
            violation(validate_pool_name("")),
            "1 validation error detected: Value '' at 'poolName' failed to satisfy constraint: Member must have length greater than or equal to 1"
        );
        let too_long = "a".repeat(129);
        assert_eq!(
            violation(validate_client_name(&too_long)),
            format!(
                "1 validation error detected: Value '{too_long}' at 'clientName' failed to satisfy constraint: Member must have length less than or equal to 128"
            )
        );
        assert_eq!(
            violation(validate_pool_name("bad/name")),
            r"1 validation error detected: Value 'bad/name' at 'poolName' failed to satisfy constraint: Member must satisfy regular expression pattern: [\w\s+=,.@-]+"
        );
        assert!(validate_client_name("   ").is_err());
    }

    #[test]
    fn test_group_name_excludes_whitespace() {
        assert!(validate_group_name("admins").is_ok());
        assert!(validate_group_name("us-east-1_Pool_Google").is_ok());
        assert!(validate_group_name("管理者").is_ok());
        assert!(validate_group_name("two words").is_err());
        assert!(validate_group_name("").is_err());
        assert!(validate_group_name(&"g".repeat(129)).is_err());
    }

    #[test]
    fn test_integer_members_name_their_path() {
        assert_eq!(
            violation(validate_auth_session_validity(2)),
            "1 validation error detected: Value '2' at 'authSessionValidity' failed to satisfy constraint: Member must have value greater than or equal to 3"
        );
        assert_eq!(
            violation(validate_auth_session_validity(16)),
            "1 validation error detected: Value '16' at 'authSessionValidity' failed to satisfy constraint: Member must have value less than or equal to 15"
        );

        let policy = |minimum_length| UserPoolPolicies {
            password_policy: Some(PasswordPolicy {
                minimum_length: Some(minimum_length),
                ..default_password_policy()
            }),
            sign_in_policy: None,
        };
        assert!(validate_user_pool_policies(&policy(6)).is_ok());
        assert_eq!(
            violation(validate_user_pool_policies(&policy(5))),
            "1 validation error detected: Value '5' at 'policies.passwordPolicy.minimumLength' failed to satisfy constraint: Member must have value greater than or equal to 6"
        );
        assert_eq!(
            violation(validate_user_pool_policies(&policy(100))),
            "1 validation error detected: Value '100' at 'policies.passwordPolicy.minimumLength' failed to satisfy constraint: Member must have value less than or equal to 99"
        );
    }
}
