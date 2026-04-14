//! Input validation functions for AWS Cognito API compliance
//!
//! Provides validation for usernames, passwords, emails, and URLs
//! to match AWS Cognito's validation rules.

use crate::error::{AppError, Result};
use crate::types::{
    ExplicitAuthFlow, OAuthFlow, TokenValidityUnit, UserPoolId, UserPoolPolicies,
    VerificationMessageTemplate,
};

/// Minimum password length (AWS default is 6)
const MIN_PASSWORD_LENGTH: usize = 6;

/// Maximum password length
const MAX_PASSWORD_LENGTH: usize = 256;

/// Maximum username length
const MAX_USERNAME_LENGTH: usize = 128;

/// Validate username is not empty and within bounds
pub fn validate_username(username: &str) -> Result<()> {
    let trimmed = username.trim();

    if trimmed.is_empty() {
        return Err(AppError::InvalidParameter(
            "Username cannot be empty".to_string(),
        ));
    }

    if trimmed.len() > MAX_USERNAME_LENGTH {
        return Err(AppError::InvalidParameter(format!(
            "Username cannot exceed {} characters",
            MAX_USERNAME_LENGTH
        )));
    }

    // Username should not contain spaces (AWS Cognito rule)
    if trimmed.contains(' ') {
        return Err(AppError::InvalidParameter(
            "Username cannot contain spaces".to_string(),
        ));
    }

    Ok(())
}

/// Validate password meets minimum requirements
pub fn validate_password(password: &str) -> Result<()> {
    if password.is_empty() {
        return Err(AppError::InvalidParameter(
            "Password cannot be empty".to_string(),
        ));
    }

    if password.len() < MIN_PASSWORD_LENGTH {
        return Err(AppError::InvalidParameter(format!(
            "Password must be at least {} characters",
            MIN_PASSWORD_LENGTH
        )));
    }

    if password.len() > MAX_PASSWORD_LENGTH {
        return Err(AppError::InvalidParameter(format!(
            "Password cannot exceed {} characters",
            MAX_PASSWORD_LENGTH
        )));
    }

    Ok(())
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
pub fn validate_pool_name(name: &str) -> Result<()> {
    let trimmed = name.trim();

    if trimmed.is_empty() {
        return Err(AppError::InvalidParameter(
            "Pool name cannot be empty".to_string(),
        ));
    }

    if trimmed.len() > 128 {
        return Err(AppError::InvalidParameter(
            "Pool name cannot exceed 128 characters".to_string(),
        ));
    }

    if !trimmed
        .chars()
        .all(|c| c.is_alphanumeric() || c.is_whitespace() || "_+=,.@-".contains(c))
    {
        return Err(AppError::InvalidParameter(
            "Pool name contains unsupported characters".to_string(),
        ));
    }

    Ok(())
}

/// Validate client name is not empty
pub fn validate_client_name(name: &str) -> Result<()> {
    let trimmed = name.trim();

    if trimmed.is_empty() {
        return Err(AppError::InvalidParameter(
            "Client name cannot be empty".to_string(),
        ));
    }

    if trimmed.len() > 128 {
        return Err(AppError::InvalidParameter(
            "Client name cannot exceed 128 characters".to_string(),
        ));
    }

    Ok(())
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
        if let Some(minimum_length) = password_policy.minimum_length
            && !(6..=99).contains(&minimum_length)
        {
            return Err(AppError::InvalidParameter(
                "PasswordPolicy.MinimumLength must be between 6 and 99".to_string(),
            ));
        }

        if let Some(password_history_size) = password_policy.password_history_size
            && !(0..=24).contains(&password_history_size)
        {
            return Err(AppError::InvalidParameter(
                "PasswordPolicy.PasswordHistorySize must be between 0 and 24".to_string(),
            ));
        }

        if let Some(days) = password_policy.temporary_password_validity_days
            && !(0..=365).contains(&days)
        {
            return Err(AppError::InvalidParameter(
                "PasswordPolicy.TemporaryPasswordValidityDays must be between 0 and 365"
                    .to_string(),
            ));
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

/// Validate group name is not empty
pub fn validate_group_name(name: &str) -> Result<()> {
    let trimmed = name.trim();

    if trimmed.is_empty() {
        return Err(AppError::InvalidParameter(
            "Group name cannot be empty".to_string(),
        ));
    }

    if trimmed.len() > 128 {
        return Err(AppError::InvalidParameter(
            "Group name cannot exceed 128 characters".to_string(),
        ));
    }

    Ok(())
}

/// Parse and validate a UserPoolId from a string
///
/// Returns InvalidParameter error if the format is invalid
pub fn parse_user_pool_id(value: &str) -> Result<UserPoolId> {
    UserPoolId::new(value).map_err(|e| AppError::InvalidParameter(e.to_string()))
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

    #[test]
    fn test_validate_password_valid() {
        assert!(validate_password("password123").is_ok());
        assert!(validate_password("123456").is_ok());
    }

    #[test]
    fn test_validate_password_too_short() {
        assert!(validate_password("12345").is_err());
        assert!(validate_password("").is_err());
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
}
