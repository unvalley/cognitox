//! Input validation functions for AWS Cognito API compliance
//!
//! Provides validation for usernames, passwords, emails, and URLs
//! to match AWS Cognito's validation rules.

use crate::error::{AppError, Result};
use crate::types::UserPoolId;

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

    // Must start with http:// or https://
    if !trimmed.starts_with("http://") && !trimmed.starts_with("https://") {
        return Err(AppError::InvalidParameter(
            "Callback URL must start with http:// or https://".to_string(),
        ));
    }

    // For non-localhost URLs, AWS requires HTTPS in production
    // But for local development, we allow HTTP for localhost
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
