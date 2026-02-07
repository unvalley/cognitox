use std::fmt;
use std::str::FromStr;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// User Pool ID with AWS Cognito format validation
///
/// Format: `[\w-]+_[0-9a-zA-Z]+` (e.g., `us-east-1_AbCdEfGhI` or `local_abc123def`)
/// Length: 1-55 characters
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct UserPoolId(String);

impl UserPoolId {
    /// Minimum length for UserPoolId
    pub const MIN_LENGTH: usize = 1;

    /// Maximum length for UserPoolId
    pub const MAX_LENGTH: usize = 55;

    /// Create a new UserPoolId with validation
    pub fn new(value: impl Into<String>) -> Result<Self, UserPoolIdError> {
        let value = value.into();
        Self::validate(&value)?;
        Ok(Self(value))
    }

    /// Create a new UserPoolId for local development
    /// Format: `local_{random_alphanumeric}`
    pub fn new_local() -> Self {
        let random_part: String = uuid::Uuid::new_v4()
            .to_string()
            .replace("-", "")
            .chars()
            .take(9)
            .collect();
        Self(format!("local_{}", random_part))
    }

    /// Get the inner string value
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Validate the UserPoolId format
    fn validate(value: &str) -> Result<(), UserPoolIdError> {
        // Length check
        if value.is_empty() {
            return Err(UserPoolIdError::Empty);
        }
        if value.len() > Self::MAX_LENGTH {
            return Err(UserPoolIdError::TooLong(value.len()));
        }

        // Pattern check: [\w-]+_[0-9a-zA-Z]+
        // Must contain exactly one underscore separating two parts
        let parts: Vec<&str> = value.splitn(2, '_').collect();
        if parts.len() != 2 {
            return Err(UserPoolIdError::InvalidFormat);
        }

        let (prefix, suffix) = (parts[0], parts[1]);

        // Prefix: [\w-]+ (word chars and hyphens)
        if prefix.is_empty()
            || !prefix
                .chars()
                .all(|c| c.is_alphanumeric() || c == '_' || c == '-')
        {
            return Err(UserPoolIdError::InvalidFormat);
        }

        // Suffix: [0-9a-zA-Z]+ (alphanumeric only)
        if suffix.is_empty() || !suffix.chars().all(|c| c.is_ascii_alphanumeric()) {
            return Err(UserPoolIdError::InvalidFormat);
        }

        Ok(())
    }
}

impl fmt::Display for UserPoolId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for UserPoolId {
    type Err = UserPoolIdError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

impl TryFrom<String> for UserPoolId {
    type Error = UserPoolIdError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<UserPoolId> for String {
    fn from(id: UserPoolId) -> Self {
        id.0
    }
}

impl AsRef<str> for UserPoolId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// Error type for UserPoolId validation
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UserPoolIdError {
    Empty,
    TooLong(usize),
    InvalidFormat,
}

impl fmt::Display for UserPoolIdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UserPoolIdError::Empty => write!(f, "UserPoolId cannot be empty"),
            UserPoolIdError::TooLong(len) => {
                write!(
                    f,
                    "UserPoolId exceeds maximum length of {} (got {})",
                    UserPoolId::MAX_LENGTH,
                    len
                )
            }
            UserPoolIdError::InvalidFormat => {
                write!(
                    f,
                    "UserPoolId must match pattern [\\w-]+_[0-9a-zA-Z]+ (e.g., us-east-1_AbCdEfGhI)"
                )
            }
        }
    }
}

impl std::error::Error for UserPoolIdError {}

/// User Pool Client ID
pub type ClientId = String;

/// User's unique identifier
pub type UserId = Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserPool {
    pub id: UserPoolId,
    pub name: String,
    pub creation_date: DateTime<Utc>,
    pub last_modified_date: DateTime<Utc>,
}

/// Token validity time units
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TokenValidityUnits {
    pub access_token: Option<String>,  // seconds, minutes, hours, days
    pub id_token: Option<String>,      // seconds, minutes, hours, days
    pub refresh_token: Option<String>, // seconds, minutes, hours, days
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserPoolClient {
    pub client_id: ClientId,
    pub user_pool_id: UserPoolId,
    pub client_name: String,
    pub client_secret: Option<String>,
    pub creation_date: DateTime<Utc>,
    pub last_modified_date: DateTime<Utc>,

    // OAuth configuration
    pub allowed_oauth_flows: Vec<String>,
    pub allowed_oauth_scopes: Vec<String>,
    pub allowed_oauth_flows_user_pool_client: bool,
    pub callback_urls: Vec<String>,
    pub logout_urls: Vec<String>,
    pub default_redirect_uri: Option<String>,
    pub supported_identity_providers: Vec<String>,

    // Auth flows
    pub explicit_auth_flows: Vec<String>,

    // Token validity
    pub access_token_validity: Option<i32>,
    pub id_token_validity: Option<i32>,
    pub refresh_token_validity: Option<i32>,
    pub token_validity_units: Option<TokenValidityUnits>,

    // Security settings
    pub enable_token_revocation: bool,
    pub prevent_user_existence_errors: Option<String>,
    pub enable_propagate_additional_user_context_data: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: UserId,
    pub user_pool_id: UserPoolId,
    pub username: String,
    pub email: Option<String>,
    pub phone_number: Option<String>,
    pub password_hash: String,
    pub enabled: bool,
    pub user_status: UserStatus,
    pub attributes: Vec<UserAttribute>,
    pub creation_date: DateTime<Utc>,
    pub last_modified_date: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum UserStatus {
    #[default]
    Unconfirmed,
    Confirmed,
    Archived,
    Compromised,
    Unknown,
    ResetRequired,
    ForceChangePassword,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct UserAttribute {
    pub name: String,
    pub value: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfirmationCode {
    pub user_id: UserId,
    pub code: String,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefreshToken {
    pub token: String,
    pub user_id: UserId,
    pub client_id: ClientId,
    pub expires_at: DateTime<Utc>,
}

/// Authentication flow types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AuthFlow {
    UserSrpAuth,
    RefreshTokenAuth,
    RefreshToken,
    CustomAuth,
    AdminNoSrpAuth,
    UserPasswordAuth,
    AdminUserPasswordAuth,
}

/// Challenge types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ChallengeType {
    SmsMfa,
    SoftwareTokenMfa,
    SelectMfaType,
    MfaSetup,
    PasswordVerifier,
    CustomChallenge,
    DeviceSrpAuth,
    DevicePasswordVerifier,
    AdminNoSrpAuth,
    NewPasswordRequired,
}

/// Group ID
pub type GroupName = String;

/// User group
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Group {
    pub group_name: GroupName,
    pub user_pool_id: UserPoolId,
    pub description: Option<String>,
    pub role_arn: Option<String>,
    pub precedence: Option<i32>,
    pub creation_date: DateTime<Utc>,
    pub last_modified_date: DateTime<Utc>,
}

/// Password reset code
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordResetCode {
    pub user_id: UserId,
    pub code: String,
    pub expires_at: DateTime<Utc>,
}

/// OAuth 2.0 Authorization Code
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationCode {
    pub code: String,
    pub user_id: UserId,
    pub client_id: ClientId,
    pub redirect_uri: String,
    pub scope: Vec<String>,
    pub nonce: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub expires_at: DateTime<Utc>,
}

/// Domain prefix for User Pool
pub type DomainPrefix = String;

/// User Pool Domain status
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DomainStatus {
    #[default]
    Creating,
    Active,
    Deleting,
    Updating,
    Failed,
}

/// Custom domain configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomDomainConfig {
    pub certificate_arn: String,
}

/// User Pool Domain
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserPoolDomain {
    pub domain: DomainPrefix,
    pub user_pool_id: UserPoolId,
    pub status: DomainStatus,
    pub version: Option<String>,
    pub s3_bucket: Option<String>,
    pub cloud_front_distribution: Option<String>,
    pub custom_domain_config: Option<CustomDomainConfig>,
    pub managed_login_version: Option<i32>,
}

/// Managed Login Branding ID
pub type BrandingId = String;

/// Color settings for managed login branding
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BrandingColorSettings {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub background_color: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub primary_color: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secondary_color: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text_color: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub link_color: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub button_color: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub button_text_color: Option<String>,
}

/// Asset settings for managed login branding
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BrandingAssets {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logo_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub favicon_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub background_image_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub css_url: Option<String>,
}

/// Managed Login Branding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManagedLoginBranding {
    pub branding_id: BrandingId,
    pub user_pool_id: UserPoolId,
    pub client_id: Option<ClientId>,
    pub use_cognito_provided_values: bool,
    pub settings: Option<BrandingSettings>,
    pub assets: Option<BrandingAssets>,
    pub creation_date: chrono::DateTime<chrono::Utc>,
    pub last_modified_date: chrono::DateTime<chrono::Utc>,
}

/// Combined branding settings
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BrandingSettings {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub colors: Option<BrandingColorSettings>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub page_title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sign_in_header: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sign_in_subheader: Option<String>,
}
