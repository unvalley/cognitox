use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// User Pool ID (format: region_poolId)
pub type UserPoolId = String;

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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserPoolClient {
    pub client_id: ClientId,
    pub user_pool_id: UserPoolId,
    pub client_name: String,
    pub client_secret: Option<String>,
    pub creation_date: DateTime<Utc>,
    pub last_modified_date: DateTime<Utc>,
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
