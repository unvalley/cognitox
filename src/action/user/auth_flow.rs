use chrono::{Duration, Utc};
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::{
    error::{AppError, Result},
    jwt::{
        generate_access_token, generate_id_token, resolve_access_token_expiry,
        resolve_id_token_expiry, resolve_refresh_token_expiry,
    },
    storage::Storage,
    types::{
        AuthEvent, AuthFlow, ChallengeType, ClientId, ExplicitAuthFlow, PendingAuthChallenge,
        RefreshToken, User, UserPoolClient, UserPoolId, UserStatus,
    },
};

use super::helpers::{
    SOFTWARE_TOKEN_MFA_FACTOR, hash_password, preferred_mfa_setting, verify_password,
    verify_secret_hash,
};
use super::verify_software_token::generate_totp_code;

pub(crate) struct AuthParameters<'a> {
    inner: &'a std::collections::HashMap<String, String>,
}

impl<'a> AuthParameters<'a> {
    pub(crate) fn new(inner: &'a std::collections::HashMap<String, String>) -> Self {
        Self { inner }
    }

    pub(crate) fn require(&self, key: &str) -> Result<&'a str> {
        self.inner
            .get(key)
            .map(String::as_str)
            .ok_or_else(|| AppError::InvalidParameter(format!("{key} required")))
    }

    pub(crate) fn secret_hash(&self) -> Option<&'a str> {
        self.inner.get("SECRET_HASH").map(String::as_str)
    }
}

pub(crate) struct ChallengeResponses<'a> {
    inner: &'a std::collections::HashMap<String, String>,
}

impl<'a> ChallengeResponses<'a> {
    pub(crate) fn new(inner: &'a std::collections::HashMap<String, String>) -> Self {
        Self { inner }
    }

    pub(crate) fn require(&self, key: &str) -> Result<&'a str> {
        self.inner
            .get(key)
            .map(String::as_str)
            .ok_or_else(|| AppError::InvalidParameter(format!("{key} required")))
    }

    pub(crate) fn get(&self, key: &str) -> Option<&'a str> {
        self.inner.get(key).map(String::as_str)
    }

    pub(crate) fn secret_hash(&self) -> Option<&'a str> {
        self.get("SECRET_HASH")
    }
}

pub(crate) enum PasswordAuthResult {
    Authenticated(User),
    Challenged(Value),
}

pub(crate) enum UserInitiateAuthFlow {
    UserPasswordAuth,
    RefreshTokenAuth,
}

fn parse_enum_variant<T: DeserializeOwned>(raw: &str) -> std::result::Result<T, serde_json::Error> {
    serde_json::from_str::<T>(&format!("\"{raw}\""))
}

impl UserInitiateAuthFlow {
    pub(crate) fn parse(raw: &str) -> Result<Self> {
        match parse_enum_variant::<AuthFlow>(raw) {
            Ok(AuthFlow::UserPasswordAuth) => Ok(Self::UserPasswordAuth),
            Ok(AuthFlow::RefreshTokenAuth | AuthFlow::RefreshToken) => Ok(Self::RefreshTokenAuth),
            Ok(AuthFlow::UserSrpAuth) => Err(AppError::NotImplemented(raw.to_string())),
            Ok(_) | Err(_) => Err(AppError::NotImplemented(format!("Auth flow: {raw}"))),
        }
    }
}

pub(crate) enum AdminInitiateAuthFlow {
    PasswordAuth,
    RefreshTokenAuth,
}

impl AdminInitiateAuthFlow {
    pub(crate) fn parse(raw: &str) -> Result<Self> {
        match parse_enum_variant::<AuthFlow>(raw) {
            Ok(AuthFlow::AdminUserPasswordAuth | AuthFlow::AdminNoSrpAuth) => {
                Ok(Self::PasswordAuth)
            }
            Ok(AuthFlow::RefreshTokenAuth | AuthFlow::RefreshToken) => Ok(Self::RefreshTokenAuth),
            Ok(_) | Err(_) => Err(AppError::NotImplemented(format!("Auth flow: {raw}"))),
        }
    }
}

pub(crate) enum AuthChallengeName {
    NewPasswordRequired,
    SoftwareTokenMfa,
}

impl AuthChallengeName {
    pub(crate) fn parse(raw: &str) -> Result<Self> {
        match parse_enum_variant::<ChallengeType>(raw) {
            Ok(ChallengeType::NewPasswordRequired) => Ok(Self::NewPasswordRequired),
            Ok(ChallengeType::SoftwareTokenMfa) => Ok(Self::SoftwareTokenMfa),
            Ok(_) | Err(_) => Err(AppError::NotImplemented(format!("Challenge: {raw}"))),
        }
    }
}

pub(crate) fn challenge_type_name(challenge_name: ChallengeType) -> &'static str {
    match challenge_name {
        ChallengeType::NewPasswordRequired => "NEW_PASSWORD_REQUIRED",
        ChallengeType::SoftwareTokenMfa => "SOFTWARE_TOKEN_MFA",
        ChallengeType::SmsMfa => "SMS_MFA",
        ChallengeType::SelectMfaType => "SELECT_MFA_TYPE",
        ChallengeType::MfaSetup => "MFA_SETUP",
        ChallengeType::PasswordVerifier => "PASSWORD_VERIFIER",
        ChallengeType::CustomChallenge => "CUSTOM_CHALLENGE",
        ChallengeType::DeviceSrpAuth => "DEVICE_SRP_AUTH",
        ChallengeType::DevicePasswordVerifier => "DEVICE_PASSWORD_VERIFIER",
        ChallengeType::AdminNoSrpAuth => "ADMIN_NO_SRP_AUTH",
    }
}

fn explicit_flows_allow(client: &UserPoolClient, allowed: &[ExplicitAuthFlow]) -> bool {
    client.explicit_auth_flows.is_empty()
        || client
            .explicit_auth_flows
            .iter()
            .any(|flow| allowed.contains(flow))
}

pub(crate) fn require_user_password_auth_flow(client: &UserPoolClient) -> Result<()> {
    if explicit_flows_allow(
        client,
        &[
            ExplicitAuthFlow::UserPasswordAuth,
            ExplicitAuthFlow::AllowUserPasswordAuth,
        ],
    ) {
        Ok(())
    } else {
        Err(AppError::NotAuthorized(
            "USER_PASSWORD_AUTH is not enabled for this client".to_string(),
        ))
    }
}

pub(crate) fn require_admin_password_auth_flow(client: &UserPoolClient) -> Result<()> {
    if explicit_flows_allow(
        client,
        &[
            ExplicitAuthFlow::AdminNoSrpAuth,
            ExplicitAuthFlow::AllowAdminUserPasswordAuth,
        ],
    ) {
        Ok(())
    } else {
        Err(AppError::NotAuthorized(
            "ADMIN_USER_PASSWORD_AUTH is not enabled for this client".to_string(),
        ))
    }
}

pub(crate) fn require_refresh_token_auth_flow(client: &UserPoolClient) -> Result<()> {
    if explicit_flows_allow(client, &[ExplicitAuthFlow::AllowRefreshTokenAuth]) {
        Ok(())
    } else {
        Err(AppError::NotAuthorized(
            "REFRESH_TOKEN_AUTH is not enabled for this client".to_string(),
        ))
    }
}

pub(crate) fn build_auth_response(authentication_result: Value) -> Value {
    json!({
        "AuthenticationResult": authentication_result,
        "AvailableChallenges": [],
        "ChallengeName": null,
        "ChallengeParameters": {},
        "Session": null
    })
}

pub(crate) fn build_challenge_response(
    session: &str,
    challenge_name: ChallengeType,
    user_id: &Uuid,
) -> Value {
    json!({
        "AuthenticationResult": null,
        "AvailableChallenges": [challenge_type_name(challenge_name)],
        "ChallengeName": challenge_type_name(challenge_name),
        "ChallengeParameters": {
            "USER_ID_FOR_SRP": user_id.to_string(),
            "userAttributes": "{}"
        },
        "Session": session
    })
}

pub(crate) async fn create_auth_challenge(
    storage: &Storage,
    client_id: ClientId,
    user_pool_id: UserPoolId,
    user_id: Uuid,
    challenge_name: ChallengeType,
) -> Value {
    let session = Uuid::new_v4().to_string();
    storage
        .save_auth_challenge_session(PendingAuthChallenge {
            session: session.clone(),
            challenge_name,
            user_id,
            client_id,
            user_pool_id,
            expires_at: Utc::now() + Duration::minutes(5),
        })
        .await;

    build_challenge_response(&session, challenge_name, &user_id)
}

pub(crate) async fn create_new_password_required_challenge(
    storage: &Storage,
    client_id: ClientId,
    user_pool_id: UserPoolId,
    user_id: Uuid,
) -> Value {
    create_auth_challenge(
        storage,
        client_id,
        user_pool_id,
        user_id,
        ChallengeType::NewPasswordRequired,
    )
    .await
}

async fn preferred_auth_challenge(storage: &Storage, user: &User) -> Option<ChallengeType> {
    let factors = storage.list_user_auth_factors(&user.id).await;
    match preferred_mfa_setting(user, &factors).as_deref() {
        Some(SOFTWARE_TOKEN_MFA_FACTOR) => Some(ChallengeType::SoftwareTokenMfa),
        _ => None,
    }
}

pub(crate) async fn authenticate_with_password(
    storage: &Storage,
    client: &UserPoolClient,
    client_id: &ClientId,
    user_pool_id: &UserPoolId,
    username: &str,
    password: &str,
    provided_secret_hash: Option<&str>,
) -> Result<PasswordAuthResult> {
    let user = storage
        .get_user_by_username(user_pool_id, username)
        .await
        .ok_or(AppError::UserNotFound)?;
    verify_secret_hash(client, username, provided_secret_hash)?;

    if !user.enabled {
        return Err(AppError::UserDisabled);
    }

    if !verify_password(password, &user.password_hash) {
        return Err(AppError::NotAuthorized(
            "Incorrect username or password.".to_string(),
        ));
    }

    if user.user_status == UserStatus::ForceChangePassword {
        return Ok(PasswordAuthResult::Challenged(
            create_new_password_required_challenge(
                storage,
                client_id.clone(),
                user_pool_id.clone(),
                user.id,
            )
            .await,
        ));
    }

    if user.user_status != UserStatus::Confirmed {
        return Err(AppError::UserNotConfirmed);
    }

    if let Some(challenge_name) = preferred_auth_challenge(storage, &user).await {
        let response = create_auth_challenge(
            storage,
            client_id.clone(),
            user_pool_id.clone(),
            user.id,
            challenge_name,
        )
        .await;
        return Ok(PasswordAuthResult::Challenged(response));
    }

    Ok(PasswordAuthResult::Authenticated(user))
}

pub(crate) async fn authenticate_with_refresh_token(
    storage: &Storage,
    client: &UserPoolClient,
    client_id: &ClientId,
    user_pool_id: &UserPoolId,
    refresh_token: &str,
    provided_secret_hash: Option<&str>,
) -> Result<User> {
    let stored_token = storage
        .get_refresh_token(refresh_token)
        .await
        .ok_or(AppError::InvalidRefreshToken)?;

    if stored_token.client_id != *client_id {
        return Err(AppError::InvalidRefreshToken);
    }

    if stored_token.expires_at < Utc::now() {
        return Err(AppError::InvalidRefreshToken);
    }

    let user = storage
        .get_user(&stored_token.user_id)
        .await
        .ok_or(AppError::UserNotFound)?;

    if user.user_pool_id != *user_pool_id {
        return Err(AppError::InvalidRefreshToken);
    }

    verify_secret_hash(client, &user.username, provided_secret_hash)?;

    if !user.enabled {
        return Err(AppError::UserDisabled);
    }

    Ok(user)
}

pub(crate) async fn resolve_challenge_session(
    storage: &Storage,
    session: &str,
    client_id: &ClientId,
    user_pool_id: &UserPoolId,
    expected_challenge: ChallengeType,
) -> Result<PendingAuthChallenge> {
    let challenge = storage
        .get_auth_challenge_session(session)
        .await
        .ok_or_else(|| AppError::InvalidParameter("Invalid session".to_string()))?;

    if challenge.challenge_name != expected_challenge
        || challenge.client_id != *client_id
        || challenge.user_pool_id != *user_pool_id
    {
        return Err(AppError::InvalidParameter("Invalid session".to_string()));
    }

    if challenge.expires_at < Utc::now() {
        storage.delete_auth_challenge_session(session).await;
        return Err(AppError::InvalidParameter("Session expired".to_string()));
    }

    Ok(challenge)
}

pub(crate) async fn resolve_new_password_challenge(
    storage: &Storage,
    session: &str,
    client_id: &ClientId,
    user_pool_id: &UserPoolId,
) -> Result<PendingAuthChallenge> {
    resolve_challenge_session(
        storage,
        session,
        client_id,
        user_pool_id,
        ChallengeType::NewPasswordRequired,
    )
    .await
}

pub(crate) async fn resolve_software_token_mfa_challenge(
    storage: &Storage,
    session: &str,
    client_id: &ClientId,
    user_pool_id: &UserPoolId,
) -> Result<PendingAuthChallenge> {
    resolve_challenge_session(
        storage,
        session,
        client_id,
        user_pool_id,
        ChallengeType::SoftwareTokenMfa,
    )
    .await
}

pub(crate) async fn complete_new_password_challenge(
    storage: &Storage,
    user: &User,
    new_password: &str,
    session: Option<&str>,
) -> Result<User> {
    let mut user = user.clone();
    user.password_hash = hash_password(new_password).map_err(AppError::Internal)?;
    user.user_status = UserStatus::Confirmed;
    user.last_modified_date = Utc::now();

    storage
        .update_user(user.clone())
        .await
        .ok_or(AppError::UserNotFound)?;

    if let Some(session) = session {
        storage.delete_auth_challenge_session(session).await;
    }

    Ok(user)
}

pub(crate) fn validate_software_token_mfa_code(code: &str) -> Result<()> {
    if code.trim().is_empty() {
        return Err(AppError::InvalidParameter(
            "SOFTWARE_TOKEN_MFA_CODE must not be empty".to_string(),
        ));
    }
    if code.len() != 6 || !code.chars().all(|ch| ch.is_ascii_digit()) {
        return Err(AppError::InvalidParameter(
            "SOFTWARE_TOKEN_MFA_CODE must be a 6-digit code".to_string(),
        ));
    }
    Ok(())
}

pub(crate) async fn complete_software_token_mfa_challenge(
    storage: &Storage,
    user: &User,
    code: &str,
    session: &str,
) -> Result<User> {
    validate_software_token_mfa_code(code)?;

    let factors = storage.list_user_auth_factors(&user.id).await;
    if !factors
        .iter()
        .any(|factor| factor == SOFTWARE_TOKEN_MFA_FACTOR)
    {
        return Err(AppError::InvalidParameter(
            "User does not have SOFTWARE_TOKEN_MFA configured".to_string(),
        ));
    }

    let secret = storage
        .get_software_token_secret(&user.id)
        .await
        .ok_or_else(|| {
            AppError::InvalidParameter(
                "User does not have SOFTWARE_TOKEN_MFA configured".to_string(),
            )
        })?;
    let now = Utc::now().timestamp();
    let mut valid = false;
    for step in -1..=1 {
        if generate_totp_code(&secret, now + step * 30)? == code {
            valid = true;
            break;
        }
    }
    if !valid {
        return Err(AppError::InvalidParameter(
            "Invalid software token code".to_string(),
        ));
    }

    storage.delete_auth_challenge_session(session).await;
    Ok(user.clone())
}

pub(crate) async fn issue_authentication_result(
    storage: &Storage,
    client: &UserPoolClient,
    client_id: &ClientId,
    user_pool_id: &UserPoolId,
    user: &User,
    include_refresh_token: bool,
    record_sign_in_event: bool,
) -> Result<Value> {
    let groups = storage.get_groups_for_user(&user.id).await;

    let access_expiry = resolve_access_token_expiry(client);
    let id_expiry = resolve_id_token_expiry(client);
    let refresh_expiry = resolve_refresh_token_expiry(client);

    let access_token = generate_access_token(
        user,
        client_id.as_str(),
        user_pool_id,
        &groups,
        &client.allowed_oauth_scopes,
        access_expiry,
    )
    .map_err(AppError::Internal)?;
    let id_token = generate_id_token(
        user,
        client_id.as_str(),
        user_pool_id,
        &groups,
        None,
        id_expiry,
    )
    .map_err(AppError::Internal)?;

    let mut result = json!({
        "AccessToken": access_token,
        "IdToken": id_token,
        "ExpiresIn": access_expiry.num_seconds(),
        "TokenType": "Bearer"
    });

    if include_refresh_token {
        let refresh_token = Uuid::new_v4().to_string();
        storage
            .save_refresh_token(RefreshToken {
                token: refresh_token.clone(),
                user_id: user.id,
                client_id: client_id.clone(),
                expires_at: Utc::now() + refresh_expiry,
            })
            .await;
        result["RefreshToken"] = json!(refresh_token);
    }

    if record_sign_in_event {
        storage
            .create_auth_event(AuthEvent {
                event_id: Uuid::new_v4().to_string(),
                user_id: user.id,
                event_type: "SignIn".to_string(),
                creation_date: Utc::now(),
                event_response: "Pass".to_string(),
                feedback_value: None,
                feedback_provided_by: None,
                feedback_date: None,
            })
            .await;
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::{
        AdminInitiateAuthFlow, AuthChallengeName, ChallengeType, UserInitiateAuthFlow,
        challenge_type_name, validate_software_token_mfa_code,
    };
    use crate::error::AppError;

    #[test]
    fn test_user_initiate_auth_flow_parse_supported() {
        assert!(matches!(
            UserInitiateAuthFlow::parse("USER_PASSWORD_AUTH").unwrap(),
            UserInitiateAuthFlow::UserPasswordAuth
        ));
        assert!(matches!(
            UserInitiateAuthFlow::parse("REFRESH_TOKEN_AUTH").unwrap(),
            UserInitiateAuthFlow::RefreshTokenAuth
        ));
        assert!(matches!(
            UserInitiateAuthFlow::parse("REFRESH_TOKEN").unwrap(),
            UserInitiateAuthFlow::RefreshTokenAuth
        ));
    }

    #[test]
    fn test_user_initiate_auth_flow_parse_preserves_not_implemented_messages() {
        assert!(matches!(
            UserInitiateAuthFlow::parse("USER_SRP_AUTH"),
            Err(AppError::NotImplemented(message)) if message == "USER_SRP_AUTH"
        ));
        assert!(matches!(
            UserInitiateAuthFlow::parse("USER_AUTH"),
            Err(AppError::NotImplemented(message)) if message == "Auth flow: USER_AUTH"
        ));
    }

    #[test]
    fn test_admin_initiate_auth_flow_parse_supported() {
        assert!(matches!(
            AdminInitiateAuthFlow::parse("ADMIN_USER_PASSWORD_AUTH").unwrap(),
            AdminInitiateAuthFlow::PasswordAuth
        ));
        assert!(matches!(
            AdminInitiateAuthFlow::parse("ADMIN_NO_SRP_AUTH").unwrap(),
            AdminInitiateAuthFlow::PasswordAuth
        ));
        assert!(matches!(
            AdminInitiateAuthFlow::parse("REFRESH_TOKEN_AUTH").unwrap(),
            AdminInitiateAuthFlow::RefreshTokenAuth
        ));
    }

    #[test]
    fn test_auth_challenge_name_parse_supported() {
        assert!(matches!(
            AuthChallengeName::parse("NEW_PASSWORD_REQUIRED").unwrap(),
            AuthChallengeName::NewPasswordRequired
        ));
        assert!(matches!(
            AuthChallengeName::parse("SOFTWARE_TOKEN_MFA").unwrap(),
            AuthChallengeName::SoftwareTokenMfa
        ));
    }

    #[test]
    fn test_auth_challenge_name_parse_unsupported() {
        assert!(matches!(
            AuthChallengeName::parse("SMS_MFA"),
            Err(AppError::NotImplemented(message)) if message == "Challenge: SMS_MFA"
        ));
    }

    #[test]
    fn test_challenge_type_name_supported_values() {
        assert_eq!(
            challenge_type_name(ChallengeType::NewPasswordRequired),
            "NEW_PASSWORD_REQUIRED"
        );
        assert_eq!(
            challenge_type_name(ChallengeType::SoftwareTokenMfa),
            "SOFTWARE_TOKEN_MFA"
        );
    }

    #[test]
    fn test_validate_software_token_mfa_code() {
        assert!(validate_software_token_mfa_code("123456").is_ok());
        assert!(matches!(
            validate_software_token_mfa_code(""),
            Err(AppError::InvalidParameter(_))
        ));
        assert!(matches!(
            validate_software_token_mfa_code("12ab56"),
            Err(AppError::InvalidParameter(_))
        ));
    }
}
