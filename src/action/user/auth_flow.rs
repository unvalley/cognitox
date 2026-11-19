//! The authentication state machine behind `InitiateAuth`,
//! `RespondToAuthChallenge`, and their `Admin*` variants.
//!
//! The handlers parse the transport shape and hand over to [`initiate_auth`]
//! and [`respond_to_auth_challenge`]. Everything a sign-in can go through
//! lives here: the first factor (password, SRP, one-time code, refresh
//! token), the follow-up challenges (`NEW_PASSWORD_REQUIRED`, the MFA
//! challenges), and token issuance. Design notes: `docs/auth-flow-design.md`.

use std::collections::HashMap;

use chrono::{Duration, Utc};
use serde_json::{Map, Value, json};
use uuid::Uuid;

use crate::{
    error::{AppError, Result},
    jwt::{
        AccessTokenRequest, GroupClaims, IdTokenRequest, TokenSession, issue_access_token,
        issue_id_token, resolve_access_token_expiry, resolve_id_token_expiry,
        resolve_refresh_token_expiry,
    },
    srp,
    storage::Storage,
    types::{
        AuthEvent, AuthFlow, ChallengeType, ExplicitAuthFlow, FirstAuthFactor, MfaConfiguration,
        PendingAuthChallenge, PreventUserExistenceErrors, RefreshToken,
        RefreshTokenRotationFeature, SrpChallengeState, User, UserAttribute, UserPool,
        UserPoolClient, UserStatus,
    },
    validation::validate_password_against_policy,
};

use super::helpers::{
    AttributeWriter, EMAIL_OTP_FACTOR, SMS_MFA_FACTOR, SOFTWARE_TOKEN_MFA_FACTOR,
    apply_user_attribute_updates, generate_numeric_code, mask_email, mask_phone_number,
    preferred_mfa_setting, set_user_password, store_srp_verifier, validate_attribute_write,
    verify_password, verify_secret_hash,
};
use super::verify_software_token::is_valid_totp_code;

const INCORRECT_CREDENTIALS: &str = "Incorrect username or password.";
const INVALID_SESSION: &str = "Invalid session for the user.";
const EXPIRED_SESSION: &str = "Invalid session for the user, session is expired.";
const CODE_MISMATCH: &str = "Invalid code received for user";
/// Default `AuthSessionValidity`, in minutes.
const DEFAULT_SESSION_MINUTES: i64 = 3;
/// Wrong answers a challenge session tolerates before it is discarded.
const MAX_CHALLENGE_ATTEMPTS: u32 = 3;
/// Default `TemporaryPasswordValidityDays`.
const DEFAULT_TEMPORARY_PASSWORD_DAYS: i64 = 7;

/// Which API a request came through. The admin operations accept the
/// server-side flows; the public ones do not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AuthApi {
    User,
    Admin,
}

/// What every step of a sign-in needs to know about the request.
pub(crate) struct AuthContext<'a> {
    pub storage: &'a Storage,
    pub pool: &'a UserPool,
    pub client: &'a UserPoolClient,
    pub api: AuthApi,
}

const AUTH_FLOWS: &[(&str, AuthFlow)] = &[
    ("USER_SRP_AUTH", AuthFlow::UserSrpAuth),
    ("REFRESH_TOKEN_AUTH", AuthFlow::RefreshTokenAuth),
    ("REFRESH_TOKEN", AuthFlow::RefreshToken),
    ("CUSTOM_AUTH", AuthFlow::CustomAuth),
    ("ADMIN_NO_SRP_AUTH", AuthFlow::AdminNoSrpAuth),
    ("USER_PASSWORD_AUTH", AuthFlow::UserPasswordAuth),
    ("ADMIN_USER_PASSWORD_AUTH", AuthFlow::AdminUserPasswordAuth),
    ("USER_AUTH", AuthFlow::UserAuth),
];

fn enum_violation(value: &str, member: &str, allowed: &[&str]) -> AppError {
    AppError::InvalidParameter(format!(
        "1 validation error detected: Value '{value}' at '{member}' failed to satisfy constraint: Member must satisfy enum value set: [{}]",
        allowed.join(", ")
    ))
}

fn parse_auth_flow(raw: &str) -> Result<AuthFlow> {
    AUTH_FLOWS
        .iter()
        .find(|(name, _)| *name == raw)
        .map(|(_, flow)| *flow)
        .ok_or_else(|| {
            let allowed: Vec<&str> = AUTH_FLOWS.iter().map(|(name, _)| *name).collect();
            enum_violation(raw, "authFlow", &allowed)
        })
}

fn parse_challenge_name(raw: &str) -> Result<ChallengeType> {
    ChallengeType::parse(raw).ok_or_else(|| {
        let allowed: Vec<&str> = ChallengeType::ALL
            .iter()
            .map(|challenge| challenge.as_str())
            .collect();
        enum_violation(raw, "challengeName", &allowed)
    })
}

fn required<'a>(values: &'a HashMap<String, String>, key: &str) -> Result<&'a str> {
    values
        .get(key)
        .map(String::as_str)
        .ok_or_else(|| AppError::InvalidParameter(format!("Missing required parameter {key}")))
}

fn optional<'a>(values: &'a HashMap<String, String>, key: &str) -> Option<&'a str> {
    values.get(key).map(String::as_str)
}

/// Whether the app client's `ExplicitAuthFlows` permit a flow.
///
/// A client created without the setting gets Cognito's default,
/// `ALLOW_CUSTOM_AUTH`, `ALLOW_USER_SRP_AUTH`, and `ALLOW_REFRESH_TOKEN_AUTH`.
/// The legacy values (no `ALLOW_` prefix) leave SRP and refresh enabled.
fn flow_enabled(client: &UserPoolClient, flow: AuthFlow) -> bool {
    use ExplicitAuthFlow as Flow;

    let flows = &client.explicit_auth_flows;
    let has = |flow: Flow| flows.contains(&flow);
    let legacy = flows.iter().all(|flow| flow.is_legacy());
    let unset = flows.is_empty();

    match flow {
        AuthFlow::UserPasswordAuth => {
            has(Flow::AllowUserPasswordAuth) || has(Flow::UserPasswordAuth)
        }
        AuthFlow::AdminNoSrpAuth | AuthFlow::AdminUserPasswordAuth => {
            has(Flow::AllowAdminUserPasswordAuth) || has(Flow::AdminNoSrpAuth)
        }
        AuthFlow::UserSrpAuth => {
            has(Flow::AllowUserSrpAuth) || (legacy && !has(Flow::CustomAuthFlowOnly))
        }
        AuthFlow::RefreshTokenAuth | AuthFlow::RefreshToken => {
            has(Flow::AllowRefreshTokenAuth) || legacy
        }
        AuthFlow::CustomAuth => has(Flow::AllowCustomAuth) || legacy,
        AuthFlow::UserAuth => has(Flow::AllowUserAuth) && !unset,
    }
}

fn require_flow_enabled(client: &UserPoolClient, flow: AuthFlow) -> Result<()> {
    if flow_enabled(client, flow) {
        return Ok(());
    }
    let message = match flow {
        AuthFlow::UserPasswordAuth => "USER_PASSWORD_AUTH flow not enabled for this client",
        AuthFlow::UserSrpAuth => "USER_SRP_AUTH is not enabled for the client.",
        AuthFlow::RefreshTokenAuth | AuthFlow::RefreshToken => {
            "Refresh Token auth flow not enabled for this client"
        }
        AuthFlow::CustomAuth => "CUSTOM_AUTH is not enabled for the client.",
        AuthFlow::UserAuth => "USER_AUTH flow not enabled for this client",
        AuthFlow::AdminNoSrpAuth | AuthFlow::AdminUserPasswordAuth => {
            "Auth flow not enabled for this client"
        }
    };
    Err(AppError::InvalidParameter(message.to_string()))
}

pub(crate) fn require_refresh_token_auth_flow(client: &UserPoolClient) -> Result<()> {
    require_flow_enabled(client, AuthFlow::RefreshTokenAuth)
}

/// The flows each API accepts, whatever the app client allows.
fn require_flow_supported_by_api(api: AuthApi, flow: AuthFlow) -> Result<()> {
    let supported = match flow {
        AuthFlow::AdminNoSrpAuth | AuthFlow::AdminUserPasswordAuth => api == AuthApi::Admin,
        AuthFlow::UserPasswordAuth => api == AuthApi::User,
        _ => true,
    };
    if supported {
        Ok(())
    } else {
        Err(AppError::InvalidParameter(
            "Initiate Auth method not supported.".to_string(),
        ))
    }
}

fn session_lifetime(client: &UserPoolClient) -> Duration {
    Duration::minutes(
        client
            .auth_session_validity
            .map_or(DEFAULT_SESSION_MINUTES, i64::from),
    )
}

fn user_id_for_srp(user: &User) -> &str {
    &user.username
}

fn prevents_user_existence_errors(client: &UserPoolClient) -> bool {
    client.prevent_user_existence_errors == Some(PreventUserExistenceErrors::Enabled)
}

/// What a missing user looks like to the caller: `UserNotFoundException`
/// with `LEGACY` error handling, the wrong-password error when the app
/// client hides whether a user exists.
fn user_not_found(client: &UserPoolClient) -> AppError {
    if prevents_user_existence_errors(client) {
        AppError::NotAuthorized(INCORRECT_CREDENTIALS.to_string())
    } else {
        AppError::UserNotFound
    }
}

async fn find_user(ctx: &AuthContext<'_>, username: &str) -> Result<User> {
    ctx.storage
        .get_user_by_username(&ctx.pool.id, username)
        .await
        .ok_or_else(|| user_not_found(ctx.client))
}

fn require_enabled(user: &User) -> Result<()> {
    if user.enabled {
        Ok(())
    } else {
        Err(AppError::UserDisabled)
    }
}

/// Start an authentication.
pub(crate) async fn initiate_auth(
    ctx: &AuthContext<'_>,
    auth_flow: &str,
    params: &HashMap<String, String>,
    session: Option<&str>,
) -> Result<Value> {
    let flow = parse_auth_flow(auth_flow)?;
    require_flow_supported_by_api(ctx.api, flow)?;
    require_flow_enabled(ctx.client, flow)?;

    match flow {
        AuthFlow::UserPasswordAuth | AuthFlow::AdminNoSrpAuth | AuthFlow::AdminUserPasswordAuth => {
            let username = required(params, "USERNAME")?;
            let password = required(params, "PASSWORD")?;
            verify_secret_hash(ctx.client, username, optional(params, "SECRET_HASH"))?;
            let user = find_user(ctx, username).await?;
            let user = check_password(ctx, user, password).await?;
            after_password(ctx, user, false).await
        }
        AuthFlow::UserSrpAuth => {
            let username = required(params, "USERNAME")?;
            let srp_a = required(params, "SRP_A")?;
            verify_secret_hash(ctx.client, username, optional(params, "SECRET_HASH"))?;
            begin_srp(ctx, username, srp_a, false).await
        }
        AuthFlow::RefreshTokenAuth | AuthFlow::RefreshToken => {
            // An app client that rotates refresh tokens has to refresh
            // with GetTokensFromRefreshToken, which returns the new one.
            // (The wording of this error is the emulator's own.)
            let rotates = ctx
                .client
                .refresh_token_rotation
                .as_ref()
                .is_some_and(|rotation| {
                    rotation.feature == Some(RefreshTokenRotationFeature::Enabled)
                });
            if rotates {
                return Err(AppError::InvalidParameter(
                    "Refresh token rotation is enabled for this client; use GetTokensFromRefreshToken"
                        .to_string(),
                ));
            }
            let refresh_token = required(params, "REFRESH_TOKEN")?;
            let (user, stored) = authenticate_with_refresh_token(
                ctx.storage,
                ctx.client,
                refresh_token,
                RefreshSecret::Hash(optional(params, "SECRET_HASH")),
            )
            .await?;
            let session = TokenSession::resumed(stored.origin_jti.clone(), stored.auth_time);
            let result = issue_tokens(ctx, &user, &session, None).await?;
            Ok(authenticated(result))
        }
        AuthFlow::UserAuth => {
            let username = required(params, "USERNAME")?;
            verify_secret_hash(ctx.client, username, optional(params, "SECRET_HASH"))?;
            if let Some(session) = session {
                // Resuming after a mid-flow SignUp/ConfirmSignUp session is
                // not something the emulator hands out.
                load_session(ctx, session, &[ChallengeType::SelectChallenge]).await?;
            }
            let user = find_user(ctx, username).await?;
            require_enabled(&user)?;
            let available = available_first_factors(ctx, &user).await;
            match optional(params, "PREFERRED_CHALLENGE").and_then(ChallengeType::parse) {
                Some(preferred) if available.contains(&preferred) => {
                    let mut response = start_first_factor(ctx, user, preferred, params).await?;
                    // A challenge that opens choice-based sign-in lists the
                    // alternatives next to the one it issues.
                    if response.get("ChallengeName").is_some() {
                        response["AvailableChallenges"] = json!(
                            available
                                .iter()
                                .map(|challenge| challenge.as_str())
                                .collect::<Vec<_>>()
                        );
                    }
                    Ok(response)
                }
                _ => select_challenge(ctx, &user, &available).await,
            }
        }
        AuthFlow::CustomAuth => Err(AppError::NotImplemented(
            "CUSTOM_AUTH requires Lambda triggers, which the emulator does not run".to_string(),
        )),
    }
}

/// Answer a challenge.
pub(crate) async fn respond_to_auth_challenge(
    ctx: &AuthContext<'_>,
    challenge_name: &str,
    session: Option<&str>,
    responses: &HashMap<String, String>,
) -> Result<Value> {
    let challenge_name = parse_challenge_name(challenge_name)?;

    if challenge_name == ChallengeType::PasswordVerifier {
        return finish_srp(ctx, session, responses).await;
    }

    let session = session
        .ok_or_else(|| AppError::InvalidParameter("Missing required parameter Session".into()))?;
    let pending = load_session(ctx, session, &[challenge_name]).await?;
    let user = session_user(ctx, &pending, responses).await?;

    match challenge_name {
        ChallengeType::NewPasswordRequired => {
            let new_password = required(responses, "NEW_PASSWORD")?;
            if user.user_status != UserStatus::ForceChangePassword {
                return Err(AppError::NotAuthorized(INVALID_SESSION.to_string()));
            }
            validate_password_against_policy(ctx.pool, new_password)?;

            let mut user = user;
            let updates: Vec<UserAttribute> = responses
                .iter()
                .filter_map(|(key, value)| {
                    key.strip_prefix("userAttributes.")
                        .map(|name| UserAttribute {
                            name: name.to_string(),
                            value: Some(value.clone()),
                        })
                })
                .collect();
            // The app client's write permissions apply here as anywhere.
            validate_attribute_write(
                ctx.pool,
                AttributeWriter::Client(Some(ctx.client)),
                &updates,
                false,
            )?;
            apply_user_attribute_updates(&mut user, updates);
            set_user_password(&mut user, new_password)?;
            user.user_status = UserStatus::Confirmed;
            user.last_modified_date = Utc::now();
            let user = ctx
                .storage
                .update_user(user)
                .await
                .ok_or(AppError::UserNotFound)?;

            ctx.storage.delete_auth_challenge_session(session).await;
            after_first_factor(ctx, user, pending.user_auth).await
        }
        ChallengeType::SoftwareTokenMfa => {
            let code = required(responses, "SOFTWARE_TOKEN_MFA_CODE")?;
            let secret = ctx.storage.get_software_token_secret(&user.id).await;
            let valid = match secret {
                Some(secret) => {
                    is_valid_totp_code(&secret, code, Utc::now().timestamp()).unwrap_or(false)
                }
                None => false,
            };
            if !valid {
                return Err(wrong_answer(ctx, &pending, CODE_MISMATCH).await);
            }
            ctx.storage.delete_auth_challenge_session(session).await;
            complete(ctx, &user).await
        }
        ChallengeType::SmsMfa | ChallengeType::EmailOtp | ChallengeType::SmsOtp => {
            let key = match challenge_name {
                ChallengeType::SmsMfa => "SMS_MFA_CODE",
                ChallengeType::EmailOtp => "EMAIL_OTP_CODE",
                _ => "SMS_OTP_CODE",
            };
            // The API reference also names the email code `EMAIL_MFA_CODE`.
            let code = match optional(responses, "EMAIL_MFA_CODE") {
                Some(code) if challenge_name == ChallengeType::EmailOtp => code,
                _ => required(responses, key)?,
            };
            if pending.code.as_deref() != Some(code.trim()) {
                return Err(wrong_answer(ctx, &pending, CODE_MISMATCH).await);
            }
            ctx.storage.delete_auth_challenge_session(session).await;
            complete(ctx, &user).await
        }
        ChallengeType::SelectMfaType => {
            // The API reference calls the email factor `EMAIL_MFA` here;
            // the challenge and the SDKs call it `EMAIL_OTP`.
            let answer = match required(responses, "ANSWER")? {
                "EMAIL_MFA" => EMAIL_OTP_FACTOR,
                answer => answer,
            };
            if !pending.choices.iter().any(|choice| choice == answer) {
                return Err(AppError::InvalidParameter(format!(
                    "Invalid ANSWER {answer} for SELECT_MFA_TYPE"
                )));
            }
            ctx.storage.delete_auth_challenge_session(session).await;
            mfa_challenge(ctx, &user, answer).await
        }
        ChallengeType::MfaSetup => {
            if !pending.mfa_setup_complete {
                return Err(AppError::NotAuthorized(INVALID_SESSION.to_string()));
            }
            ctx.storage.delete_auth_challenge_session(session).await;
            complete(ctx, &user).await
        }
        ChallengeType::SelectChallenge => {
            let answer = required(responses, "ANSWER")?;
            let chosen = ChallengeType::parse(answer)
                .filter(|chosen| {
                    pending
                        .choices
                        .iter()
                        .any(|choice| choice == chosen.as_str())
                })
                .ok_or_else(|| {
                    AppError::InvalidParameter(format!(
                        "Invalid ANSWER {answer} for SELECT_CHALLENGE"
                    ))
                })?;
            ctx.storage.delete_auth_challenge_session(session).await;
            start_first_factor(ctx, user, chosen, responses).await
        }
        ChallengeType::Password => {
            let password = required(responses, "PASSWORD")?;
            let user = match check_password(ctx, user, password).await {
                Ok(user) => user,
                Err(error) => {
                    wrong_answer(ctx, &pending, INCORRECT_CREDENTIALS).await;
                    return Err(error);
                }
            };
            ctx.storage.delete_auth_challenge_session(session).await;
            after_password(ctx, user, true).await
        }
        ChallengeType::PasswordSrp => {
            let srp_a = required(responses, "SRP_A")?;
            ctx.storage.delete_auth_challenge_session(session).await;
            begin_srp(ctx, &user.username, srp_a, true).await
        }
        ChallengeType::WebAuthn => Err(AppError::NotImplemented(
            "WEB_AUTHN sign-in is not supported by the emulator".to_string(),
        )),
        ChallengeType::CustomChallenge
        | ChallengeType::DeviceSrpAuth
        | ChallengeType::DevicePasswordVerifier
        | ChallengeType::AdminNoSrpAuth => Err(AppError::NotImplemented(format!(
            "Challenge: {}",
            challenge_name.as_str()
        ))),
        ChallengeType::PasswordVerifier => unreachable!("handled before the session lookup"),
    }
}

/// Load the pending challenge a `Session` refers to.
async fn load_session(
    ctx: &AuthContext<'_>,
    session: &str,
    expected: &[ChallengeType],
) -> Result<PendingAuthChallenge> {
    let pending = ctx
        .storage
        .get_auth_challenge_session(session)
        .await
        .ok_or_else(|| AppError::NotAuthorized(INVALID_SESSION.to_string()))?;

    if pending.client_id != ctx.client.client_id || pending.user_pool_id != ctx.pool.id {
        return Err(AppError::NotAuthorized(INVALID_SESSION.to_string()));
    }
    if pending.expires_at < Utc::now() {
        ctx.storage.delete_auth_challenge_session(session).await;
        return Err(AppError::NotAuthorized(EXPIRED_SESSION.to_string()));
    }
    if !expected.contains(&pending.challenge_name) {
        return Err(AppError::NotAuthorized(INVALID_SESSION.to_string()));
    }
    Ok(pending)
}

/// The user a challenge session belongs to, after checking the response's
/// `USERNAME` and `SECRET_HASH` against it.
async fn session_user(
    ctx: &AuthContext<'_>,
    pending: &PendingAuthChallenge,
    responses: &HashMap<String, String>,
) -> Result<User> {
    let user = ctx
        .storage
        .get_user(&pending.user_id)
        .await
        .ok_or_else(|| user_not_found(ctx.client))?;
    require_enabled(&user)?;

    let username = optional(responses, "USERNAME");
    if let Some(username) = username
        && !names_user(ctx, &user, username).await
    {
        return Err(AppError::NotAuthorized(INVALID_SESSION.to_string()));
    }
    verify_secret_hash(
        ctx.client,
        username.unwrap_or(&user.username),
        optional(responses, "SECRET_HASH"),
    )?;
    Ok(user)
}

/// Whether `username` is one of the names the user can be addressed by.
async fn names_user(ctx: &AuthContext<'_>, user: &User, username: &str) -> bool {
    if username == user.username || username == user.id.to_string() {
        return true;
    }
    ctx.storage
        .get_user_by_username(&ctx.pool.id, username)
        .await
        .is_some_and(|found| found.id == user.id)
}

/// Count a wrong answer against the session and build the error to return.
async fn wrong_answer(
    ctx: &AuthContext<'_>,
    pending: &PendingAuthChallenge,
    message: &str,
) -> AppError {
    let attempts = ctx
        .storage
        .update_auth_challenge_session(&pending.session, |pending| {
            pending.failed_attempts += 1;
            pending.failed_attempts
        })
        .await
        .unwrap_or(MAX_CHALLENGE_ATTEMPTS);
    if attempts >= MAX_CHALLENGE_ATTEMPTS {
        ctx.storage
            .delete_auth_challenge_session(&pending.session)
            .await;
    }
    if message == INCORRECT_CREDENTIALS {
        AppError::NotAuthorized(message.to_string())
    } else {
        AppError::CodeMismatch(message.to_string())
    }
}

/// Verify a password presented in clear.
async fn check_password(ctx: &AuthContext<'_>, user: User, password: &str) -> Result<User> {
    require_enabled(&user)?;
    if !verify_password(password, &user.password_hash) {
        return Err(AppError::NotAuthorized(INCORRECT_CREDENTIALS.to_string()));
    }
    if user.srp_verifier.is_some() {
        return Ok(user);
    }
    // A user from a snapshot that predates SRP support: now that the
    // password is known, derive its verifier.
    let mut user = user;
    store_srp_verifier(&mut user, password);
    Ok(ctx.storage.update_user(user.clone()).await.unwrap_or(user))
}

/// Answer `SRP_A` with a `PASSWORD_VERIFIER` challenge.
///
/// `USER_SRP_AUTH` returns no `Session`: the client hands the
/// `SECRET_BLOCK` back, and that identifies the exchange.
async fn begin_srp(
    ctx: &AuthContext<'_>,
    username: &str,
    srp_a: &str,
    user_auth: bool,
) -> Result<Value> {
    if !srp::is_valid_client_public(srp_a) {
        return Err(AppError::InvalidParameter(
            "Invalid SRP_A value provided".to_string(),
        ));
    }

    let user = ctx
        .storage
        .get_user_by_username(&ctx.pool.id, username)
        .await;
    let user = match user {
        Some(user) => {
            require_enabled(&user)?;
            Some(user)
        }
        None if prevents_user_existence_errors(ctx.client) => None,
        None => return Err(AppError::UserNotFound),
    };

    // An unknown user, or one whose verifier could not be derived yet, gets
    // a challenge nobody can answer, as Cognito does when it hides whether
    // the user exists.
    let stored = user.as_ref().and_then(|user| {
        Some(srp::PasswordVerifier {
            salt: user.srp_salt.clone()?,
            verifier: user.srp_verifier.clone()?,
        })
    });
    if user.is_some() && stored.is_none() {
        tracing::warn!(
            "{username} has no SRP verifier (the password was set before cognitox supported \
             USER_SRP_AUTH); sign in once with a password flow or reset the password"
        );
    }
    let srp_name = user.as_ref().map_or_else(
        || username.to_string(),
        |user| user_id_for_srp(user).to_string(),
    );
    let answerable = stored.is_some();
    let stored = stored.unwrap_or_else(|| {
        srp::generate_verifier(ctx.pool.id.as_str(), &srp_name, &Uuid::new_v4().to_string())
    });
    let ephemeral = srp::server_ephemeral(&stored.verifier)
        .ok_or_else(|| AppError::Internal("Invalid stored SRP verifier".to_string()))?;
    let secret_block = srp::generate_secret_block();

    ctx.storage
        .save_auth_challenge_session(PendingAuthChallenge {
            session: secret_block.clone(),
            challenge_name: ChallengeType::PasswordVerifier,
            user_id: user
                .as_ref()
                .filter(|_| answerable)
                .map_or_else(Uuid::nil, |user| user.id),
            client_id: ctx.client.client_id.clone(),
            user_pool_id: ctx.pool.id.clone(),
            expires_at: Utc::now() + session_lifetime(ctx.client),
            srp: Some(SrpChallengeState {
                client_public: srp_a.to_string(),
                server_private: ephemeral.private,
                server_public: ephemeral.public.clone(),
                secret_block: secret_block.clone(),
            }),
            code: None,
            choices: Vec::new(),
            mfa_setup_complete: false,
            failed_attempts: 0,
            user_auth,
        })
        .await;

    let mut response = json!({
        "ChallengeName": ChallengeType::PasswordVerifier.as_str(),
        "ChallengeParameters": {
            "SALT": stored.salt,
            "SECRET_BLOCK": secret_block,
            "SRP_B": ephemeral.public,
            "USERNAME": srp_name,
            "USER_ID_FOR_SRP": srp_name,
        },
    });
    if user_auth {
        response["Session"] = json!(secret_block);
    }
    Ok(response)
}

/// Check the client's proof of the password and continue the sign-in.
async fn finish_srp(
    ctx: &AuthContext<'_>,
    session: Option<&str>,
    responses: &HashMap<String, String>,
) -> Result<Value> {
    let username = required(responses, "USERNAME")?;
    let secret_block = required(responses, "PASSWORD_CLAIM_SECRET_BLOCK")?;
    let signature = required(responses, "PASSWORD_CLAIM_SIGNATURE")?;
    let timestamp = required(responses, "TIMESTAMP")?;
    verify_secret_hash(ctx.client, username, optional(responses, "SECRET_HASH"))?;

    let incorrect = || AppError::NotAuthorized(INCORRECT_CREDENTIALS.to_string());

    let pending = ctx
        .storage
        .get_auth_challenge_session(secret_block)
        .await
        .ok_or_else(incorrect)?;
    // The exchange is single use, whatever the outcome.
    ctx.storage
        .delete_auth_challenge_session(secret_block)
        .await;

    if pending.challenge_name != ChallengeType::PasswordVerifier
        || pending.client_id != ctx.client.client_id
        || pending.user_pool_id != ctx.pool.id
        || session.is_some_and(|session| session != pending.session)
    {
        return Err(incorrect());
    }
    if pending.expires_at < Utc::now() {
        return Err(AppError::NotAuthorized(EXPIRED_SESSION.to_string()));
    }

    let state = pending.srp.as_ref().ok_or_else(incorrect)?;
    let user = ctx
        .storage
        .get_user(&pending.user_id)
        .await
        .ok_or_else(incorrect)?;
    require_enabled(&user)?;
    if !names_user(ctx, &user, username).await {
        return Err(incorrect());
    }

    let verifier = user.srp_verifier.as_deref().ok_or_else(incorrect)?;
    let proven = srp::PasswordClaim {
        user_pool_id: ctx.pool.id.as_str(),
        user_id_for_srp: user_id_for_srp(&user),
        verifier,
        client_public: &state.client_public,
        server_private: &state.server_private,
        server_public: &state.server_public,
        secret_block: &state.secret_block,
        timestamp,
    }
    .verify(signature);
    if !proven {
        return Err(incorrect());
    }

    after_password(ctx, user, pending.user_auth).await
}

/// The password is known to be right: apply the account-state checks and
/// the `NEW_PASSWORD_REQUIRED` step, then move on to MFA.
async fn after_password(ctx: &AuthContext<'_>, user: User, user_auth: bool) -> Result<Value> {
    match user.user_status {
        UserStatus::Unconfirmed => return Err(AppError::UserNotConfirmed),
        UserStatus::ResetRequired => return Err(AppError::PasswordResetRequired),
        UserStatus::ForceChangePassword => {
            if temporary_password_expired(ctx.pool, &user) {
                return Err(AppError::NotAuthorized(
                    "Temporary password has expired and must be reset by an administrator."
                        .to_string(),
                ));
            }
            let mut parameters = Map::new();
            parameters.insert("USER_ID_FOR_SRP".to_string(), json!(user_id_for_srp(&user)));
            parameters.insert(
                "requiredAttributes".to_string(),
                json!(missing_required_attributes(ctx.pool, &user)),
            );
            parameters.insert(
                "userAttributes".to_string(),
                json!(user_attributes_json(&user)),
            );
            return Ok(challenge(
                ctx,
                &user,
                ChallengeType::NewPasswordRequired,
                parameters,
                ChallengeState {
                    user_auth,
                    ..ChallengeState::default()
                },
            )
            .await);
        }
        _ => {}
    }
    after_first_factor(ctx, user, user_auth).await
}

fn temporary_password_expired(pool: &UserPool, user: &User) -> bool {
    let days = pool
        .policies
        .as_ref()
        .and_then(|policies| policies.password_policy.as_ref())
        .and_then(|policy| policy.temporary_password_validity_days)
        .map_or(DEFAULT_TEMPORARY_PASSWORD_DAYS, i64::from);
    user.password_set_at
        .is_some_and(|set_at| set_at + Duration::days(days) < Utc::now())
}

/// `requiredAttributes`: the schema's required attributes the user lacks,
/// as a JSON array of `userAttributes.<name>` strings.
fn missing_required_attributes(pool: &UserPool, user: &User) -> String {
    let missing: Vec<String> = pool
        .schema_attributes
        .iter()
        .flatten()
        .filter(|attribute| attribute.required == Some(true))
        .filter(|attribute| {
            !user
                .attributes
                .iter()
                .any(|existing| existing.name == attribute.name && existing.value.is_some())
        })
        .map(|attribute| format!("userAttributes.{}", attribute.name))
        .collect();
    serde_json::to_string(&missing).unwrap_or_else(|_| "[]".to_string())
}

/// `userAttributes`: the user's attributes as a JSON object string.
fn user_attributes_json(user: &User) -> String {
    let attributes: Map<String, Value> = user
        .attributes
        .iter()
        .filter(|attribute| !matches!(attribute.name.as_str(), "sub" | "preferred_mfa_setting"))
        .filter_map(|attribute| Some((attribute.name.clone(), json!(attribute.value.clone()?))))
        .collect();
    Value::Object(attributes).to_string()
}

/// The first factor is done. Passwordless factors finish the sign-in;
/// a password is followed by MFA when the user or the pool calls for it.
async fn after_first_factor(ctx: &AuthContext<'_>, user: User, user_auth: bool) -> Result<Value> {
    let _ = user_auth;
    let factors = ctx.storage.list_user_auth_factors(&user.id).await;
    let mfa = ctx.pool.mfa_configuration.unwrap_or(MfaConfiguration::Off);

    if factors.is_empty() {
        if mfa != MfaConfiguration::On {
            return complete(ctx, &user).await;
        }
        // MFA is required and the user has none set up. A phone number is
        // enough for SMS; otherwise the user has to register a factor now.
        if ctx.pool.sms_mfa_configuration.is_some() && user.phone_number.is_some() {
            return mfa_challenge(ctx, &user, SMS_MFA_FACTOR).await;
        }
        let mut can_setup = Vec::new();
        if software_token_mfa_enabled(ctx.pool) {
            can_setup.push(SOFTWARE_TOKEN_MFA_FACTOR.to_string());
        }
        if ctx.pool.email_mfa_configuration.is_some() && user.email.is_some() {
            can_setup.push(EMAIL_OTP_FACTOR.to_string());
        }
        if can_setup.is_empty() {
            can_setup.push(SOFTWARE_TOKEN_MFA_FACTOR.to_string());
        }
        let mut parameters = Map::new();
        parameters.insert("USER_ID_FOR_SRP".to_string(), json!(user_id_for_srp(&user)));
        parameters.insert(
            "MFAS_CAN_SETUP".to_string(),
            json!(serde_json::to_string(&can_setup).unwrap_or_default()),
        );
        return Ok(challenge(
            ctx,
            &user,
            ChallengeType::MfaSetup,
            parameters,
            ChallengeState {
                choices: can_setup,
                ..ChallengeState::default()
            },
        )
        .await);
    }

    if let Some(preferred) = preferred_mfa_setting(&user, &[]) {
        return mfa_challenge(ctx, &user, &preferred).await;
    }
    if let [only] = factors.as_slice() {
        return mfa_challenge(ctx, &user, only).await;
    }

    let mut parameters = Map::new();
    parameters.insert("USER_ID_FOR_SRP".to_string(), json!(user_id_for_srp(&user)));
    parameters.insert(
        "MFAS_CAN_CHOOSE".to_string(),
        json!(serde_json::to_string(&factors).unwrap_or_default()),
    );
    Ok(challenge(
        ctx,
        &user,
        ChallengeType::SelectMfaType,
        parameters,
        ChallengeState {
            choices: factors,
            ..ChallengeState::default()
        },
    )
    .await)
}

fn software_token_mfa_enabled(pool: &UserPool) -> bool {
    pool.software_token_mfa_configuration
        .as_ref()
        .and_then(|configuration| configuration.enabled)
        .unwrap_or(false)
}

/// Issue the challenge for one MFA factor.
async fn mfa_challenge(ctx: &AuthContext<'_>, user: &User, factor: &str) -> Result<Value> {
    let mut parameters = Map::new();
    parameters.insert("USER_ID_FOR_SRP".to_string(), json!(user_id_for_srp(user)));

    match factor {
        SOFTWARE_TOKEN_MFA_FACTOR => Ok(challenge(
            ctx,
            user,
            ChallengeType::SoftwareTokenMfa,
            parameters,
            ChallengeState::default(),
        )
        .await),
        SMS_MFA_FACTOR => {
            let phone_number = user.phone_number.as_deref().ok_or_else(|| {
                AppError::InvalidParameter("User has no phone number for SMS MFA".to_string())
            })?;
            let code = deliver_code(user, "SMS_MFA", phone_number);
            parameters.insert("CODE_DELIVERY_DELIVERY_MEDIUM".to_string(), json!("SMS"));
            parameters.insert(
                "CODE_DELIVERY_DESTINATION".to_string(),
                json!(mask_phone_number(phone_number)),
            );
            Ok(challenge(
                ctx,
                user,
                ChallengeType::SmsMfa,
                parameters,
                ChallengeState {
                    code: Some(code),
                    ..ChallengeState::default()
                },
            )
            .await)
        }
        EMAIL_OTP_FACTOR => Ok(email_otp_challenge(ctx, user, false).await?),
        other => Err(AppError::InvalidParameter(format!(
            "Unsupported MFA factor {other}"
        ))),
    }
}

async fn email_otp_challenge(ctx: &AuthContext<'_>, user: &User, user_auth: bool) -> Result<Value> {
    let email = user
        .email
        .as_deref()
        .ok_or_else(|| AppError::InvalidParameter("User has no email address".to_string()))?;
    let code = deliver_code(user, "EMAIL_OTP", email);
    let mut parameters = Map::new();
    parameters.insert("CODE_DELIVERY_DELIVERY_MEDIUM".to_string(), json!("EMAIL"));
    parameters.insert(
        "CODE_DELIVERY_DESTINATION".to_string(),
        json!(mask_email(email)),
    );
    Ok(challenge(
        ctx,
        user,
        ChallengeType::EmailOtp,
        parameters,
        ChallengeState {
            code: Some(code),
            user_auth,
            ..ChallengeState::default()
        },
    )
    .await)
}

/// "Send" a one-time code. Nothing leaves the emulator; the code is logged
/// at debug level like every other code it generates.
fn deliver_code(user: &User, purpose: &str, destination: &str) -> String {
    use rand::Rng;

    // Cognito's sign-in one-time passwords are eight digits; the codes of
    // SMS MFA, like confirmation codes, are six.
    let code = match purpose {
        "SMS_MFA" => generate_numeric_code(),
        _ => format!("{:08}", rand::thread_rng().gen_range(0..100_000_000)),
    };
    tracing::debug!(
        "{purpose} code for {} (to {destination}): {code}",
        user.username
    );
    code
}

/// The first factors `USER_AUTH` can offer this user.
async fn available_first_factors(ctx: &AuthContext<'_>, user: &User) -> Vec<ChallengeType> {
    let allowed = ctx
        .pool
        .policies
        .as_ref()
        .and_then(|policies| policies.sign_in_policy.as_ref())
        .and_then(|policy| policy.allowed_first_auth_factors.clone())
        .unwrap_or_else(|| vec![FirstAuthFactor::Password]);

    let mut available = Vec::new();
    for factor in allowed {
        match factor {
            FirstAuthFactor::Password => {
                available.push(ChallengeType::PasswordSrp);
                available.push(ChallengeType::Password);
            }
            FirstAuthFactor::EmailOtp if user.email.is_some() => {
                available.push(ChallengeType::EmailOtp);
            }
            FirstAuthFactor::SmsOtp if user.phone_number.is_some() => {
                available.push(ChallengeType::SmsOtp);
            }
            FirstAuthFactor::WebAuthn
                if !ctx
                    .storage
                    .list_webauthn_credentials(&user.id)
                    .await
                    .is_empty() =>
            {
                available.push(ChallengeType::WebAuthn);
            }
            _ => {}
        }
    }
    available
}

async fn select_challenge(
    ctx: &AuthContext<'_>,
    user: &User,
    available: &[ChallengeType],
) -> Result<Value> {
    let choices: Vec<String> = available
        .iter()
        .map(|challenge| challenge.as_str().to_string())
        .collect();
    let mut response = challenge(
        ctx,
        user,
        ChallengeType::SelectChallenge,
        Map::new(),
        ChallengeState {
            choices: choices.clone(),
            user_auth: true,
            ..ChallengeState::default()
        },
    )
    .await;
    response["AvailableChallenges"] = json!(choices);
    Ok(response)
}

/// Begin the first factor a `USER_AUTH` sign-in settled on. `values` are
/// the `AuthParameters` or `ChallengeResponses` that came with the choice.
async fn start_first_factor(
    ctx: &AuthContext<'_>,
    user: User,
    factor: ChallengeType,
    values: &HashMap<String, String>,
) -> Result<Value> {
    match factor {
        ChallengeType::Password => match optional(values, "PASSWORD") {
            Some(password) => {
                let user = check_password(ctx, user, password).await?;
                after_password(ctx, user, true).await
            }
            None => Ok(challenge(
                ctx,
                &user,
                ChallengeType::Password,
                Map::new(),
                ChallengeState {
                    user_auth: true,
                    ..ChallengeState::default()
                },
            )
            .await),
        },
        ChallengeType::PasswordSrp => match optional(values, "SRP_A") {
            Some(srp_a) => begin_srp(ctx, &user.username, srp_a, true).await,
            None => Ok(challenge(
                ctx,
                &user,
                ChallengeType::PasswordSrp,
                Map::new(),
                ChallengeState {
                    user_auth: true,
                    ..ChallengeState::default()
                },
            )
            .await),
        },
        ChallengeType::EmailOtp => {
            require_confirmed(&user)?;
            email_otp_challenge(ctx, &user, true).await
        }
        ChallengeType::SmsOtp => {
            require_confirmed(&user)?;
            let phone_number = user.phone_number.as_deref().ok_or_else(|| {
                AppError::InvalidParameter("User has no phone number".to_string())
            })?;
            let code = deliver_code(&user, "SMS_OTP", phone_number);
            let mut parameters = Map::new();
            parameters.insert("CODE_DELIVERY_DELIVERY_MEDIUM".to_string(), json!("SMS"));
            parameters.insert(
                "CODE_DELIVERY_DESTINATION".to_string(),
                json!(mask_phone_number(phone_number)),
            );
            Ok(challenge(
                ctx,
                &user,
                ChallengeType::SmsOtp,
                parameters,
                ChallengeState {
                    code: Some(code),
                    user_auth: true,
                    ..ChallengeState::default()
                },
            )
            .await)
        }
        _ => Err(AppError::NotImplemented(format!(
            "{} sign-in is not supported by the emulator",
            factor.as_str()
        ))),
    }
}

fn require_confirmed(user: &User) -> Result<()> {
    match user.user_status {
        UserStatus::Confirmed => Ok(()),
        UserStatus::ResetRequired => Err(AppError::PasswordResetRequired),
        _ => Err(AppError::UserNotConfirmed),
    }
}

/// Per-challenge data kept with the session.
#[derive(Default)]
struct ChallengeState {
    code: Option<String>,
    choices: Vec<String>,
    user_auth: bool,
}

/// Store a pending challenge and build the response announcing it.
async fn challenge(
    ctx: &AuthContext<'_>,
    user: &User,
    challenge_name: ChallengeType,
    parameters: Map<String, Value>,
    state: ChallengeState,
) -> Value {
    let session = new_session_token();
    ctx.storage
        .save_auth_challenge_session(PendingAuthChallenge {
            session: session.clone(),
            challenge_name,
            user_id: user.id,
            client_id: ctx.client.client_id.clone(),
            user_pool_id: ctx.pool.id.clone(),
            expires_at: Utc::now() + session_lifetime(ctx.client),
            srp: None,
            code: state.code,
            choices: state.choices,
            mfa_setup_complete: false,
            failed_attempts: 0,
            user_auth: state.user_auth,
        })
        .await;

    json!({
        "ChallengeName": challenge_name.as_str(),
        "ChallengeParameters": parameters,
        "Session": session,
    })
}

/// An opaque session string. Cognito's are long base64url blobs; clients
/// only ever echo them.
pub(crate) fn new_session_token() -> String {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use rand::RngCore;

    let mut bytes = [0u8; 96];
    rand::thread_rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Every factor is satisfied: sign the user in.
async fn complete(ctx: &AuthContext<'_>, user: &User) -> Result<Value> {
    require_confirmed(user)?;
    let session = TokenSession::new(ctx.client.enable_token_revocation);
    let refresh_token = new_refresh_token(ctx, user, &session, Vec::new()).await;
    let result = issue_tokens(ctx, user, &session, Some(refresh_token)).await?;

    ctx.storage
        .create_auth_event(AuthEvent {
            event_id: session.event_id.clone(),
            user_id: user.id,
            event_type: "SignIn".to_string(),
            creation_date: Utc::now(),
            event_response: "Pass".to_string(),
            feedback_value: None,
            feedback_provided_by: None,
            feedback_date: None,
        })
        .await;

    Ok(authenticated(result))
}

async fn new_refresh_token(
    ctx: &AuthContext<'_>,
    user: &User,
    session: &TokenSession,
    scope: Vec<String>,
) -> String {
    let token = new_session_token();
    ctx.storage
        .save_refresh_token(RefreshToken {
            token: token.clone(),
            user_id: user.id,
            client_id: ctx.client.client_id.clone(),
            expires_at: Utc::now() + resolve_refresh_token_expiry(ctx.client),
            origin_jti: session.origin_jti.clone(),
            auth_time: Some(session.auth_time),
            scope,
        })
        .await;
    token
}

/// `cognito:groups`, `cognito:roles`, and `cognito:preferred_role` for a user.
pub(crate) async fn group_claims(storage: &Storage, user: &User) -> GroupClaims {
    let mut groups = Vec::new();
    for name in storage.get_groups_for_user(&user.id).await {
        if let Some(group) = storage.get_group(&user.user_pool_id, &name).await {
            groups.push(group);
        }
    }
    GroupClaims::from_groups(groups)
}

/// Build an `AuthenticationResult` for the user pools API.
async fn issue_tokens(
    ctx: &AuthContext<'_>,
    user: &User,
    session: &TokenSession,
    refresh_token: Option<String>,
) -> Result<Value> {
    authentication_result(ctx.storage, ctx.client, user, session, refresh_token).await
}

/// Access and ID tokens (and optionally a refresh token) in the shape of
/// `AuthenticationResultType`.
pub(crate) async fn authentication_result(
    storage: &Storage,
    client: &UserPoolClient,
    user: &User,
    session: &TokenSession,
    refresh_token: Option<String>,
) -> Result<Value> {
    let groups = group_claims(storage, user).await;
    let access_expiry = resolve_access_token_expiry(client);

    let access_token = issue_access_token(&AccessTokenRequest {
        user,
        client_id: client.client_id.as_str(),
        user_pool_id: &client.user_pool_id,
        groups: &groups,
        session,
        // User pools API authentication grants only the user-admin scope.
        scopes: &[],
        oauth: false,
        expiry: access_expiry,
    })
    .map_err(AppError::Internal)?;
    let id_token = issue_id_token(&IdTokenRequest {
        user,
        client_id: client.client_id.as_str(),
        user_pool_id: &client.user_pool_id,
        groups: &groups,
        session,
        nonce: None,
        access_token: None,
        readable_attributes: &client.read_attributes,
        oauth_scopes: None,
        expiry: resolve_id_token_expiry(client),
    })
    .map_err(AppError::Internal)?;

    let mut result = json!({
        "AccessToken": access_token,
        "ExpiresIn": access_expiry.num_seconds(),
        "IdToken": id_token,
        "TokenType": "Bearer",
    });
    if let Some(refresh_token) = refresh_token {
        result["RefreshToken"] = json!(refresh_token);
    }
    Ok(result)
}

fn authenticated(authentication_result: Value) -> Value {
    json!({
        "AuthenticationResult": authentication_result,
        "ChallengeParameters": {},
    })
}

/// How the caller proves it is the confidential client a refresh token was
/// issued to.
pub(crate) enum RefreshSecret<'a> {
    /// `SECRET_HASH` over the username (`REFRESH_TOKEN_AUTH`).
    Hash(Option<&'a str>),
    /// The client secret itself, already checked by the caller.
    Verified,
}

/// Validate a refresh token and return the user it belongs to.
pub(crate) async fn authenticate_with_refresh_token(
    storage: &Storage,
    client: &UserPoolClient,
    refresh_token: &str,
    secret: RefreshSecret<'_>,
) -> Result<(User, RefreshToken)> {
    let Some(stored) = storage.get_refresh_token(refresh_token).await else {
        return Err(if storage.is_refresh_token_revoked(refresh_token).await {
            AppError::RefreshTokenRevoked
        } else {
            AppError::InvalidRefreshToken
        });
    };

    if stored.client_id != client.client_id {
        return Err(AppError::InvalidRefreshToken);
    }
    if stored.expires_at < Utc::now() {
        return Err(AppError::RefreshTokenExpired);
    }

    let user = storage
        .get_user(&stored.user_id)
        .await
        .ok_or(AppError::UserNotFound)?;
    if user.user_pool_id != client.user_pool_id {
        return Err(AppError::InvalidRefreshToken);
    }

    if let RefreshSecret::Hash(provided) = secret {
        verify_refresh_secret_hash(client, &user, provided)?;
    }
    require_enabled(&user)?;

    Ok((user, stored))
}

/// `SECRET_HASH` for a refresh is computed over the user's username; clients
/// that signed in with an alias commonly send the hash over the `sub`.
fn verify_refresh_secret_hash(
    client: &UserPoolClient,
    user: &User,
    provided: Option<&str>,
) -> Result<()> {
    verify_secret_hash(client, &user.username, provided).or_else(|error| {
        match verify_secret_hash(client, &user.id.to_string(), provided) {
            Ok(()) => Ok(()),
            Err(_) => Err(error),
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ClientId, UserPoolId};

    fn client(flows: &[ExplicitAuthFlow]) -> UserPoolClient {
        let mut client = UserPoolClient::new_for_test(
            ClientId::generate(),
            UserPoolId::new("us-east-1_Test").unwrap(),
        );
        client.explicit_auth_flows = flows.to_vec();
        client
    }

    #[test]
    fn unknown_auth_flow_is_a_validation_error() {
        assert!(matches!(
            parse_auth_flow("NOPE"),
            Err(AppError::InvalidParameter(message))
                if message.starts_with("1 validation error detected: Value 'NOPE' at 'authFlow'")
        ));
        assert_eq!(parse_auth_flow("USER_AUTH").unwrap(), AuthFlow::UserAuth);
        assert_eq!(
            parse_auth_flow("REFRESH_TOKEN").unwrap(),
            AuthFlow::RefreshToken
        );
    }

    #[test]
    fn unknown_challenge_name_is_a_validation_error() {
        assert!(matches!(
            parse_challenge_name("NOPE"),
            Err(AppError::InvalidParameter(message))
                if message.contains("at 'challengeName'")
        ));
        assert_eq!(
            parse_challenge_name("EMAIL_OTP").unwrap(),
            ChallengeType::EmailOtp
        );
    }

    #[test]
    fn default_client_allows_srp_and_refresh_only() {
        let client = client(&[]);
        assert!(flow_enabled(&client, AuthFlow::UserSrpAuth));
        assert!(flow_enabled(&client, AuthFlow::RefreshTokenAuth));
        assert!(flow_enabled(&client, AuthFlow::CustomAuth));
        assert!(!flow_enabled(&client, AuthFlow::UserPasswordAuth));
        assert!(!flow_enabled(&client, AuthFlow::AdminUserPasswordAuth));
        assert!(!flow_enabled(&client, AuthFlow::UserAuth));
    }

    #[test]
    fn allow_flows_are_exact() {
        let client = client(&[
            ExplicitAuthFlow::AllowUserPasswordAuth,
            ExplicitAuthFlow::AllowRefreshTokenAuth,
        ]);
        assert!(flow_enabled(&client, AuthFlow::UserPasswordAuth));
        assert!(flow_enabled(&client, AuthFlow::RefreshToken));
        assert!(!flow_enabled(&client, AuthFlow::UserSrpAuth));
        assert!(!flow_enabled(&client, AuthFlow::AdminNoSrpAuth));
    }

    #[test]
    fn legacy_flows_keep_srp_and_refresh() {
        let admin = client(&[ExplicitAuthFlow::AdminNoSrpAuth]);
        assert!(flow_enabled(&admin, AuthFlow::AdminUserPasswordAuth));
        assert!(flow_enabled(&admin, AuthFlow::UserSrpAuth));
        assert!(flow_enabled(&admin, AuthFlow::RefreshTokenAuth));
        assert!(!flow_enabled(&admin, AuthFlow::UserPasswordAuth));

        let custom_only = client(&[ExplicitAuthFlow::CustomAuthFlowOnly]);
        assert!(!flow_enabled(&custom_only, AuthFlow::UserSrpAuth));
    }

    #[test]
    fn api_restricts_server_side_flows() {
        assert!(
            require_flow_supported_by_api(AuthApi::User, AuthFlow::AdminUserPasswordAuth).is_err()
        );
        assert!(
            require_flow_supported_by_api(AuthApi::Admin, AuthFlow::AdminUserPasswordAuth).is_ok()
        );
        assert!(require_flow_supported_by_api(AuthApi::Admin, AuthFlow::UserPasswordAuth).is_err());
        assert!(require_flow_supported_by_api(AuthApi::User, AuthFlow::UserSrpAuth).is_ok());
    }

    #[test]
    fn session_tokens_are_opaque_and_unique() {
        let first = new_session_token();
        assert!(first.len() >= 100);
        assert_ne!(first, new_session_token());
    }
}
