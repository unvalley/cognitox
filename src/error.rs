use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Serialize;

#[derive(Serialize)]
struct CognitoErrorResponse {
    #[serde(rename = "__type")]
    error_type: String,
    message: String,
}

#[derive(Serialize)]
struct OAuthErrorResponse {
    error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    error_description: Option<String>,
}

enum ErrorFormat {
    Cognito,
    OAuth,
}

fn build_error_response(
    status: StatusCode,
    format: ErrorFormat,
    code: String,
    message: Option<String>,
) -> Response {
    match format {
        ErrorFormat::Cognito => {
            let body = CognitoErrorResponse {
                error_type: code,
                message: message.unwrap_or_else(|| "Unknown error".to_string()),
            };
            (status, Json(body)).into_response()
        }
        ErrorFormat::OAuth => {
            let body = OAuthErrorResponse {
                error: code,
                error_description: message,
            };
            (status, Json(body)).into_response()
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("User not found")]
    UserNotFound,

    #[error("User pool not found")]
    UserPoolNotFound,

    #[error("User pool client not found")]
    UserPoolClientNotFound,

    #[error("User pool domain not found")]
    UserPoolDomainNotFound,

    #[error("User pool domain already exists")]
    UserPoolDomainAlreadyExists,

    #[error("User import job not found")]
    UserImportJobNotFound,

    #[error("Terms document not found")]
    TermsNotFound,

    #[error("WebAuthn credential not found")]
    WebAuthnCredentialNotFound,

    #[error("Identity provider not found")]
    IdentityProviderNotFound,

    #[error("Identity provider already exists")]
    IdentityProviderAlreadyExists,

    #[error("Resource server not found")]
    ResourceServerNotFound,

    #[error("Resource server already exists")]
    ResourceServerAlreadyExists,

    #[error("Device not found")]
    DeviceNotFound,

    #[error("Auth event not found")]
    AuthEventNotFound,

    #[error("User already exists")]
    UserAlreadyExists,

    #[error("Invalid password")]
    InvalidPassword,

    #[error("Invalid confirmation code")]
    InvalidConfirmationCode,

    #[error("Invalid access token")]
    InvalidAccessToken,

    #[error("Invalid refresh token")]
    InvalidRefreshToken,

    #[error("User not confirmed")]
    UserNotConfirmed,

    #[error("User is disabled.")]
    UserDisabled,

    #[error("Password reset required for the user")]
    PasswordResetRequired,

    #[error("{0}")]
    EnableSoftwareTokenMfa(String),

    #[error("Group not found")]
    GroupNotFound,

    #[error("Group already exists")]
    GroupAlreadyExists,

    #[error("Expired code")]
    ExpiredCode,

    #[error("Limit exceeded")]
    LimitExceeded,

    #[error("Invalid parameter: {0}")]
    InvalidParameter(String),

    #[error("{0}")]
    Serialization(String),

    #[error("{0}")]
    PreconditionNotMet(String),

    #[error("Internal server error: {0}")]
    Internal(String),

    #[error("Storage error: {0}")]
    Storage(String),

    #[error("Not authorized: {0}")]
    NotAuthorized(String),

    #[error("Not implemented: {0}")]
    NotImplemented(String),
}

#[derive(Debug)]
pub struct OAuthError {
    pub error: String,
    pub error_description: Option<String>,
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, error_type) = match &self {
            AppError::UserNotFound => (StatusCode::BAD_REQUEST, "UserNotFoundException"),
            AppError::UserPoolNotFound => (StatusCode::BAD_REQUEST, "ResourceNotFoundException"),
            AppError::UserPoolClientNotFound => {
                (StatusCode::BAD_REQUEST, "ResourceNotFoundException")
            }
            AppError::UserPoolDomainNotFound => {
                (StatusCode::BAD_REQUEST, "ResourceNotFoundException")
            }
            AppError::UserPoolDomainAlreadyExists => {
                (StatusCode::BAD_REQUEST, "InvalidParameterException")
            }
            AppError::UserImportJobNotFound => {
                (StatusCode::BAD_REQUEST, "ResourceNotFoundException")
            }
            AppError::TermsNotFound => (StatusCode::BAD_REQUEST, "ResourceNotFoundException"),
            AppError::WebAuthnCredentialNotFound => {
                (StatusCode::BAD_REQUEST, "ResourceNotFoundException")
            }
            AppError::IdentityProviderNotFound => {
                (StatusCode::BAD_REQUEST, "ResourceNotFoundException")
            }
            AppError::IdentityProviderAlreadyExists => {
                (StatusCode::BAD_REQUEST, "DuplicateProviderException")
            }
            AppError::ResourceServerNotFound => {
                (StatusCode::BAD_REQUEST, "ResourceNotFoundException")
            }
            AppError::ResourceServerAlreadyExists => {
                (StatusCode::BAD_REQUEST, "InvalidParameterException")
            }
            AppError::DeviceNotFound => (StatusCode::BAD_REQUEST, "ResourceNotFoundException"),
            AppError::AuthEventNotFound => (StatusCode::BAD_REQUEST, "ResourceNotFoundException"),
            AppError::UserAlreadyExists => (StatusCode::BAD_REQUEST, "UsernameExistsException"),
            AppError::InvalidPassword => (StatusCode::BAD_REQUEST, "InvalidPasswordException"),
            AppError::InvalidConfirmationCode => (StatusCode::BAD_REQUEST, "CodeMismatchException"),
            // Cognito answers every NotAuthorizedException with HTTP 400; SDKs
            // dispatch on `__type`, browsers/tests on the status code.
            AppError::InvalidAccessToken => (StatusCode::BAD_REQUEST, "NotAuthorizedException"),
            AppError::InvalidRefreshToken => (StatusCode::BAD_REQUEST, "NotAuthorizedException"),
            AppError::UserNotConfirmed => (StatusCode::BAD_REQUEST, "UserNotConfirmedException"),
            // There is no UserDisabledException in Cognito; a disabled user
            // gets NotAuthorizedException "User is disabled.".
            AppError::UserDisabled => (StatusCode::BAD_REQUEST, "NotAuthorizedException"),
            AppError::PasswordResetRequired => {
                (StatusCode::BAD_REQUEST, "PasswordResetRequiredException")
            }
            AppError::EnableSoftwareTokenMfa(_) => {
                (StatusCode::BAD_REQUEST, "EnableSoftwareTokenMFAException")
            }
            AppError::GroupNotFound => (StatusCode::BAD_REQUEST, "ResourceNotFoundException"),
            AppError::GroupAlreadyExists => (StatusCode::BAD_REQUEST, "GroupExistsException"),
            AppError::ExpiredCode => (StatusCode::BAD_REQUEST, "ExpiredCodeException"),
            AppError::LimitExceeded => (StatusCode::BAD_REQUEST, "LimitExceededException"),
            AppError::InvalidParameter(_) => (StatusCode::BAD_REQUEST, "InvalidParameterException"),
            AppError::Serialization(_) => (StatusCode::BAD_REQUEST, "SerializationException"),
            AppError::PreconditionNotMet(_) => {
                (StatusCode::BAD_REQUEST, "PreconditionNotMetException")
            }
            AppError::Internal(_) => (StatusCode::INTERNAL_SERVER_ERROR, "InternalErrorException"),
            AppError::Storage(_) => (StatusCode::INTERNAL_SERVER_ERROR, "InternalErrorException"),
            AppError::NotAuthorized(_) => (StatusCode::BAD_REQUEST, "NotAuthorizedException"),
            AppError::NotImplemented(_) => (StatusCode::NOT_IMPLEMENTED, "NotImplementedException"),
        };

        build_error_response(
            status,
            ErrorFormat::Cognito,
            error_type.to_string(),
            Some(self.to_string()),
        )
    }
}

impl IntoResponse for OAuthError {
    fn into_response(self) -> Response {
        build_error_response(
            StatusCode::BAD_REQUEST,
            ErrorFormat::OAuth,
            self.error,
            self.error_description,
        )
    }
}

pub type Result<T> = std::result::Result<T, AppError>;
