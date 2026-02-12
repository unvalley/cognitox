use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Serialize;

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

    #[error("User is disabled")]
    UserDisabled,

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

    #[error("Internal server error: {0}")]
    Internal(String),

    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("Not implemented: {0}")]
    NotImplemented(String),
}

#[derive(Serialize)]
struct ErrorResponse {
    #[serde(rename = "__type")]
    error_type: String,
    message: String,
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
                (StatusCode::BAD_REQUEST, "InvalidParameterException")
            }
            AppError::ResourceServerNotFound => {
                (StatusCode::BAD_REQUEST, "ResourceNotFoundException")
            }
            AppError::ResourceServerAlreadyExists => {
                (StatusCode::BAD_REQUEST, "InvalidParameterException")
            }
            AppError::UserAlreadyExists => (StatusCode::BAD_REQUEST, "UsernameExistsException"),
            AppError::InvalidPassword => (StatusCode::BAD_REQUEST, "InvalidPasswordException"),
            AppError::InvalidConfirmationCode => (StatusCode::BAD_REQUEST, "CodeMismatchException"),
            AppError::InvalidAccessToken => (StatusCode::UNAUTHORIZED, "NotAuthorizedException"),
            AppError::InvalidRefreshToken => (StatusCode::UNAUTHORIZED, "NotAuthorizedException"),
            AppError::UserNotConfirmed => (StatusCode::BAD_REQUEST, "UserNotConfirmedException"),
            AppError::UserDisabled => (StatusCode::BAD_REQUEST, "UserDisabledException"),
            AppError::GroupNotFound => (StatusCode::BAD_REQUEST, "ResourceNotFoundException"),
            AppError::GroupAlreadyExists => (StatusCode::BAD_REQUEST, "GroupExistsException"),
            AppError::ExpiredCode => (StatusCode::BAD_REQUEST, "ExpiredCodeException"),
            AppError::LimitExceeded => (StatusCode::BAD_REQUEST, "LimitExceededException"),
            AppError::InvalidParameter(_) => (StatusCode::BAD_REQUEST, "InvalidParameterException"),
            AppError::Internal(_) => (StatusCode::INTERNAL_SERVER_ERROR, "InternalErrorException"),
            AppError::Database(_) => (StatusCode::INTERNAL_SERVER_ERROR, "InternalErrorException"),
            AppError::NotImplemented(_) => (StatusCode::NOT_IMPLEMENTED, "NotImplementedException"),
        };

        let body = ErrorResponse {
            error_type: error_type.to_string(),
            message: self.to_string(),
        };

        (status, Json(body)).into_response()
    }
}

pub type Result<T> = std::result::Result<T, AppError>;
