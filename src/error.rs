use axum::{
    Json,
    http::{HeaderValue, StatusCode, header},
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
    #[error("User does not exist.")]
    UserNotFound,

    #[error("User pool does not exist.")]
    UserPoolNotFound,

    #[error("User pool client does not exist.")]
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

    /// `UsernameExistsException` with a message naming the sign-in
    /// attribute that is taken.
    #[error("{0}")]
    UsernameExists(String),

    /// `UsernameExistsException` as AdminCreateUser words it.
    #[error("User account already exists")]
    UserAccountAlreadyExists,

    #[error("An account with the {0} already exists.")]
    AliasExists(&'static str),

    #[error("{0}")]
    UnsupportedUserState(String),

    #[error("{0}")]
    InvalidPassword(String),

    #[error("Invalid verification code provided, please try again.")]
    InvalidConfirmationCode,

    /// `CodeMismatchException` with an operation-specific message.
    #[error("{0}")]
    CodeMismatch(String),

    #[error("Invalid Access Token")]
    InvalidAccessToken,

    #[error("Access Token has expired")]
    AccessTokenExpired,

    #[error("Access Token has been revoked")]
    AccessTokenRevoked,

    #[error("Invalid Refresh Token")]
    InvalidRefreshToken,

    #[error("Refresh Token has expired")]
    RefreshTokenExpired,

    #[error("Refresh Token has been revoked")]
    RefreshTokenRevoked,

    #[error("User is not confirmed.")]
    UserNotConfirmed,

    #[error("User is disabled.")]
    UserDisabled,

    #[error("Password reset required for the user")]
    PasswordResetRequired,

    #[error("Group not found.")]
    GroupNotFound,

    #[error("A group with the name already exists.")]
    GroupAlreadyExists,

    #[error("Invalid code provided, please request a code again.")]
    ExpiredCode,

    #[error("Attempt limit exceeded, please try after some time.")]
    LimitExceeded,

    #[error("{0}")]
    InvalidParameter(String),

    /// `EnableSoftwareTokenMFAException`: the TOTP code did not verify.
    #[error("{0}")]
    EnableSoftwareTokenMfa(String),

    /// `SoftwareTokenMFANotFoundException`
    #[error(
        "Software token TOTP multi-factor authentication (MFA) is not enabled for the user pool."
    )]
    SoftwareTokenMfaNotFound,

    /// `UnsupportedOperationException`: not enabled for the app client.
    #[error("{0}")]
    UnsupportedOperation(String),

    /// The request body could not be mapped onto the operation's input shape.
    #[error("{0}")]
    Serialization(String),

    #[error("Internal server error: {0}")]
    Internal(String),

    #[error("Storage error: {0}")]
    Storage(String),

    #[error("{0}")]
    NotAuthorized(String),

    #[error("Not implemented: {0}")]
    NotImplemented(String),

    #[error("Unknown operation {0}")]
    UnknownOperation(String),
}

#[derive(Debug)]
pub struct OAuthError {
    pub error: String,
    pub error_description: Option<String>,
}

impl AppError {
    /// HTTP status and `__type` of the Cognito exception this error maps to.
    ///
    /// Cognito answers every client error with HTTP 400, including
    /// `NotAuthorizedException`; only service faults are 5xx.
    pub fn status_and_type(&self) -> (StatusCode, &'static str) {
        match self {
            AppError::UserNotFound => (StatusCode::BAD_REQUEST, "UserNotFoundException"),
            AppError::UserPoolNotFound
            | AppError::UserPoolClientNotFound
            | AppError::UserPoolDomainNotFound
            | AppError::UserImportJobNotFound
            | AppError::TermsNotFound
            | AppError::WebAuthnCredentialNotFound
            | AppError::IdentityProviderNotFound
            | AppError::ResourceServerNotFound
            | AppError::DeviceNotFound
            | AppError::AuthEventNotFound
            | AppError::GroupNotFound => (StatusCode::BAD_REQUEST, "ResourceNotFoundException"),
            AppError::IdentityProviderAlreadyExists => {
                (StatusCode::BAD_REQUEST, "DuplicateProviderException")
            }
            AppError::UserPoolDomainAlreadyExists
            | AppError::ResourceServerAlreadyExists
            | AppError::InvalidParameter(_) => {
                (StatusCode::BAD_REQUEST, "InvalidParameterException")
            }
            AppError::Serialization(_) => (StatusCode::BAD_REQUEST, "SerializationException"),
            AppError::UnsupportedOperation(_) => {
                (StatusCode::BAD_REQUEST, "UnsupportedOperationException")
            }
            AppError::EnableSoftwareTokenMfa(_) => {
                (StatusCode::BAD_REQUEST, "EnableSoftwareTokenMFAException")
            }
            AppError::SoftwareTokenMfaNotFound => {
                (StatusCode::BAD_REQUEST, "SoftwareTokenMFANotFoundException")
            }
            AppError::UserAlreadyExists
            | AppError::UserAccountAlreadyExists
            | AppError::UsernameExists(_) => (StatusCode::BAD_REQUEST, "UsernameExistsException"),
            AppError::AliasExists(_) => (StatusCode::BAD_REQUEST, "AliasExistsException"),
            AppError::UnsupportedUserState(_) => {
                (StatusCode::BAD_REQUEST, "UnsupportedUserStateException")
            }
            AppError::InvalidPassword(_) => (StatusCode::BAD_REQUEST, "InvalidPasswordException"),
            AppError::InvalidConfirmationCode | AppError::CodeMismatch(_) => {
                (StatusCode::BAD_REQUEST, "CodeMismatchException")
            }
            // Cognito has no `UserDisabledException`: a disabled user is
            // reported as `NotAuthorizedException: User is disabled.`
            AppError::InvalidAccessToken
            | AppError::AccessTokenExpired
            | AppError::AccessTokenRevoked
            | AppError::InvalidRefreshToken
            | AppError::RefreshTokenExpired
            | AppError::RefreshTokenRevoked
            | AppError::UserDisabled
            | AppError::NotAuthorized(_) => (StatusCode::BAD_REQUEST, "NotAuthorizedException"),
            AppError::UserNotConfirmed => (StatusCode::BAD_REQUEST, "UserNotConfirmedException"),
            AppError::PasswordResetRequired => {
                (StatusCode::BAD_REQUEST, "PasswordResetRequiredException")
            }
            AppError::GroupAlreadyExists => (StatusCode::BAD_REQUEST, "GroupExistsException"),
            AppError::ExpiredCode => (StatusCode::BAD_REQUEST, "ExpiredCodeException"),
            AppError::LimitExceeded => (StatusCode::BAD_REQUEST, "LimitExceededException"),
            AppError::Internal(_) | AppError::Storage(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "InternalErrorException")
            }
            AppError::NotImplemented(_) => (StatusCode::NOT_IMPLEMENTED, "NotImplementedException"),
            AppError::UnknownOperation(_) => (StatusCode::BAD_REQUEST, "UnknownOperationException"),
        }
    }

    /// The message Cognito would send, naming the resource from the request
    /// where Cognito does (`User pool <id> does not exist.`).
    pub fn message_for_request(&self, request: Option<&serde_json::Value>) -> String {
        let field = |name: &str| {
            request
                .and_then(|body| body.get(name))
                .and_then(serde_json::Value::as_str)
        };
        match self {
            AppError::UserPoolNotFound => match field("UserPoolId") {
                Some(id) => format!("User pool {id} does not exist."),
                None => self.to_string(),
            },
            AppError::UserPoolClientNotFound => match field("ClientId") {
                Some(id) => format!("User pool client {id} does not exist."),
                None => self.to_string(),
            },
            _ => self.to_string(),
        }
    }

    /// Render the error as the cognito-idp JSON 1.1 protocol does.
    pub fn into_cognito_response(self, request: Option<&serde_json::Value>) -> Response {
        let (status, error_type) = self.status_and_type();
        let message = self.message_for_request(request);
        let mut response = build_error_response(
            status,
            ErrorFormat::Cognito,
            error_type.to_string(),
            Some(message.clone()),
        );
        let headers = response.headers_mut();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/x-amz-json-1.1"),
        );
        if let Ok(value) = HeaderValue::from_str(&format!("{error_type}:")) {
            headers.insert("x-amzn-errortype", value);
        }
        if let Ok(value) = HeaderValue::from_str(&message) {
            headers.insert("x-amzn-errormessage", value);
        }
        response
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        self.into_cognito_response(None)
    }
}

impl IntoResponse for OAuthError {
    fn into_response(self) -> Response {
        let invalid_token = self.error == "invalid_token";
        let status = if invalid_token {
            StatusCode::UNAUTHORIZED
        } else {
            StatusCode::BAD_REQUEST
        };
        let mut response = build_error_response(
            status,
            ErrorFormat::OAuth,
            self.error,
            self.error_description,
        );
        if invalid_token {
            response.headers_mut().insert(
                header::WWW_AUTHENTICATE,
                HeaderValue::from_static("Bearer error=\"invalid_token\""),
            );
        }
        response
    }
}

pub type Result<T> = std::result::Result<T, AppError>;
