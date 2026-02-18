//! AWS Cognito Identity Provider API handler
//!
//! This module implements the main entry point for Cognito User Pools API requests.
//! Requests are routed based on the `X-Amz-Target` header.

use std::str::FromStr;

use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use serde_json::Value;
use tracing::{info, warn};

use super::extractor::AmzJson;
use crate::{
    action::{group, user, user_pool},
    error::AppError,
    storage::Storage,
};

/// Target header prefix for Cognito operations
const TARGET_PREFIX: &str = "AWSCognitoIdentityProviderService.";

/// Handle incoming Cognito API requests
pub async fn handle_request(
    State(storage): State<Storage>,
    headers: HeaderMap,
    AmzJson(body): AmzJson<Value>,
) -> impl IntoResponse {
    let target = headers
        .get("x-amz-target")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    info!("Received request with target: {}", target);

    let operation_str = target.strip_prefix(TARGET_PREFIX).unwrap_or(target);

    let result = match operation_str.parse::<Action>() {
        Ok(op) => dispatch_action(&storage, op, body).await,
        Err(e) => {
            warn!("Unknown operation: {}", e.0);
            Err(AppError::NotImplemented(e.0))
        }
    };

    match result {
        Ok(response) => (
            StatusCode::OK,
            [("content-type", "application/x-amz-json-1.1")],
            Json(response),
        )
            .into_response(),
        Err(e) => e.into_response(),
    }
}

#[derive(Debug, Clone)]
pub struct UnknownAction(pub String);

macro_rules! define_action_registry {
    ($($variant:ident => $handler:path,)+) => {
        /// All Cognito Identity Provider operations.
        ///
        /// <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_Operations.html>
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum Action {
            $($variant,)+
        }

        impl Action {
            /// Returns true if this operation is implemented.
            /// Generated from the same registry as dispatch and parsing.
            pub const fn is_implemented(&self) -> bool {
                matches!(self, $(Self::$variant)|+)
            }

            /// Returns the AWS documentation URL for this operation.
            pub fn doc_url(&self) -> String {
                format!(
                    "https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_{:?}.html",
                    self
                )
            }
        }

        impl FromStr for Action {
            type Err = UnknownAction;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                match s {
                    $(stringify!($variant) => Ok(Self::$variant),)+
                    _ => Err(UnknownAction(s.to_string())),
                }
            }
        }

        async fn dispatch_action(
            storage: &Storage,
            action: Action,
            body: Value,
        ) -> Result<Value, AppError> {
            match action {
                $(Action::$variant => $handler(storage, body).await,)+
            }
        }
    };
}

define_action_registry! {
    CreateUserPool => user_pool::create_user_pool::handler,
    DeleteUserPool => user_pool::delete_user_pool::handler,
    DescribeUserPool => user_pool::describe_user_pool::handler,
    ListUserPools => user_pool::list_user_pools::handler,
    UpdateUserPool => user_pool::update_user_pool::handler,
    CreateUserPoolClient => user_pool::create_user_pool_client::handler,
    DeleteUserPoolClient => user_pool::delete_user_pool_client::handler,
    DescribeUserPoolClient => user_pool::describe_user_pool_client::handler,
    ListUserPoolClients => user_pool::list_user_pool_clients::handler,
    UpdateUserPoolClient => user_pool::update_user_pool_client::handler,
    CreateUserPoolDomain => user_pool::create_user_pool_domain::handler,
    DeleteUserPoolDomain => user_pool::delete_user_pool_domain::handler,
    DescribeUserPoolDomain => user_pool::describe_user_pool_domain::handler,
    UpdateUserPoolDomain => user_pool::update_user_pool_domain::handler,
    CreateManagedLoginBranding => user_pool::create_managed_login_branding::handler,
    DeleteManagedLoginBranding => user_pool::delete_managed_login_branding::handler,
    DescribeManagedLoginBranding => user_pool::describe_managed_login_branding::handler,
    DescribeManagedLoginBrandingByClient => user_pool::describe_managed_login_branding_by_client::handler,
    UpdateManagedLoginBranding => user_pool::update_managed_login_branding::handler,
    SignUp => user::sign_up::handler,
    ConfirmSignUp => user::confirm_sign_up::handler,
    ResendConfirmationCode => user::resend_confirmation_code::handler,
    InitiateAuth => user::initiate_auth::handler,
    RespondToAuthChallenge => user::respond_to_auth_challenge::handler,
    GetUser => user::get_user::handler,
    DeleteUser => user::delete_user::handler,
    DeleteUserAttributes => user::delete_user_attributes::handler,
    UpdateUserAttributes => user::update_user_attributes::handler,
    ListUsers => user::list_users::handler,
    ChangePassword => user::change_password::handler,
    ForgotPassword => user::forgot_password::handler,
    ConfirmForgotPassword => user::confirm_forgot_password::handler,
    GlobalSignOut => user::global_sign_out::handler,
    RevokeToken => user::revoke_token::handler,
    GetTokensFromRefreshToken => user::get_tokens_from_refresh_token::handler,
    GetUserAttributeVerificationCode => user::get_user_attribute_verification_code::handler,
    VerifyUserAttribute => user::verify_user_attribute::handler,
    AdminConfirmSignUp => user::admin_confirm_sign_up::handler,
    AdminCreateUser => user::admin_create_user::handler,
    AdminDeleteUser => user::admin_delete_user::handler,
    AdminDeleteUserAttributes => user::admin_delete_user_attributes::handler,
    AdminDisableProviderForUser => user::admin_disable_provider_for_user::handler,
    AdminDisableUser => user::admin_disable_user::handler,
    AdminEnableUser => user::admin_enable_user::handler,
    AdminForgetDevice => user::admin_forget_device::handler,
    AdminGetDevice => user::admin_get_device::handler,
    AdminGetUser => user::admin_get_user::handler,
    AdminInitiateAuth => user::admin_initiate_auth::handler,
    AdminLinkProviderForUser => user::admin_link_provider_for_user::handler,
    AdminListDevices => user::admin_list_devices::handler,
    AdminListUserAuthEvents => user::admin_list_user_auth_events::handler,
    AdminResetUserPassword => user::admin_reset_user_password::handler,
    AdminRespondToAuthChallenge => user::admin_respond_to_auth_challenge::handler,
    AdminUpdateAuthEventFeedback => user::admin_update_auth_event_feedback::handler,
    AdminUpdateDeviceStatus => user::admin_update_device_status::handler,
    AdminSetUserPassword => user::admin_set_user_password::handler,
    AdminUpdateUserAttributes => user::admin_update_user_attributes::handler,
    AdminUserGlobalSignOut => user::admin_user_global_sign_out::handler,
    AdminAddUserToGroup => group::admin_add_user_to_group::handler,
    AdminRemoveUserFromGroup => group::admin_remove_user_from_group::handler,
    AdminListGroupsForUser => group::admin_list_groups_for_user::handler,
    CreateGroup => group::create_group::handler,
    DeleteGroup => group::delete_group::handler,
    GetGroup => group::get_group::handler,
    ListGroups => group::list_groups::handler,
    ListUsersInGroup => group::list_users_in_group::handler,
    UpdateGroup => group::update_group::handler,
    CreateIdentityProvider => user_pool::create_identity_provider::handler,
    DeleteIdentityProvider => user_pool::delete_identity_provider::handler,
    DescribeIdentityProvider => user_pool::describe_identity_provider::handler,
    GetIdentityProviderByIdentifier => user_pool::get_identity_provider_by_identifier::handler,
    ListIdentityProviders => user_pool::list_identity_providers::handler,
    UpdateIdentityProvider => user_pool::update_identity_provider::handler,
    CreateResourceServer => user_pool::create_resource_server::handler,
    DeleteResourceServer => user_pool::delete_resource_server::handler,
    DescribeResourceServer => user_pool::describe_resource_server::handler,
    ListResourceServers => user_pool::list_resource_servers::handler,
    UpdateResourceServer => user_pool::update_resource_server::handler,
    AddCustomAttributes => user_pool::add_custom_attributes::handler,
    GetSigningCertificate => user_pool::get_signing_certificate::handler,
    UpdateAuthEventFeedback => user::update_auth_event_feedback::handler,
    UpdateDeviceStatus => user::update_device_status::handler,
    SetUserMFAPreference => user::set_user_mfa_preference::handler,
    AdminSetUserMFAPreference => user::admin_set_user_mfa_preference::handler,
    AssociateSoftwareToken => user::associate_software_token::handler,
    VerifySoftwareToken => user::verify_software_token::handler,
    GetUserPoolMfaConfig => user_pool::get_user_pool_mfa_config::handler,
    SetUserPoolMfaConfig => user_pool::set_user_pool_mfa_config::handler,
    GetUserAuthFactors => user::get_user_auth_factors::handler,
    ConfirmDevice => user::confirm_device::handler,
    ForgetDevice => user::forget_device::handler,
    GetDevice => user::get_device::handler,
    ListDevices => user::list_devices::handler,
    SetUserSettings => user::set_user_settings::handler,
    AdminSetUserSettings => user::admin_set_user_settings::handler,
    CreateUserImportJob => user_pool::create_user_import_job::handler,
    DescribeUserImportJob => user_pool::describe_user_import_job::handler,
    GetCSVHeader => user_pool::get_csv_header::handler,
    ListUserImportJobs => user_pool::list_user_import_jobs::handler,
    StartUserImportJob => user_pool::start_user_import_job::handler,
    StopUserImportJob => user_pool::stop_user_import_job::handler,
    CompleteWebAuthnRegistration => user::complete_webauthn_registration::handler,
    DeleteWebAuthnCredential => user::delete_webauthn_credential::handler,
    ListWebAuthnCredentials => user::list_webauthn_credentials::handler,
    StartWebAuthnRegistration => user::start_webauthn_registration::handler,
    CreateTerms => user_pool::create_terms::handler,
    DeleteTerms => user_pool::delete_terms::handler,
    DescribeTerms => user_pool::describe_terms::handler,
    ListTerms => user_pool::list_terms::handler,
    UpdateTerms => user_pool::update_terms::handler,
    DescribeRiskConfiguration => user_pool::describe_risk_configuration::handler,
    SetRiskConfiguration => user_pool::set_risk_configuration::handler,
    GetUICustomization => user_pool::get_ui_customization::handler,
    SetUICustomization => user_pool::set_ui_customization::handler,
    GetLogDeliveryConfiguration => user_pool::get_log_delivery_configuration::handler,
    SetLogDeliveryConfiguration => user_pool::set_log_delivery_configuration::handler,
    ListTagsForResource => user_pool::list_tags_for_resource::handler,
    TagResource => user_pool::tag_resource::handler,
    UntagResource => user_pool::untag_resource::handler,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_operation() {
        assert_eq!("SignUp".parse::<Action>().unwrap(), Action::SignUp);
        assert_eq!(
            "AdminCreateUser".parse::<Action>().unwrap(),
            Action::AdminCreateUser
        );
    }

    #[test]
    fn test_unknown_operation() {
        assert!("UnknownOp".parse::<Action>().is_err());
    }

    #[test]
    fn test_is_implemented() {
        assert!(Action::SignUp.is_implemented());
        assert!(Action::CreateUserPool.is_implemented());
        assert!(Action::AdminAddUserToGroup.is_implemented());
        assert!(Action::AdminInitiateAuth.is_implemented());
        assert!(Action::AdminRespondToAuthChallenge.is_implemented());
        assert!(Action::AdminForgetDevice.is_implemented());
    }

    #[test]
    fn test_doc_url() {
        assert_eq!(
            Action::SignUp.doc_url(),
            "https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_SignUp.html"
        );
    }
}
