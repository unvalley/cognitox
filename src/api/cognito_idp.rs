//! AWS Cognito Identity Provider API handler
//!
//! This module implements the main entry point for Cognito User Pools API requests.
//! Requests are routed based on the `X-Amz-Target` header.

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

/// Dispatch to the appropriate action handler
async fn dispatch_action(
    storage: &Storage,
    action: Action,
    body: Value,
) -> Result<Value, AppError> {
    use Action::*;

    match action {
        // User Pool Actions
        CreateUserPool => user_pool::create_user_pool::handler(storage, body).await,
        DeleteUserPool => user_pool::delete_user_pool::handler(storage, body).await,
        DescribeUserPool => user_pool::describe_user_pool::handler(storage, body).await,
        ListUserPools => user_pool::list_user_pools::handler(storage, body).await,
        UpdateUserPool => user_pool::update_user_pool::handler(storage, body).await,

        // User Pool Client Actions
        CreateUserPoolClient => user_pool::create_user_pool_client::handler(storage, body).await,
        DeleteUserPoolClient => user_pool::delete_user_pool_client::handler(storage, body).await,
        DescribeUserPoolClient => {
            user_pool::describe_user_pool_client::handler(storage, body).await
        }
        ListUserPoolClients => user_pool::list_user_pool_clients::handler(storage, body).await,
        UpdateUserPoolClient => user_pool::update_user_pool_client::handler(storage, body).await,

        // User Pool Domain Actions
        CreateUserPoolDomain => user_pool::create_user_pool_domain::handler(storage, body).await,
        DeleteUserPoolDomain => user_pool::delete_user_pool_domain::handler(storage, body).await,
        DescribeUserPoolDomain => {
            user_pool::describe_user_pool_domain::handler(storage, body).await
        }
        UpdateUserPoolDomain => user_pool::update_user_pool_domain::handler(storage, body).await,

        // Managed Login Branding Actions
        CreateManagedLoginBranding => {
            user_pool::create_managed_login_branding::handler(storage, body).await
        }
        DeleteManagedLoginBranding => {
            user_pool::delete_managed_login_branding::handler(storage, body).await
        }
        DescribeManagedLoginBranding => {
            user_pool::describe_managed_login_branding::handler(storage, body).await
        }
        DescribeManagedLoginBrandingByClient => {
            user_pool::describe_managed_login_branding_by_client::handler(storage, body).await
        }
        UpdateManagedLoginBranding => {
            user_pool::update_managed_login_branding::handler(storage, body).await
        }

        // User Actions
        SignUp => user::sign_up::handler(storage, body).await,
        ConfirmSignUp => user::confirm_sign_up::handler(storage, body).await,
        ResendConfirmationCode => user::resend_confirmation_code::handler(storage, body).await,
        InitiateAuth => user::initiate_auth::handler(storage, body).await,
        RespondToAuthChallenge => user::respond_to_auth_challenge::handler(storage, body).await,
        GetUser => user::get_user::handler(storage, body).await,
        DeleteUser => user::delete_user::handler(storage, body).await,
        DeleteUserAttributes => user::delete_user_attributes::handler(storage, body).await,
        UpdateUserAttributes => user::update_user_attributes::handler(storage, body).await,
        ListUsers => user::list_users::handler(storage, body).await,
        ChangePassword => user::change_password::handler(storage, body).await,
        ForgotPassword => user::forgot_password::handler(storage, body).await,
        ConfirmForgotPassword => user::confirm_forgot_password::handler(storage, body).await,
        GlobalSignOut => user::global_sign_out::handler(storage, body).await,
        RevokeToken => user::revoke_token::handler(storage, body).await,
        GetUserAttributeVerificationCode => {
            user::get_user_attribute_verification_code::handler(storage, body).await
        }
        VerifyUserAttribute => user::verify_user_attribute::handler(storage, body).await,

        // Admin Actions
        AdminConfirmSignUp => user::admin_confirm_sign_up::handler(storage, body).await,
        AdminCreateUser => user::admin_create_user::handler(storage, body).await,
        AdminDeleteUser => user::admin_delete_user::handler(storage, body).await,
        AdminDeleteUserAttributes => {
            user::admin_delete_user_attributes::handler(storage, body).await
        }
        AdminDisableUser => user::admin_disable_user::handler(storage, body).await,
        AdminEnableUser => user::admin_enable_user::handler(storage, body).await,
        AdminGetUser => user::admin_get_user::handler(storage, body).await,
        AdminInitiateAuth => user::admin_initiate_auth::handler(storage, body).await,
        AdminResetUserPassword => user::admin_reset_user_password::handler(storage, body).await,
        AdminSetUserPassword => user::admin_set_user_password::handler(storage, body).await,
        AdminUpdateUserAttributes => {
            user::admin_update_user_attributes::handler(storage, body).await
        }
        AdminUserGlobalSignOut => user::admin_user_global_sign_out::handler(storage, body).await,
        AdminAddUserToGroup => group::admin_add_user_to_group::handler(storage, body).await,
        AdminRemoveUserFromGroup => {
            group::admin_remove_user_from_group::handler(storage, body).await
        }
        AdminListGroupsForUser => group::admin_list_groups_for_user::handler(storage, body).await,

        // Group Actions
        CreateGroup => group::create_group::handler(storage, body).await,
        DeleteGroup => group::delete_group::handler(storage, body).await,
        GetGroup => group::get_group::handler(storage, body).await,
        ListGroups => group::list_groups::handler(storage, body).await,
        ListUsersInGroup => group::list_users_in_group::handler(storage, body).await,
        UpdateGroup => group::update_group::handler(storage, body).await,

        // Other Actions
        AddCustomAttributes => user_pool::add_custom_attributes::handler(storage, body).await,
        GetSigningCertificate => user_pool::get_signing_certificate::handler(storage, body).await,

        // MFA Actions
        SetUserMFAPreference => user::set_user_mfa_preference::handler(storage, body).await,
        AdminSetUserMFAPreference => {
            user::admin_set_user_mfa_preference::handler(storage, body).await
        }
        GetUserPoolMfaConfig => user_pool::get_user_pool_mfa_config::handler(storage, body).await,
        SetUserPoolMfaConfig => user_pool::set_user_pool_mfa_config::handler(storage, body).await,

        // Not implemented operations
        op => {
            warn!("Operation not implemented: {:?}", op);
            Err(AppError::NotImplemented(format!("{:?}", op)))
        }
    }
}

use std::str::FromStr;

/// All Cognito Identity Provider operations
///
/// <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_Operations.html>
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Action {
    // Admin Actions
    AdminAddUserToGroup,
    AdminConfirmSignUp,
    AdminCreateUser,
    AdminDeleteUser,
    AdminDeleteUserAttributes,
    AdminDisableProviderForUser,
    AdminDisableUser,
    AdminEnableUser,
    AdminForgetDevice,
    AdminGetDevice,
    AdminGetUser,
    AdminInitiateAuth,
    AdminLinkProviderForUser,
    AdminListDevices,
    AdminListGroupsForUser,
    AdminListUserAuthEvents,
    AdminRemoveUserFromGroup,
    AdminResetUserPassword,
    AdminRespondToAuthChallenge,
    AdminSetUserMFAPreference,
    AdminSetUserPassword,
    AdminSetUserSettings,
    AdminUpdateAuthEventFeedback,
    AdminUpdateDeviceStatus,
    AdminUpdateUserAttributes,
    AdminUserGlobalSignOut,

    // User Pool Actions
    CreateUserPool,
    DeleteUserPool,
    DescribeUserPool,
    ListUserPools,
    UpdateUserPool,

    // User Pool Client Actions
    CreateUserPoolClient,
    DeleteUserPoolClient,
    DescribeUserPoolClient,
    ListUserPoolClients,
    UpdateUserPoolClient,

    // User Pool Domain Actions
    CreateUserPoolDomain,
    DeleteUserPoolDomain,
    DescribeUserPoolDomain,
    UpdateUserPoolDomain,

    // Managed Login Branding Actions
    CreateManagedLoginBranding,
    DeleteManagedLoginBranding,
    DescribeManagedLoginBranding,
    DescribeManagedLoginBrandingByClient,
    UpdateManagedLoginBranding,

    // User Actions
    DeleteUser,
    DeleteUserAttributes,
    GetUser,
    ListUsers,
    UpdateUserAttributes,
    VerifyUserAttribute,

    // Authentication Actions
    ChangePassword,
    ConfirmForgotPassword,
    ConfirmSignUp,
    ForgotPassword,
    GlobalSignOut,
    InitiateAuth,
    ResendConfirmationCode,
    RespondToAuthChallenge,
    RevokeToken,
    SignUp,
    GetUserAttributeVerificationCode,

    // MFA Actions
    AssociateSoftwareToken,
    SetUserMFAPreference,
    VerifySoftwareToken,
    GetUserPoolMfaConfig,
    SetUserPoolMfaConfig,
    SetUserSettings,
    GetUserAuthFactors,

    // Device Actions
    ConfirmDevice,
    ForgetDevice,
    GetDevice,
    ListDevices,

    // Group Actions
    CreateGroup,
    DeleteGroup,
    GetGroup,
    ListGroups,
    ListUsersInGroup,
    UpdateGroup,

    // Identity Provider Actions
    CreateIdentityProvider,
    DeleteIdentityProvider,
    DescribeIdentityProvider,
    GetIdentityProviderByIdentifier,
    ListIdentityProviders,
    UpdateIdentityProvider,

    // Resource Server Actions
    CreateResourceServer,
    DeleteResourceServer,
    DescribeResourceServer,
    ListResourceServers,
    UpdateResourceServer,

    // User Import Actions
    CreateUserImportJob,
    DescribeUserImportJob,
    GetCSVHeader,
    ListUserImportJobs,
    StartUserImportJob,
    StopUserImportJob,

    // WebAuthn Actions
    CompleteWebAuthnRegistration,
    DeleteWebAuthnCredential,
    ListWebAuthnCredentials,
    StartWebAuthnRegistration,

    // Risk Configuration Actions
    DescribeRiskConfiguration,
    SetRiskConfiguration,

    // UI Customization Actions
    GetUICustomization,
    SetUICustomization,

    // Log Configuration Actions
    GetLogDeliveryConfiguration,
    SetLogDeliveryConfiguration,

    // Tagging Actions
    ListTagsForResource,
    TagResource,
    UntagResource,

    // Other Actions
    AddCustomAttributes,
    GetSigningCertificate,
    UpdateAuthEventFeedback,
    UpdateDeviceStatus,
}

impl Action {
    /// Returns true if this operation is implemented
    pub const fn is_implemented(&self) -> bool {
        matches!(
            self,
            // User Pool Actions
            Self::CreateUserPool
                | Self::DeleteUserPool
                | Self::DescribeUserPool
                | Self::ListUserPools
                | Self::UpdateUserPool
                // User Pool Client Actions
                | Self::CreateUserPoolClient
                | Self::DeleteUserPoolClient
                | Self::DescribeUserPoolClient
                | Self::ListUserPoolClients
                | Self::UpdateUserPoolClient
                // User Pool Domain Actions
                | Self::CreateUserPoolDomain
                | Self::DeleteUserPoolDomain
                | Self::DescribeUserPoolDomain
                | Self::UpdateUserPoolDomain
                // Managed Login Branding Actions
                | Self::CreateManagedLoginBranding
                | Self::DeleteManagedLoginBranding
                | Self::DescribeManagedLoginBranding
                | Self::DescribeManagedLoginBrandingByClient
                | Self::UpdateManagedLoginBranding
                // User Actions
                | Self::SignUp
                | Self::ConfirmSignUp
                | Self::ResendConfirmationCode
                | Self::InitiateAuth
                | Self::RespondToAuthChallenge
                | Self::GetUser
                | Self::DeleteUser
                | Self::DeleteUserAttributes
                | Self::UpdateUserAttributes
                | Self::ListUsers
                | Self::ChangePassword
                | Self::ForgotPassword
                | Self::ConfirmForgotPassword
                | Self::GlobalSignOut
                | Self::RevokeToken
                | Self::GetUserAttributeVerificationCode
                | Self::VerifyUserAttribute
                // Admin Actions
                | Self::AdminConfirmSignUp
                | Self::AdminCreateUser
                | Self::AdminDeleteUser
                | Self::AdminDeleteUserAttributes
                | Self::AdminDisableUser
                | Self::AdminEnableUser
                | Self::AdminGetUser
                | Self::AdminInitiateAuth
                | Self::AdminResetUserPassword
                | Self::AdminSetUserPassword
                | Self::AdminUpdateUserAttributes
                | Self::AdminUserGlobalSignOut
                | Self::AdminAddUserToGroup
                | Self::AdminRemoveUserFromGroup
                | Self::AdminListGroupsForUser
                // Group Actions
                | Self::CreateGroup
                | Self::DeleteGroup
                | Self::GetGroup
                | Self::ListGroups
                | Self::ListUsersInGroup
                | Self::UpdateGroup
                // Other Actions
                | Self::AddCustomAttributes
                | Self::GetSigningCertificate
                // MFA Actions
                | Self::SetUserMFAPreference
                | Self::AdminSetUserMFAPreference
                | Self::GetUserPoolMfaConfig
                | Self::SetUserPoolMfaConfig
        )
    }

    /// Returns the AWS documentation URL for this operation
    pub fn doc_url(&self) -> String {
        format!(
            "https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_{:?}.html",
            self
        )
    }
}

#[derive(Debug, Clone)]
pub struct UnknownAction(pub String);

impl FromStr for Action {
    type Err = UnknownAction;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            // Admin Actions
            "AdminAddUserToGroup" => Ok(Self::AdminAddUserToGroup),
            "AdminConfirmSignUp" => Ok(Self::AdminConfirmSignUp),
            "AdminCreateUser" => Ok(Self::AdminCreateUser),
            "AdminDeleteUser" => Ok(Self::AdminDeleteUser),
            "AdminDeleteUserAttributes" => Ok(Self::AdminDeleteUserAttributes),
            "AdminDisableProviderForUser" => Ok(Self::AdminDisableProviderForUser),
            "AdminDisableUser" => Ok(Self::AdminDisableUser),
            "AdminEnableUser" => Ok(Self::AdminEnableUser),
            "AdminForgetDevice" => Ok(Self::AdminForgetDevice),
            "AdminGetDevice" => Ok(Self::AdminGetDevice),
            "AdminGetUser" => Ok(Self::AdminGetUser),
            "AdminInitiateAuth" => Ok(Self::AdminInitiateAuth),
            "AdminLinkProviderForUser" => Ok(Self::AdminLinkProviderForUser),
            "AdminListDevices" => Ok(Self::AdminListDevices),
            "AdminListGroupsForUser" => Ok(Self::AdminListGroupsForUser),
            "AdminListUserAuthEvents" => Ok(Self::AdminListUserAuthEvents),
            "AdminRemoveUserFromGroup" => Ok(Self::AdminRemoveUserFromGroup),
            "AdminResetUserPassword" => Ok(Self::AdminResetUserPassword),
            "AdminRespondToAuthChallenge" => Ok(Self::AdminRespondToAuthChallenge),
            "AdminSetUserMFAPreference" => Ok(Self::AdminSetUserMFAPreference),
            "AdminSetUserPassword" => Ok(Self::AdminSetUserPassword),
            "AdminSetUserSettings" => Ok(Self::AdminSetUserSettings),
            "AdminUpdateAuthEventFeedback" => Ok(Self::AdminUpdateAuthEventFeedback),
            "AdminUpdateDeviceStatus" => Ok(Self::AdminUpdateDeviceStatus),
            "AdminUpdateUserAttributes" => Ok(Self::AdminUpdateUserAttributes),
            "AdminUserGlobalSignOut" => Ok(Self::AdminUserGlobalSignOut),

            // User Pool Actions
            "CreateUserPool" => Ok(Self::CreateUserPool),
            "DeleteUserPool" => Ok(Self::DeleteUserPool),
            "DescribeUserPool" => Ok(Self::DescribeUserPool),
            "ListUserPools" => Ok(Self::ListUserPools),
            "UpdateUserPool" => Ok(Self::UpdateUserPool),

            // User Pool Client Actions
            "CreateUserPoolClient" => Ok(Self::CreateUserPoolClient),
            "DeleteUserPoolClient" => Ok(Self::DeleteUserPoolClient),
            "DescribeUserPoolClient" => Ok(Self::DescribeUserPoolClient),
            "ListUserPoolClients" => Ok(Self::ListUserPoolClients),
            "UpdateUserPoolClient" => Ok(Self::UpdateUserPoolClient),

            // User Pool Domain Actions
            "CreateUserPoolDomain" => Ok(Self::CreateUserPoolDomain),
            "DeleteUserPoolDomain" => Ok(Self::DeleteUserPoolDomain),
            "DescribeUserPoolDomain" => Ok(Self::DescribeUserPoolDomain),
            "UpdateUserPoolDomain" => Ok(Self::UpdateUserPoolDomain),

            // Managed Login Branding Actions
            "CreateManagedLoginBranding" => Ok(Self::CreateManagedLoginBranding),
            "DeleteManagedLoginBranding" => Ok(Self::DeleteManagedLoginBranding),
            "DescribeManagedLoginBranding" => Ok(Self::DescribeManagedLoginBranding),
            "DescribeManagedLoginBrandingByClient" => {
                Ok(Self::DescribeManagedLoginBrandingByClient)
            }
            "UpdateManagedLoginBranding" => Ok(Self::UpdateManagedLoginBranding),

            // User Actions
            "DeleteUser" => Ok(Self::DeleteUser),
            "DeleteUserAttributes" => Ok(Self::DeleteUserAttributes),
            "GetUser" => Ok(Self::GetUser),
            "ListUsers" => Ok(Self::ListUsers),
            "UpdateUserAttributes" => Ok(Self::UpdateUserAttributes),
            "VerifyUserAttribute" => Ok(Self::VerifyUserAttribute),

            // Authentication Actions
            "ChangePassword" => Ok(Self::ChangePassword),
            "ConfirmForgotPassword" => Ok(Self::ConfirmForgotPassword),
            "ConfirmSignUp" => Ok(Self::ConfirmSignUp),
            "ForgotPassword" => Ok(Self::ForgotPassword),
            "GlobalSignOut" => Ok(Self::GlobalSignOut),
            "InitiateAuth" => Ok(Self::InitiateAuth),
            "ResendConfirmationCode" => Ok(Self::ResendConfirmationCode),
            "RespondToAuthChallenge" => Ok(Self::RespondToAuthChallenge),
            "RevokeToken" => Ok(Self::RevokeToken),
            "SignUp" => Ok(Self::SignUp),
            "GetUserAttributeVerificationCode" => Ok(Self::GetUserAttributeVerificationCode),

            // MFA Actions
            "AssociateSoftwareToken" => Ok(Self::AssociateSoftwareToken),
            "SetUserMFAPreference" => Ok(Self::SetUserMFAPreference),
            "VerifySoftwareToken" => Ok(Self::VerifySoftwareToken),
            "GetUserPoolMfaConfig" => Ok(Self::GetUserPoolMfaConfig),
            "SetUserPoolMfaConfig" => Ok(Self::SetUserPoolMfaConfig),
            "SetUserSettings" => Ok(Self::SetUserSettings),
            "GetUserAuthFactors" => Ok(Self::GetUserAuthFactors),

            // Device Actions
            "ConfirmDevice" => Ok(Self::ConfirmDevice),
            "ForgetDevice" => Ok(Self::ForgetDevice),
            "GetDevice" => Ok(Self::GetDevice),
            "ListDevices" => Ok(Self::ListDevices),

            // Group Actions
            "CreateGroup" => Ok(Self::CreateGroup),
            "DeleteGroup" => Ok(Self::DeleteGroup),
            "GetGroup" => Ok(Self::GetGroup),
            "ListGroups" => Ok(Self::ListGroups),
            "ListUsersInGroup" => Ok(Self::ListUsersInGroup),
            "UpdateGroup" => Ok(Self::UpdateGroup),

            // Identity Provider Actions
            "CreateIdentityProvider" => Ok(Self::CreateIdentityProvider),
            "DeleteIdentityProvider" => Ok(Self::DeleteIdentityProvider),
            "DescribeIdentityProvider" => Ok(Self::DescribeIdentityProvider),
            "GetIdentityProviderByIdentifier" => Ok(Self::GetIdentityProviderByIdentifier),
            "ListIdentityProviders" => Ok(Self::ListIdentityProviders),
            "UpdateIdentityProvider" => Ok(Self::UpdateIdentityProvider),

            // Resource Server Actions
            "CreateResourceServer" => Ok(Self::CreateResourceServer),
            "DeleteResourceServer" => Ok(Self::DeleteResourceServer),
            "DescribeResourceServer" => Ok(Self::DescribeResourceServer),
            "ListResourceServers" => Ok(Self::ListResourceServers),
            "UpdateResourceServer" => Ok(Self::UpdateResourceServer),

            // User Import Actions
            "CreateUserImportJob" => Ok(Self::CreateUserImportJob),
            "DescribeUserImportJob" => Ok(Self::DescribeUserImportJob),
            "GetCSVHeader" => Ok(Self::GetCSVHeader),
            "ListUserImportJobs" => Ok(Self::ListUserImportJobs),
            "StartUserImportJob" => Ok(Self::StartUserImportJob),
            "StopUserImportJob" => Ok(Self::StopUserImportJob),

            // WebAuthn Actions
            "CompleteWebAuthnRegistration" => Ok(Self::CompleteWebAuthnRegistration),
            "DeleteWebAuthnCredential" => Ok(Self::DeleteWebAuthnCredential),
            "ListWebAuthnCredentials" => Ok(Self::ListWebAuthnCredentials),
            "StartWebAuthnRegistration" => Ok(Self::StartWebAuthnRegistration),

            // Risk Configuration Actions
            "DescribeRiskConfiguration" => Ok(Self::DescribeRiskConfiguration),
            "SetRiskConfiguration" => Ok(Self::SetRiskConfiguration),

            // UI Customization Actions
            "GetUICustomization" => Ok(Self::GetUICustomization),
            "SetUICustomization" => Ok(Self::SetUICustomization),

            // Log Configuration Actions
            "GetLogDeliveryConfiguration" => Ok(Self::GetLogDeliveryConfiguration),
            "SetLogDeliveryConfiguration" => Ok(Self::SetLogDeliveryConfiguration),

            // Tagging Actions
            "ListTagsForResource" => Ok(Self::ListTagsForResource),
            "TagResource" => Ok(Self::TagResource),
            "UntagResource" => Ok(Self::UntagResource),

            // Other Actions
            "AddCustomAttributes" => Ok(Self::AddCustomAttributes),
            "GetSigningCertificate" => Ok(Self::GetSigningCertificate),
            "UpdateAuthEventFeedback" => Ok(Self::UpdateAuthEventFeedback),
            "UpdateDeviceStatus" => Ok(Self::UpdateDeviceStatus),

            _ => Err(UnknownAction(s.to_string())),
        }
    }
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
        assert!(!Action::AdminForgetDevice.is_implemented());
    }

    #[test]
    fn test_doc_url() {
        assert_eq!(
            Action::SignUp.doc_url(),
            "https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_SignUp.html"
        );
    }
}
