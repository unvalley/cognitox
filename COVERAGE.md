# Coverage

Based on [Amazon Cognito User Pools API Reference](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_Operations.html)

## cognito-idp

100% implemented (119/119)

### Admin Operations
- [x] AdminAddUserToGroup ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AdminAddUserToGroup.html), [cognitox](src/action/group/admin_add_user_to_group.rs))
- [x] AdminConfirmSignUp ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AdminConfirmSignUp.html), [cognitox](src/action/user/admin_confirm_sign_up.rs))
- [x] AdminCreateUser ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AdminCreateUser.html), [cognitox](src/action/user/admin_create_user.rs))
- [x] AdminDeleteUser ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AdminDeleteUser.html), [cognitox](src/action/user/admin_delete_user.rs))
- [x] AdminDeleteUserAttributes ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AdminDeleteUserAttributes.html), [cognitox](src/action/user/admin_delete_user_attributes.rs))
- [x] AdminDisableProviderForUser ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AdminDisableProviderForUser.html), [cognitox](src/action/user/admin_disable_provider_for_user.rs))
- [x] AdminDisableUser ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AdminDisableUser.html), [cognitox](src/action/user/admin_disable_user.rs))
- [x] AdminEnableUser ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AdminEnableUser.html), [cognitox](src/action/user/admin_enable_user.rs))
- [x] AdminForgetDevice ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AdminForgetDevice.html), [cognitox](src/action/user/admin_forget_device.rs))
- [x] AdminGetDevice ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AdminGetDevice.html), [cognitox](src/action/user/admin_get_device.rs))
- [x] AdminGetUser ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AdminGetUser.html), [cognitox](src/action/user/admin_get_user.rs))
- [x] AdminInitiateAuth ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AdminInitiateAuth.html), [cognitox](src/action/user/admin_initiate_auth.rs))
- [x] AdminLinkProviderForUser ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AdminLinkProviderForUser.html), [cognitox](src/action/user/admin_link_provider_for_user.rs))
- [x] AdminListDevices ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AdminListDevices.html), [cognitox](src/action/user/admin_list_devices.rs))
- [x] AdminListGroupsForUser ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AdminListGroupsForUser.html), [cognitox](src/action/group/admin_list_groups_for_user.rs))
- [x] AdminListUserAuthEvents ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AdminListUserAuthEvents.html), [cognitox](src/action/user/admin_list_user_auth_events.rs))
- [x] AdminRemoveUserFromGroup ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AdminRemoveUserFromGroup.html), [cognitox](src/action/group/admin_remove_user_from_group.rs))
- [x] AdminResetUserPassword ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AdminResetUserPassword.html), [cognitox](src/action/user/admin_reset_user_password.rs))
- [x] AdminRespondToAuthChallenge ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AdminRespondToAuthChallenge.html), [cognitox](src/action/user/admin_respond_to_auth_challenge.rs))
- [x] AdminSetUserMFAPreference ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AdminSetUserMFAPreference.html), [cognitox](src/action/user/admin_set_user_mfa_preference.rs))
- [x] AdminSetUserPassword ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AdminSetUserPassword.html), [cognitox](src/action/user/admin_set_user_password.rs))
- [x] AdminSetUserSettings ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AdminSetUserSettings.html), [cognitox](src/action/user/admin_set_user_settings.rs))
- [x] AdminUpdateAuthEventFeedback ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AdminUpdateAuthEventFeedback.html), [cognitox](src/action/user/admin_update_auth_event_feedback.rs))
- [x] AdminUpdateDeviceStatus ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AdminUpdateDeviceStatus.html), [cognitox](src/action/user/admin_update_device_status.rs))
- [x] AdminUpdateUserAttributes ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AdminUpdateUserAttributes.html), [cognitox](src/action/user/admin_update_user_attributes.rs))
- [x] AdminUserGlobalSignOut ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AdminUserGlobalSignOut.html), [cognitox](src/action/user/admin_user_global_sign_out.rs))

### User Pool Operations
- [x] CreateUserPool ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_CreateUserPool.html), [cognitox](src/action/user_pool/create_user_pool.rs))
- [x] DeleteUserPool ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_DeleteUserPool.html), [cognitox](src/action/user_pool/delete_user_pool.rs))
- [x] DescribeUserPool ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_DescribeUserPool.html), [cognitox](src/action/user_pool/describe_user_pool.rs))
- [x] ListUserPools ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_ListUserPools.html), [cognitox](src/action/user_pool/list_user_pools.rs))
- [x] UpdateUserPool ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_UpdateUserPool.html), [cognitox](src/action/user_pool/update_user_pool.rs))

### User Pool Client Operations
- [x] CreateUserPoolClient ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_CreateUserPoolClient.html), [cognitox](src/action/user_pool/create_user_pool_client.rs))
- [x] DeleteUserPoolClient ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_DeleteUserPoolClient.html), [cognitox](src/action/user_pool/delete_user_pool_client.rs))
- [x] DescribeUserPoolClient ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_DescribeUserPoolClient.html), [cognitox](src/action/user_pool/describe_user_pool_client.rs))
- [x] ListUserPoolClients ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_ListUserPoolClients.html), [cognitox](src/action/user_pool/list_user_pool_clients.rs))
- [x] UpdateUserPoolClient ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_UpdateUserPoolClient.html), [cognitox](src/action/user_pool/update_user_pool_client.rs))

### User Pool Domain Operations
- [x] CreateUserPoolDomain ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_CreateUserPoolDomain.html), [cognitox](src/action/user_pool/create_user_pool_domain.rs))
- [x] DeleteUserPoolDomain ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_DeleteUserPoolDomain.html), [cognitox](src/action/user_pool/delete_user_pool_domain.rs))
- [x] DescribeUserPoolDomain ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_DescribeUserPoolDomain.html), [cognitox](src/action/user_pool/describe_user_pool_domain.rs))
- [x] UpdateUserPoolDomain ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_UpdateUserPoolDomain.html), [cognitox](src/action/user_pool/update_user_pool_domain.rs))

### User Operations
- [x] DeleteUser ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_DeleteUser.html), [cognitox](src/action/user/delete_user.rs))
- [x] DeleteUserAttributes ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_DeleteUserAttributes.html), [cognitox](src/action/user/delete_user_attributes.rs))
- [x] GetUser ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_GetUser.html), [cognitox](src/action/user/get_user.rs))
- [x] ListUsers ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_ListUsers.html), [cognitox](src/action/user/list_users.rs))
- [x] UpdateUserAttributes ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_UpdateUserAttributes.html), [cognitox](src/action/user/update_user_attributes.rs))
- [x] VerifyUserAttribute ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_VerifyUserAttribute.html), [cognitox](src/action/user/verify_user_attribute.rs))

### Authentication Operations
- [x] ChangePassword ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_ChangePassword.html), [cognitox](src/action/user/change_password.rs))
- [x] ConfirmForgotPassword ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_ConfirmForgotPassword.html), [cognitox](src/action/user/confirm_forgot_password.rs))
- [x] ConfirmSignUp ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_ConfirmSignUp.html), [cognitox](src/action/user/confirm_sign_up.rs))
- [x] ForgotPassword ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_ForgotPassword.html), [cognitox](src/action/user/forgot_password.rs))
- [x] GlobalSignOut ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_GlobalSignOut.html), [cognitox](src/action/user/global_sign_out.rs))
- [x] InitiateAuth ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_InitiateAuth.html), [cognitox](src/action/user/initiate_auth.rs))
- [x] ResendConfirmationCode ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_ResendConfirmationCode.html), [cognitox](src/action/user/resend_confirmation_code.rs))
- [x] RespondToAuthChallenge ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_RespondToAuthChallenge.html), [cognitox](src/action/user/respond_to_auth_challenge.rs))
- [x] RevokeToken ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_RevokeToken.html), [cognitox](src/action/user/revoke_token.rs))
- [x] SignUp ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_SignUp.html), [cognitox](src/action/user/sign_up.rs))
- [x] GetUserAttributeVerificationCode ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_GetUserAttributeVerificationCode.html), [cognitox](src/action/user/get_user_attribute_verification_code.rs))

### MFA Operations
- [x] AssociateSoftwareToken ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AssociateSoftwareToken.html), [cognitox](src/action/user/associate_software_token.rs))
- [x] SetUserMFAPreference ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_SetUserMFAPreference.html), [cognitox](src/action/user/set_user_mfa_preference.rs))
- [x] VerifySoftwareToken ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_VerifySoftwareToken.html), [cognitox](src/action/user/verify_software_token.rs))
- [x] GetUserPoolMfaConfig ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_GetUserPoolMfaConfig.html), [cognitox](src/action/user_pool/get_user_pool_mfa_config.rs))
- [x] SetUserPoolMfaConfig ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_SetUserPoolMfaConfig.html), [cognitox](src/action/user_pool/set_user_pool_mfa_config.rs))
- [x] SetUserSettings ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_SetUserSettings.html), [cognitox](src/action/user/set_user_settings.rs))
- [x] GetUserAuthFactors ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_GetUserAuthFactors.html), [cognitox](src/action/user/get_user_auth_factors.rs))

### Device Operations
- [x] ConfirmDevice ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_ConfirmDevice.html), [cognitox](src/action/user/confirm_device.rs))
- [x] ForgetDevice ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_ForgetDevice.html), [cognitox](src/action/user/forget_device.rs))
- [x] GetDevice ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_GetDevice.html), [cognitox](src/action/user/get_device.rs))
- [x] ListDevices ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_ListDevices.html), [cognitox](src/action/user/list_devices.rs))

### Group Operations
- [x] CreateGroup ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_CreateGroup.html), [cognitox](src/action/group/create_group.rs))
- [x] DeleteGroup ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_DeleteGroup.html), [cognitox](src/action/group/delete_group.rs))
- [x] GetGroup ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_GetGroup.html), [cognitox](src/action/group/get_group.rs))
- [x] ListGroups ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_ListGroups.html), [cognitox](src/action/group/list_groups.rs))
- [x] ListUsersInGroup ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_ListUsersInGroup.html), [cognitox](src/action/group/list_users_in_group.rs))
- [x] UpdateGroup ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_UpdateGroup.html), [cognitox](src/action/group/update_group.rs))

### Identity Provider Operations
- [x] CreateIdentityProvider ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_CreateIdentityProvider.html), [cognitox](src/action/user_pool/create_identity_provider.rs))
- [x] DeleteIdentityProvider ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_DeleteIdentityProvider.html), [cognitox](src/action/user_pool/delete_identity_provider.rs))
- [x] DescribeIdentityProvider ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_DescribeIdentityProvider.html), [cognitox](src/action/user_pool/describe_identity_provider.rs))
- [x] GetIdentityProviderByIdentifier ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_GetIdentityProviderByIdentifier.html), [cognitox](src/action/user_pool/get_identity_provider_by_identifier.rs))
- [x] ListIdentityProviders ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_ListIdentityProviders.html), [cognitox](src/action/user_pool/list_identity_providers.rs))
- [x] UpdateIdentityProvider ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_UpdateIdentityProvider.html), [cognitox](src/action/user_pool/update_identity_provider.rs))

### Resource Server Operations
- [x] CreateResourceServer ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_CreateResourceServer.html), [cognitox](src/action/user_pool/create_resource_server.rs))
- [x] DeleteResourceServer ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_DeleteResourceServer.html), [cognitox](src/action/user_pool/delete_resource_server.rs))
- [x] DescribeResourceServer ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_DescribeResourceServer.html), [cognitox](src/action/user_pool/describe_resource_server.rs))
- [x] ListResourceServers ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_ListResourceServers.html), [cognitox](src/action/user_pool/list_resource_servers.rs))
- [x] UpdateResourceServer ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_UpdateResourceServer.html), [cognitox](src/action/user_pool/update_resource_server.rs))

### User Import Operations
- [x] CreateUserImportJob ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_CreateUserImportJob.html), [cognitox](src/action/user_pool/create_user_import_job.rs))
- [x] DescribeUserImportJob ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_DescribeUserImportJob.html), [cognitox](src/action/user_pool/describe_user_import_job.rs))
- [x] GetCSVHeader ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_GetCSVHeader.html), [cognitox](src/action/user_pool/get_csv_header.rs))
- [x] ListUserImportJobs ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_ListUserImportJobs.html), [cognitox](src/action/user_pool/list_user_import_jobs.rs))
- [x] StartUserImportJob ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_StartUserImportJob.html), [cognitox](src/action/user_pool/start_user_import_job.rs))
- [x] StopUserImportJob ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_StopUserImportJob.html), [cognitox](src/action/user_pool/stop_user_import_job.rs))

### WebAuthn Operations
- [x] CompleteWebAuthnRegistration ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_CompleteWebAuthnRegistration.html), [cognitox](src/action/user/complete_webauthn_registration.rs))
- [x] DeleteWebAuthnCredential ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_DeleteWebAuthnCredential.html), [cognitox](src/action/user/delete_webauthn_credential.rs))
- [x] ListWebAuthnCredentials ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_ListWebAuthnCredentials.html), [cognitox](src/action/user/list_webauthn_credentials.rs))
- [x] StartWebAuthnRegistration ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_StartWebAuthnRegistration.html), [cognitox](src/action/user/start_webauthn_registration.rs))

### Managed Login Branding Operations
- [x] CreateManagedLoginBranding ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_CreateManagedLoginBranding.html), [cognitox](src/action/user_pool/create_managed_login_branding.rs))
- [x] DeleteManagedLoginBranding ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_DeleteManagedLoginBranding.html), [cognitox](src/action/user_pool/delete_managed_login_branding.rs))
- [x] DescribeManagedLoginBranding ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_DescribeManagedLoginBranding.html), [cognitox](src/action/user_pool/describe_managed_login_branding.rs))
- [x] DescribeManagedLoginBrandingByClient ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_DescribeManagedLoginBrandingByClient.html), [cognitox](src/action/user_pool/describe_managed_login_branding_by_client.rs))
- [x] UpdateManagedLoginBranding ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_UpdateManagedLoginBranding.html), [cognitox](src/action/user_pool/update_managed_login_branding.rs))

### Terms Operations
- [x] CreateTerms ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_CreateTerms.html), [cognitox](src/action/user_pool/create_terms.rs))
- [x] DeleteTerms ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_DeleteTerms.html), [cognitox](src/action/user_pool/delete_terms.rs))
- [x] DescribeTerms ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_DescribeTerms.html), [cognitox](src/action/user_pool/describe_terms.rs))
- [x] ListTerms ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_ListTerms.html), [cognitox](src/action/user_pool/list_terms.rs))
- [x] UpdateTerms ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_UpdateTerms.html), [cognitox](src/action/user_pool/update_terms.rs))

### Risk Configuration Operations
- [x] DescribeRiskConfiguration ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_DescribeRiskConfiguration.html), [cognitox](src/action/user_pool/describe_risk_configuration.rs))
- [x] SetRiskConfiguration ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_SetRiskConfiguration.html), [cognitox](src/action/user_pool/set_risk_configuration.rs))

### UI Customization Operations
- [x] GetUICustomization ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_GetUICustomization.html), [cognitox](src/action/user_pool/get_ui_customization.rs))
- [x] SetUICustomization ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_SetUICustomization.html), [cognitox](src/action/user_pool/set_ui_customization.rs))

### Log Configuration Operations
- [x] GetLogDeliveryConfiguration ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_GetLogDeliveryConfiguration.html), [cognitox](src/action/user_pool/get_log_delivery_configuration.rs))
- [x] SetLogDeliveryConfiguration ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_SetLogDeliveryConfiguration.html), [cognitox](src/action/user_pool/set_log_delivery_configuration.rs))

### Token Operations
- [x] GetTokensFromRefreshToken ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_GetTokensFromRefreshToken.html), [cognitox](src/action/user/get_tokens_from_refresh_token.rs))

### Tagging Operations
- [x] ListTagsForResource ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_ListTagsForResource.html), [cognitox](src/action/user_pool/list_tags_for_resource.rs))
- [x] TagResource ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_TagResource.html), [cognitox](src/action/user_pool/tag_resource.rs))
- [x] UntagResource ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_UntagResource.html), [cognitox](src/action/user_pool/untag_resource.rs))

### Other Operations
- [x] AddCustomAttributes ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AddCustomAttributes.html), [cognitox](src/action/user_pool/add_custom_attributes.rs))
- [x] GetSigningCertificate ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_GetSigningCertificate.html), [cognitox](src/action/user_pool/get_signing_certificate.rs))
- [x] UpdateAuthEventFeedback ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_UpdateAuthEventFeedback.html), [cognitox](src/action/user/update_auth_event_feedback.rs))
- [x] UpdateDeviceStatus ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_UpdateDeviceStatus.html), [cognitox](src/action/user/update_device_status.rs))
