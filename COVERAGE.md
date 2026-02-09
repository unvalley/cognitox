# Coverage

Based on [Amazon Cognito User Pools API Reference](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_Operations.html)

## cognito-idp

46% implemented (55/119)

### Admin Operations
- [x] AdminAddUserToGroup ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AdminAddUserToGroup.html), [cognitox](src/action/group/admin_add_user_to_group.rs))
- [x] AdminConfirmSignUp ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AdminConfirmSignUp.html), [cognitox](src/action/user/admin_confirm_sign_up.rs))
- [x] AdminCreateUser ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AdminCreateUser.html), [cognitox](src/action/user/admin_create_user.rs))
- [x] AdminDeleteUser ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AdminDeleteUser.html), [cognitox](src/action/user/admin_delete_user.rs))
- [x] AdminDeleteUserAttributes ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AdminDeleteUserAttributes.html), [cognitox](src/action/user/admin_delete_user_attributes.rs))
- [ ] AdminDisableProviderForUser ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AdminDisableProviderForUser.html))
- [x] AdminDisableUser ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AdminDisableUser.html), [cognitox](src/action/user/admin_disable_user.rs))
- [x] AdminEnableUser ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AdminEnableUser.html), [cognitox](src/action/user/admin_enable_user.rs))
- [ ] AdminForgetDevice ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AdminForgetDevice.html))
- [ ] AdminGetDevice ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AdminGetDevice.html))
- [x] AdminGetUser ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AdminGetUser.html), [cognitox](src/action/user/admin_get_user.rs))
- [x] AdminInitiateAuth ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AdminInitiateAuth.html), [cognitox](src/action/user/admin_initiate_auth.rs))
- [ ] AdminLinkProviderForUser ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AdminLinkProviderForUser.html))
- [ ] AdminListDevices ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AdminListDevices.html))
- [x] AdminListGroupsForUser ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AdminListGroupsForUser.html), [cognitox](src/action/group/admin_list_groups_for_user.rs))
- [ ] AdminListUserAuthEvents ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AdminListUserAuthEvents.html))
- [x] AdminRemoveUserFromGroup ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AdminRemoveUserFromGroup.html), [cognitox](src/action/group/admin_remove_user_from_group.rs))
- [x] AdminResetUserPassword ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AdminResetUserPassword.html), [cognitox](src/action/user/admin_reset_user_password.rs))
- [ ] AdminRespondToAuthChallenge ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AdminRespondToAuthChallenge.html))
- [ ] AdminSetUserMFAPreference ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AdminSetUserMFAPreference.html))
- [x] AdminSetUserPassword ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AdminSetUserPassword.html), [cognitox](src/action/user/admin_set_user_password.rs))
- [ ] AdminSetUserSettings ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AdminSetUserSettings.html))
- [ ] AdminUpdateAuthEventFeedback ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AdminUpdateAuthEventFeedback.html))
- [ ] AdminUpdateDeviceStatus ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AdminUpdateDeviceStatus.html))
- [x] AdminUpdateUserAttributes ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AdminUpdateUserAttributes.html), [cognitox](src/action/user/admin_update_user_attributes.rs))
- [ ] AdminUserGlobalSignOut ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AdminUserGlobalSignOut.html))

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
- [ ] DeleteUserAttributes ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_DeleteUserAttributes.html))
- [x] GetUser ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_GetUser.html), [cognitox](src/action/user/get_user.rs))
- [x] ListUsers ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_ListUsers.html), [cognitox](src/action/user/list_users.rs))
- [x] UpdateUserAttributes ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_UpdateUserAttributes.html), [cognitox](src/action/user/update_user_attributes.rs))
- [ ] VerifyUserAttribute ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_VerifyUserAttribute.html))

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
- [ ] GetUserAttributeVerificationCode ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_GetUserAttributeVerificationCode.html))

### MFA Operations
- [ ] AssociateSoftwareToken ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AssociateSoftwareToken.html))
- [ ] SetUserMFAPreference ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_SetUserMFAPreference.html))
- [ ] VerifySoftwareToken ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_VerifySoftwareToken.html))
- [ ] GetUserPoolMfaConfig ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_GetUserPoolMfaConfig.html))
- [ ] SetUserPoolMfaConfig ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_SetUserPoolMfaConfig.html))
- [ ] SetUserSettings ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_SetUserSettings.html))
- [ ] GetUserAuthFactors ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_GetUserAuthFactors.html))

### Device Operations
- [ ] ConfirmDevice ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_ConfirmDevice.html))
- [ ] ForgetDevice ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_ForgetDevice.html))
- [ ] GetDevice ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_GetDevice.html))
- [ ] ListDevices ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_ListDevices.html))

### Group Operations
- [x] CreateGroup ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_CreateGroup.html), [cognitox](src/action/group/create_group.rs))
- [x] DeleteGroup ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_DeleteGroup.html), [cognitox](src/action/group/delete_group.rs))
- [x] GetGroup ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_GetGroup.html), [cognitox](src/action/group/get_group.rs))
- [x] ListGroups ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_ListGroups.html), [cognitox](src/action/group/list_groups.rs))
- [x] ListUsersInGroup ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_ListUsersInGroup.html), [cognitox](src/action/group/list_users_in_group.rs))
- [x] UpdateGroup ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_UpdateGroup.html), [cognitox](src/action/group/update_group.rs))

### Identity Provider Operations
- [ ] CreateIdentityProvider ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_CreateIdentityProvider.html))
- [ ] DeleteIdentityProvider ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_DeleteIdentityProvider.html))
- [ ] DescribeIdentityProvider ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_DescribeIdentityProvider.html))
- [ ] GetIdentityProviderByIdentifier ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_GetIdentityProviderByIdentifier.html))
- [ ] ListIdentityProviders ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_ListIdentityProviders.html))
- [ ] UpdateIdentityProvider ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_UpdateIdentityProvider.html))

### Resource Server Operations
- [ ] CreateResourceServer ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_CreateResourceServer.html))
- [ ] DeleteResourceServer ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_DeleteResourceServer.html))
- [ ] DescribeResourceServer ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_DescribeResourceServer.html))
- [ ] ListResourceServers ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_ListResourceServers.html))
- [ ] UpdateResourceServer ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_UpdateResourceServer.html))

### User Import Operations
- [ ] CreateUserImportJob ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_CreateUserImportJob.html))
- [ ] DescribeUserImportJob ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_DescribeUserImportJob.html))
- [ ] GetCSVHeader ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_GetCSVHeader.html))
- [ ] ListUserImportJobs ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_ListUserImportJobs.html))
- [ ] StartUserImportJob ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_StartUserImportJob.html))
- [ ] StopUserImportJob ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_StopUserImportJob.html))

### WebAuthn Operations
- [ ] CompleteWebAuthnRegistration ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_CompleteWebAuthnRegistration.html))
- [ ] DeleteWebAuthnCredential ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_DeleteWebAuthnCredential.html))
- [ ] ListWebAuthnCredentials ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_ListWebAuthnCredentials.html))
- [ ] StartWebAuthnRegistration ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_StartWebAuthnRegistration.html))

### Managed Login Branding Operations
- [x] CreateManagedLoginBranding ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_CreateManagedLoginBranding.html), [cognitox](src/action/user_pool/create_managed_login_branding.rs))
- [x] DeleteManagedLoginBranding ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_DeleteManagedLoginBranding.html), [cognitox](src/action/user_pool/delete_managed_login_branding.rs))
- [x] DescribeManagedLoginBranding ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_DescribeManagedLoginBranding.html), [cognitox](src/action/user_pool/describe_managed_login_branding.rs))
- [x] DescribeManagedLoginBrandingByClient ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_DescribeManagedLoginBrandingByClient.html), [cognitox](src/action/user_pool/describe_managed_login_branding_by_client.rs))
- [x] UpdateManagedLoginBranding ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_UpdateManagedLoginBranding.html), [cognitox](src/action/user_pool/update_managed_login_branding.rs))

### Terms Operations
- [ ] CreateTerms ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_CreateTerms.html))
- [ ] DeleteTerms ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_DeleteTerms.html))
- [ ] DescribeTerms ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_DescribeTerms.html))
- [ ] ListTerms ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_ListTerms.html))
- [ ] UpdateTerms ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_UpdateTerms.html))

### Risk Configuration Operations
- [ ] DescribeRiskConfiguration ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_DescribeRiskConfiguration.html))
- [ ] SetRiskConfiguration ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_SetRiskConfiguration.html))

### UI Customization Operations
- [ ] GetUICustomization ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_GetUICustomization.html))
- [ ] SetUICustomization ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_SetUICustomization.html))

### Log Configuration Operations
- [ ] GetLogDeliveryConfiguration ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_GetLogDeliveryConfiguration.html))
- [ ] SetLogDeliveryConfiguration ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_SetLogDeliveryConfiguration.html))

### Token Operations
- [ ] GetTokensFromRefreshToken ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_GetTokensFromRefreshToken.html))

### Tagging Operations
- [ ] ListTagsForResource ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_ListTagsForResource.html))
- [ ] TagResource ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_TagResource.html))
- [ ] UntagResource ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_UntagResource.html))

### Other Operations
- [ ] AddCustomAttributes ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AddCustomAttributes.html))
- [ ] GetSigningCertificate ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_GetSigningCertificate.html))
- [ ] UpdateAuthEventFeedback ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_UpdateAuthEventFeedback.html))
- [ ] UpdateDeviceStatus ([spec](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_UpdateDeviceStatus.html))
