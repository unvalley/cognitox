# Coverage

Based on [Amazon Cognito User Pools API Reference](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_Operations.html)

## cognito-idp

39% implemented (47/119)

### Admin Operations
- [x] [AdminAddUserToGroup](src/action/group/admin_add_user_to_group.rs)
- [x] [AdminConfirmSignUp](src/action/user/admin_confirm_sign_up.rs)
- [x] [AdminCreateUser](src/action/user/admin_create_user.rs)
- [x] [AdminDeleteUser](src/action/user/admin_delete_user.rs)
- [ ] AdminDeleteUserAttributes
- [ ] AdminDisableProviderForUser
- [x] [AdminDisableUser](src/action/user/admin_disable_user.rs)
- [x] [AdminEnableUser](src/action/user/admin_enable_user.rs)
- [ ] AdminForgetDevice
- [ ] AdminGetDevice
- [x] [AdminGetUser](src/action/user/admin_get_user.rs)
- [ ] AdminInitiateAuth
- [ ] AdminLinkProviderForUser
- [ ] AdminListDevices
- [x] [AdminListGroupsForUser](src/action/group/admin_list_groups_for_user.rs)
- [ ] AdminListUserAuthEvents
- [x] [AdminRemoveUserFromGroup](src/action/group/admin_remove_user_from_group.rs)
- [ ] AdminResetUserPassword
- [ ] AdminRespondToAuthChallenge
- [ ] AdminSetUserMFAPreference
- [x] [AdminSetUserPassword](src/action/user/admin_set_user_password.rs)
- [ ] AdminSetUserSettings
- [ ] AdminUpdateAuthEventFeedback
- [ ] AdminUpdateDeviceStatus
- [ ] AdminUpdateUserAttributes
- [ ] AdminUserGlobalSignOut

### User Pool Operations
- [x] [CreateUserPool](src/action/user_pool/create_user_pool.rs)
- [x] [DeleteUserPool](src/action/user_pool/delete_user_pool.rs)
- [x] [DescribeUserPool](src/action/user_pool/describe_user_pool.rs)
- [x] [ListUserPools](src/action/user_pool/list_user_pools.rs)
- [ ] UpdateUserPool

### User Pool Client Operations
- [x] [CreateUserPoolClient](src/action/user_pool/create_user_pool_client.rs)
- [x] [DeleteUserPoolClient](src/action/user_pool/delete_user_pool_client.rs)
- [x] [DescribeUserPoolClient](src/action/user_pool/describe_user_pool_client.rs)
- [x] [ListUserPoolClients](src/action/user_pool/list_user_pool_clients.rs)
- [x] [UpdateUserPoolClient](src/action/user_pool/update_user_pool_client.rs)

### User Pool Domain Operations
- [x] [CreateUserPoolDomain](src/action/user_pool/create_user_pool_domain.rs)
- [x] [DeleteUserPoolDomain](src/action/user_pool/delete_user_pool_domain.rs)
- [x] [DescribeUserPoolDomain](src/action/user_pool/describe_user_pool_domain.rs)
- [x] [UpdateUserPoolDomain](src/action/user_pool/update_user_pool_domain.rs)

### User Operations
- [x] [DeleteUser](src/action/user/delete_user.rs)
- [ ] DeleteUserAttributes
- [x] [GetUser](src/action/user/get_user.rs)
- [x] [ListUsers](src/action/user/list_users.rs)
- [ ] UpdateUserAttributes
- [ ] VerifyUserAttribute

### Authentication Operations
- [x] [ChangePassword](src/action/user/change_password.rs)
- [x] [ConfirmForgotPassword](src/action/user/confirm_forgot_password.rs)
- [x] [ConfirmSignUp](src/action/user/confirm_sign_up.rs)
- [x] [ForgotPassword](src/action/user/forgot_password.rs)
- [x] [GlobalSignOut](src/action/user/global_sign_out.rs)
- [x] [InitiateAuth](src/action/user/initiate_auth.rs)
- [x] [ResendConfirmationCode](src/action/user/resend_confirmation_code.rs)
- [x] [RespondToAuthChallenge](src/action/user/respond_to_auth_challenge.rs)
- [ ] RevokeToken
- [x] [SignUp](src/action/user/sign_up.rs)
- [ ] GetUserAttributeVerificationCode

### MFA Operations
- [ ] AssociateSoftwareToken
- [ ] SetUserMFAPreference
- [ ] VerifySoftwareToken
- [ ] GetUserPoolMfaConfig
- [ ] SetUserPoolMfaConfig
- [ ] SetUserSettings
- [ ] GetUserAuthFactors

### Device Operations
- [ ] ConfirmDevice
- [ ] ForgetDevice
- [ ] GetDevice
- [ ] ListDevices

### Group Operations
- [x] [CreateGroup](src/action/group/create_group.rs)
- [x] [DeleteGroup](src/action/group/delete_group.rs)
- [x] [GetGroup](src/action/group/get_group.rs)
- [x] [ListGroups](src/action/group/list_groups.rs)
- [x] [ListUsersInGroup](src/action/group/list_users_in_group.rs)
- [ ] UpdateGroup

### Identity Provider Operations
- [ ] CreateIdentityProvider
- [ ] DeleteIdentityProvider
- [ ] DescribeIdentityProvider
- [ ] GetIdentityProviderByIdentifier
- [ ] ListIdentityProviders
- [ ] UpdateIdentityProvider

### Resource Server Operations
- [ ] CreateResourceServer
- [ ] DeleteResourceServer
- [ ] DescribeResourceServer
- [ ] ListResourceServers
- [ ] UpdateResourceServer

### User Import Operations
- [ ] CreateUserImportJob
- [ ] DescribeUserImportJob
- [ ] GetCSVHeader
- [ ] ListUserImportJobs
- [ ] StartUserImportJob
- [ ] StopUserImportJob

### WebAuthn Operations
- [ ] CompleteWebAuthnRegistration
- [ ] DeleteWebAuthnCredential
- [ ] ListWebAuthnCredentials
- [ ] StartWebAuthnRegistration

### Managed Login Branding Operations
- [x] [CreateManagedLoginBranding](src/action/user_pool/create_managed_login_branding.rs)
- [x] [DeleteManagedLoginBranding](src/action/user_pool/delete_managed_login_branding.rs)
- [x] [DescribeManagedLoginBranding](src/action/user_pool/describe_managed_login_branding.rs)
- [x] [DescribeManagedLoginBrandingByClient](src/action/user_pool/describe_managed_login_branding_by_client.rs)
- [x] [UpdateManagedLoginBranding](src/action/user_pool/update_managed_login_branding.rs)

### Terms Operations
- [ ] CreateTerms
- [ ] DeleteTerms
- [ ] DescribeTerms
- [ ] ListTerms
- [ ] UpdateTerms

### Risk Configuration Operations
- [ ] DescribeRiskConfiguration
- [ ] SetRiskConfiguration

### UI Customization Operations
- [ ] GetUICustomization
- [ ] SetUICustomization

### Log Configuration Operations
- [ ] GetLogDeliveryConfiguration
- [ ] SetLogDeliveryConfiguration

### Token Operations
- [ ] GetTokensFromRefreshToken

### Tagging Operations
- [ ] ListTagsForResource
- [ ] TagResource
- [ ] UntagResource

### Other Operations
- [ ] AddCustomAttributes
- [ ] GetSigningCertificate
- [ ] UpdateAuthEventFeedback
- [ ] UpdateDeviceStatus
