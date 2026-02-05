# Coverage

Based on [Amazon Cognito User Pools API Reference](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_Operations.html)

## cognito-idp

34% implemented (41/119)

### Admin Operations
- [x] AdminAddUserToGroup
- [x] AdminConfirmSignUp
- [x] AdminCreateUser
- [x] AdminDeleteUser
- [ ] AdminDeleteUserAttributes
- [ ] AdminDisableProviderForUser
- [x] AdminDisableUser
- [x] AdminEnableUser
- [ ] AdminForgetDevice
- [ ] AdminGetDevice
- [x] AdminGetUser
- [ ] AdminInitiateAuth
- [ ] AdminLinkProviderForUser
- [ ] AdminListDevices
- [x] AdminListGroupsForUser
- [ ] AdminListUserAuthEvents
- [x] AdminRemoveUserFromGroup
- [ ] AdminResetUserPassword
- [ ] AdminRespondToAuthChallenge
- [ ] AdminSetUserMFAPreference
- [x] AdminSetUserPassword
- [ ] AdminSetUserSettings
- [ ] AdminUpdateAuthEventFeedback
- [ ] AdminUpdateDeviceStatus
- [ ] AdminUpdateUserAttributes
- [ ] AdminUserGlobalSignOut

### User Pool Operations
- [x] CreateUserPool
- [x] DeleteUserPool
- [x] DescribeUserPool
- [x] ListUserPools
- [ ] UpdateUserPool

### User Pool Client Operations
- [x] CreateUserPoolClient
- [x] DeleteUserPoolClient
- [x] DescribeUserPoolClient
- [x] ListUserPoolClients
- [x] UpdateUserPoolClient

### User Pool Domain Operations
- [x] CreateUserPoolDomain
- [x] DeleteUserPoolDomain
- [x] DescribeUserPoolDomain
- [x] UpdateUserPoolDomain

### User Operations
- [x] DeleteUser
- [ ] DeleteUserAttributes
- [x] GetUser
- [x] ListUsers
- [ ] UpdateUserAttributes
- [ ] VerifyUserAttribute

### Authentication Operations
- [x] ChangePassword
- [x] ConfirmForgotPassword
- [x] ConfirmSignUp
- [x] ForgotPassword
- [x] GlobalSignOut
- [x] InitiateAuth
- [x] ResendConfirmationCode
- [ ] RespondToAuthChallenge
- [ ] RevokeToken
- [x] SignUp
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
- [x] CreateGroup
- [x] DeleteGroup
- [x] GetGroup
- [x] ListGroups
- [x] ListUsersInGroup
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
- [ ] CreateManagedLoginBranding
- [ ] DeleteManagedLoginBranding
- [ ] DescribeManagedLoginBranding
- [ ] DescribeManagedLoginBrandingByClient
- [ ] UpdateManagedLoginBranding

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
