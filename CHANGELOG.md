# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- `NotAuthorizedException` responses now use HTTP 400 like Cognito (previously 401)
- Disabled users now receive `NotAuthorizedException` "User is disabled." instead of the
  non-existent `UserDisabledException`; `RESET_REQUIRED` users receive
  `PasswordResetRequiredException` at sign-in
- `AdminRespondToAuthChallenge` with `NEW_PASSWORD_REQUIRED` requires the `Session` from
  `AdminInitiateAuth`; a bare `USERNAME` is no longer accepted
- Challenge parameters follow Cognito's shape: `USER_ID_FOR_SRP` carries the username and
  `requiredAttributes` / `userAttributes` are JSON documents
- The Hosted UI login form applies the same client policy as `/oauth2/authorize`
  (registered `redirect_uri`, OAuth enabled, `code` flow allowed, `AllowedOAuthScopes`)
- An omitted OAuth `scope` now resolves to every scope configured on the client
- Malformed request bodies return a Cognito-style `SerializationException` JSON body
- `AdminSetUserPassword` with `Permanent: true` confirms the user from any status
- Duplicate identity providers return `DuplicateProviderException`; user import jobs can
  only be started from `Created` and stopped from `Pending`/`InProgress`
  (`PreconditionNotMetException` otherwise)

### Fixed

- `email_verified` / `phone_number_verified` in ID tokens and `/oauth2/userInfo` reflect the
  stored attributes instead of always being `true`
- ID tokens echo the OIDC `nonce` from the authorization request
- `/oauth2/userInfo` honours `GlobalSignOut` revocation and answers bearer failures with
  401 plus `WWW-Authenticate`
- `/oauth2/token` accepts HTTP Basic client authentication as advertised in discovery
- Implicit flow rejects unconfirmed users; the auth-code grant rejects users disabled during
  the code lifetime
- `AdminDisableUser` revokes the user's tokens, and tokens of disabled users are rejected
- `VerifySoftwareToken` works with only an `AccessToken` after `AssociateSoftwareToken`
  (Amplify `setUpTOTP` / `verifyTOTPSetup`)
- Disabling the preferred MFA factor no longer leaves an unanswerable
  `SOFTWARE_TOKEN_MFA` challenge at sign-in
- `SignUp` honours `AllowAdminCreateUserOnly`; `AdminConfirmSignUp` rejects already
  confirmed users
- `DeleteGroup` no longer strips membership from same-named groups in other pools
- `DeleteUserPoolClient` cascades to tokens, codes, sessions, terms, UI/risk configuration
  and branding scoped to the client
- Concurrent creates of the same group, identity provider, resource server or domain can
  no longer both succeed
- Email masking no longer panics on non-ASCII local parts
- Admin/Hosted UI calls the API on its own origin instead of a hardcoded `localhost:9229`

## [0.1.0] - 2026-04-04

### Added

- Full implementation of all 119 AWS Cognito User Pools API operations
- Spec drift detection against the AWS API surface
- Built-in Hosted UI for login, signup, confirmation, and password reset flows
- Admin Console for managing user pools, users, clients, and groups
- OAuth 2.0 / OpenID Connect endpoints (authorization code, implicit, client credentials, refresh token)
- JWT token generation (RS256) with JWKS endpoint
- Optional file-based persistence (`DATA_FILE` environment variable)
- Automatic cleanup of expired tokens and codes
- Cascade deletion of related data when a user pool is removed
- Docker support with multi-stage build, health check, and non-root execution
- Configurable token validity via `UserPoolClient` settings
- WebAuthn credential management
- User import job management
- Managed login branding and UI customization
- Risk configuration storage
- Resource server and identity provider management

[0.1.0]: https://github.com/unvalley/cognitox/releases/tag/v0.1.0
