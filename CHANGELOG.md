# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
