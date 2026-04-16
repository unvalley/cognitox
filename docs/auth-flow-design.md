# Auth Flow Design

## Goals

- Remove duplicated auth logic across:
  - `InitiateAuth`
  - `RespondToAuthChallenge`
  - `AdminInitiateAuth`
  - `AdminRespondToAuthChallenge`
- Separate transport parsing from auth state transitions.
- Make it possible to add missing Cognito flows and challenges without copying token issuance and session validation logic again.
- Keep current behavior stable while introducing structure incrementally.

## Current Problems

- Password auth, refresh-token auth, token issuance, and `NEW_PASSWORD_REQUIRED` session handling are implemented four times with small variations.
- Flow and challenge selection are string-driven inside large handlers.
- `PendingAuthChallenge` stores only a string challenge name, and handlers re-implement the same session validation rules.
- Adding a new challenge today would require edits in multiple handlers instead of one shared state machine layer.

## Target Shape

Auth behavior should be split into three layers:

1. Request layer
   - Parse API-specific request fields.
   - Normalize request-specific shapes like `AuthParameters` and `ChallengeResponses`.
   - Convert transport strings into typed flow/challenge intents where possible.

2. Auth engine layer
   - Validate password auth.
   - Validate refresh-token auth.
   - Create and validate challenge sessions.
   - Finalize challenge completion.
   - Issue tokens and auth events.

3. Response layer
   - Build Cognito-compatible success/challenge payloads.
   - Keep API-specific envelope differences local to handlers.

## Incremental Plan

### Phase 1

- Extract shared helpers for:
  - authentication result generation
  - refresh-token authentication
  - `NEW_PASSWORD_REQUIRED` challenge creation
  - challenge session validation
  - password-challenge completion
- Keep existing request structs and public handler behavior mostly unchanged.
- Use this phase to make the four handlers structurally similar.

Status:
- Done. Shared helpers now own password auth, refresh-token auth, token issuance, and `NEW_PASSWORD_REQUIRED` session lifecycle.

### Phase 2

- Introduce typed request-side flow/challenge enums with graceful fallback for unsupported values.
- Replace most raw string matching with typed dispatch.
- Extend `PendingAuthChallenge` so challenge metadata is typed and can carry parameters needed for MFA and SRP.

Status:
- In progress. Handlers now parse flow/challenge names through typed helpers while preserving existing `NotImplemented` responses for unsupported values.
- `PendingAuthChallenge` now stores a typed `ChallengeType`.
- `SOFTWARE_TOKEN_MFA` is wired into `InitiateAuth` / `RespondToAuthChallenge` and the admin variants as the first non-password follow-up challenge.

### Phase 3

- Add missing Cognito flows:
  - `USER_AUTH`
  - `CUSTOM_AUTH`
  - `USER_SRP_AUTH`
  - additional admin variants as needed
- Add missing challenges:
  - `SMS_MFA`
  - `SOFTWARE_TOKEN_MFA`
  - `SELECT_MFA_TYPE`
  - `MFA_SETUP`
  - `CUSTOM_CHALLENGE`

### Phase 4

- Move challenge progression to an explicit state machine.
- Model challenge transitions in one place instead of branching ad hoc inside handlers.
- Add compatibility tests per flow/challenge pair.

## State Model Notes

`PendingAuthChallenge` is the seed of the state machine. It should eventually represent:

- challenge type
- subject user
- client and pool binding
- expiry
- challenge-scoped metadata

For now, Phase 1 keeps the existing storage shape and only centralizes validation logic around it.

## Immediate Non-Goals

- Full SRP implementation
- Full MFA challenge matrix
- Reworking Hosted UI or OAuth2 flows
- Changing externally visible behavior unless needed for correctness
