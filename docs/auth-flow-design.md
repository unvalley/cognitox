# Auth Flow Design

`InitiateAuth`, `RespondToAuthChallenge`, and their `Admin*` variants share one
state machine, `src/action/user/auth_flow.rs`. The handlers only parse the
request, load the app client and user pool, and call `initiate_auth` or
`respond_to_auth_challenge` with an `AuthContext`.

## Layers

1. **Request** (the handler files): the `Request` struct of each operation and
   the pool/client lookup. `AuthApi::User` or `AuthApi::Admin` records which
   API the call came through, because the server-side flows
   (`ADMIN_USER_PASSWORD_AUTH`, `ADMIN_NO_SRP_AUTH`) exist only on the admin
   operations and `USER_PASSWORD_AUTH` only on the public one.
2. **Engine** (`auth_flow.rs`): flow and challenge parsing, the
   `ExplicitAuthFlows` check, the first factor, the follow-up challenges, and
   token issuance.
3. **Primitives**: `src/srp.rs` (SRP-6a as Cognito runs it), `src/jwt.rs`
   (claims and signing), `helpers.rs` (password storage, secret hash, codes).

## A sign-in, step by step

```
first factor ──► after_password ──► after_first_factor ──► complete
 password            │                    │
 SRP                 ├─ UNCONFIRMED       ├─ no factor, MFA not required ─► tokens
 one-time code ──────┼─ RESET_REQUIRED    ├─ MFA required, none set up ──► MFA_SETUP
 (USER_AUTH)         └─ FORCE_CHANGE_     ├─ one factor / a preference ──► SOFTWARE_TOKEN_MFA,
                        PASSWORD ──►      │                                SMS_MFA, EMAIL_OTP
                        NEW_PASSWORD_     └─ several, no preference ────► SELECT_MFA_TYPE
                        REQUIRED
```

- **Password flows** verify the bcrypt hash. **`USER_SRP_AUTH`** answers
  `SRP_A` with `PASSWORD_VERIFIER` and checks the client's
  `PASSWORD_CLAIM_SIGNATURE` against the stored verifier. Every code path that
  sets a password goes through `helpers::set_user_password`, which stores both
  the hash and the verifier; a user from a snapshot that predates SRP gets a
  verifier the next time a password flow succeeds.
- **`USER_AUTH`** offers the pool's `AllowedFirstAuthFactors` as
  `SELECT_CHALLENGE` unless `PREFERRED_CHALLENGE` names an available one.
  A one-time code finishes the sign-in; a password continues as above.
- **`REFRESH_TOKEN_AUTH`** issues access and ID tokens that keep the
  `origin_jti` and `auth_time` of the sign-in the refresh token came from.

## Sessions

A challenge is a `PendingAuthChallenge` in storage, keyed by its `Session`
string and bound to the user, app client, pool, and challenge name. It lives
for the client's `AuthSessionValidity` (3 minutes by default), survives wrong
answers up to a small limit, and is replaced by a new session whenever the
sign-in moves to another challenge.

`USER_SRP_AUTH` is the exception: Cognito returns no `Session` with
`PASSWORD_VERIFIER`, and clients hand back the `SECRET_BLOCK` instead, so the
exchange is keyed by its secret block and is single use.

`MFA_SETUP` spans three operations. `AssociateSoftwareToken` and
`VerifySoftwareToken` each exchange the session for a new one, and the final
`RespondToAuthChallenge` succeeds once the pending challenge is marked
`mfa_setup_complete`.

## User existence

With `PreventUserExistenceErrors: ENABLED` an unknown user looks like a wrong
password. For SRP that means handing out a `PASSWORD_VERIFIER` challenge
nobody can answer, as Cognito does.

## Not implemented

- `CUSTOM_AUTH` and `CUSTOM_CHALLENGE`: they are defined by Lambda triggers.
- `WEB_AUTHN` sign-in and the device SRP challenges
  (`DEVICE_SRP_AUTH`, `DEVICE_PASSWORD_VERIFIER`).
- Lockout after repeated failed sign-ins.
