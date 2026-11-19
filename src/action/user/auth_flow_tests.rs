//! Sign-in scenarios driven through the handlers, the way an SDK would.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{Duration, Utc};
use serde_json::{Value, json};

use crate::{
    action::{
        user::{
            admin_create_user, admin_initiate_auth, admin_set_user_password,
            associate_software_token, change_password, confirm_sign_up, get_user, global_sign_out,
            initiate_auth, respond_to_auth_challenge, revoke_token, set_user_mfa_preference,
            sign_up, verify_software_token, verify_software_token::generate_totp_code,
        },
        user_pool::{create_user_pool, create_user_pool_client, set_user_pool_mfa_config},
    },
    error::AppError,
    srp::client::SrpClient,
    storage::Storage,
    types::UserPoolId,
};

const PASSWORD: &str = "Password123!";
const TIMESTAMP: &str = "Thu Nov 19 03:04:05 UTC 2026";

struct Fixture {
    storage: Storage,
    pool_id: String,
    client_id: String,
}

impl Fixture {
    /// A pool that auto-verifies email and a public client that allows
    /// every flow the tests use, each extended with the given settings.
    async fn new(pool_settings: Value, client_settings: Value) -> Self {
        let storage = Storage::new();

        let mut pool_request = json!({
            "PoolName": "test",
            "AutoVerifiedAttributes": ["email"],
        });
        merge(&mut pool_request, pool_settings);
        let pool = create_user_pool::handler(&storage, pool_request)
            .await
            .unwrap();
        let pool_id = pool["UserPool"]["Id"].as_str().unwrap().to_string();

        let mut client_request = json!({
            "UserPoolId": pool_id,
            "ClientName": "test-client",
            "ExplicitAuthFlows": [
                "ALLOW_USER_PASSWORD_AUTH",
                "ALLOW_ADMIN_USER_PASSWORD_AUTH",
                "ALLOW_USER_SRP_AUTH",
                "ALLOW_USER_AUTH",
                "ALLOW_REFRESH_TOKEN_AUTH"
            ],
        });
        merge(&mut client_request, client_settings);
        let client = create_user_pool_client::handler(&storage, client_request)
            .await
            .unwrap();
        let client_id = client["UserPoolClient"]["ClientId"]
            .as_str()
            .unwrap()
            .to_string();

        Self {
            storage,
            pool_id,
            client_id,
        }
    }

    async fn default() -> Self {
        Self::new(json!({}), json!({})).await
    }

    /// Sign up and confirm a user with the code the emulator "sent".
    async fn confirmed_user(&self, username: &str, attributes: Value) {
        let signed_up = sign_up::handler(
            &self.storage,
            json!({
                "ClientId": self.client_id,
                "Username": username,
                "Password": PASSWORD,
                "UserAttributes": attributes,
            }),
        )
        .await
        .unwrap();
        let user_id = uuid::Uuid::parse_str(signed_up["UserSub"].as_str().unwrap()).unwrap();
        let code = self
            .storage
            .get_confirmation_code(&user_id)
            .await
            .unwrap()
            .code;
        confirm_sign_up::handler(
            &self.storage,
            json!({
                "ClientId": self.client_id,
                "Username": username,
                "ConfirmationCode": code,
            }),
        )
        .await
        .unwrap();
    }

    async fn initiate(&self, auth_flow: &str, parameters: Value) -> Result<Value, AppError> {
        initiate_auth::handler(
            &self.storage,
            json!({
                "ClientId": self.client_id,
                "AuthFlow": auth_flow,
                "AuthParameters": parameters,
            }),
        )
        .await
    }

    async fn respond(
        &self,
        challenge_name: &str,
        session: Option<&str>,
        responses: Value,
    ) -> Result<Value, AppError> {
        let mut request = json!({
            "ClientId": self.client_id,
            "ChallengeName": challenge_name,
            "ChallengeResponses": responses,
        });
        if let Some(session) = session {
            request["Session"] = json!(session);
        }
        respond_to_auth_challenge::handler(&self.storage, request).await
    }

    async fn password_sign_in(&self, username: &str, password: &str) -> Result<Value, AppError> {
        self.initiate(
            "USER_PASSWORD_AUTH",
            json!({"USERNAME": username, "PASSWORD": password}),
        )
        .await
    }

    /// `USER_SRP_AUTH` up to the answer to `PASSWORD_VERIFIER`.
    async fn srp_sign_in(&self, username: &str, password: &str) -> Result<Value, AppError> {
        let client = SrpClient::new();
        let challenge = self
            .initiate(
                "USER_SRP_AUTH",
                json!({"USERNAME": username, "SRP_A": client.public_hex()}),
            )
            .await?;
        assert_eq!(challenge["ChallengeName"], "PASSWORD_VERIFIER");
        // The exchange is identified by its secret block, not a session.
        assert!(challenge.get("Session").is_none());

        let parameters = &challenge["ChallengeParameters"];
        let user_id_for_srp = parameters["USER_ID_FOR_SRP"].as_str().unwrap();
        let secret_block = parameters["SECRET_BLOCK"].as_str().unwrap();
        let signature = client.signature(&self.pool_id, password, parameters, TIMESTAMP);
        self.respond(
            "PASSWORD_VERIFIER",
            None,
            json!({
                "USERNAME": user_id_for_srp,
                "PASSWORD_CLAIM_SECRET_BLOCK": secret_block,
                "PASSWORD_CLAIM_SIGNATURE": signature,
                "TIMESTAMP": TIMESTAMP,
            }),
        )
        .await
    }

    /// The one-time code waiting in a challenge session.
    async fn delivered_code(&self, session: &str) -> String {
        self.storage
            .get_auth_challenge_session(session)
            .await
            .unwrap()
            .code
            .unwrap()
    }
}

fn merge(target: &mut Value, extra: Value) {
    if let (Some(target), Value::Object(extra)) = (target.as_object_mut(), extra) {
        target.extend(extra);
    }
}

fn claims(token: &Value) -> Value {
    let payload = token.as_str().unwrap().split('.').nth(1).unwrap();
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).unwrap()).unwrap()
}

fn header(token: &Value) -> Value {
    let header = token.as_str().unwrap().split('.').next().unwrap();
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(header).unwrap()).unwrap()
}

fn assert_tokens(result: &Value) -> &Value {
    let tokens = &result["AuthenticationResult"];
    assert!(tokens["AccessToken"].is_string(), "no tokens in {result}");
    assert!(tokens["IdToken"].is_string());
    assert_eq!(tokens["TokenType"], "Bearer");
    assert!(result.get("ChallengeName").is_none());
    assert!(result.get("Session").is_none());
    tokens
}

fn not_authorized(result: Result<Value, AppError>, expected: &str) {
    match result {
        Err(AppError::NotAuthorized(message)) => assert_eq!(message, expected),
        other => panic!("expected NotAuthorizedException({expected}), got {other:?}"),
    }
}

#[tokio::test]
async fn srp_sign_in_issues_tokens() {
    let fixture = Fixture::default().await;
    fixture.confirmed_user("alice", json!([])).await;

    let result = fixture.srp_sign_in("alice", PASSWORD).await.unwrap();
    let tokens = assert_tokens(&result);
    assert!(tokens["RefreshToken"].is_string());
}

#[tokio::test]
async fn srp_sign_in_rejects_a_wrong_password() {
    let fixture = Fixture::default().await;
    fixture.confirmed_user("alice", json!([])).await;

    not_authorized(
        fixture.srp_sign_in("alice", "Wrong-Password1!").await,
        "Incorrect username or password.",
    );
}

#[tokio::test]
async fn srp_challenge_cannot_be_answered_twice() {
    let fixture = Fixture::default().await;
    fixture.confirmed_user("alice", json!([])).await;

    let client = SrpClient::new();
    let challenge = fixture
        .initiate(
            "USER_SRP_AUTH",
            json!({"USERNAME": "alice", "SRP_A": client.public_hex()}),
        )
        .await
        .unwrap();
    let parameters = &challenge["ChallengeParameters"];
    let responses = json!({
        "USERNAME": "alice",
        "PASSWORD_CLAIM_SECRET_BLOCK": parameters["SECRET_BLOCK"],
        "PASSWORD_CLAIM_SIGNATURE": client.signature(&fixture.pool_id, PASSWORD, parameters, TIMESTAMP),
        "TIMESTAMP": TIMESTAMP,
    });

    assert_tokens(
        &fixture
            .respond("PASSWORD_VERIFIER", None, responses.clone())
            .await
            .unwrap(),
    );
    not_authorized(
        fixture.respond("PASSWORD_VERIFIER", None, responses).await,
        "Incorrect username or password.",
    );
}

#[tokio::test]
async fn srp_follows_every_password_change() {
    let fixture = Fixture::default().await;
    fixture.confirmed_user("alice", json!([])).await;

    let signed_in = fixture.srp_sign_in("alice", PASSWORD).await.unwrap();
    change_password::handler(
        &fixture.storage,
        json!({
            "AccessToken": signed_in["AuthenticationResult"]["AccessToken"],
            "PreviousPassword": PASSWORD,
            "ProposedPassword": "Changed-Password2!",
        }),
    )
    .await
    .unwrap();
    assert!(fixture.srp_sign_in("alice", PASSWORD).await.is_err());
    assert_tokens(
        &fixture
            .srp_sign_in("alice", "Changed-Password2!")
            .await
            .unwrap(),
    );

    admin_set_user_password::handler(
        &fixture.storage,
        json!({
            "UserPoolId": fixture.pool_id,
            "Username": "alice",
            "Password": "Admin-Password3!",
            "Permanent": true,
        }),
    )
    .await
    .unwrap();
    assert_tokens(
        &fixture
            .srp_sign_in("alice", "Admin-Password3!")
            .await
            .unwrap(),
    );
}

#[tokio::test]
async fn srp_with_a_temporary_password_asks_for_a_new_one() {
    let fixture = Fixture::default().await;
    admin_create_user::handler(
        &fixture.storage,
        json!({
            "UserPoolId": fixture.pool_id,
            "Username": "bob",
            "TemporaryPassword": "TempPass123!",
            "UserAttributes": [{"Name": "email", "Value": "bob@example.com"}],
        }),
    )
    .await
    .unwrap();

    let challenge = fixture.srp_sign_in("bob", "TempPass123!").await.unwrap();
    assert_eq!(challenge["ChallengeName"], "NEW_PASSWORD_REQUIRED");
    let parameters = &challenge["ChallengeParameters"];
    assert_eq!(parameters["USER_ID_FOR_SRP"], "bob");
    // Both are JSON documents inside strings; clients JSON.parse them.
    assert_eq!(parameters["requiredAttributes"], "[]");
    let attributes: Value =
        serde_json::from_str(parameters["userAttributes"].as_str().unwrap()).unwrap();
    assert_eq!(attributes["email"], "bob@example.com");

    let result = fixture
        .respond(
            "NEW_PASSWORD_REQUIRED",
            challenge["Session"].as_str(),
            json!({
                "USERNAME": "bob",
                "NEW_PASSWORD": "Brand-New-Password4!",
                "userAttributes.name": "Bob",
            }),
        )
        .await
        .unwrap();
    let tokens = assert_tokens(&result);
    assert_eq!(claims(&tokens["IdToken"])["name"], "Bob");

    assert_tokens(
        &fixture
            .srp_sign_in("bob", "Brand-New-Password4!")
            .await
            .unwrap(),
    );
}

#[tokio::test]
async fn unknown_user_follows_prevent_user_existence_errors() {
    let legacy = Fixture::default().await;
    assert!(matches!(
        legacy.password_sign_in("nobody", PASSWORD).await,
        Err(AppError::UserNotFound)
    ));
    assert!(matches!(
        legacy.srp_sign_in("nobody", PASSWORD).await,
        Err(AppError::UserNotFound)
    ));

    let hidden = Fixture::new(json!({}), json!({"PreventUserExistenceErrors": "ENABLED"})).await;
    not_authorized(
        hidden.password_sign_in("nobody", PASSWORD).await,
        "Incorrect username or password.",
    );
    // SRP hands out a challenge even for a user that does not exist.
    not_authorized(
        hidden.srp_sign_in("nobody", PASSWORD).await,
        "Incorrect username or password.",
    );
}

#[tokio::test]
async fn default_client_allows_srp_but_not_plain_passwords() {
    let fixture = Fixture::new(json!({}), json!({"ExplicitAuthFlows": null})).await;
    fixture.confirmed_user("alice", json!([])).await;

    assert!(matches!(
        fixture.password_sign_in("alice", PASSWORD).await,
        Err(AppError::InvalidParameter(message))
            if message == "USER_PASSWORD_AUTH flow not enabled for this client"
    ));
    assert_tokens(&fixture.srp_sign_in("alice", PASSWORD).await.unwrap());
}

#[tokio::test]
async fn admin_flows_are_not_available_on_the_public_api() {
    let fixture = Fixture::default().await;
    fixture.confirmed_user("alice", json!([])).await;

    assert!(matches!(
        fixture
            .initiate(
                "ADMIN_USER_PASSWORD_AUTH",
                json!({"USERNAME": "alice", "PASSWORD": PASSWORD}),
            )
            .await,
        Err(AppError::InvalidParameter(message)) if message == "Initiate Auth method not supported."
    ));
    assert!(matches!(
        fixture.initiate("NOT_A_FLOW", json!({})).await,
        Err(AppError::InvalidParameter(message)) if message.contains("at 'authFlow'")
    ));

    let admin = admin_initiate_auth::handler(
        &fixture.storage,
        json!({
            "UserPoolId": fixture.pool_id,
            "ClientId": fixture.client_id,
            "AuthFlow": "ADMIN_USER_PASSWORD_AUTH",
            "AuthParameters": {"USERNAME": "alice", "PASSWORD": PASSWORD},
        }),
    )
    .await
    .unwrap();
    assert_tokens(&admin);
}

#[tokio::test]
async fn missing_auth_parameters_are_named() {
    let fixture = Fixture::default().await;
    assert!(matches!(
        fixture.initiate("USER_PASSWORD_AUTH", json!({"USERNAME": "alice"})).await,
        Err(AppError::InvalidParameter(message)) if message == "Missing required parameter PASSWORD"
    ));
    assert!(matches!(
        fixture.initiate("USER_SRP_AUTH", json!({"USERNAME": "alice"})).await,
        Err(AppError::InvalidParameter(message)) if message == "Missing required parameter SRP_A"
    ));
}

#[tokio::test]
async fn tokens_carry_cognitos_claims() {
    let fixture = Fixture::default().await;
    fixture
        .confirmed_user(
            "alice",
            json!([
                {"Name": "email", "Value": "alice@example.com"},
                {"Name": "name", "Value": "Alice"},
            ]),
        )
        .await;

    let result = fixture.password_sign_in("alice", PASSWORD).await.unwrap();
    let tokens = assert_tokens(&result);
    let access = claims(&tokens["AccessToken"]);
    let id = claims(&tokens["IdToken"]);

    assert_eq!(header(&tokens["IdToken"]).as_object().unwrap().len(), 2);
    assert_eq!(header(&tokens["IdToken"])["alg"], "RS256");

    assert_eq!(access["token_use"], "access");
    assert_eq!(access["scope"], "aws.cognito.signin.user.admin");
    assert_eq!(access["username"], "alice");
    assert_eq!(access["client_id"], fixture.client_id.as_str());
    assert!(access.get("aud").is_none());
    for claim in ["jti", "origin_jti", "event_id"] {
        assert!(access[claim].is_string(), "access token lacks {claim}");
        assert!(id[claim].is_string(), "ID token lacks {claim}");
    }
    assert_ne!(access["jti"], id["jti"]);
    assert_eq!(access["origin_jti"], id["origin_jti"]);
    assert_eq!(access["event_id"], id["event_id"]);

    assert_eq!(id["token_use"], "id");
    assert_eq!(id["aud"], fixture.client_id.as_str());
    assert_eq!(id["cognito:username"], "alice");
    assert_eq!(id["email"], "alice@example.com");
    // Confirming with the emailed code verified the address.
    assert_eq!(id["email_verified"], true);
    assert_eq!(id["name"], "Alice");
    assert_eq!(id["sub"], access["sub"]);
    assert!(id.get("cognito:groups").is_none());

    // Tokens from a refresh descend from the same authentication.
    let refreshed = fixture
        .initiate(
            "REFRESH_TOKEN_AUTH",
            json!({"REFRESH_TOKEN": tokens["RefreshToken"]}),
        )
        .await
        .unwrap();
    let refreshed_tokens = assert_tokens(&refreshed);
    assert!(refreshed_tokens.get("RefreshToken").is_none());
    let refreshed_access = claims(&refreshed_tokens["AccessToken"]);
    assert_eq!(refreshed_access["origin_jti"], access["origin_jti"]);
    assert_eq!(refreshed_access["auth_time"], access["auth_time"]);
    assert_ne!(refreshed_access["jti"], access["jti"]);
}

#[tokio::test]
async fn revoking_a_refresh_token_ends_only_its_session() {
    let fixture = Fixture::default().await;
    fixture.confirmed_user("alice", json!([])).await;

    let first = fixture.password_sign_in("alice", PASSWORD).await.unwrap();
    let second = fixture.password_sign_in("alice", PASSWORD).await.unwrap();
    let first = &first["AuthenticationResult"];
    let second = &second["AuthenticationResult"];

    revoke_token::handler(
        &fixture.storage,
        json!({"ClientId": fixture.client_id, "Token": first["RefreshToken"]}),
    )
    .await
    .unwrap();

    assert!(matches!(
        fixture
            .initiate(
                "REFRESH_TOKEN_AUTH",
                json!({"REFRESH_TOKEN": first["RefreshToken"]})
            )
            .await,
        Err(AppError::RefreshTokenRevoked)
    ));
    assert!(matches!(
        get_user::handler(
            &fixture.storage,
            json!({"AccessToken": first["AccessToken"]})
        )
        .await,
        Err(AppError::AccessTokenRevoked)
    ));
    // The other sign-in is untouched.
    get_user::handler(
        &fixture.storage,
        json!({"AccessToken": second["AccessToken"]}),
    )
    .await
    .unwrap();
    assert_tokens(
        &fixture
            .initiate(
                "REFRESH_TOKEN_AUTH",
                json!({"REFRESH_TOKEN": second["RefreshToken"]}),
            )
            .await
            .unwrap(),
    );

    // Global sign-out ends every session of the user.
    global_sign_out::handler(
        &fixture.storage,
        json!({"AccessToken": second["AccessToken"]}),
    )
    .await
    .unwrap();
    assert!(matches!(
        fixture
            .initiate(
                "REFRESH_TOKEN_AUTH",
                json!({"REFRESH_TOKEN": second["RefreshToken"]})
            )
            .await,
        Err(AppError::RefreshTokenRevoked)
    ));
    assert!(matches!(
        fixture
            .initiate(
                "REFRESH_TOKEN_AUTH",
                json!({"REFRESH_TOKEN": "never-issued"})
            )
            .await,
        Err(AppError::InvalidRefreshToken)
    ));
}

#[tokio::test]
async fn required_mfa_walks_the_user_through_totp_setup() {
    let fixture = Fixture::default().await;
    set_user_pool_mfa_config::handler(
        &fixture.storage,
        json!({
            "UserPoolId": fixture.pool_id,
            "MfaConfiguration": "ON",
            "SoftwareTokenMfaConfiguration": {"Enabled": true},
        }),
    )
    .await
    .unwrap();
    fixture.confirmed_user("alice", json!([])).await;

    let challenge = fixture.srp_sign_in("alice", PASSWORD).await.unwrap();
    assert_eq!(challenge["ChallengeName"], "MFA_SETUP");
    assert_eq!(
        challenge["ChallengeParameters"]["MFAS_CAN_SETUP"],
        "[\"SOFTWARE_TOKEN_MFA\"]"
    );
    let session = challenge["Session"].as_str().unwrap();

    // Answering before a device is verified does not get around the setup.
    not_authorized(
        fixture
            .respond("MFA_SETUP", Some(session), json!({"USERNAME": "alice"}))
            .await,
        "Invalid session for the user.",
    );

    let associated =
        associate_software_token::handler(&fixture.storage, json!({"Session": session}))
            .await
            .unwrap();
    let secret = associated["SecretCode"].as_str().unwrap();
    let session = associated["Session"].as_str().unwrap();

    let verified = verify_software_token::handler(
        &fixture.storage,
        json!({
            "Session": session,
            "UserCode": generate_totp_code(secret, Utc::now().timestamp()).unwrap(),
        }),
    )
    .await
    .unwrap();
    assert_eq!(verified["Status"], "SUCCESS");

    let result = fixture
        .respond(
            "MFA_SETUP",
            verified["Session"].as_str(),
            json!({"USERNAME": "alice"}),
        )
        .await
        .unwrap();
    assert_tokens(&result);

    // From now on sign-in asks for a TOTP code.
    let challenge = fixture.password_sign_in("alice", PASSWORD).await.unwrap();
    assert_eq!(challenge["ChallengeName"], "SOFTWARE_TOKEN_MFA");
    let session = challenge["Session"].as_str();

    let right_code = generate_totp_code(secret, Utc::now().timestamp()).unwrap();
    let wrong_code = if right_code == "000000" {
        "000001"
    } else {
        "000000"
    };
    assert!(matches!(
        fixture
            .respond(
                "SOFTWARE_TOKEN_MFA",
                session,
                json!({"USERNAME": "alice", "SOFTWARE_TOKEN_MFA_CODE": wrong_code}),
            )
            .await,
        Err(AppError::CodeMismatch(message)) if message == "Invalid code received for user"
    ));
    // A wrong code does not burn the session.
    assert_tokens(
        &fixture
            .respond(
                "SOFTWARE_TOKEN_MFA",
                session,
                json!({"USERNAME": "alice", "SOFTWARE_TOKEN_MFA_CODE": right_code}),
            )
            .await
            .unwrap(),
    );
}

#[tokio::test]
async fn repeated_wrong_codes_end_the_challenge() {
    let fixture = Fixture::default().await;
    fixture
        .confirmed_user(
            "alice",
            json!([{"Name": "phone_number", "Value": "+15555550100"}]),
        )
        .await;
    let signed_in = fixture.password_sign_in("alice", PASSWORD).await.unwrap();
    set_user_mfa_preference::handler(
        &fixture.storage,
        json!({
            "AccessToken": signed_in["AuthenticationResult"]["AccessToken"],
            "SMSMfaSettings": {"Enabled": true, "PreferredMfa": true},
        }),
    )
    .await
    .unwrap();

    let challenge = fixture.password_sign_in("alice", PASSWORD).await.unwrap();
    assert_eq!(challenge["ChallengeName"], "SMS_MFA");
    assert_eq!(
        challenge["ChallengeParameters"]["CODE_DELIVERY_DELIVERY_MEDIUM"],
        "SMS"
    );
    let session = challenge["Session"].as_str().unwrap();
    let code = fixture.delivered_code(session).await;
    let wrong_code = if code == "000000" { "000001" } else { "000000" };

    for _ in 0..3 {
        assert!(matches!(
            fixture
                .respond(
                    "SMS_MFA",
                    Some(session),
                    json!({"USERNAME": "alice", "SMS_MFA_CODE": wrong_code}),
                )
                .await,
            Err(AppError::CodeMismatch(_))
        ));
    }
    not_authorized(
        fixture
            .respond(
                "SMS_MFA",
                Some(session),
                json!({"USERNAME": "alice", "SMS_MFA_CODE": code}),
            )
            .await,
        "Invalid session for the user.",
    );
}

#[tokio::test]
async fn sms_mfa_code_completes_the_sign_in() {
    let fixture = Fixture::default().await;
    fixture
        .confirmed_user(
            "alice",
            json!([{"Name": "phone_number", "Value": "+15555550100"}]),
        )
        .await;
    let signed_in = fixture.password_sign_in("alice", PASSWORD).await.unwrap();
    set_user_mfa_preference::handler(
        &fixture.storage,
        json!({
            "AccessToken": signed_in["AuthenticationResult"]["AccessToken"],
            "SMSMfaSettings": {"Enabled": true, "PreferredMfa": true},
        }),
    )
    .await
    .unwrap();

    let challenge = fixture.srp_sign_in("alice", PASSWORD).await.unwrap();
    assert_eq!(challenge["ChallengeName"], "SMS_MFA");
    let session = challenge["Session"].as_str().unwrap();
    let code = fixture.delivered_code(session).await;
    assert_eq!(code.len(), 6);

    assert_tokens(
        &fixture
            .respond(
                "SMS_MFA",
                Some(session),
                json!({"USERNAME": "alice", "SMS_MFA_CODE": code}),
            )
            .await
            .unwrap(),
    );
}

#[tokio::test]
async fn several_factors_without_a_preference_let_the_user_choose() {
    let fixture = Fixture::default().await;
    fixture
        .confirmed_user(
            "alice",
            json!([{"Name": "phone_number", "Value": "+15555550100"}]),
        )
        .await;
    let signed_in = fixture.password_sign_in("alice", PASSWORD).await.unwrap();
    let access_token = &signed_in["AuthenticationResult"]["AccessToken"];

    let associated =
        associate_software_token::handler(&fixture.storage, json!({"AccessToken": access_token}))
            .await
            .unwrap();
    let secret = associated["SecretCode"].as_str().unwrap();
    verify_software_token::handler(
        &fixture.storage,
        json!({
            "AccessToken": access_token,
            "UserCode": generate_totp_code(secret, Utc::now().timestamp()).unwrap(),
        }),
    )
    .await
    .unwrap();
    set_user_mfa_preference::handler(
        &fixture.storage,
        json!({
            "AccessToken": access_token,
            "SMSMfaSettings": {"Enabled": true},
            "SoftwareTokenMfaSettings": {"Enabled": true},
        }),
    )
    .await
    .unwrap();

    let challenge = fixture.password_sign_in("alice", PASSWORD).await.unwrap();
    assert_eq!(challenge["ChallengeName"], "SELECT_MFA_TYPE");
    let choices: Vec<String> = serde_json::from_str(
        challenge["ChallengeParameters"]["MFAS_CAN_CHOOSE"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(choices, ["SMS_MFA", "SOFTWARE_TOKEN_MFA"]);

    let challenge = fixture
        .respond(
            "SELECT_MFA_TYPE",
            challenge["Session"].as_str(),
            json!({"USERNAME": "alice", "ANSWER": "SOFTWARE_TOKEN_MFA"}),
        )
        .await
        .unwrap();
    assert_eq!(challenge["ChallengeName"], "SOFTWARE_TOKEN_MFA");
    assert_tokens(
        &fixture
            .respond(
                "SOFTWARE_TOKEN_MFA",
                challenge["Session"].as_str(),
                json!({
                    "USERNAME": "alice",
                    "SOFTWARE_TOKEN_MFA_CODE":
                        generate_totp_code(secret, Utc::now().timestamp()).unwrap(),
                }),
            )
            .await
            .unwrap(),
    );
}

#[tokio::test]
async fn expired_and_foreign_sessions_are_refused() {
    let fixture = Fixture::default().await;
    admin_create_user::handler(
        &fixture.storage,
        json!({
            "UserPoolId": fixture.pool_id,
            "Username": "bob",
            "TemporaryPassword": "TempPass123!",
        }),
    )
    .await
    .unwrap();
    let challenge = fixture
        .password_sign_in("bob", "TempPass123!")
        .await
        .unwrap();
    let session = challenge["Session"].as_str().unwrap();
    let responses = json!({"USERNAME": "bob", "NEW_PASSWORD": "Brand-New-Password4!"});

    not_authorized(
        fixture
            .respond("NEW_PASSWORD_REQUIRED", Some("made-up"), responses.clone())
            .await,
        "Invalid session for the user.",
    );
    // The session is bound to the challenge it was issued for.
    not_authorized(
        fixture
            .respond("SOFTWARE_TOKEN_MFA", Some(session), responses.clone())
            .await,
        "Invalid session for the user.",
    );
    // ...and to the user.
    not_authorized(
        fixture
            .respond(
                "NEW_PASSWORD_REQUIRED",
                Some(session),
                json!({"USERNAME": "mallory", "NEW_PASSWORD": "Brand-New-Password4!"}),
            )
            .await,
        "Invalid session for the user.",
    );

    fixture
        .storage
        .update_auth_challenge_session(session, |pending| {
            pending.expires_at = Utc::now() - Duration::seconds(1);
        })
        .await
        .unwrap();
    not_authorized(
        fixture
            .respond("NEW_PASSWORD_REQUIRED", Some(session), responses)
            .await,
        "Invalid session for the user, session is expired.",
    );
}

#[tokio::test]
async fn expired_temporary_password_cannot_sign_in() {
    let fixture = Fixture::default().await;
    admin_create_user::handler(
        &fixture.storage,
        json!({
            "UserPoolId": fixture.pool_id,
            "Username": "bob",
            "TemporaryPassword": "TempPass123!",
        }),
    )
    .await
    .unwrap();

    let pool_id = UserPoolId::new(fixture.pool_id.clone()).unwrap();
    let mut user = fixture
        .storage
        .get_user_by_username(&pool_id, "bob")
        .await
        .unwrap();
    user.password_set_at = Some(Utc::now() - Duration::days(8));
    fixture.storage.update_user(user).await.unwrap();

    not_authorized(
        fixture.password_sign_in("bob", "TempPass123!").await,
        "Temporary password has expired and must be reset by an administrator.",
    );
}

#[tokio::test]
async fn account_state_is_checked_after_the_password() {
    let fixture = Fixture::default().await;
    sign_up::handler(
        &fixture.storage,
        json!({
            "ClientId": fixture.client_id,
            "Username": "carol",
            "Password": PASSWORD,
        }),
    )
    .await
    .unwrap();

    // A wrong password says nothing about the account.
    not_authorized(
        fixture.password_sign_in("carol", "Wrong-Password1!").await,
        "Incorrect username or password.",
    );
    assert!(matches!(
        fixture.password_sign_in("carol", PASSWORD).await,
        Err(AppError::UserNotConfirmed)
    ));
    assert!(matches!(
        fixture.srp_sign_in("carol", PASSWORD).await,
        Err(AppError::UserNotConfirmed)
    ));
}

#[tokio::test]
async fn user_auth_offers_the_pools_first_factors() {
    let fixture = Fixture::new(
        json!({
            "Policies": {
                "SignInPolicy": {"AllowedFirstAuthFactors": ["PASSWORD", "EMAIL_OTP"]}
            }
        }),
        json!({}),
    )
    .await;
    fixture
        .confirmed_user(
            "alice",
            json!([{"Name": "email", "Value": "alice@example.com"}]),
        )
        .await;

    // No preference: the user picks.
    let challenge = fixture
        .initiate("USER_AUTH", json!({"USERNAME": "alice"}))
        .await
        .unwrap();
    assert_eq!(challenge["ChallengeName"], "SELECT_CHALLENGE");
    assert_eq!(
        challenge["AvailableChallenges"],
        json!(["PASSWORD", "PASSWORD_SRP", "EMAIL_OTP"])
    );

    let challenge = fixture
        .respond(
            "SELECT_CHALLENGE",
            challenge["Session"].as_str(),
            json!({"USERNAME": "alice", "ANSWER": "EMAIL_OTP"}),
        )
        .await
        .unwrap();
    assert_eq!(challenge["ChallengeName"], "EMAIL_OTP");
    assert_eq!(
        challenge["ChallengeParameters"]["CODE_DELIVERY_DELIVERY_MEDIUM"],
        "EMAIL"
    );
    let session = challenge["Session"].as_str().unwrap();
    let code = fixture.delivered_code(session).await;
    assert_tokens(
        &fixture
            .respond(
                "EMAIL_OTP",
                Some(session),
                json!({"USERNAME": "alice", "EMAIL_OTP_CODE": code}),
            )
            .await
            .unwrap(),
    );

    // A preferred password, given up front, signs in directly.
    assert_tokens(
        &fixture
            .initiate(
                "USER_AUTH",
                json!({
                    "USERNAME": "alice",
                    "PREFERRED_CHALLENGE": "PASSWORD",
                    "PASSWORD": PASSWORD,
                }),
            )
            .await
            .unwrap(),
    );

    // A preferred factor the pool does not offer falls back to the choice.
    let challenge = fixture
        .initiate(
            "USER_AUTH",
            json!({"USERNAME": "alice", "PREFERRED_CHALLENGE": "SMS_OTP"}),
        )
        .await
        .unwrap();
    assert_eq!(challenge["ChallengeName"], "SELECT_CHALLENGE");

    // PASSWORD_SRP runs the SRP exchange inside the session.
    let client = SrpClient::new();
    let challenge = fixture
        .respond(
            "SELECT_CHALLENGE",
            challenge["Session"].as_str(),
            json!({
                "USERNAME": "alice",
                "ANSWER": "PASSWORD_SRP",
                "SRP_A": client.public_hex(),
            }),
        )
        .await
        .unwrap();
    assert_eq!(challenge["ChallengeName"], "PASSWORD_VERIFIER");
    let parameters = &challenge["ChallengeParameters"];
    let secret_block = parameters["SECRET_BLOCK"].as_str().unwrap();
    let result = fixture
        .respond(
            "PASSWORD_VERIFIER",
            challenge["Session"].as_str(),
            json!({
                "USERNAME": "alice",
                "PASSWORD_CLAIM_SECRET_BLOCK": secret_block,
                "PASSWORD_CLAIM_SIGNATURE": client.signature(&fixture.pool_id, PASSWORD, parameters, TIMESTAMP),
                "TIMESTAMP": TIMESTAMP,
            }),
        )
        .await
        .unwrap();
    assert_tokens(&result);
}

#[tokio::test]
async fn user_auth_needs_the_client_to_allow_it() {
    let fixture = Fixture::new(
        json!({}),
        json!({"ExplicitAuthFlows": ["ALLOW_USER_SRP_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"]}),
    )
    .await;
    assert!(matches!(
        fixture.initiate("USER_AUTH", json!({"USERNAME": "alice"})).await,
        Err(AppError::InvalidParameter(message))
            if message == "USER_AUTH flow not enabled for this client"
    ));
}
