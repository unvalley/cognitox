// Signs in to cognitox with amazon-cognito-identity-js, the browser library
// behind Amplify's classic auth. It speaks USER_SRP_AUTH by default, so this
// checks the emulator against a real SRP client: sign-up, sign-in,
// NEW_PASSWORD_REQUIRED, TOTP MFA, refresh, and global sign-out.
//
//   COGNITOX_URL   emulator endpoint (default http://localhost:9229)
//   COGNITOX_LOG   optional path to the server's log, started with
//                  RUST_LOG=cognitox=debug; lets the demo read the codes the
//                  emulator would have emailed and exercise those steps too
import { createHmac } from "node:crypto";
import { readFileSync } from "node:fs";
import cognito from "amazon-cognito-identity-js";

const { AuthenticationDetails, CognitoUser, CognitoUserAttribute, CognitoUserPool } = cognito;

const endpoint = process.env.COGNITOX_URL ?? "http://localhost:9229";
const logFile = process.env.COGNITOX_LOG;

async function api(target, body) {
  const response = await fetch(endpoint, {
    method: "POST",
    headers: {
      "content-type": "application/x-amz-json-1.1",
      "x-amz-target": `AWSCognitoIdentityProviderService.${target}`,
    },
    body: JSON.stringify(body),
  });
  const json = await response.json();
  if (!response.ok) throw new Error(`${target}: ${json.__type}: ${json.message}`);
  return json;
}

// The code the emulator logged for `who` (it delivers no email or SMS).
function loggedCode(kind, who) {
  const line = readFileSync(logFile, "utf8")
    .split("\n")
    .filter((entry) => entry.includes(kind) && entry.includes(who))
    .at(-1);
  const code = line?.match(/(\d{6})\s*$/)?.[1];
  if (!code) throw new Error(`no "${kind}" code for ${who} in ${logFile}`);
  return code;
}

function totp(secret, time = Date.now()) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const bits = [...secret].map((char) => alphabet.indexOf(char).toString(2).padStart(5, "0")).join("");
  const key = Buffer.from(bits.match(/.{8}/g).map((byte) => parseInt(byte, 2)));
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(time / 30_000)));
  const digest = createHmac("sha1", key).update(counter).digest();
  const offset = digest.at(-1) & 15;
  return String((digest.readUInt32BE(offset) & 0x7fffffff) % 1_000_000).padStart(6, "0");
}

let failures = 0;
function check(name, passed, detail = "") {
  if (!passed) failures += 1;
  console.log(`${passed ? "ok  " : "FAIL"} ${name}${detail ? `  (${detail})` : ""}`);
}
const describe = (error) => (error ? `${error.code}: ${error.message}` : "");

function signIn(pool, username, password) {
  return new Promise((resolve) => {
    const user = new CognitoUser({ Username: username, Pool: pool });
    user.authenticateUser(new AuthenticationDetails({ Username: username, Password: password }), {
      onSuccess: (session) => resolve({ kind: "success", session, user }),
      onFailure: (error) => resolve({ kind: "failure", error }),
      newPasswordRequired: (userAttributes) => resolve({ kind: "newPassword", userAttributes, user }),
      totpRequired: () => resolve({ kind: "totp", user }),
      mfaSetup: () => resolve({ kind: "mfaSetup", user }),
    });
  });
}
const callback = (run) => new Promise((resolve) => run((error, result) => resolve({ error, result })));
const handlers = (run) =>
  new Promise((resolve) =>
    run({ onSuccess: (result) => resolve({ result }), onFailure: (error) => resolve({ error }) }),
  );

// An app client created without ExplicitAuthFlows allows SRP, as in Cognito.
const { UserPool: poolDescription } = await api("CreateUserPool", {
  PoolName: "cognito-identity-js-demo",
  AutoVerifiedAttributes: ["email"],
});
const { UserPoolClient: client } = await api("CreateUserPoolClient", {
  UserPoolId: poolDescription.Id,
  ClientName: "web",
});
const pool = new CognitoUserPool({ UserPoolId: poolDescription.Id, ClientId: client.ClientId, endpoint });

// Sign up, and confirm with the emailed code when the log is available.
const signUp = await callback((done) =>
  pool.signUp("alice", "Password123!", [new CognitoUserAttribute({ Name: "email", Value: "alice@example.com" })], null, done),
);
check("signUp", !signUp.error, describe(signUp.error));
let attempt = await signIn(pool, "alice", "Password123!");
check("unconfirmed user is refused", attempt.error?.code === "UserNotConfirmedException", describe(attempt.error));
if (logFile) {
  const confirmed = await callback((done) =>
    new CognitoUser({ Username: "alice", Pool: pool }).confirmRegistration(loggedCode("SignUp confirmation code", "alice"), false, done),
  );
  check("confirmRegistration with the emailed code", !confirmed.error, describe(confirmed.error));
} else {
  await api("AdminConfirmSignUp", { UserPoolId: poolDescription.Id, Username: "alice" });
}

// USER_SRP_AUTH.
attempt = await signIn(pool, "alice", "Password123!");
check("SRP sign-in", attempt.kind === "success", describe(attempt.error));
const idToken = attempt.session.getIdToken().decodePayload();
check("ID token claims", idToken.email === "alice@example.com" && idToken["cognito:username"] === "alice");
const refreshed = await callback((done) => attempt.user.refreshSession(attempt.session.getRefreshToken(), done));
check("refreshSession", !refreshed.error && refreshed.result.isValid(), describe(refreshed.error));

let rejected = await signIn(pool, "alice", "WrongPassword1!");
check("wrong password", rejected.error?.message === "Incorrect username or password.", describe(rejected.error));
rejected = await signIn(pool, "nobody", "Password123!");
check("unknown user", rejected.error?.code === "UserNotFoundException", describe(rejected.error));

// A user created by an administrator has to replace the temporary password.
await api("AdminCreateUser", {
  UserPoolId: poolDescription.Id,
  Username: "bob",
  TemporaryPassword: "TempPass123!",
  UserAttributes: [
    { Name: "email", Value: "bob@example.com" },
    { Name: "email_verified", Value: "true" },
  ],
});
let invited = await signIn(pool, "bob", "TempPass123!");
check("temporary password asks for a new one", invited.kind === "newPassword", describe(invited.error));
const completed = await handlers((callbacks) => invited.user.completeNewPasswordChallenge("NewPassword123!", {}, callbacks));
check("completeNewPasswordChallenge", !completed.error, describe(completed.error));
invited = await signIn(pool, "bob", "NewPassword123!");
check("SRP sign-in with the new password", invited.kind === "success", describe(invited.error));

// TOTP: register a device, turn it on, and sign in with a code.
const secret = await new Promise((resolve, reject) =>
  attempt.user.associateSoftwareToken({ associateSecretCode: resolve, onFailure: reject }),
);
const verified = await handlers((callbacks) => attempt.user.verifySoftwareToken(totp(secret), "demo", callbacks));
check("verifySoftwareToken", !verified.error, describe(verified.error));
const preference = await callback((done) => attempt.user.setUserMfaPreference(null, { PreferredMfa: true, Enabled: true }, done));
check("setUserMfaPreference", !preference.error, describe(preference.error));
const challenged = await signIn(pool, "alice", "Password123!");
check("sign-in asks for a TOTP code", challenged.kind === "totp", challenged.kind);
const afterMfa = await handlers((callbacks) => challenged.user.sendMFACode(totp(secret), callbacks, "SOFTWARE_TOKEN_MFA"));
check("sendMFACode", !afterMfa.error, describe(afterMfa.error));

// Forgot password, completed when the code can be read from the log.
const bob = new CognitoUser({ Username: "bob", Pool: pool });
const forgot = await handlers((callbacks) => bob.forgotPassword(callbacks));
check("forgotPassword", !forgot.error, describe(forgot.error));
if (logFile && !forgot.error) {
  const reset = await handlers((callbacks) => bob.confirmPassword(loggedCode("ForgotPassword code", "bob"), "ResetPassword123!", callbacks));
  check("confirmPassword with the emailed code", !reset.error, describe(reset.error));
  const afterReset = await signIn(pool, "bob", "ResetPassword123!");
  check("SRP sign-in with the reset password", afterReset.kind === "success", describe(afterReset.error));
}

// Global sign-out revokes the refresh token.
const signedOut = await handlers((callbacks) => invited.user.globalSignOut(callbacks));
check("globalSignOut", !signedOut.error, describe(signedOut.error));
const afterSignOut = await callback((done) => invited.user.refreshSession(invited.session.getRefreshToken(), done));
check("refresh after sign-out is revoked", afterSignOut.error?.message === "Refresh Token has been revoked", describe(afterSignOut.error));

console.log(failures ? `\n${failures} check(s) failed` : "\nAll checks passed");
process.exit(failures ? 1 : 0);
