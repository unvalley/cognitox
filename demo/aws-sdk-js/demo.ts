/**
 * cognitox AWS SDK for JavaScript demo
 *
 * Demonstrates the full user lifecycle using the official AWS SDK
 * pointed at the local cognitox emulator.
 *
 * Usage:
 *   npm install
 *   npm run demo
 *
 * Requires cognitox running on localhost:9229 (default).
 */

import {
  CognitoIdentityProviderClient,
  CreateUserPoolCommand,
  CreateUserPoolClientCommand,
  SignUpCommand,
  AdminConfirmSignUpCommand,
  InitiateAuthCommand,
  GetUserCommand,
  ListUsersCommand,
  DeleteUserCommand,
  DeleteUserPoolCommand,
} from "@aws-sdk/client-cognito-identity-provider";

const ENDPOINT = process.env.COGNITOX_URL || "http://localhost:9229";

const client = new CognitoIdentityProviderClient({
  region: "local",
  endpoint: ENDPOINT,
  credentials: { accessKeyId: "local", secretAccessKey: "local" },
});

function log(label: string, data?: unknown) {
  console.log(`\n✓ ${label}`);
  if (data) console.log(JSON.stringify(data, null, 2));
}

async function main() {
  console.log(`\ncognitox AWS SDK demo (endpoint: ${ENDPOINT})\n${"=".repeat(50)}`);

  // 1. Create User Pool
  const pool = await client.send(
    new CreateUserPoolCommand({ PoolName: "sdk-demo-pool" })
  );
  const poolId = pool.UserPool!.Id!;
  log("CreateUserPool", { Id: poolId, Name: pool.UserPool!.Name });

  // 2. Create User Pool Client
  const appClient = await client.send(
    new CreateUserPoolClientCommand({
      UserPoolId: poolId,
      ClientName: "sdk-demo-client",
      ExplicitAuthFlows: ["ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
    })
  );
  const clientId = appClient.UserPoolClient!.ClientId!;
  log("CreateUserPoolClient", { ClientId: clientId });

  // 3. Sign Up
  const signUp = await client.send(
    new SignUpCommand({
      ClientId: clientId,
      Username: "demo-user",
      Password: "P@ssw0rd!",
      UserAttributes: [
        { Name: "email", Value: "demo@example.com" },
      ],
    })
  );
  log("SignUp", { UserSub: signUp.UserSub, UserConfirmed: signUp.UserConfirmed });

  // 4. Admin Confirm Sign Up
  await client.send(
    new AdminConfirmSignUpCommand({
      UserPoolId: poolId,
      Username: "demo-user",
    })
  );
  log("AdminConfirmSignUp");

  // 5. Initiate Auth (USER_PASSWORD_AUTH)
  const auth = await client.send(
    new InitiateAuthCommand({
      ClientId: clientId,
      AuthFlow: "USER_PASSWORD_AUTH",
      AuthParameters: {
        USERNAME: "demo-user",
        PASSWORD: "P@ssw0rd!",
      },
    })
  );
  const accessToken = auth.AuthenticationResult!.AccessToken!;
  log("InitiateAuth", {
    TokenType: auth.AuthenticationResult!.TokenType,
    ExpiresIn: auth.AuthenticationResult!.ExpiresIn,
  });

  // 6. Get User (with access token)
  const user = await client.send(
    new GetUserCommand({ AccessToken: accessToken })
  );
  log("GetUser", { Username: user.Username, Attributes: user.UserAttributes });

  // 7. List Users
  const list = await client.send(
    new ListUsersCommand({ UserPoolId: poolId })
  );
  log("ListUsers", { Count: list.Users?.length });

  // 8. Cleanup
  await client.send(
    new DeleteUserCommand({ AccessToken: accessToken })
  );
  log("DeleteUser");

  await client.send(
    new DeleteUserPoolCommand({ UserPoolId: poolId })
  );
  log("DeleteUserPool");

  console.log("\n" + "=".repeat(50));
  console.log("Demo complete! All operations succeeded.\n");
}

main().catch((err) => {
  console.error("Demo failed:", err);
  process.exit(1);
});
