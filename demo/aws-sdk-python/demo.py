"""
cognitox AWS SDK for Python (boto3) demo

Demonstrates the full user lifecycle using boto3
pointed at the local cognitox emulator.

Usage:
    pip install -r requirements.txt
    python demo.py

Requires cognitox running on localhost:9229 (default).
"""

import json
import os
import sys

import boto3

ENDPOINT = os.environ.get("COGNITOX_URL", "http://localhost:9229")


def log(label: str, data=None):
    print(f"\n✓ {label}")
    if data:
        print(json.dumps(data, indent=2, default=str))


def main():
    print(f"\ncognitox boto3 demo (endpoint: {ENDPOINT})")
    print("=" * 50)

    client = boto3.client(
        "cognito-idp",
        region_name="local",
        endpoint_url=ENDPOINT,
        aws_access_key_id="local",
        aws_secret_access_key="local",
    )

    # 1. Create User Pool
    pool = client.create_user_pool(PoolName="boto3-demo-pool")
    pool_id = pool["UserPool"]["Id"]
    log("CreateUserPool", {"Id": pool_id, "Name": pool["UserPool"]["Name"]})

    # 2. Create User Pool Client
    app_client = client.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName="boto3-demo-client",
        ExplicitAuthFlows=["ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
    )
    client_id = app_client["UserPoolClient"]["ClientId"]
    log("CreateUserPoolClient", {"ClientId": client_id})

    # 3. Sign Up
    sign_up = client.sign_up(
        ClientId=client_id,
        Username="demo-user",
        Password="P@ssw0rd!",
        UserAttributes=[{"Name": "email", "Value": "demo@example.com"}],
    )
    log("SignUp", {"UserSub": sign_up["UserSub"], "UserConfirmed": sign_up["UserConfirmed"]})

    # 4. Admin Confirm Sign Up
    client.admin_confirm_sign_up(UserPoolId=pool_id, Username="demo-user")
    log("AdminConfirmSignUp")

    # 5. Initiate Auth
    auth = client.initiate_auth(
        ClientId=client_id,
        AuthFlow="USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": "demo-user", "PASSWORD": "P@ssw0rd!"},
    )
    access_token = auth["AuthenticationResult"]["AccessToken"]
    log("InitiateAuth", {
        "TokenType": auth["AuthenticationResult"]["TokenType"],
        "ExpiresIn": auth["AuthenticationResult"]["ExpiresIn"],
    })

    # 6. Get User
    user = client.get_user(AccessToken=access_token)
    log("GetUser", {"Username": user["Username"], "Attributes": user.get("UserAttributes", [])})

    # 7. List Users
    users = client.list_users(UserPoolId=pool_id)
    log("ListUsers", {"Count": len(users.get("Users", []))})

    # 8. Cleanup
    client.delete_user(AccessToken=access_token)
    log("DeleteUser")

    client.delete_user_pool(UserPoolId=pool_id)
    log("DeleteUserPool")

    print("\n" + "=" * 50)
    print("Demo complete! All operations succeeded.\n")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"Demo failed: {e}", file=sys.stderr)
        sys.exit(1)
