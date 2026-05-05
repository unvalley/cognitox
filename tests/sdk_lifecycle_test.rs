mod common;

use common::TestClient;
use serde_json::json;

#[tokio::test]
async fn sdk_demo_lifecycle_over_cognito_json_api() {
    let client = TestClient::new();

    let pool = client
        .cognito_request("CreateUserPool", json!({"PoolName": "sdk-demo-pool"}))
        .await;
    let pool_id = pool["UserPool"]["Id"].as_str().unwrap();
    assert_eq!(pool["UserPool"]["Name"], "sdk-demo-pool");

    let app_client = client
        .cognito_request(
            "CreateUserPoolClient",
            json!({
                "UserPoolId": pool_id,
                "ClientName": "sdk-demo-client",
                "ExplicitAuthFlows": [
                    "ALLOW_USER_PASSWORD_AUTH",
                    "ALLOW_REFRESH_TOKEN_AUTH"
                ]
            }),
        )
        .await;
    let client_id = app_client["UserPoolClient"]["ClientId"].as_str().unwrap();

    let sign_up = client
        .cognito_request(
            "SignUp",
            json!({
                "ClientId": client_id,
                "Username": "demo-user",
                "Password": "P@ssw0rd!",
                "UserAttributes": [
                    {"Name": "email", "Value": "demo@example.com"}
                ]
            }),
        )
        .await;
    assert_eq!(sign_up["UserConfirmed"], false);
    assert!(sign_up["UserSub"].as_str().is_some());

    client
        .cognito_request(
            "AdminConfirmSignUp",
            json!({
                "UserPoolId": pool_id,
                "Username": "demo-user"
            }),
        )
        .await;

    let auth = client
        .cognito_request(
            "InitiateAuth",
            json!({
                "ClientId": client_id,
                "AuthFlow": "USER_PASSWORD_AUTH",
                "AuthParameters": {
                    "USERNAME": "demo-user",
                    "PASSWORD": "P@ssw0rd!"
                }
            }),
        )
        .await;
    let result = &auth["AuthenticationResult"];
    let access_token = result["AccessToken"].as_str().unwrap();
    assert_eq!(result["TokenType"], "Bearer");
    assert!(result["ExpiresIn"].as_i64().unwrap() > 0);
    assert!(result["RefreshToken"].as_str().is_some());

    let user = client
        .cognito_request("GetUser", json!({"AccessToken": access_token}))
        .await;
    assert_eq!(user["Username"], "demo-user");
    assert!(
        user["UserAttributes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|attr| attr["Name"] == "email" && attr["Value"] == "demo@example.com")
    );

    let users = client
        .cognito_request("ListUsers", json!({"UserPoolId": pool_id}))
        .await;
    assert_eq!(users["Users"].as_array().unwrap().len(), 1);

    client
        .cognito_request("DeleteUser", json!({"AccessToken": access_token}))
        .await;
    client
        .cognito_request("DeleteUserPool", json!({"UserPoolId": pool_id}))
        .await;
}
