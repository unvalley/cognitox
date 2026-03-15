mod common;

use axum::http::StatusCode;
use common::TestClient;
use serde_json::json;

async fn create_pool(client: &TestClient, name: &str) -> String {
    let (_, body) = client
        .request("CreateUserPool", json!({ "PoolName": name }))
        .await;
    body["UserPool"]["Id"].as_str().unwrap().to_string()
}

async fn create_client(
    client: &TestClient,
    user_pool_id: &str,
    client_name: &str,
    oauth_enabled: bool,
) -> String {
    let mut request = json!({
        "UserPoolId": user_pool_id,
        "ClientName": client_name,
        "CallbackURLs": ["https://example.com/callback"]
    });

    if oauth_enabled {
        request["AllowedOAuthFlows"] = json!(["code", "implicit"]);
        request["AllowedOAuthScopes"] = json!(["openid", "email"]);
        request["AllowedOAuthFlowsUserPoolClient"] = json!(true);
    }

    let (_, body) = client.request("CreateUserPoolClient", request).await;
    body["UserPoolClient"]["ClientId"]
        .as_str()
        .unwrap()
        .to_string()
}

#[tokio::test]
async fn delete_user_pool_invalidates_its_clients() {
    let client = TestClient::new();
    let pool_id = create_pool(&client, "pool-to-delete").await;
    let client_id = create_client(&client, &pool_id, "stale-client", false).await;

    let (delete_status, _) = client
        .request("DeleteUserPool", json!({ "UserPoolId": pool_id }))
        .await;
    assert_eq!(delete_status, StatusCode::OK);

    let (sign_up_status, sign_up_body) = client
        .request(
            "SignUp",
            json!({
                "ClientId": client_id,
                "Username": "orphan-user",
                "Password": "Password123!"
            }),
        )
        .await;

    assert_eq!(sign_up_status, StatusCode::BAD_REQUEST);
    assert_eq!(sign_up_body["__type"], "ResourceNotFoundException");
}

#[tokio::test]
async fn delete_user_pool_client_rejects_cross_pool_client_ids() {
    let client = TestClient::new();
    let pool_1_id = create_pool(&client, "pool-1").await;
    let pool_2_id = create_pool(&client, "pool-2").await;
    let client_1_id = create_client(&client, &pool_1_id, "client-1", false).await;

    let (delete_status, delete_body) = client
        .request(
            "DeleteUserPoolClient",
            json!({
                "UserPoolId": pool_2_id,
                "ClientId": client_1_id
            }),
        )
        .await;

    assert_eq!(delete_status, StatusCode::BAD_REQUEST);
    assert_eq!(delete_body["__type"], "ResourceNotFoundException");

    let (describe_status, describe_body) = client
        .request(
            "DescribeUserPoolClient",
            json!({
                "UserPoolId": pool_1_id,
                "ClientId": client_1_id
            }),
        )
        .await;

    assert_eq!(describe_status, StatusCode::OK);
    assert_eq!(describe_body["UserPoolClient"]["ClientId"], client_1_id);
}

#[tokio::test]
async fn implicit_flow_rejects_unconfirmed_users() {
    let client = TestClient::new();
    let pool_id = create_pool(&client, "oauth-pool").await;
    let client_id = create_client(&client, &pool_id, "oauth-client", true).await;

    let (sign_up_status, _) = client
        .request(
            "SignUp",
            json!({
                "ClientId": client_id,
                "Username": "unconfirmed-user",
                "Password": "Password123!",
                "UserAttributes": [
                    { "Name": "email", "Value": "user@example.com" }
                ]
            }),
        )
        .await;
    assert_eq!(sign_up_status, StatusCode::OK);

    let response = client
        .get(&format!(
            "/oauth2/authorize?response_type=token&client_id={client_id}&redirect_uri=https://example.com/callback&scope=openid&username=unconfirmed-user&password=Password123!"
        ))
        .await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["error"], "access_denied");
    assert_eq!(body["error_description"], "User not confirmed");
}
