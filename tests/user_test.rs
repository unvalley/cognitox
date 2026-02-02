//! User API tests

mod common;

use axum::http::StatusCode;
use serde_json::json;

use common::TestClient;

async fn setup_pool_and_client(client: &TestClient) -> (String, String) {
    let (_, pool_body) = client
        .request("CreateUserPool", json!({ "PoolName": "TestPool" }))
        .await;

    let pool_id = pool_body["UserPool"]["Id"].as_str().unwrap().to_string();

    let (_, client_body) = client
        .request(
            "CreateUserPoolClient",
            json!({ "UserPoolId": pool_id, "ClientName": "TestClient" }),
        )
        .await;

    let client_id = client_body["UserPoolClient"]["ClientId"]
        .as_str()
        .unwrap()
        .to_string();

    (pool_id, client_id)
}

#[tokio::test]
async fn test_sign_up() {
    let client = TestClient::new();
    let (_, client_id) = setup_pool_and_client(&client).await;

    let (status, body) = client
        .request(
            "SignUp",
            json!({
                "ClientId": client_id,
                "Username": "testuser",
                "Password": "Password123!",
                "UserAttributes": [
                    { "Name": "email", "Value": "test@example.com" }
                ]
            }),
        )
        .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["UserConfirmed"], false);
    assert!(body["UserSub"].as_str().is_some());
}

#[tokio::test]
async fn test_sign_up_duplicate_user() {
    let client = TestClient::new();
    let (_, client_id) = setup_pool_and_client(&client).await;

    client
        .request(
            "SignUp",
            json!({
                "ClientId": client_id,
                "Username": "testuser",
                "Password": "Password123!"
            }),
        )
        .await;

    let (status, body) = client
        .request(
            "SignUp",
            json!({
                "ClientId": client_id,
                "Username": "testuser",
                "Password": "Password456!"
            }),
        )
        .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["__type"], "UsernameExistsException");
}

#[tokio::test]
async fn test_admin_create_user() {
    let client = TestClient::new();
    let (pool_id, _) = setup_pool_and_client(&client).await;

    let (status, body) = client
        .request(
            "AdminCreateUser",
            json!({
                "UserPoolId": pool_id,
                "Username": "adminuser",
                "TemporaryPassword": "TempPass123!",
                "UserAttributes": [
                    { "Name": "email", "Value": "admin@example.com" }
                ]
            }),
        )
        .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["User"]["Username"], "adminuser");
    assert_eq!(body["User"]["UserStatus"], "FORCE_CHANGE_PASSWORD");
}

#[tokio::test]
async fn test_admin_get_user() {
    let client = TestClient::new();
    let (pool_id, _) = setup_pool_and_client(&client).await;

    client
        .request(
            "AdminCreateUser",
            json!({
                "UserPoolId": pool_id,
                "Username": "testuser"
            }),
        )
        .await;

    let (status, body) = client
        .request(
            "AdminGetUser",
            json!({
                "UserPoolId": pool_id,
                "Username": "testuser"
            }),
        )
        .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["Username"], "testuser");
}

#[tokio::test]
async fn test_admin_get_user_not_found() {
    let client = TestClient::new();
    let (pool_id, _) = setup_pool_and_client(&client).await;

    let (status, body) = client
        .request(
            "AdminGetUser",
            json!({
                "UserPoolId": pool_id,
                "Username": "nonexistent"
            }),
        )
        .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["__type"], "UserNotFoundException");
}

#[tokio::test]
async fn test_admin_delete_user() {
    let client = TestClient::new();
    let (pool_id, _) = setup_pool_and_client(&client).await;

    client
        .request(
            "AdminCreateUser",
            json!({
                "UserPoolId": pool_id,
                "Username": "testuser"
            }),
        )
        .await;

    let (status, _) = client
        .request(
            "AdminDeleteUser",
            json!({
                "UserPoolId": pool_id,
                "Username": "testuser"
            }),
        )
        .await;

    assert_eq!(status, StatusCode::OK);

    // Verify deleted
    let (status, _) = client
        .request(
            "AdminGetUser",
            json!({
                "UserPoolId": pool_id,
                "Username": "testuser"
            }),
        )
        .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_list_users() {
    let client = TestClient::new();
    let (pool_id, _) = setup_pool_and_client(&client).await;

    client
        .request(
            "AdminCreateUser",
            json!({ "UserPoolId": pool_id, "Username": "user1" }),
        )
        .await;
    client
        .request(
            "AdminCreateUser",
            json!({ "UserPoolId": pool_id, "Username": "user2" }),
        )
        .await;

    let (status, body) = client
        .request("ListUsers", json!({ "UserPoolId": pool_id }))
        .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["Users"].as_array().unwrap().len(), 2);
}
