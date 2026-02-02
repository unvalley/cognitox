//! User Pool API tests

mod common;

use axum::http::StatusCode;
use serde_json::json;

use common::TestClient;

#[tokio::test]
async fn test_create_user_pool() {
    let client = TestClient::new();

    let (status, body) = client
        .request("CreateUserPool", json!({ "PoolName": "TestPool" }))
        .await;

    assert_eq!(status, StatusCode::OK);
    assert!(body["UserPool"]["Id"].as_str().is_some());
    assert_eq!(body["UserPool"]["Name"], "TestPool");
}

#[tokio::test]
async fn test_list_user_pools() {
    let client = TestClient::new();

    // Create two pools
    client
        .request("CreateUserPool", json!({ "PoolName": "Pool1" }))
        .await;
    client
        .request("CreateUserPool", json!({ "PoolName": "Pool2" }))
        .await;

    let (status, body) = client
        .request("ListUserPools", json!({ "MaxResults": 10 }))
        .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["UserPools"].as_array().unwrap().len(), 2);
}

#[tokio::test]
async fn test_describe_user_pool() {
    let client = TestClient::new();

    let (_, create_body) = client
        .request("CreateUserPool", json!({ "PoolName": "TestPool" }))
        .await;

    let pool_id = create_body["UserPool"]["Id"].as_str().unwrap();

    let (status, body) = client
        .request("DescribeUserPool", json!({ "UserPoolId": pool_id }))
        .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["UserPool"]["Id"], pool_id);
    assert_eq!(body["UserPool"]["Name"], "TestPool");
}

#[tokio::test]
async fn test_describe_user_pool_not_found() {
    let client = TestClient::new();

    let (status, body) = client
        .request("DescribeUserPool", json!({ "UserPoolId": "nonexistent" }))
        .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["__type"], "ResourceNotFoundException");
}

#[tokio::test]
async fn test_delete_user_pool() {
    let client = TestClient::new();

    let (_, create_body) = client
        .request("CreateUserPool", json!({ "PoolName": "TestPool" }))
        .await;

    let pool_id = create_body["UserPool"]["Id"].as_str().unwrap();

    let (status, _) = client
        .request("DeleteUserPool", json!({ "UserPoolId": pool_id }))
        .await;

    assert_eq!(status, StatusCode::OK);

    // Verify it's deleted
    let (status, _) = client
        .request("DescribeUserPool", json!({ "UserPoolId": pool_id }))
        .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_create_user_pool_client() {
    let client = TestClient::new();

    let (_, pool_body) = client
        .request("CreateUserPool", json!({ "PoolName": "TestPool" }))
        .await;

    let pool_id = pool_body["UserPool"]["Id"].as_str().unwrap();

    let (status, body) = client
        .request(
            "CreateUserPoolClient",
            json!({
                "UserPoolId": pool_id,
                "ClientName": "TestClient"
            }),
        )
        .await;

    assert_eq!(status, StatusCode::OK);
    assert!(body["UserPoolClient"]["ClientId"].as_str().is_some());
    assert_eq!(body["UserPoolClient"]["ClientName"], "TestClient");
    assert_eq!(body["UserPoolClient"]["UserPoolId"], pool_id);
}

#[tokio::test]
async fn test_create_user_pool_client_with_secret() {
    let client = TestClient::new();

    let (_, pool_body) = client
        .request("CreateUserPool", json!({ "PoolName": "TestPool" }))
        .await;

    let pool_id = pool_body["UserPool"]["Id"].as_str().unwrap();

    let (status, body) = client
        .request(
            "CreateUserPoolClient",
            json!({
                "UserPoolId": pool_id,
                "ClientName": "TestClient",
                "GenerateSecret": true
            }),
        )
        .await;

    assert_eq!(status, StatusCode::OK);
    assert!(body["UserPoolClient"]["ClientSecret"].as_str().is_some());
}

#[tokio::test]
async fn test_list_user_pool_clients() {
    let client = TestClient::new();

    let (_, pool_body) = client
        .request("CreateUserPool", json!({ "PoolName": "TestPool" }))
        .await;

    let pool_id = pool_body["UserPool"]["Id"].as_str().unwrap();

    // Create two clients
    client
        .request(
            "CreateUserPoolClient",
            json!({ "UserPoolId": pool_id, "ClientName": "Client1" }),
        )
        .await;
    client
        .request(
            "CreateUserPoolClient",
            json!({ "UserPoolId": pool_id, "ClientName": "Client2" }),
        )
        .await;

    let (status, body) = client
        .request(
            "ListUserPoolClients",
            json!({ "UserPoolId": pool_id, "MaxResults": 10 }),
        )
        .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["UserPoolClients"].as_array().unwrap().len(), 2);
}

#[tokio::test]
async fn test_delete_user_pool_client() {
    let client = TestClient::new();

    let (_, pool_body) = client
        .request("CreateUserPool", json!({ "PoolName": "TestPool" }))
        .await;

    let pool_id = pool_body["UserPool"]["Id"].as_str().unwrap();

    let (_, client_body) = client
        .request(
            "CreateUserPoolClient",
            json!({ "UserPoolId": pool_id, "ClientName": "TestClient" }),
        )
        .await;

    let client_id = client_body["UserPoolClient"]["ClientId"].as_str().unwrap();

    let (status, _) = client
        .request(
            "DeleteUserPoolClient",
            json!({ "UserPoolId": pool_id, "ClientId": client_id }),
        )
        .await;

    assert_eq!(status, StatusCode::OK);

    // Verify it's deleted
    let (_, list_body) = client
        .request(
            "ListUserPoolClients",
            json!({ "UserPoolId": pool_id, "MaxResults": 10 }),
        )
        .await;

    assert_eq!(list_body["UserPoolClients"].as_array().unwrap().len(), 0);
}
