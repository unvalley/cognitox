//! Group API tests

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
async fn test_create_group() {
    let client = TestClient::new();
    let (pool_id, _) = setup_pool_and_client(&client).await;

    let (status, body) = client
        .request(
            "CreateGroup",
            json!({
                "UserPoolId": pool_id,
                "GroupName": "Admins",
                "Description": "Administrator group",
                "Precedence": 1
            }),
        )
        .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["Group"]["GroupName"], "Admins");
    assert_eq!(body["Group"]["Description"], "Administrator group");
    assert_eq!(body["Group"]["Precedence"], 1);
}

#[tokio::test]
async fn test_create_group_duplicate() {
    let client = TestClient::new();
    let (pool_id, _) = setup_pool_and_client(&client).await;

    client
        .request(
            "CreateGroup",
            json!({
                "UserPoolId": pool_id,
                "GroupName": "Admins"
            }),
        )
        .await;

    let (status, body) = client
        .request(
            "CreateGroup",
            json!({
                "UserPoolId": pool_id,
                "GroupName": "Admins"
            }),
        )
        .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["__type"], "GroupExistsException");
}

#[tokio::test]
async fn test_get_group() {
    let client = TestClient::new();
    let (pool_id, _) = setup_pool_and_client(&client).await;

    client
        .request(
            "CreateGroup",
            json!({
                "UserPoolId": pool_id,
                "GroupName": "Admins",
                "Description": "Admin group"
            }),
        )
        .await;

    let (status, body) = client
        .request(
            "GetGroup",
            json!({
                "UserPoolId": pool_id,
                "GroupName": "Admins"
            }),
        )
        .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["Group"]["GroupName"], "Admins");
    assert_eq!(body["Group"]["Description"], "Admin group");
}

#[tokio::test]
async fn test_get_group_not_found() {
    let client = TestClient::new();
    let (pool_id, _) = setup_pool_and_client(&client).await;

    let (status, body) = client
        .request(
            "GetGroup",
            json!({
                "UserPoolId": pool_id,
                "GroupName": "NonExistent"
            }),
        )
        .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["__type"], "ResourceNotFoundException");
}

#[tokio::test]
async fn test_delete_group() {
    let client = TestClient::new();
    let (pool_id, _) = setup_pool_and_client(&client).await;

    client
        .request(
            "CreateGroup",
            json!({
                "UserPoolId": pool_id,
                "GroupName": "ToDelete"
            }),
        )
        .await;

    let (status, _) = client
        .request(
            "DeleteGroup",
            json!({
                "UserPoolId": pool_id,
                "GroupName": "ToDelete"
            }),
        )
        .await;

    assert_eq!(status, StatusCode::OK);

    // Verify deleted
    let (status, _) = client
        .request(
            "GetGroup",
            json!({
                "UserPoolId": pool_id,
                "GroupName": "ToDelete"
            }),
        )
        .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_list_groups() {
    let client = TestClient::new();
    let (pool_id, _) = setup_pool_and_client(&client).await;

    client
        .request(
            "CreateGroup",
            json!({ "UserPoolId": pool_id, "GroupName": "Admins" }),
        )
        .await;
    client
        .request(
            "CreateGroup",
            json!({ "UserPoolId": pool_id, "GroupName": "Users" }),
        )
        .await;

    let (status, body) = client
        .request("ListGroups", json!({ "UserPoolId": pool_id }))
        .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["Groups"].as_array().unwrap().len(), 2);
}

#[tokio::test]
async fn test_admin_add_user_to_group() {
    let client = TestClient::new();
    let (pool_id, _) = setup_pool_and_client(&client).await;

    // Create user
    client
        .request(
            "AdminCreateUser",
            json!({
                "UserPoolId": pool_id,
                "Username": "testuser"
            }),
        )
        .await;

    // Create group
    client
        .request(
            "CreateGroup",
            json!({
                "UserPoolId": pool_id,
                "GroupName": "Admins"
            }),
        )
        .await;

    // Add user to group
    let (status, _) = client
        .request(
            "AdminAddUserToGroup",
            json!({
                "UserPoolId": pool_id,
                "Username": "testuser",
                "GroupName": "Admins"
            }),
        )
        .await;

    assert_eq!(status, StatusCode::OK);

    // Verify user is in group
    let (status, body) = client
        .request(
            "AdminListGroupsForUser",
            json!({
                "UserPoolId": pool_id,
                "Username": "testuser"
            }),
        )
        .await;

    assert_eq!(status, StatusCode::OK);
    let groups = body["Groups"].as_array().unwrap();
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0]["GroupName"], "Admins");
}

#[tokio::test]
async fn test_admin_remove_user_from_group() {
    let client = TestClient::new();
    let (pool_id, _) = setup_pool_and_client(&client).await;

    // Create user
    client
        .request(
            "AdminCreateUser",
            json!({
                "UserPoolId": pool_id,
                "Username": "testuser"
            }),
        )
        .await;

    // Create group
    client
        .request(
            "CreateGroup",
            json!({
                "UserPoolId": pool_id,
                "GroupName": "Admins"
            }),
        )
        .await;

    // Add user to group
    client
        .request(
            "AdminAddUserToGroup",
            json!({
                "UserPoolId": pool_id,
                "Username": "testuser",
                "GroupName": "Admins"
            }),
        )
        .await;

    // Remove user from group
    let (status, _) = client
        .request(
            "AdminRemoveUserFromGroup",
            json!({
                "UserPoolId": pool_id,
                "Username": "testuser",
                "GroupName": "Admins"
            }),
        )
        .await;

    assert_eq!(status, StatusCode::OK);

    // Verify user is no longer in group
    let (_, body) = client
        .request(
            "AdminListGroupsForUser",
            json!({
                "UserPoolId": pool_id,
                "Username": "testuser"
            }),
        )
        .await;

    assert!(body["Groups"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn test_list_users_in_group() {
    let client = TestClient::new();
    let (pool_id, _) = setup_pool_and_client(&client).await;

    // Create users
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

    // Create group
    client
        .request(
            "CreateGroup",
            json!({ "UserPoolId": pool_id, "GroupName": "Admins" }),
        )
        .await;

    // Add users to group
    client
        .request(
            "AdminAddUserToGroup",
            json!({
                "UserPoolId": pool_id,
                "Username": "user1",
                "GroupName": "Admins"
            }),
        )
        .await;
    client
        .request(
            "AdminAddUserToGroup",
            json!({
                "UserPoolId": pool_id,
                "Username": "user2",
                "GroupName": "Admins"
            }),
        )
        .await;

    let (status, body) = client
        .request(
            "ListUsersInGroup",
            json!({
                "UserPoolId": pool_id,
                "GroupName": "Admins"
            }),
        )
        .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["Users"].as_array().unwrap().len(), 2);
}
