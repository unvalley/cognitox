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

#[tokio::test]
async fn test_describe_user_pool_client() {
    let client = TestClient::new();

    let (_, pool_body) = client
        .request("CreateUserPool", json!({ "PoolName": "TestPool" }))
        .await;

    let pool_id = pool_body["UserPool"]["Id"].as_str().unwrap();

    let (_, create_body) = client
        .request(
            "CreateUserPoolClient",
            json!({
                "UserPoolId": pool_id,
                "ClientName": "TestClient",
                "GenerateSecret": true
            }),
        )
        .await;

    let client_id = create_body["UserPoolClient"]["ClientId"].as_str().unwrap();

    let (status, body) = client
        .request(
            "DescribeUserPoolClient",
            json!({
                "UserPoolId": pool_id,
                "ClientId": client_id
            }),
        )
        .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["UserPoolClient"]["ClientId"], client_id);
    assert_eq!(body["UserPoolClient"]["ClientName"], "TestClient");
    assert_eq!(body["UserPoolClient"]["UserPoolId"], pool_id);
    assert!(body["UserPoolClient"]["ClientSecret"].as_str().is_some());
}

#[tokio::test]
async fn test_describe_user_pool_client_not_found() {
    let client = TestClient::new();

    let (_, pool_body) = client
        .request("CreateUserPool", json!({ "PoolName": "TestPool" }))
        .await;

    let pool_id = pool_body["UserPool"]["Id"].as_str().unwrap();

    let (status, body) = client
        .request(
            "DescribeUserPoolClient",
            json!({
                "UserPoolId": pool_id,
                "ClientId": "nonexistent"
            }),
        )
        .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["__type"], "ResourceNotFoundException");
}

// ==================== User Pool Domain Tests ====================

#[tokio::test]
async fn test_create_user_pool_domain() {
    let client = TestClient::new();

    let (_, pool_body) = client
        .request("CreateUserPool", json!({ "PoolName": "TestPool" }))
        .await;

    let pool_id = pool_body["UserPool"]["Id"].as_str().unwrap();

    let (status, _) = client
        .request(
            "CreateUserPoolDomain",
            json!({
                "Domain": "my-test-domain",
                "UserPoolId": pool_id
            }),
        )
        .await;

    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn test_create_user_pool_domain_with_managed_login() {
    let client = TestClient::new();

    let (_, pool_body) = client
        .request("CreateUserPool", json!({ "PoolName": "TestPool" }))
        .await;

    let pool_id = pool_body["UserPool"]["Id"].as_str().unwrap();

    let (status, _) = client
        .request(
            "CreateUserPoolDomain",
            json!({
                "Domain": "my-managed-domain",
                "UserPoolId": pool_id,
                "ManagedLoginVersion": 2
            }),
        )
        .await;

    assert_eq!(status, StatusCode::OK);

    // Verify the domain was created with ManagedLoginVersion
    let (_, describe_body) = client
        .request(
            "DescribeUserPoolDomain",
            json!({ "Domain": "my-managed-domain" }),
        )
        .await;

    assert_eq!(describe_body["DomainDescription"]["ManagedLoginVersion"], 2);
}

#[tokio::test]
async fn test_describe_user_pool_domain() {
    let client = TestClient::new();

    let (_, pool_body) = client
        .request("CreateUserPool", json!({ "PoolName": "TestPool" }))
        .await;

    let pool_id = pool_body["UserPool"]["Id"].as_str().unwrap();

    client
        .request(
            "CreateUserPoolDomain",
            json!({
                "Domain": "describe-test-domain",
                "UserPoolId": pool_id
            }),
        )
        .await;

    let (status, body) = client
        .request(
            "DescribeUserPoolDomain",
            json!({ "Domain": "describe-test-domain" }),
        )
        .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["DomainDescription"]["Domain"], "describe-test-domain");
    assert_eq!(body["DomainDescription"]["UserPoolId"], pool_id);
    assert_eq!(body["DomainDescription"]["Status"], "ACTIVE");
}

#[tokio::test]
async fn test_describe_user_pool_domain_not_found() {
    let client = TestClient::new();

    let (status, body) = client
        .request(
            "DescribeUserPoolDomain",
            json!({ "Domain": "nonexistent-domain" }),
        )
        .await;

    assert_eq!(status, StatusCode::OK);
    // AWS returns an empty DomainDescription when domain doesn't exist
    assert!(body["DomainDescription"].as_object().unwrap().is_empty());
}

#[tokio::test]
async fn test_delete_user_pool_domain() {
    let client = TestClient::new();

    let (_, pool_body) = client
        .request("CreateUserPool", json!({ "PoolName": "TestPool" }))
        .await;

    let pool_id = pool_body["UserPool"]["Id"].as_str().unwrap();

    client
        .request(
            "CreateUserPoolDomain",
            json!({
                "Domain": "delete-test-domain",
                "UserPoolId": pool_id
            }),
        )
        .await;

    let (status, _) = client
        .request(
            "DeleteUserPoolDomain",
            json!({
                "Domain": "delete-test-domain",
                "UserPoolId": pool_id
            }),
        )
        .await;

    assert_eq!(status, StatusCode::OK);

    // Verify it's deleted
    let (_, body) = client
        .request(
            "DescribeUserPoolDomain",
            json!({ "Domain": "delete-test-domain" }),
        )
        .await;

    assert!(body["DomainDescription"].as_object().unwrap().is_empty());
}

#[tokio::test]
async fn test_update_user_pool_domain() {
    let client = TestClient::new();

    let (_, pool_body) = client
        .request("CreateUserPool", json!({ "PoolName": "TestPool" }))
        .await;

    let pool_id = pool_body["UserPool"]["Id"].as_str().unwrap();

    client
        .request(
            "CreateUserPoolDomain",
            json!({
                "Domain": "update-test-domain",
                "UserPoolId": pool_id
            }),
        )
        .await;

    let (status, _) = client
        .request(
            "UpdateUserPoolDomain",
            json!({
                "Domain": "update-test-domain",
                "UserPoolId": pool_id,
                "ManagedLoginVersion": 2
            }),
        )
        .await;

    assert_eq!(status, StatusCode::OK);

    // Verify the update
    let (_, body) = client
        .request(
            "DescribeUserPoolDomain",
            json!({ "Domain": "update-test-domain" }),
        )
        .await;

    assert_eq!(body["DomainDescription"]["ManagedLoginVersion"], 2);
    assert_eq!(body["DomainDescription"]["Version"], "2"); // Version should be incremented
}

#[tokio::test]
async fn test_create_user_pool_domain_duplicate() {
    let client = TestClient::new();

    let (_, pool_body) = client
        .request("CreateUserPool", json!({ "PoolName": "TestPool" }))
        .await;

    let pool_id = pool_body["UserPool"]["Id"].as_str().unwrap();

    // Create first domain
    client
        .request(
            "CreateUserPoolDomain",
            json!({
                "Domain": "duplicate-test-domain",
                "UserPoolId": pool_id
            }),
        )
        .await;

    // Try to create domain with same name for different pool
    let (_, pool_body2) = client
        .request("CreateUserPool", json!({ "PoolName": "TestPool2" }))
        .await;

    let pool_id2 = pool_body2["UserPool"]["Id"].as_str().unwrap();

    let (status, body) = client
        .request(
            "CreateUserPoolDomain",
            json!({
                "Domain": "duplicate-test-domain",
                "UserPoolId": pool_id2
            }),
        )
        .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["__type"], "InvalidParameterException");
}

// ==================== User Pool Client OAuth Tests ====================

#[tokio::test]
async fn test_create_user_pool_client_with_oauth() {
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
                "ClientName": "OAuthClient",
                "AllowedOAuthFlows": ["code", "implicit"],
                "AllowedOAuthScopes": ["openid", "email", "profile"],
                "AllowedOAuthFlowsUserPoolClient": true,
                "CallbackURLs": ["https://example.com/callback"],
                "LogoutURLs": ["https://example.com/logout"],
                "SupportedIdentityProviders": ["COGNITO"],
                "ExplicitAuthFlows": ["ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"]
            }),
        )
        .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["UserPoolClient"]["AllowedOAuthFlows"],
        json!(["code", "implicit"])
    );
    assert_eq!(
        body["UserPoolClient"]["AllowedOAuthScopes"],
        json!(["openid", "email", "profile"])
    );
    assert_eq!(
        body["UserPoolClient"]["AllowedOAuthFlowsUserPoolClient"],
        true
    );
    assert_eq!(
        body["UserPoolClient"]["CallbackURLs"],
        json!(["https://example.com/callback"])
    );
    assert_eq!(
        body["UserPoolClient"]["LogoutURLs"],
        json!(["https://example.com/logout"])
    );
}

#[tokio::test]
async fn test_create_user_pool_client_with_token_validity() {
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
                "ClientName": "TokenClient",
                "AccessTokenValidity": 60,
                "IdTokenValidity": 60,
                "RefreshTokenValidity": 30,
                "TokenValidityUnits": {
                    "AccessToken": "minutes",
                    "IdToken": "minutes",
                    "RefreshToken": "days"
                }
            }),
        )
        .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["UserPoolClient"]["AccessTokenValidity"], 60);
    assert_eq!(body["UserPoolClient"]["IdTokenValidity"], 60);
    assert_eq!(body["UserPoolClient"]["RefreshTokenValidity"], 30);
    assert_eq!(
        body["UserPoolClient"]["TokenValidityUnits"]["AccessToken"],
        "minutes"
    );
}

#[tokio::test]
async fn test_update_user_pool_client() {
    let client = TestClient::new();

    let (_, pool_body) = client
        .request("CreateUserPool", json!({ "PoolName": "TestPool" }))
        .await;

    let pool_id = pool_body["UserPool"]["Id"].as_str().unwrap();

    let (_, create_body) = client
        .request(
            "CreateUserPoolClient",
            json!({
                "UserPoolId": pool_id,
                "ClientName": "OriginalClient"
            }),
        )
        .await;

    let client_id = create_body["UserPoolClient"]["ClientId"].as_str().unwrap();

    // Update the client with OAuth settings
    let (status, body) = client
        .request(
            "UpdateUserPoolClient",
            json!({
                "UserPoolId": pool_id,
                "ClientId": client_id,
                "ClientName": "UpdatedClient",
                "AllowedOAuthFlows": ["code"],
                "AllowedOAuthScopes": ["openid", "email"],
                "AllowedOAuthFlowsUserPoolClient": true,
                "CallbackURLs": ["https://updated.example.com/callback"]
            }),
        )
        .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["UserPoolClient"]["ClientName"], "UpdatedClient");
    assert_eq!(body["UserPoolClient"]["AllowedOAuthFlows"], json!(["code"]));
    assert_eq!(
        body["UserPoolClient"]["AllowedOAuthScopes"],
        json!(["openid", "email"])
    );
    assert_eq!(
        body["UserPoolClient"]["CallbackURLs"],
        json!(["https://updated.example.com/callback"])
    );
}

#[tokio::test]
async fn test_update_user_pool_client_not_found() {
    let client = TestClient::new();

    let (_, pool_body) = client
        .request("CreateUserPool", json!({ "PoolName": "TestPool" }))
        .await;

    let pool_id = pool_body["UserPool"]["Id"].as_str().unwrap();

    let (status, body) = client
        .request(
            "UpdateUserPoolClient",
            json!({
                "UserPoolId": pool_id,
                "ClientId": "nonexistent",
                "ClientName": "UpdatedClient"
            }),
        )
        .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["__type"], "ResourceNotFoundException");
}
