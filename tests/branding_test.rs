//! Managed Login Branding API tests

mod common;

use axum::http::StatusCode;
use common::TestClient;
use serde_json::json;

#[tokio::test]
async fn test_create_managed_login_branding() {
    let client = TestClient::new();

    // Create a user pool first
    let (_, pool_body) = client
        .request("CreateUserPool", json!({ "PoolName": "test-pool" }))
        .await;

    let user_pool_id = pool_body["UserPool"]["Id"].as_str().unwrap();

    // Create branding
    let (status, body) = client
        .request(
            "CreateManagedLoginBranding",
            json!({
                "UserPoolId": user_pool_id,
                "UseCognitoProvidedValues": true,
                "Settings": {
                    "PageTitle": "My App Login",
                    "SignInHeader": "Welcome",
                    "SignInSubheader": "Please sign in",
                    "Colors": {
                        "PrimaryColor": "#007bff",
                        "BackgroundColor": "#ffffff"
                    }
                },
                "Assets": {
                    "LogoUrl": "https://example.com/logo.png"
                }
            }),
        )
        .await;

    assert_eq!(status, StatusCode::OK);
    assert!(body["ManagedLoginBranding"]["ManagedLoginBrandingId"]
        .as_str()
        .is_some());
    assert_eq!(body["ManagedLoginBranding"]["UserPoolId"], user_pool_id);
    assert_eq!(
        body["ManagedLoginBranding"]["UseCognitoProvidedValues"],
        true
    );
    assert_eq!(
        body["ManagedLoginBranding"]["Settings"]["PageTitle"],
        "My App Login"
    );
    assert_eq!(
        body["ManagedLoginBranding"]["Settings"]["Colors"]["PrimaryColor"],
        "#007bff"
    );
    assert_eq!(
        body["ManagedLoginBranding"]["Assets"]["LogoUrl"],
        "https://example.com/logo.png"
    );
}

#[tokio::test]
async fn test_describe_managed_login_branding() {
    let client = TestClient::new();

    // Create user pool
    let (_, pool_body) = client
        .request("CreateUserPool", json!({ "PoolName": "test-pool" }))
        .await;

    let user_pool_id = pool_body["UserPool"]["Id"].as_str().unwrap();

    // Create branding
    let (_, create_body) = client
        .request(
            "CreateManagedLoginBranding",
            json!({
                "UserPoolId": user_pool_id,
                "Settings": {
                    "PageTitle": "Test Title"
                }
            }),
        )
        .await;

    let branding_id = create_body["ManagedLoginBranding"]["ManagedLoginBrandingId"]
        .as_str()
        .unwrap();

    // Describe branding
    let (status, body) = client
        .request(
            "DescribeManagedLoginBranding",
            json!({
                "ManagedLoginBrandingId": branding_id,
                "UserPoolId": user_pool_id
            }),
        )
        .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["ManagedLoginBranding"]["ManagedLoginBrandingId"],
        branding_id
    );
    assert_eq!(
        body["ManagedLoginBranding"]["Settings"]["PageTitle"],
        "Test Title"
    );
}

#[tokio::test]
async fn test_describe_managed_login_branding_not_found() {
    let client = TestClient::new();

    // Create user pool
    let (_, pool_body) = client
        .request("CreateUserPool", json!({ "PoolName": "test-pool" }))
        .await;

    let user_pool_id = pool_body["UserPool"]["Id"].as_str().unwrap();

    // Try to describe non-existent branding
    let (status, _) = client
        .request(
            "DescribeManagedLoginBranding",
            json!({
                "ManagedLoginBrandingId": "non-existent-id",
                "UserPoolId": user_pool_id
            }),
        )
        .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_update_managed_login_branding() {
    let client = TestClient::new();

    // Create user pool
    let (_, pool_body) = client
        .request("CreateUserPool", json!({ "PoolName": "test-pool" }))
        .await;

    let user_pool_id = pool_body["UserPool"]["Id"].as_str().unwrap();

    // Create branding
    let (_, create_body) = client
        .request(
            "CreateManagedLoginBranding",
            json!({
                "UserPoolId": user_pool_id,
                "Settings": {
                    "PageTitle": "Original Title"
                }
            }),
        )
        .await;

    let branding_id = create_body["ManagedLoginBranding"]["ManagedLoginBrandingId"]
        .as_str()
        .unwrap();

    // Update branding
    let (status, body) = client
        .request(
            "UpdateManagedLoginBranding",
            json!({
                "ManagedLoginBrandingId": branding_id,
                "UserPoolId": user_pool_id,
                "Settings": {
                    "PageTitle": "Updated Title",
                    "SignInHeader": "New Header"
                }
            }),
        )
        .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["ManagedLoginBranding"]["Settings"]["PageTitle"],
        "Updated Title"
    );
    assert_eq!(
        body["ManagedLoginBranding"]["Settings"]["SignInHeader"],
        "New Header"
    );
}

#[tokio::test]
async fn test_delete_managed_login_branding() {
    let client = TestClient::new();

    // Create user pool
    let (_, pool_body) = client
        .request("CreateUserPool", json!({ "PoolName": "test-pool" }))
        .await;

    let user_pool_id = pool_body["UserPool"]["Id"].as_str().unwrap();

    // Create branding
    let (_, create_body) = client
        .request(
            "CreateManagedLoginBranding",
            json!({ "UserPoolId": user_pool_id }),
        )
        .await;

    let branding_id = create_body["ManagedLoginBranding"]["ManagedLoginBrandingId"]
        .as_str()
        .unwrap();

    // Delete branding
    let (status, _) = client
        .request(
            "DeleteManagedLoginBranding",
            json!({
                "ManagedLoginBrandingId": branding_id,
                "UserPoolId": user_pool_id
            }),
        )
        .await;

    assert_eq!(status, StatusCode::OK);

    // Verify it's deleted by trying to describe
    let (describe_status, _) = client
        .request(
            "DescribeManagedLoginBranding",
            json!({
                "ManagedLoginBrandingId": branding_id,
                "UserPoolId": user_pool_id
            }),
        )
        .await;

    assert_eq!(describe_status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_describe_managed_login_branding_by_client() {
    let client = TestClient::new();

    // Create user pool
    let (_, pool_body) = client
        .request("CreateUserPool", json!({ "PoolName": "test-pool" }))
        .await;

    let user_pool_id = pool_body["UserPool"]["Id"].as_str().unwrap();

    // Create user pool client
    let (_, client_body) = client
        .request(
            "CreateUserPoolClient",
            json!({
                "UserPoolId": user_pool_id,
                "ClientName": "test-client"
            }),
        )
        .await;

    let client_id = client_body["UserPoolClient"]["ClientId"].as_str().unwrap();

    // Create branding (without client_id - pool-level branding)
    client
        .request(
            "CreateManagedLoginBranding",
            json!({
                "UserPoolId": user_pool_id,
                "Settings": {
                    "PageTitle": "Pool-level Branding"
                }
            }),
        )
        .await;

    // Describe branding by client (should fall back to pool-level)
    let (status, body) = client
        .request(
            "DescribeManagedLoginBrandingByClient",
            json!({
                "ClientId": client_id,
                "UserPoolId": user_pool_id
            }),
        )
        .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["ManagedLoginBranding"]["Settings"]["PageTitle"],
        "Pool-level Branding"
    );
}

#[tokio::test]
async fn test_create_branding_duplicate() {
    let client = TestClient::new();

    // Create user pool
    let (_, pool_body) = client
        .request("CreateUserPool", json!({ "PoolName": "test-pool" }))
        .await;

    let user_pool_id = pool_body["UserPool"]["Id"].as_str().unwrap();

    // Create first branding
    let (first_status, _) = client
        .request(
            "CreateManagedLoginBranding",
            json!({ "UserPoolId": user_pool_id }),
        )
        .await;

    assert_eq!(first_status, StatusCode::OK);

    // Try to create second branding for same pool
    let (second_status, _) = client
        .request(
            "CreateManagedLoginBranding",
            json!({ "UserPoolId": user_pool_id }),
        )
        .await;

    assert_eq!(second_status, StatusCode::BAD_REQUEST);
}
