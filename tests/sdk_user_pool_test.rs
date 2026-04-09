//! Integration tests for User Pool operations using aws-sdk-rust.

mod sdk_common;

use aws_sdk_cognitoidentityprovider::types::ExplicitAuthFlowsType;
use sdk_common::TestServer;

#[tokio::test]
async fn test_create_and_describe_user_pool() {
    let server = TestServer::start().await;
    let client = server.client().await;

    let result = client
        .create_user_pool()
        .pool_name("sdk-test-pool")
        .send()
        .await
        .expect("CreateUserPool failed");

    let pool = result.user_pool().expect("missing user_pool in response");
    let pool_id = pool.id().expect("missing pool id");
    assert_eq!(pool.name().unwrap(), "sdk-test-pool");

    // Describe
    let described = client
        .describe_user_pool()
        .user_pool_id(pool_id)
        .send()
        .await
        .expect("DescribeUserPool failed");

    let described_pool = described.user_pool().unwrap();
    assert_eq!(described_pool.id().unwrap(), pool_id);
    assert_eq!(described_pool.name().unwrap(), "sdk-test-pool");
}

#[tokio::test]
async fn test_list_user_pools() {
    let server = TestServer::start().await;
    let client = server.client().await;

    for i in 0..3 {
        client
            .create_user_pool()
            .pool_name(format!("pool-{i}"))
            .send()
            .await
            .unwrap();
    }

    let result = client
        .list_user_pools()
        .max_results(10)
        .send()
        .await
        .expect("ListUserPools failed");

    assert_eq!(result.user_pools().len(), 3);
}

#[tokio::test]
async fn test_delete_user_pool() {
    let server = TestServer::start().await;
    let client = server.client().await;

    let pool = client
        .create_user_pool()
        .pool_name("to-delete")
        .send()
        .await
        .unwrap();
    let pool_id = pool.user_pool().unwrap().id().unwrap();

    client
        .delete_user_pool()
        .user_pool_id(pool_id)
        .send()
        .await
        .expect("DeleteUserPool failed");

    // Verify it's gone
    let result = client
        .describe_user_pool()
        .user_pool_id(pool_id)
        .send()
        .await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_create_user_pool_client() {
    let server = TestServer::start().await;
    let client = server.client().await;

    let pool = client
        .create_user_pool()
        .pool_name("client-test-pool")
        .send()
        .await
        .unwrap();
    let pool_id = pool.user_pool().unwrap().id().unwrap();

    let result = client
        .create_user_pool_client()
        .user_pool_id(pool_id)
        .client_name("test-app")
        .explicit_auth_flows(ExplicitAuthFlowsType::AllowUserPasswordAuth)
        .explicit_auth_flows(ExplicitAuthFlowsType::AllowRefreshTokenAuth)
        .send()
        .await
        .expect("CreateUserPoolClient failed");

    let app_client = result.user_pool_client().unwrap();
    assert_eq!(app_client.client_name().unwrap(), "test-app");
    assert!(app_client.client_id().is_some());
}
