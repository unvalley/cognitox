//! Integration tests for user authentication flow using aws-sdk-rust.

mod sdk_common;

use aws_sdk_cognitoidentityprovider::types::{AttributeType, AuthFlowType, ExplicitAuthFlowsType};
use sdk_common::TestServer;

/// Helper: create a pool + client + confirmed user, return (pool_id, client_id, username).
async fn setup_user(
    client: &aws_sdk_cognitoidentityprovider::Client,
    pool_name: &str,
) -> (String, String, String) {
    let pool = client
        .create_user_pool()
        .pool_name(pool_name)
        .send()
        .await
        .unwrap();
    let pool_id = pool.user_pool().unwrap().id().unwrap().to_string();

    let app = client
        .create_user_pool_client()
        .user_pool_id(&pool_id)
        .client_name("auth-test-client")
        .explicit_auth_flows(ExplicitAuthFlowsType::AllowUserPasswordAuth)
        .explicit_auth_flows(ExplicitAuthFlowsType::AllowRefreshTokenAuth)
        .send()
        .await
        .unwrap();
    let client_id = app
        .user_pool_client()
        .unwrap()
        .client_id()
        .unwrap()
        .to_string();

    let username = "testuser";
    let password = "P@ssw0rd!";

    client
        .sign_up()
        .client_id(&client_id)
        .username(username)
        .password(password)
        .user_attributes(
            AttributeType::builder()
                .name("email")
                .value("test@example.com")
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap();

    client
        .admin_confirm_sign_up()
        .user_pool_id(&pool_id)
        .username(username)
        .send()
        .await
        .unwrap();

    (pool_id, client_id, username.to_string())
}

#[tokio::test]
async fn test_sign_up_and_confirm() {
    let server = TestServer::start().await;
    let client = server.client().await;

    let pool = client
        .create_user_pool()
        .pool_name("signup-test")
        .send()
        .await
        .unwrap();
    let pool_id = pool.user_pool().unwrap().id().unwrap();

    let app = client
        .create_user_pool_client()
        .user_pool_id(pool_id)
        .client_name("signup-client")
        .explicit_auth_flows(ExplicitAuthFlowsType::AllowUserPasswordAuth)
        .send()
        .await
        .unwrap();
    let client_id = app.user_pool_client().unwrap().client_id().unwrap();

    let signup = client
        .sign_up()
        .client_id(client_id)
        .username("newuser")
        .password("P@ssw0rd!")
        .user_attributes(
            AttributeType::builder()
                .name("email")
                .value("new@example.com")
                .build()
                .unwrap(),
        )
        .send()
        .await
        .expect("SignUp failed");

    assert!(!signup.user_confirmed());
    assert!(!signup.user_sub().is_empty());

    client
        .admin_confirm_sign_up()
        .user_pool_id(pool_id)
        .username("newuser")
        .send()
        .await
        .expect("AdminConfirmSignUp failed");

    // Verify user is confirmed via AdminGetUser
    let user = client
        .admin_get_user()
        .user_pool_id(pool_id)
        .username("newuser")
        .send()
        .await
        .expect("AdminGetUser failed");

    assert_eq!(user.user_status().unwrap().as_str(), "CONFIRMED");
}

#[tokio::test]
async fn test_initiate_auth_user_password() {
    let server = TestServer::start().await;
    let client = server.client().await;

    let (_pool_id, client_id, _username) = setup_user(&client, "auth-test").await;

    let auth = client
        .initiate_auth()
        .client_id(&client_id)
        .auth_flow(AuthFlowType::UserPasswordAuth)
        .auth_parameters("USERNAME", "testuser")
        .auth_parameters("PASSWORD", "P@ssw0rd!")
        .send()
        .await
        .expect("InitiateAuth failed");

    let result = auth.authentication_result().expect("missing auth result");
    assert!(result.access_token().is_some());
    assert!(result.id_token().is_some());
    assert!(result.refresh_token().is_some());
}

#[tokio::test]
async fn test_get_user_with_access_token() {
    let server = TestServer::start().await;
    let client = server.client().await;

    let (_pool_id, client_id, _username) = setup_user(&client, "getuser-test").await;

    let auth = client
        .initiate_auth()
        .client_id(&client_id)
        .auth_flow(AuthFlowType::UserPasswordAuth)
        .auth_parameters("USERNAME", "testuser")
        .auth_parameters("PASSWORD", "P@ssw0rd!")
        .send()
        .await
        .unwrap();

    let access_token = auth
        .authentication_result()
        .unwrap()
        .access_token()
        .unwrap();

    let user = client
        .get_user()
        .access_token(access_token)
        .send()
        .await
        .expect("GetUser failed");

    assert_eq!(user.username(), "testuser");

    let email_attr = user
        .user_attributes()
        .iter()
        .find(|a| a.name() == "email")
        .expect("email attribute missing");
    assert_eq!(email_attr.value().unwrap(), "test@example.com");
}

#[tokio::test]
async fn test_invalid_password_returns_error() {
    let server = TestServer::start().await;
    let client = server.client().await;

    let (_pool_id, client_id, _username) = setup_user(&client, "badpw-test").await;

    let result = client
        .initiate_auth()
        .client_id(&client_id)
        .auth_flow(AuthFlowType::UserPasswordAuth)
        .auth_parameters("USERNAME", "testuser")
        .auth_parameters("PASSWORD", "WrongPassword!")
        .send()
        .await;

    assert!(result.is_err());
}

#[tokio::test]
async fn test_global_sign_out_invalidates_refresh_token() {
    let server = TestServer::start().await;
    let client = server.client().await;

    let (_pool_id, client_id, _username) = setup_user(&client, "signout-test").await;

    let auth = client
        .initiate_auth()
        .client_id(&client_id)
        .auth_flow(AuthFlowType::UserPasswordAuth)
        .auth_parameters("USERNAME", "testuser")
        .auth_parameters("PASSWORD", "P@ssw0rd!")
        .send()
        .await
        .unwrap();

    let auth_result = auth.authentication_result().unwrap();
    let access_token = auth_result.access_token().unwrap();
    let refresh_token = auth_result.refresh_token().unwrap();

    client
        .global_sign_out()
        .access_token(access_token)
        .send()
        .await
        .expect("GlobalSignOut failed");

    // Refresh token should be invalidated after global sign out
    let result = client
        .initiate_auth()
        .client_id(&client_id)
        .auth_flow(AuthFlowType::RefreshTokenAuth)
        .auth_parameters("REFRESH_TOKEN", refresh_token)
        .send()
        .await;
    assert!(result.is_err());
}
