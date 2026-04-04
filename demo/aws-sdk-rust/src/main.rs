//! cognitox AWS SDK for Rust demo
//!
//! Demonstrates the full user lifecycle using the official AWS SDK for Rust
//! pointed at the local cognitox emulator.
//!
//! Usage:
//!   cargo run
//!
//! Requires cognitox running on localhost:9229 (default).

use aws_sdk_cognitoidentityprovider::{
    config::{Credentials, Region},
    types::{AttributeType, AuthFlowType, ExplicitAuthFlowsType},
    Client,
};

fn log(label: &str, data: Option<&str>) {
    println!("\n✓ {label}");
    if let Some(d) = data {
        println!("{d}");
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let endpoint =
        std::env::var("COGNITOX_URL").unwrap_or_else(|_| "http://localhost:9229".to_string());

    println!("\ncognitox AWS SDK for Rust demo (endpoint: {endpoint})");
    println!("{}", "=".repeat(50));

    let config = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .region(Region::new("local"))
        .credentials_provider(Credentials::new("local", "local", None, None, "demo"))
        .endpoint_url(&endpoint)
        .load()
        .await;

    let client = Client::new(&config);

    // 1. Create User Pool
    let pool = client
        .create_user_pool()
        .pool_name("rust-demo-pool")
        .send()
        .await?;
    let pool_id = pool.user_pool().unwrap().id().unwrap();
    log(
        "CreateUserPool",
        Some(&format!(
            "  Id: {pool_id}\n  Name: {}",
            pool.user_pool().unwrap().name().unwrap()
        )),
    );

    // 2. Create User Pool Client
    let app_client = client
        .create_user_pool_client()
        .user_pool_id(pool_id)
        .client_name("rust-demo-client")
        .explicit_auth_flows(ExplicitAuthFlowsType::AllowUserPasswordAuth)
        .explicit_auth_flows(ExplicitAuthFlowsType::AllowRefreshTokenAuth)
        .send()
        .await?;
    let client_id = app_client
        .user_pool_client()
        .unwrap()
        .client_id()
        .unwrap();
    log("CreateUserPoolClient", Some(&format!("  ClientId: {client_id}")));

    // 3. Sign Up
    let sign_up = client
        .sign_up()
        .client_id(client_id)
        .username("demo-user")
        .password("P@ssw0rd!")
        .user_attributes(
            AttributeType::builder()
                .name("email")
                .value("demo@example.com")
                .build()
                .unwrap(),
        )
        .send()
        .await?;
    log(
        "SignUp",
        Some(&format!(
            "  UserSub: {}\n  UserConfirmed: {}",
            sign_up.user_sub(),
            sign_up.user_confirmed()
        )),
    );

    // 4. Admin Confirm Sign Up
    client
        .admin_confirm_sign_up()
        .user_pool_id(pool_id)
        .username("demo-user")
        .send()
        .await?;
    log("AdminConfirmSignUp", None);

    // 5. Initiate Auth
    let auth = client
        .initiate_auth()
        .client_id(client_id)
        .auth_flow(AuthFlowType::UserPasswordAuth)
        .auth_parameters("USERNAME", "demo-user")
        .auth_parameters("PASSWORD", "P@ssw0rd!")
        .send()
        .await?;
    let auth_result = auth.authentication_result().unwrap();
    let access_token = auth_result.access_token().unwrap();
    log(
        "InitiateAuth",
        Some(&format!(
            "  TokenType: {}\n  ExpiresIn: {}",
            auth_result.token_type().unwrap(),
            auth_result.expires_in()
        )),
    );

    // 6. Get User
    let user = client
        .get_user()
        .access_token(access_token)
        .send()
        .await?;
    let attrs: Vec<String> = user
        .user_attributes()
        .iter()
        .map(|a| format!("{}={}", a.name(), a.value().unwrap_or("-")))
        .collect();
    log(
        "GetUser",
        Some(&format!(
            "  Username: {}\n  Attributes: [{}]",
            user.username(),
            attrs.join(", ")
        )),
    );

    // 7. List Users
    let list = client
        .list_users()
        .user_pool_id(pool_id)
        .send()
        .await?;
    log(
        "ListUsers",
        Some(&format!("  Count: {}", list.users().len())),
    );

    // 8. Cleanup
    client
        .delete_user()
        .access_token(access_token)
        .send()
        .await?;
    log("DeleteUser", None);

    client
        .delete_user_pool()
        .user_pool_id(pool_id)
        .send()
        .await?;
    log("DeleteUserPool", None);

    println!("\n{}", "=".repeat(50));
    println!("Demo complete! All operations succeeded.\n");

    Ok(())
}
