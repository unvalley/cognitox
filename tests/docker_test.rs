//! Docker container integration tests
//!
//! Run with: cargo test --test docker_test -- --ignored --nocapture

use reqwest::Client;
use serde_json::{json, Value};
use std::process::{Command, Stdio};
use std::time::Duration;

const CONTAINER_NAME: &str = "cognitox-test";
const IMAGE_NAME: &str = "cognitox:test";
const PORT: u16 = 9229;

struct DockerContainer {
    name: String,
}

impl DockerContainer {
    fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
        }
    }

    fn build_image() -> Result<(), String> {
        let output = Command::new("docker")
            .args(["build", "-t", IMAGE_NAME, "."])
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .output()
            .map_err(|e| format!("Failed to run docker build: {}", e))?;

        if !output.status.success() {
            return Err("Docker build failed".to_string());
        }
        Ok(())
    }

    fn start(&self) -> Result<(), String> {
        let output = Command::new("docker")
            .args([
                "run",
                "-d",
                "--name",
                &self.name,
                "-p",
                &format!("{}:{}", PORT, PORT),
                "-e",
                &format!("PORT={}", PORT),
                "-e",
                "RUST_LOG=cognito_emulator=info",
                IMAGE_NAME,
            ])
            .output()
            .map_err(|e| format!("Failed to start container: {}", e))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!("Failed to start container: {}", stderr));
        }
        Ok(())
    }

    fn stop(&self) {
        let _ = Command::new("docker")
            .args(["rm", "-f", &self.name])
            .output();
    }
}

impl Drop for DockerContainer {
    fn drop(&mut self) {
        println!("Cleaning up container: {}", self.name);
        self.stop();
    }
}

async fn wait_for_healthy(client: &Client, base_url: &str) -> Result<(), String> {
    let health_url = format!("{}/health", base_url);

    for i in 1..=30 {
        match client.get(&health_url).send().await {
            Ok(resp) if resp.status().is_success() => {
                println!("Container is healthy!");
                return Ok(());
            }
            _ => {
                println!("Waiting for container... ({}/30)", i);
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        }
    }
    Err("Container failed to become healthy".to_string())
}

async fn cognito_request(client: &Client, base_url: &str, action: &str, body: Value) -> Value {
    let response = client
        .post(base_url)
        .header("Content-Type", "application/x-amz-json-1.1")
        .header(
            "X-Amz-Target",
            format!("AWSCognitoIdentityProviderService.{}", action),
        )
        .json(&body)
        .send()
        .await
        .expect("Request failed");

    response.json().await.unwrap_or(Value::Null)
}

#[tokio::test]
#[ignore] // Run with: cargo test --test docker_test -- --ignored
async fn test_docker_container() {
    // Build image
    println!("=== Building Docker image ===");
    DockerContainer::build_image().expect("Failed to build Docker image");

    // Start container (will be cleaned up on drop)
    println!("=== Starting container ===");
    let container = DockerContainer::new(CONTAINER_NAME);
    container.stop(); // Clean up any existing container
    container.start().expect("Failed to start container");

    let client = Client::new();
    let base_url = format!("http://localhost:{}", PORT);

    // Wait for healthy
    println!("=== Waiting for container to be healthy ===");
    wait_for_healthy(&client, &base_url)
        .await
        .expect("Container not healthy");

    // Test 1: Health endpoint
    println!("Test 1: Health endpoint");
    let health_resp: Value = client
        .get(format!("{}/health", base_url))
        .send()
        .await
        .expect("Health request failed")
        .json()
        .await
        .expect("Failed to parse health response");
    assert_eq!(health_resp["status"], "ok");
    println!("  PASS: Health endpoint returns ok");

    // Test 2: CreateUserPool
    println!("Test 2: CreateUserPool");
    let create_pool_resp =
        cognito_request(&client, &base_url, "CreateUserPool", json!({"PoolName": "TestPool"}))
            .await;
    assert!(create_pool_resp.get("UserPool").is_some());
    let pool_id = create_pool_resp["UserPool"]["Id"]
        .as_str()
        .expect("Pool ID not found");
    println!("  PASS: Pool ID = {}", pool_id);

    // Test 3: ListUserPools
    println!("Test 3: ListUserPools");
    let list_pools_resp =
        cognito_request(&client, &base_url, "ListUserPools", json!({"MaxResults": 10})).await;
    assert!(list_pools_resp.get("UserPools").is_some());
    println!("  PASS: ListUserPools returns UserPools");

    // Test 4: DescribeUserPool
    println!("Test 4: DescribeUserPool");
    let describe_pool_resp = cognito_request(
        &client,
        &base_url,
        "DescribeUserPool",
        json!({"UserPoolId": pool_id}),
    )
    .await;
    assert!(describe_pool_resp.get("UserPool").is_some());
    println!("  PASS: DescribeUserPool returns UserPool");

    // Test 5: CreateUserPoolClient
    println!("Test 5: CreateUserPoolClient");
    let create_client_resp = cognito_request(
        &client,
        &base_url,
        "CreateUserPoolClient",
        json!({"UserPoolId": pool_id, "ClientName": "TestClient"}),
    )
    .await;
    assert!(create_client_resp.get("UserPoolClient").is_some());
    let client_id = create_client_resp["UserPoolClient"]["ClientId"]
        .as_str()
        .expect("Client ID not found");
    println!("  PASS: Client ID = {}", client_id);

    // Test 6: SignUp
    println!("Test 6: SignUp");
    let signup_resp = cognito_request(
        &client,
        &base_url,
        "SignUp",
        json!({
            "ClientId": client_id,
            "Username": "testuser",
            "Password": "TestPass123!"
        }),
    )
    .await;
    assert!(signup_resp.get("UserSub").is_some());
    println!("  PASS: SignUp returns UserSub");

    // Test 7: AdminGetUser
    println!("Test 7: AdminGetUser");
    let admin_get_user_resp = cognito_request(
        &client,
        &base_url,
        "AdminGetUser",
        json!({"UserPoolId": pool_id, "Username": "testuser"}),
    )
    .await;
    assert!(admin_get_user_resp.get("Username").is_some());
    println!("  PASS: AdminGetUser returns Username");

    // Test 8: DeleteUserPool
    println!("Test 8: DeleteUserPool");
    let delete_pool_resp = cognito_request(
        &client,
        &base_url,
        "DeleteUserPool",
        json!({"UserPoolId": pool_id}),
    )
    .await;
    assert!(delete_pool_resp.is_null() || delete_pool_resp == json!({}));
    println!("  PASS: DeleteUserPool succeeded");

    println!("\n=== All tests passed! ===");
}
