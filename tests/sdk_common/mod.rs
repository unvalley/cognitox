//! Common utilities for aws-sdk-rust integration tests.
//!
//! Spins up the cognitox server on a random port and provides an
//! [`aws_sdk_cognitoidentityprovider::Client`] pointed at it.

use std::net::SocketAddr;

use aws_sdk_cognitoidentityprovider::{
    Client,
    config::{Credentials, Region},
};
use cognito_emulator::{api, storage::Storage};
use tokio::net::TcpListener;
use tower_http::cors::{Any, CorsLayer};

/// A running cognitox server bound to a random port.
pub struct TestServer {
    pub addr: SocketAddr,
}

impl TestServer {
    /// Start a cognitox server on a random available port.
    pub async fn start() -> Self {
        let storage = Storage::new();
        let app = api::create_router(storage).layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods(Any)
                .allow_headers(Any),
        );

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("failed to bind to random port");
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        Self { addr }
    }

    /// Build an AWS SDK Cognito client pointed at this server.
    pub async fn client(&self) -> Client {
        let endpoint = format!("http://{}", self.addr);
        let config = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .region(Region::new("local"))
            .credentials_provider(Credentials::new("test", "test", None, None, "test"))
            .endpoint_url(&endpoint)
            .load()
            .await;
        Client::new(&config)
    }

    /// Endpoint URL for this server.
    #[allow(dead_code)]
    pub fn endpoint(&self) -> String {
        format!("http://{}", self.addr)
    }
}
