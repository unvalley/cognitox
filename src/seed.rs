//! Seed user pools and clients with fixed IDs at startup (`COGNITOX_SEED_FILE`).
//!
//! Cognito assigns IDs itself, so configuration that has to name a user pool
//! or client cannot be written before they exist. A seed file declares them up
//! front: each user pool is a `CreateUserPool` request plus `Id` and `Clients`,
//! and each client is a `CreateUserPoolClient` request without `UserPoolId`,
//! plus `ClientId` and an optional `ClientSecret`. Entries that already exist,
//! for example from a persisted snapshot, are left as they are.

use std::path::Path;

use serde::Deserialize;
use serde_json::{Map, Value};

use crate::{
    action::user_pool::{create_user_pool, create_user_pool_client},
    storage::Storage,
    types::{ClientId, UserPoolId},
};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct SeedFile {
    user_pools: Vec<SeedUserPool>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct SeedUserPool {
    id: String,
    #[serde(default)]
    clients: Vec<SeedClient>,
    #[serde(flatten)]
    request: Map<String, Value>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct SeedClient {
    client_id: String,
    client_secret: Option<String>,
    #[serde(flatten)]
    request: Map<String, Value>,
}

/// Read a seed file and apply it to `storage`.
pub async fn apply_file(storage: &Storage, path: &Path) -> Result<(), String> {
    let json = std::fs::read_to_string(path)
        .map_err(|e| format!("Failed to read seed file {}: {e}", path.display()))?;
    apply(storage, &json).await
}

/// Create the user pools and clients in a seed file that do not exist yet.
pub async fn apply(storage: &Storage, json: &str) -> Result<(), String> {
    let seed: SeedFile =
        serde_json::from_str(json).map_err(|e| format!("Invalid seed file: {e}"))?;

    for pool in seed.user_pools {
        let user_pool_id = UserPoolId::new(pool.id.as_str())
            .map_err(|e| format!("Invalid seed user pool ID {}: {e}", pool.id))?;
        if !storage.user_pool_exists(&user_pool_id).await {
            create_user_pool::create(storage, Value::Object(pool.request), user_pool_id.clone())
                .await
                .map_err(|e| format!("Failed to seed user pool {user_pool_id}: {e}"))?;
            tracing::info!("Seeded user pool {user_pool_id}");
        }

        for client in pool.clients {
            let client_id = ClientId::new(client.client_id.as_str())
                .map_err(|e| format!("Invalid seed client ID {}: {e}", client.client_id))?;
            if storage.get_user_pool_client(&client_id).await.is_some() {
                continue;
            }

            let mut request = client.request;
            request.insert(
                "UserPoolId".to_string(),
                Value::String(user_pool_id.to_string()),
            );
            if client.client_secret.is_some() {
                request.insert("GenerateSecret".to_string(), Value::Bool(true));
            }
            create_user_pool_client::create(
                storage,
                Value::Object(request),
                client_id.clone(),
                client.client_secret,
            )
            .await
            .map_err(|e| format!("Failed to seed client {client_id}: {e}"))?;
            tracing::info!("Seeded client {client_id} in user pool {user_pool_id}");
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn seed_json() -> String {
        json!({
            "UserPools": [{
                "Id": "ap-northeast-1_SeedPool1",
                "PoolName": "seed-pool",
                "Clients": [
                    {
                        "ClientId": "seedwebclient",
                        "ClientSecret": "seed-web-secret",
                        "ClientName": "seed-web",
                        "ExplicitAuthFlows": ["ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"]
                    },
                    {
                        "ClientId": "seedpublicclient",
                        "ClientName": "seed-public"
                    }
                ]
            }]
        })
        .to_string()
    }

    #[tokio::test]
    async fn test_apply_creates_pools_and_clients_with_fixed_ids() {
        let storage = Storage::new();

        apply(&storage, &seed_json()).await.unwrap();

        let pool = storage
            .get_user_pool(&UserPoolId::new("ap-northeast-1_SeedPool1").unwrap())
            .await
            .unwrap();
        assert_eq!(pool.name, "seed-pool");

        let web = storage
            .get_user_pool_client(&ClientId::new("seedwebclient").unwrap())
            .await
            .unwrap();
        assert_eq!(web.user_pool_id, pool.id);
        assert_eq!(web.client_name, "seed-web");
        assert_eq!(web.client_secret.as_deref(), Some("seed-web-secret"));
        assert_eq!(web.explicit_auth_flows.len(), 2);

        let public = storage
            .get_user_pool_client(&ClientId::new("seedpublicclient").unwrap())
            .await
            .unwrap();
        assert_eq!(public.client_secret, None);
    }

    #[tokio::test]
    async fn test_apply_keeps_existing_entries() {
        let storage = Storage::new();
        apply(&storage, &seed_json()).await.unwrap();

        let renamed = seed_json()
            .replace("\"seed-pool\"", "\"renamed-pool\"")
            .replace("seed-web-secret", "other-secret");
        apply(&storage, &renamed).await.unwrap();

        let pool = storage
            .get_user_pool(&UserPoolId::new("ap-northeast-1_SeedPool1").unwrap())
            .await
            .unwrap();
        assert_eq!(pool.name, "seed-pool");
        let web = storage
            .get_user_pool_client(&ClientId::new("seedwebclient").unwrap())
            .await
            .unwrap();
        assert_eq!(web.client_secret.as_deref(), Some("seed-web-secret"));
    }

    #[tokio::test]
    async fn test_apply_rejects_invalid_ids_and_requests() {
        let storage = Storage::new();

        let invalid_pool_id = json!({ "UserPools": [{ "Id": "no-underscore", "PoolName": "p" }] });
        assert!(
            apply(&storage, &invalid_pool_id.to_string())
                .await
                .unwrap_err()
                .contains("Invalid seed user pool ID")
        );

        let missing_pool_name = json!({ "UserPools": [{ "Id": "ap-northeast-1_NoName" }] });
        assert!(
            apply(&storage, &missing_pool_name.to_string())
                .await
                .unwrap_err()
                .contains("Failed to seed user pool")
        );
    }
}
