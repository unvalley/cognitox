//! In-memory storage for Cognito entities with pluggable persistence backends.
//!
//! This module provides thread-safe in-memory storage for user pools, clients, and users.
//! Persistence is handled by a [`PersistenceBackend`] trait, allowing different storage
//! modes (memory-only, file-based, etc.) to be selected via [`StorageConfig`].

use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::RwLock;
use tracing::{debug, error};

use crate::config::{StorageConfig, StorageMode};
use crate::types::{
    AuthEvent, AuthorizationCode, BrandingId, ClientId, ConfirmationCode, Device, DomainPrefix,
    Group, GroupName, IdentityProvider, ManagedLoginBranding, PasswordResetCode,
    PendingAuthChallenge, RefreshToken, ResourceServer, TermsDocument, UiCustomization, User,
    UserId, UserImportJob, UserPool, UserPoolClient, UserPoolDomain, UserPoolId,
    WebAuthnCredential,
};

// ==================== Persistence Backend Trait ====================

/// Trait for storage persistence backends.
///
/// Implementations control how (and whether) the in-memory state is loaded
/// and saved. This enables pluggable storage modes (memory-only, file, WAL, etc.).
pub(crate) trait PersistenceBackend: Send + Sync + 'static {
    /// Load persisted state. Returns default state if no prior data exists.
    fn load(&self) -> Result<PersistedStorageState, String>;

    /// Save the given state snapshot.
    fn save(&self, state: &PersistedStorageState) -> Result<(), String>;

    /// Return the flush interval if this backend needs a periodic flush loop.
    /// Returning `None` means no background flushing (e.g. memory-only).
    fn flush_interval(&self) -> Option<Duration>;

    /// Human-readable description for logging.
    fn describe(&self) -> &str;
}

/// No-op persistence backend for pure in-memory mode.
struct NullBackend;

impl PersistenceBackend for NullBackend {
    fn load(&self) -> Result<PersistedStorageState, String> {
        Ok(PersistedStorageState::default())
    }

    fn save(&self, _state: &PersistedStorageState) -> Result<(), String> {
        Ok(())
    }

    fn flush_interval(&self) -> Option<Duration> {
        None
    }

    fn describe(&self) -> &str {
        "memory (no persistence)"
    }
}

/// File-based persistence backend using bincode + base64 snapshots.
struct FileBackend {
    data_file: PathBuf,
    flush_interval: Duration,
}

impl PersistenceBackend for FileBackend {
    fn load(&self) -> Result<PersistedStorageState, String> {
        match fs::read_to_string(&self.data_file) {
            Ok(content) => decode_snapshot(&content),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                Ok(PersistedStorageState::default())
            }
            Err(e) => Err(format!(
                "Failed to read data file {:?}: {}",
                self.data_file, e
            )),
        }
    }

    fn save(&self, state: &PersistedStorageState) -> Result<(), String> {
        let snapshot = encode_snapshot(state)?;
        write_snapshot_file(&self.data_file, &snapshot)
    }

    fn flush_interval(&self) -> Option<Duration> {
        Some(self.flush_interval)
    }

    fn describe(&self) -> &str {
        "persistent (file)"
    }
}

/// Build a persistence backend from configuration.
fn build_backend(config: &StorageConfig) -> Arc<dyn PersistenceBackend> {
    match &config.mode {
        StorageMode::Memory => Arc::new(NullBackend),
        StorageMode::Persistent { data_file } => Arc::new(FileBackend {
            data_file: data_file.clone(),
            flush_interval: Duration::from_millis(config.flush_interval_ms()),
        }),
    }
}

#[derive(Clone)]
pub struct Storage {
    pool_store: Arc<RwLock<PoolStore>>,
    principal_store: Arc<RwLock<PrincipalStore>>,
    group_store: Arc<RwLock<GroupStore>>,
    branding_store: Arc<RwLock<BrandingStore>>,
    backend: Arc<dyn PersistenceBackend>,
}

impl std::fmt::Debug for Storage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Storage")
            .field("backend", &self.backend.describe())
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct PoolStore {
    user_pools: HashMap<UserPoolId, UserPool>,
    user_pool_clients: HashMap<ClientId, UserPoolClient>,
    user_pool_domains: HashMap<DomainPrefix, UserPoolDomain>,
    user_pool_id_to_domain: HashMap<UserPoolId, DomainPrefix>,
    identity_providers: HashMap<(UserPoolId, String), IdentityProvider>,
    resource_servers: HashMap<(UserPoolId, String), ResourceServer>,
    user_import_jobs: HashMap<String, UserImportJob>,
    terms_documents: HashMap<String, TermsDocument>,
    terms_name_index: HashMap<(UserPoolId, ClientId, String), String>,
    ui_customizations: HashMap<(UserPoolId, Option<ClientId>), UiCustomization>,
    risk_configurations: HashMap<(UserPoolId, Option<ClientId>), Value>,
    log_delivery_configurations: HashMap<UserPoolId, Vec<Value>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct PrincipalStore {
    users: HashMap<UserId, User>,
    devices: HashMap<(UserId, String), Device>,
    confirmation_codes: HashMap<UserId, ConfirmationCode>,
    refresh_tokens: HashMap<String, RefreshToken>,
    auth_challenge_sessions: HashMap<String, PendingAuthChallenge>,
    software_token_sessions: HashMap<String, (UserId, String)>,
    user_auth_factors: HashMap<UserId, Vec<String>>,
    auth_events: HashMap<String, AuthEvent>,
    user_auth_event_index: HashMap<UserId, Vec<String>>,
    authorization_codes: HashMap<String, AuthorizationCode>,
    username_index: HashMap<(UserPoolId, String), UserId>,
    password_reset_codes: HashMap<UserId, PasswordResetCode>,
    webauthn_credentials: HashMap<UserId, Vec<WebAuthnCredential>>,
    webauthn_registration_challenges: HashMap<UserId, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct GroupStore {
    groups: HashMap<(UserPoolId, GroupName), Group>,
    user_groups: HashMap<UserId, Vec<GroupName>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct BrandingStore {
    managed_login_brandings: HashMap<BrandingId, ManagedLoginBranding>,
    user_pool_brandings: HashMap<UserPoolId, BrandingId>,
    client_brandings: HashMap<ClientId, BrandingId>,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub(crate) struct PersistedStorageState {
    pool_store: PoolStore,
    principal_store: PrincipalStore,
    group_store: GroupStore,
    branding_store: BrandingStore,
}

#[derive(Debug, Serialize, Deserialize)]
struct PersistedSnapshot {
    version: u32,
    encoding: String,
    payload: String,
}

const SNAPSHOT_VERSION: u32 = 1;
const SNAPSHOT_ENCODING: &str = "bincode+base64";

fn decode_snapshot(content: &str) -> Result<PersistedStorageState, String> {
    let snapshot: PersistedSnapshot =
        serde_json::from_str(content).map_err(|e| format!("Invalid JSON snapshot: {e}"))?;

    if snapshot.version != SNAPSHOT_VERSION {
        return Err(format!(
            "Unsupported snapshot version: {}",
            snapshot.version
        ));
    }

    if snapshot.encoding != SNAPSHOT_ENCODING {
        return Err(format!(
            "Unsupported snapshot encoding: {}",
            snapshot.encoding
        ));
    }

    let payload = BASE64_STANDARD
        .decode(snapshot.payload.as_bytes())
        .map_err(|e| format!("Invalid snapshot payload encoding: {e}"))?;

    bincode::deserialize::<PersistedStorageState>(&payload)
        .map_err(|e| format!("Failed to deserialize snapshot payload: {e}"))
}

fn encode_snapshot(state: &PersistedStorageState) -> Result<Vec<u8>, String> {
    let payload =
        bincode::serialize(state).map_err(|e| format!("Failed to serialize storage state: {e}"))?;
    let snapshot = PersistedSnapshot {
        version: SNAPSHOT_VERSION,
        encoding: SNAPSHOT_ENCODING.to_string(),
        payload: BASE64_STANDARD.encode(payload),
    };

    serde_json::to_vec_pretty(&snapshot).map_err(|e| format!("Failed to encode snapshot: {e}"))
}

fn write_snapshot_file(path: &Path, data: &[u8]) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("Failed to create persistence directory {:?}: {}", parent, e))?;
    }

    let tmp_path = path.with_extension("tmp");
    fs::write(&tmp_path, data)
        .map_err(|e| format!("Failed to write temp snapshot {:?}: {}", tmp_path, e))?;
    fs::rename(&tmp_path, path)
        .map_err(|e| format!("Failed to atomically move snapshot to {:?}: {}", path, e))
}

impl Storage {
    /// Create a new memory-only storage (no persistence).
    /// Convenient default for tests and simple usage.
    pub fn new() -> Self {
        Self::with_config(StorageConfig::default()).expect("Failed to initialize storage")
    }

    /// Create storage from a [`StorageConfig`].
    pub fn with_config(config: StorageConfig) -> Result<Self, String> {
        let backend = build_backend(&config);
        let initial_state = backend.load()?;

        let storage = Self {
            pool_store: Arc::new(RwLock::new(initial_state.pool_store)),
            principal_store: Arc::new(RwLock::new(initial_state.principal_store)),
            group_store: Arc::new(RwLock::new(initial_state.group_store)),
            branding_store: Arc::new(RwLock::new(initial_state.branding_store)),
            backend,
        };
        storage.start_auto_persist_loop();
        storage.start_cleanup_loop();
        Ok(storage)
    }

    /// Backward-compatible constructor: `None` → memory, `Some(path)` → persistent with default interval.
    pub fn try_with_data_file(data_file: Option<PathBuf>) -> Result<Self, String> {
        let config = match data_file {
            Some(path) => StorageConfig::persistent(path),
            None => StorageConfig::memory(),
        };
        Self::with_config(config)
    }

    fn start_auto_persist_loop(&self) {
        let Some(interval) = self.backend.flush_interval() else {
            return;
        };

        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            return;
        };

        let pool_store = Arc::downgrade(&self.pool_store);
        let principal_store = Arc::downgrade(&self.principal_store);
        let group_store = Arc::downgrade(&self.group_store);
        let branding_store = Arc::downgrade(&self.branding_store);
        let backend = Arc::clone(&self.backend);
        handle.spawn(async move {
            let mut last_snapshot: Option<Vec<u8>> = None;
            loop {
                tokio::time::sleep(interval).await;
                let Some(pool_store) = pool_store.upgrade() else {
                    break;
                };
                let Some(principal_store) = principal_store.upgrade() else {
                    break;
                };
                let Some(group_store) = group_store.upgrade() else {
                    break;
                };
                let Some(branding_store) = branding_store.upgrade() else {
                    break;
                };
                let state = Storage::capture_state(
                    &pool_store,
                    &principal_store,
                    &group_store,
                    &branding_store,
                )
                .await;
                let snapshot = {
                    match encode_snapshot(&state) {
                        Ok(snapshot) => snapshot,
                        Err(e) => {
                            error!("Failed to serialize storage snapshot: {e}");
                            continue;
                        }
                    }
                };

                if last_snapshot.as_ref() == Some(&snapshot) {
                    continue;
                }

                if let Err(e) = backend.save(&state) {
                    error!("Failed to persist storage snapshot: {e}");
                    continue;
                }

                last_snapshot = Some(snapshot);
            }
        });
    }

    fn start_cleanup_loop(&self) {
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            return;
        };

        let principal_store = Arc::downgrade(&self.principal_store);
        handle.spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(60)).await;
                let Some(principal_store) = principal_store.upgrade() else {
                    break;
                };
                Self::cleanup_expired_data(&principal_store).await;
            }
        });
    }

    async fn cleanup_expired_data(principal_store: &RwLock<PrincipalStore>) {
        let now = Utc::now();
        let mut store = principal_store.write().await;

        let expired_confirmations: Vec<_> = store
            .confirmation_codes
            .iter()
            .filter(|(_, code)| code.expires_at < now)
            .map(|(id, _)| *id)
            .collect();
        let confirmation_count = expired_confirmations.len();
        for id in expired_confirmations {
            store.confirmation_codes.remove(&id);
        }

        let expired_refresh: Vec<_> = store
            .refresh_tokens
            .iter()
            .filter(|(_, token)| token.expires_at < now)
            .map(|(key, _)| key.clone())
            .collect();
        let refresh_count = expired_refresh.len();
        for key in expired_refresh {
            store.refresh_tokens.remove(&key);
        }

        let expired_reset: Vec<_> = store
            .password_reset_codes
            .iter()
            .filter(|(_, code)| code.expires_at < now)
            .map(|(id, _)| *id)
            .collect();
        let reset_count = expired_reset.len();
        for id in expired_reset {
            store.password_reset_codes.remove(&id);
        }

        let expired_auth_codes: Vec<_> = store
            .authorization_codes
            .iter()
            .filter(|(_, code)| code.expires_at < now)
            .map(|(key, _)| key.clone())
            .collect();
        let auth_code_count = expired_auth_codes.len();
        for key in expired_auth_codes {
            store.authorization_codes.remove(&key);
        }

        let total = confirmation_count + refresh_count + reset_count + auth_code_count;
        if total > 0 {
            debug!(
                "Cleaned up {} expired entries (confirmations: {}, refresh_tokens: {}, password_resets: {}, auth_codes: {})",
                total, confirmation_count, refresh_count, reset_count, auth_code_count
            );
        }
    }

    async fn capture_state(
        pool_store: &RwLock<PoolStore>,
        principal_store: &RwLock<PrincipalStore>,
        group_store: &RwLock<GroupStore>,
        branding_store: &RwLock<BrandingStore>,
    ) -> PersistedStorageState {
        let pool_store = pool_store.read().await;
        let principal_store = principal_store.read().await;
        let group_store = group_store.read().await;
        let branding_store = branding_store.read().await;

        PersistedStorageState {
            pool_store: pool_store.clone(),
            principal_store: principal_store.clone(),
            group_store: group_store.clone(),
            branding_store: branding_store.clone(),
        }
    }

    /// Flush in-memory state to the persistence backend immediately.
    pub async fn flush_persistence(&self) -> Result<(), String> {
        let state = Self::capture_state(
            &self.pool_store,
            &self.principal_store,
            &self.group_store,
            &self.branding_store,
        )
        .await;
        self.backend.save(&state)
    }

    /// Returns a description of the active storage backend.
    pub fn backend_description(&self) -> &str {
        self.backend.describe()
    }

    // ==================== User Pool Operations ====================

    pub async fn create_user_pool(&self, pool: UserPool) -> UserPool {
        let mut store = self.pool_store.write().await;
        store.user_pools.insert(pool.id.clone(), pool.clone());
        pool
    }

    pub async fn get_user_pool(&self, id: &UserPoolId) -> Option<UserPool> {
        let store = self.pool_store.read().await;
        store.user_pools.get(id).cloned()
    }

    pub async fn delete_user_pool(&self, id: &UserPoolId) -> Option<UserPool> {
        // Acquire all write locks (always in same order to prevent deadlocks)
        let mut pool_store = self.pool_store.write().await;
        let mut principal_store = self.principal_store.write().await;
        let mut group_store = self.group_store.write().await;
        let mut branding_store = self.branding_store.write().await;

        let pool = pool_store.user_pools.remove(id)?;

        // Clean up pool_store: clients, domain, identity providers, resource servers, etc.
        let client_ids: Vec<ClientId> = pool_store
            .user_pool_clients
            .iter()
            .filter(|(_, c)| &c.user_pool_id == id)
            .map(|(cid, _)| cid.clone())
            .collect();
        for cid in &client_ids {
            pool_store.user_pool_clients.remove(cid);
            branding_store.client_brandings.remove(cid);
        }

        if let Some(domain_prefix) = pool_store.user_pool_id_to_domain.remove(id) {
            pool_store.user_pool_domains.remove(&domain_prefix);
        }

        pool_store
            .identity_providers
            .retain(|(pool_id, _), _| pool_id != id);
        pool_store
            .resource_servers
            .retain(|(pool_id, _), _| pool_id != id);
        pool_store
            .user_import_jobs
            .retain(|_, job| job.user_pool_id != *id);
        pool_store
            .terms_documents
            .retain(|_, doc| doc.user_pool_id != *id);
        pool_store
            .terms_name_index
            .retain(|(pool_id, _, _), _| pool_id != id);
        pool_store
            .ui_customizations
            .retain(|(pool_id, _), _| pool_id != id);
        pool_store
            .risk_configurations
            .retain(|(pool_id, _), _| pool_id != id);
        pool_store.log_delivery_configurations.remove(id);

        // Clean up principal_store: users and all user-associated data
        let user_ids: Vec<UserId> = principal_store
            .users
            .iter()
            .filter(|(_, u)| &u.user_pool_id == id)
            .map(|(uid, _)| *uid)
            .collect();
        for uid in &user_ids {
            principal_store.users.remove(uid);
            principal_store.confirmation_codes.remove(uid);
            principal_store.password_reset_codes.remove(uid);
            principal_store
                .devices
                .retain(|(device_uid, _), _| device_uid != uid);
            principal_store.webauthn_credentials.remove(uid);
            principal_store.webauthn_registration_challenges.remove(uid);
            principal_store.user_auth_factors.remove(uid);

            // Clean up auth events for this user
            if let Some(event_ids) = principal_store.user_auth_event_index.remove(uid) {
                for event_id in event_ids {
                    principal_store.auth_events.remove(&event_id);
                }
            }
        }

        principal_store
            .username_index
            .retain(|(pool_id, _), _| pool_id != id);
        principal_store
            .refresh_tokens
            .retain(|_, token| !user_ids.contains(&token.user_id));
        principal_store
            .software_token_sessions
            .retain(|_, (uid, _)| !user_ids.contains(uid));
        principal_store
            .authorization_codes
            .retain(|_, code| !client_ids.contains(&code.client_id));

        // Clean up group_store
        group_store.groups.retain(|(pool_id, _), _| pool_id != id);
        for uid in &user_ids {
            group_store.user_groups.remove(uid);
        }

        // Clean up branding_store
        if let Some(branding_id) = branding_store.user_pool_brandings.remove(id) {
            branding_store.managed_login_brandings.remove(&branding_id);
        }

        Some(pool)
    }

    pub async fn list_user_pools(&self) -> Vec<UserPool> {
        let store = self.pool_store.read().await;
        store.user_pools.values().cloned().collect()
    }

    pub async fn update_user_pool(&self, pool: UserPool) -> Option<UserPool> {
        let mut store = self.pool_store.write().await;
        if let std::collections::hash_map::Entry::Occupied(mut e) =
            store.user_pools.entry(pool.id.clone())
        {
            e.insert(pool.clone());
            Some(pool)
        } else {
            None
        }
    }

    // ==================== User Pool Client Operations ====================

    pub async fn create_user_pool_client(&self, client: UserPoolClient) -> UserPoolClient {
        let mut store = self.pool_store.write().await;
        store
            .user_pool_clients
            .insert(client.client_id.clone(), client.clone());
        client
    }

    pub async fn get_user_pool_client(&self, client_id: &ClientId) -> Option<UserPoolClient> {
        let store = self.pool_store.read().await;
        store.user_pool_clients.get(client_id).cloned()
    }

    pub async fn delete_user_pool_client(&self, client_id: &ClientId) -> Option<UserPoolClient> {
        let mut store = self.pool_store.write().await;
        store.user_pool_clients.remove(client_id)
    }

    pub async fn list_user_pool_clients(&self, user_pool_id: &UserPoolId) -> Vec<UserPoolClient> {
        let store = self.pool_store.read().await;
        store
            .user_pool_clients
            .values()
            .filter(|c| &c.user_pool_id == user_pool_id)
            .cloned()
            .collect()
    }

    pub async fn update_user_pool_client(&self, client: UserPoolClient) -> Option<UserPoolClient> {
        let mut store = self.pool_store.write().await;
        if let std::collections::hash_map::Entry::Occupied(mut e) =
            store.user_pool_clients.entry(client.client_id.clone())
        {
            e.insert(client.clone());
            Some(client)
        } else {
            None
        }
    }

    // ==================== User Pool Domain Operations ====================

    pub async fn create_user_pool_domain(&self, domain: UserPoolDomain) -> UserPoolDomain {
        let mut store = self.pool_store.write().await;
        store
            .user_pool_id_to_domain
            .insert(domain.user_pool_id.clone(), domain.domain.clone());
        store
            .user_pool_domains
            .insert(domain.domain.clone(), domain.clone());
        domain
    }

    pub async fn get_user_pool_domain(&self, domain: &DomainPrefix) -> Option<UserPoolDomain> {
        let store = self.pool_store.read().await;
        store.user_pool_domains.get(domain).cloned()
    }

    pub async fn get_user_pool_domain_by_user_pool_id(
        &self,
        user_pool_id: &UserPoolId,
    ) -> Option<UserPoolDomain> {
        let store = self.pool_store.read().await;
        let domain_prefix = store.user_pool_id_to_domain.get(user_pool_id)?;
        store.user_pool_domains.get(domain_prefix).cloned()
    }

    pub async fn update_user_pool_domain(&self, domain: UserPoolDomain) -> Option<UserPoolDomain> {
        let mut store = self.pool_store.write().await;
        if let std::collections::hash_map::Entry::Occupied(mut e) =
            store.user_pool_domains.entry(domain.domain.clone())
        {
            e.insert(domain.clone());
            Some(domain)
        } else {
            None
        }
    }

    pub async fn delete_user_pool_domain(&self, domain: &DomainPrefix) -> Option<UserPoolDomain> {
        let mut store = self.pool_store.write().await;
        if let Some(removed) = store.user_pool_domains.remove(domain) {
            store.user_pool_id_to_domain.remove(&removed.user_pool_id);
            Some(removed)
        } else {
            None
        }
    }

    // ==================== Identity Provider Operations ====================

    pub async fn create_identity_provider(&self, provider: IdentityProvider) -> IdentityProvider {
        let mut store = self.pool_store.write().await;
        store.identity_providers.insert(
            (
                provider.user_pool_id.clone(),
                provider.provider_name.clone(),
            ),
            provider.clone(),
        );
        provider
    }

    pub async fn get_identity_provider(
        &self,
        user_pool_id: &UserPoolId,
        provider_name: &str,
    ) -> Option<IdentityProvider> {
        let store = self.pool_store.read().await;
        store
            .identity_providers
            .get(&(user_pool_id.clone(), provider_name.to_string()))
            .cloned()
    }

    pub async fn get_identity_provider_by_identifier(
        &self,
        user_pool_id: &UserPoolId,
        identifier: &str,
    ) -> Option<IdentityProvider> {
        let store = self.pool_store.read().await;
        store
            .identity_providers
            .values()
            .find(|provider| {
                &provider.user_pool_id == user_pool_id
                    && (provider.provider_name == identifier
                        || provider.idp_identifiers.iter().any(|id| id == identifier))
            })
            .cloned()
    }

    pub async fn list_identity_providers(
        &self,
        user_pool_id: &UserPoolId,
    ) -> Vec<IdentityProvider> {
        let store = self.pool_store.read().await;
        store
            .identity_providers
            .values()
            .filter(|provider| &provider.user_pool_id == user_pool_id)
            .cloned()
            .collect()
    }

    pub async fn update_identity_provider(
        &self,
        provider: IdentityProvider,
    ) -> Option<IdentityProvider> {
        let mut store = self.pool_store.write().await;
        let key = (
            provider.user_pool_id.clone(),
            provider.provider_name.clone(),
        );
        if let std::collections::hash_map::Entry::Occupied(mut e) =
            store.identity_providers.entry(key)
        {
            e.insert(provider.clone());
            Some(provider)
        } else {
            None
        }
    }

    pub async fn delete_identity_provider(
        &self,
        user_pool_id: &UserPoolId,
        provider_name: &str,
    ) -> Option<IdentityProvider> {
        let mut store = self.pool_store.write().await;
        store
            .identity_providers
            .remove(&(user_pool_id.clone(), provider_name.to_string()))
    }

    // ==================== Resource Server Operations ====================

    pub async fn create_resource_server(&self, resource_server: ResourceServer) -> ResourceServer {
        let mut store = self.pool_store.write().await;
        store.resource_servers.insert(
            (
                resource_server.user_pool_id.clone(),
                resource_server.identifier.clone(),
            ),
            resource_server.clone(),
        );
        resource_server
    }

    pub async fn get_resource_server(
        &self,
        user_pool_id: &UserPoolId,
        identifier: &str,
    ) -> Option<ResourceServer> {
        let store = self.pool_store.read().await;
        store
            .resource_servers
            .get(&(user_pool_id.clone(), identifier.to_string()))
            .cloned()
    }

    pub async fn list_resource_servers(&self, user_pool_id: &UserPoolId) -> Vec<ResourceServer> {
        let store = self.pool_store.read().await;
        store
            .resource_servers
            .values()
            .filter(|resource_server| &resource_server.user_pool_id == user_pool_id)
            .cloned()
            .collect()
    }

    pub async fn update_resource_server(
        &self,
        resource_server: ResourceServer,
    ) -> Option<ResourceServer> {
        let mut store = self.pool_store.write().await;
        let key = (
            resource_server.user_pool_id.clone(),
            resource_server.identifier.clone(),
        );
        if let std::collections::hash_map::Entry::Occupied(mut e) =
            store.resource_servers.entry(key)
        {
            e.insert(resource_server.clone());
            Some(resource_server)
        } else {
            None
        }
    }

    pub async fn delete_resource_server(
        &self,
        user_pool_id: &UserPoolId,
        identifier: &str,
    ) -> Option<ResourceServer> {
        let mut store = self.pool_store.write().await;
        store
            .resource_servers
            .remove(&(user_pool_id.clone(), identifier.to_string()))
    }

    // ==================== User Operations ====================

    pub async fn create_user(&self, user: User) -> User {
        let mut store = self.principal_store.write().await;
        store
            .username_index
            .insert((user.user_pool_id.clone(), user.username.clone()), user.id);
        store.users.insert(user.id, user.clone());
        user
    }

    pub async fn get_user(&self, id: &UserId) -> Option<User> {
        let store = self.principal_store.read().await;
        store.users.get(id).cloned()
    }

    pub async fn get_user_by_username(
        &self,
        user_pool_id: &UserPoolId,
        username: &str,
    ) -> Option<User> {
        let store = self.principal_store.read().await;
        let user_id = store
            .username_index
            .get(&(user_pool_id.clone(), username.to_string()))?;
        store.users.get(user_id).cloned()
    }

    pub async fn update_user(&self, user: User) -> Option<User> {
        let mut store = self.principal_store.write().await;
        if let std::collections::hash_map::Entry::Occupied(mut e) = store.users.entry(user.id) {
            e.insert(user.clone());
            Some(user)
        } else {
            None
        }
    }

    pub async fn delete_user(&self, id: &UserId) -> Option<User> {
        let mut principal_store = self.principal_store.write().await;
        let mut group_store = self.group_store.write().await;

        if let Some(user) = principal_store.users.remove(id) {
            principal_store
                .username_index
                .remove(&(user.user_pool_id.clone(), user.username.clone()));
            principal_store.confirmation_codes.remove(id);
            principal_store.password_reset_codes.remove(id);
            principal_store
                .devices
                .retain(|(user_id, _), _| user_id != id);
            principal_store.user_auth_factors.remove(id);
            principal_store.webauthn_credentials.remove(id);
            principal_store.webauthn_registration_challenges.remove(id);
            principal_store
                .auth_challenge_sessions
                .retain(|_, challenge| &challenge.user_id != id);
            principal_store
                .software_token_sessions
                .retain(|_, (user_id, _)| user_id != id);
            principal_store
                .refresh_tokens
                .retain(|_, token| &token.user_id != id);
            principal_store
                .authorization_codes
                .retain(|_, code| &code.user_id != id);
            if let Some(event_ids) = principal_store.user_auth_event_index.remove(id) {
                for event_id in event_ids {
                    principal_store.auth_events.remove(&event_id);
                }
            }
            group_store.user_groups.remove(id);
            Some(user)
        } else {
            None
        }
    }

    pub async fn list_users(&self, user_pool_id: &UserPoolId) -> Vec<User> {
        let store = self.principal_store.read().await;
        store
            .users
            .values()
            .filter(|u| &u.user_pool_id == user_pool_id)
            .cloned()
            .collect()
    }

    // ==================== Device Operations ====================

    pub async fn put_device(&self, device: Device) -> Device {
        let mut store = self.principal_store.write().await;
        store
            .devices
            .insert((device.user_id, device.device_key.clone()), device.clone());
        device
    }

    pub async fn get_device_for_user(&self, user_id: &UserId, device_key: &str) -> Option<Device> {
        let store = self.principal_store.read().await;
        store
            .devices
            .get(&(*user_id, device_key.to_string()))
            .cloned()
    }

    pub async fn list_devices_for_user(&self, user_id: &UserId) -> Vec<Device> {
        let store = self.principal_store.read().await;
        store
            .devices
            .values()
            .filter(|device| &device.user_id == user_id)
            .cloned()
            .collect()
    }

    pub async fn delete_device_for_user(
        &self,
        user_id: &UserId,
        device_key: &str,
    ) -> Option<Device> {
        let mut store = self.principal_store.write().await;
        store.devices.remove(&(*user_id, device_key.to_string()))
    }

    pub async fn update_device_for_user(&self, device: Device) -> Option<Device> {
        let mut store = self.principal_store.write().await;
        let key = (device.user_id, device.device_key.clone());
        if let std::collections::hash_map::Entry::Occupied(mut e) = store.devices.entry(key) {
            e.insert(device.clone());
            Some(device)
        } else {
            None
        }
    }

    /// Confirm a user by updating their status to Confirmed
    pub async fn confirm_user(&self, user_id: &UserId) {
        let mut store = self.principal_store.write().await;
        if let Some(user) = store.users.get_mut(user_id) {
            user.user_status = crate::types::UserStatus::Confirmed;
            user.last_modified_date = chrono::Utc::now();
        }
        // Also remove the confirmation code
        store.confirmation_codes.remove(user_id);
    }

    /// Set the password for a user
    pub async fn set_user_password(&self, user_id: &UserId, password_hash: &str) {
        let mut store = self.principal_store.write().await;
        if let Some(user) = store.users.get_mut(user_id) {
            user.password_hash = password_hash.to_string();
            user.last_modified_date = chrono::Utc::now();
        }
    }

    // ==================== Confirmation Code Operations ====================

    pub async fn save_confirmation_code(&self, code: ConfirmationCode) {
        let mut store = self.principal_store.write().await;
        store.confirmation_codes.insert(code.user_id, code);
    }

    pub async fn get_confirmation_code(&self, user_id: &UserId) -> Option<ConfirmationCode> {
        let store = self.principal_store.read().await;
        store.confirmation_codes.get(user_id).cloned()
    }

    pub async fn delete_confirmation_code(&self, user_id: &UserId) {
        let mut store = self.principal_store.write().await;
        store.confirmation_codes.remove(user_id);
    }

    // ==================== Refresh Token Operations ====================

    pub async fn save_refresh_token(&self, token: RefreshToken) {
        let mut store = self.principal_store.write().await;
        store.refresh_tokens.insert(token.token.clone(), token);
    }

    pub async fn save_auth_challenge_session(&self, challenge: PendingAuthChallenge) {
        let mut store = self.principal_store.write().await;
        store
            .auth_challenge_sessions
            .insert(challenge.session.clone(), challenge);
    }

    pub async fn get_auth_challenge_session(&self, session: &str) -> Option<PendingAuthChallenge> {
        let store = self.principal_store.read().await;
        store.auth_challenge_sessions.get(session).cloned()
    }

    pub async fn delete_auth_challenge_session(&self, session: &str) {
        let mut store = self.principal_store.write().await;
        store.auth_challenge_sessions.remove(session);
    }

    pub async fn get_refresh_token(&self, token: &str) -> Option<RefreshToken> {
        let store = self.principal_store.read().await;
        store.refresh_tokens.get(token).cloned()
    }

    pub async fn delete_refresh_token(&self, token: &str) {
        let mut store = self.principal_store.write().await;
        store.refresh_tokens.remove(token);
    }

    pub async fn delete_refresh_tokens_for_user(&self, user_id: &UserId) {
        let mut store = self.principal_store.write().await;
        store.refresh_tokens.retain(|_, v| &v.user_id != user_id);
    }

    // ==================== Software Token MFA Operations ====================

    pub async fn save_software_token_session(
        &self,
        session: String,
        user_id: &UserId,
        secret: String,
    ) {
        let mut store = self.principal_store.write().await;
        store
            .software_token_sessions
            .insert(session, (*user_id, secret));
    }

    pub async fn get_software_token_session(&self, session: &str) -> Option<(UserId, String)> {
        let store = self.principal_store.read().await;
        store.software_token_sessions.get(session).cloned()
    }

    pub async fn delete_software_token_session(&self, session: &str) {
        let mut store = self.principal_store.write().await;
        store.software_token_sessions.remove(session);
    }

    pub async fn add_user_auth_factor(&self, user_id: &UserId, factor: &str) {
        let mut store = self.principal_store.write().await;
        let factors = store.user_auth_factors.entry(*user_id).or_default();
        if !factors.iter().any(|existing| existing == factor) {
            factors.push(factor.to_string());
        }
    }

    pub async fn remove_user_auth_factor(&self, user_id: &UserId, factor: &str) {
        let mut store = self.principal_store.write().await;
        if let Some(factors) = store.user_auth_factors.get_mut(user_id) {
            factors.retain(|existing| existing != factor);
        }
    }

    pub async fn list_user_auth_factors(&self, user_id: &UserId) -> Vec<String> {
        let store = self.principal_store.read().await;
        store
            .user_auth_factors
            .get(user_id)
            .cloned()
            .unwrap_or_default()
    }

    // ==================== Auth Event Operations ====================

    pub async fn create_auth_event(&self, event: AuthEvent) -> AuthEvent {
        let mut store = self.principal_store.write().await;
        store
            .user_auth_event_index
            .entry(event.user_id)
            .or_default()
            .push(event.event_id.clone());
        store
            .auth_events
            .insert(event.event_id.clone(), event.clone());
        event
    }

    pub async fn get_auth_event(&self, event_id: &str) -> Option<AuthEvent> {
        let store = self.principal_store.read().await;
        store.auth_events.get(event_id).cloned()
    }

    pub async fn update_auth_event(&self, event: AuthEvent) -> Option<AuthEvent> {
        let mut store = self.principal_store.write().await;
        if let std::collections::hash_map::Entry::Occupied(mut e) =
            store.auth_events.entry(event.event_id.clone())
        {
            e.insert(event.clone());
            Some(event)
        } else {
            None
        }
    }

    pub async fn list_auth_events_for_user(&self, user_id: &UserId) -> Vec<AuthEvent> {
        let store = self.principal_store.read().await;
        store
            .user_auth_event_index
            .get(user_id)
            .map(|ids| {
                ids.iter()
                    .filter_map(|id| store.auth_events.get(id))
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    // ==================== Group Operations ====================

    pub async fn create_group(&self, group: Group) -> Group {
        let mut store = self.group_store.write().await;
        store.groups.insert(
            (group.user_pool_id.clone(), group.group_name.clone()),
            group.clone(),
        );
        group
    }

    pub async fn get_group(
        &self,
        user_pool_id: &UserPoolId,
        group_name: &GroupName,
    ) -> Option<Group> {
        let store = self.group_store.read().await;
        store
            .groups
            .get(&(user_pool_id.clone(), group_name.clone()))
            .cloned()
    }

    pub async fn update_group(&self, group: Group) -> Option<Group> {
        let mut store = self.group_store.write().await;
        let key = (group.user_pool_id.clone(), group.group_name.clone());
        if let std::collections::hash_map::Entry::Occupied(mut e) = store.groups.entry(key) {
            e.insert(group.clone());
            Some(group)
        } else {
            None
        }
    }

    pub async fn delete_group(
        &self,
        user_pool_id: &UserPoolId,
        group_name: &GroupName,
    ) -> Option<Group> {
        let mut store = self.group_store.write().await;
        let removed = store
            .groups
            .remove(&(user_pool_id.clone(), group_name.clone()));

        if removed.is_some() {
            store.user_groups.retain(|_, groups| {
                groups.retain(|group| group != group_name);
                !groups.is_empty()
            });
        }

        removed
    }

    pub async fn list_groups(&self, user_pool_id: &UserPoolId) -> Vec<Group> {
        let store = self.group_store.read().await;
        store
            .groups
            .values()
            .filter(|g| &g.user_pool_id == user_pool_id)
            .cloned()
            .collect()
    }

    // ==================== User Group Membership Operations ====================

    pub async fn add_user_to_group(&self, user_id: &UserId, group_name: &GroupName) {
        let mut store = self.group_store.write().await;
        let groups = store.user_groups.entry(*user_id).or_default();
        if !groups.contains(group_name) {
            groups.push(group_name.clone());
        }
    }

    pub async fn remove_user_from_group(&self, user_id: &UserId, group_name: &GroupName) {
        let mut store = self.group_store.write().await;
        if let Some(groups) = store.user_groups.get_mut(user_id) {
            groups.retain(|g| g != group_name);
            if groups.is_empty() {
                store.user_groups.remove(user_id);
            }
        }
    }

    pub async fn get_groups_for_user(&self, user_id: &UserId) -> Vec<GroupName> {
        let store = self.group_store.read().await;
        store.user_groups.get(user_id).cloned().unwrap_or_default()
    }

    pub async fn get_users_in_group(
        &self,
        user_pool_id: &UserPoolId,
        group_name: &GroupName,
    ) -> Vec<User> {
        let principal_store = self.principal_store.read().await;
        let group_store = self.group_store.read().await;

        group_store
            .user_groups
            .iter()
            .filter(|(_, groups)| groups.contains(group_name))
            .filter_map(|(user_id, _)| principal_store.users.get(user_id))
            .filter(|user| &user.user_pool_id == user_pool_id)
            .cloned()
            .collect()
    }

    // ==================== Password Reset Code Operations ====================

    pub async fn save_password_reset_code(&self, code: PasswordResetCode) {
        let mut store = self.principal_store.write().await;
        store.password_reset_codes.insert(code.user_id, code);
    }

    pub async fn get_password_reset_code(&self, user_id: &UserId) -> Option<PasswordResetCode> {
        let store = self.principal_store.read().await;
        store.password_reset_codes.get(user_id).cloned()
    }

    pub async fn delete_password_reset_code(&self, user_id: &UserId) {
        let mut store = self.principal_store.write().await;
        store.password_reset_codes.remove(user_id);
    }

    // ==================== Authorization Code Operations ====================

    pub async fn save_authorization_code(&self, code: AuthorizationCode) {
        let mut store = self.principal_store.write().await;
        store.authorization_codes.insert(code.code.clone(), code);
    }

    pub async fn get_authorization_code(&self, code: &str) -> Option<AuthorizationCode> {
        let store = self.principal_store.read().await;
        store.authorization_codes.get(code).cloned()
    }

    pub async fn delete_authorization_code(&self, code: &str) -> Option<AuthorizationCode> {
        let mut store = self.principal_store.write().await;
        store.authorization_codes.remove(code)
    }

    // ==================== Managed Login Branding Operations ====================

    pub async fn create_managed_login_branding(
        &self,
        branding: ManagedLoginBranding,
    ) -> ManagedLoginBranding {
        let mut store = self.branding_store.write().await;

        // Index by user pool
        store
            .user_pool_brandings
            .insert(branding.user_pool_id.clone(), branding.branding_id.clone());

        // Index by client if specified
        if let Some(ref client_id) = branding.client_id {
            store
                .client_brandings
                .insert(client_id.clone(), branding.branding_id.clone());
        }

        store
            .managed_login_brandings
            .insert(branding.branding_id.clone(), branding.clone());
        branding
    }

    pub async fn get_managed_login_branding(
        &self,
        branding_id: &BrandingId,
    ) -> Option<ManagedLoginBranding> {
        let store = self.branding_store.read().await;
        store.managed_login_brandings.get(branding_id).cloned()
    }

    pub async fn get_managed_login_branding_by_user_pool(
        &self,
        user_pool_id: &UserPoolId,
    ) -> Option<ManagedLoginBranding> {
        let store = self.branding_store.read().await;
        let branding_id = store.user_pool_brandings.get(user_pool_id)?;
        store.managed_login_brandings.get(branding_id).cloned()
    }

    pub async fn get_managed_login_branding_by_client(
        &self,
        client_id: &ClientId,
    ) -> Option<ManagedLoginBranding> {
        let store = self.branding_store.read().await;
        let branding_id = store.client_brandings.get(client_id)?;
        store.managed_login_brandings.get(branding_id).cloned()
    }

    pub async fn update_managed_login_branding(
        &self,
        branding: ManagedLoginBranding,
    ) -> Option<ManagedLoginBranding> {
        let mut store = self.branding_store.write().await;
        if let std::collections::hash_map::Entry::Occupied(mut e) = store
            .managed_login_brandings
            .entry(branding.branding_id.clone())
        {
            e.insert(branding.clone());
            Some(branding)
        } else {
            None
        }
    }

    pub async fn delete_managed_login_branding(
        &self,
        branding_id: &BrandingId,
    ) -> Option<ManagedLoginBranding> {
        let mut store = self.branding_store.write().await;
        if let Some(branding) = store.managed_login_brandings.remove(branding_id) {
            store.user_pool_brandings.remove(&branding.user_pool_id);
            if let Some(ref client_id) = branding.client_id {
                store.client_brandings.remove(client_id);
            }
            Some(branding)
        } else {
            None
        }
    }

    // ==================== User Import Job Operations ====================

    pub async fn create_user_import_job(&self, job: UserImportJob) -> UserImportJob {
        let mut store = self.pool_store.write().await;
        store
            .user_import_jobs
            .insert(job.job_id.clone(), job.clone());
        job
    }

    pub async fn get_user_import_job(&self, job_id: &str) -> Option<UserImportJob> {
        let store = self.pool_store.read().await;
        store.user_import_jobs.get(job_id).cloned()
    }

    pub async fn list_user_import_jobs(&self, user_pool_id: &UserPoolId) -> Vec<UserImportJob> {
        let store = self.pool_store.read().await;
        store
            .user_import_jobs
            .values()
            .filter(|job| &job.user_pool_id == user_pool_id)
            .cloned()
            .collect()
    }

    pub async fn update_user_import_job(&self, job: UserImportJob) -> Option<UserImportJob> {
        let mut store = self.pool_store.write().await;
        if let std::collections::hash_map::Entry::Occupied(mut e) =
            store.user_import_jobs.entry(job.job_id.clone())
        {
            e.insert(job.clone());
            Some(job)
        } else {
            None
        }
    }

    // ==================== Terms Operations ====================

    pub async fn create_terms(&self, terms: TermsDocument) -> TermsDocument {
        let mut store = self.pool_store.write().await;
        store.terms_name_index.insert(
            (
                terms.user_pool_id.clone(),
                terms.client_id.clone(),
                terms.terms_name.clone(),
            ),
            terms.terms_id.clone(),
        );
        store
            .terms_documents
            .insert(terms.terms_id.clone(), terms.clone());
        terms
    }

    pub async fn get_terms_by_id(&self, terms_id: &str) -> Option<TermsDocument> {
        let store = self.pool_store.read().await;
        store.terms_documents.get(terms_id).cloned()
    }

    pub async fn get_terms_by_name(
        &self,
        user_pool_id: &UserPoolId,
        client_id: &ClientId,
        terms_name: &str,
    ) -> Option<TermsDocument> {
        let store = self.pool_store.read().await;
        let id = store.terms_name_index.get(&(
            user_pool_id.clone(),
            client_id.clone(),
            terms_name.to_string(),
        ))?;
        store.terms_documents.get(id).cloned()
    }

    pub async fn list_terms(&self, user_pool_id: &UserPoolId) -> Vec<TermsDocument> {
        let store = self.pool_store.read().await;
        store
            .terms_documents
            .values()
            .filter(|terms| &terms.user_pool_id == user_pool_id)
            .cloned()
            .collect()
    }

    pub async fn update_terms(&self, terms: TermsDocument) -> Option<TermsDocument> {
        let mut store = self.pool_store.write().await;
        if let std::collections::hash_map::Entry::Occupied(mut e) =
            store.terms_documents.entry(terms.terms_id.clone())
        {
            let previous = e.get().clone();
            e.insert(terms.clone());
            store.terms_name_index.remove(&(
                previous.user_pool_id,
                previous.client_id,
                previous.terms_name,
            ));
            store.terms_name_index.insert(
                (
                    terms.user_pool_id.clone(),
                    terms.client_id.clone(),
                    terms.terms_name.clone(),
                ),
                terms.terms_id.clone(),
            );
            Some(terms)
        } else {
            None
        }
    }

    pub async fn delete_terms(
        &self,
        user_pool_id: &UserPoolId,
        terms_id: &str,
    ) -> Option<TermsDocument> {
        let mut store = self.pool_store.write().await;
        let terms = store.terms_documents.get(terms_id)?.clone();
        if &terms.user_pool_id != user_pool_id {
            return None;
        }
        store.terms_name_index.remove(&(
            terms.user_pool_id.clone(),
            terms.client_id.clone(),
            terms.terms_name.clone(),
        ));
        store.terms_documents.remove(terms_id)
    }

    // ==================== UI Customization Operations ====================

    pub async fn set_ui_customization(&self, customization: UiCustomization) -> UiCustomization {
        let mut store = self.pool_store.write().await;
        store.ui_customizations.insert(
            (
                customization.user_pool_id.clone(),
                customization.client_id.clone(),
            ),
            customization.clone(),
        );
        customization
    }

    pub async fn get_ui_customization(
        &self,
        user_pool_id: &UserPoolId,
        client_id: Option<&ClientId>,
    ) -> Option<UiCustomization> {
        let store = self.pool_store.read().await;
        let key = (user_pool_id.clone(), client_id.cloned());
        if let Some(found) = store.ui_customizations.get(&key) {
            return Some(found.clone());
        }
        if client_id.is_some() {
            return store
                .ui_customizations
                .get(&(user_pool_id.clone(), None))
                .cloned();
        }
        None
    }

    // ==================== Risk Configuration Operations ====================

    pub async fn set_risk_configuration(
        &self,
        user_pool_id: &UserPoolId,
        client_id: Option<&ClientId>,
        value: Value,
    ) {
        let mut store = self.pool_store.write().await;
        store
            .risk_configurations
            .insert((user_pool_id.clone(), client_id.cloned()), value);
    }

    pub async fn get_risk_configuration(
        &self,
        user_pool_id: &UserPoolId,
        client_id: Option<&ClientId>,
    ) -> Option<Value> {
        let store = self.pool_store.read().await;
        let key = (user_pool_id.clone(), client_id.cloned());
        if let Some(found) = store.risk_configurations.get(&key) {
            return Some(found.clone());
        }
        if client_id.is_some() {
            return store
                .risk_configurations
                .get(&(user_pool_id.clone(), None))
                .cloned();
        }
        None
    }

    // ==================== Log Delivery Configuration Operations ====================

    pub async fn set_log_delivery_configuration(
        &self,
        user_pool_id: &UserPoolId,
        log_configurations: Vec<Value>,
    ) {
        let mut store = self.pool_store.write().await;
        store
            .log_delivery_configurations
            .insert(user_pool_id.clone(), log_configurations);
    }

    pub async fn get_log_delivery_configuration(
        &self,
        user_pool_id: &UserPoolId,
    ) -> Option<Vec<Value>> {
        let store = self.pool_store.read().await;
        store.log_delivery_configurations.get(user_pool_id).cloned()
    }

    // ==================== WebAuthn Operations ====================

    pub async fn save_webauthn_challenge(&self, user_id: &UserId, challenge: String) {
        let mut store = self.principal_store.write().await;
        store
            .webauthn_registration_challenges
            .insert(*user_id, challenge);
    }

    pub async fn get_webauthn_challenge(&self, user_id: &UserId) -> Option<String> {
        let store = self.principal_store.read().await;
        store.webauthn_registration_challenges.get(user_id).cloned()
    }

    pub async fn delete_webauthn_challenge(&self, user_id: &UserId) {
        let mut store = self.principal_store.write().await;
        store.webauthn_registration_challenges.remove(user_id);
    }

    pub async fn add_webauthn_credential(
        &self,
        user_id: &UserId,
        credential: WebAuthnCredential,
    ) -> WebAuthnCredential {
        let mut store = self.principal_store.write().await;
        let creds = store.webauthn_credentials.entry(*user_id).or_default();
        creds.retain(|c| c.credential_id != credential.credential_id);
        creds.push(credential.clone());
        credential
    }

    pub async fn list_webauthn_credentials(&self, user_id: &UserId) -> Vec<WebAuthnCredential> {
        let store = self.principal_store.read().await;
        store
            .webauthn_credentials
            .get(user_id)
            .cloned()
            .unwrap_or_default()
    }

    pub async fn delete_webauthn_credential(&self, user_id: &UserId, credential_id: &str) -> bool {
        let mut store = self.principal_store.write().await;
        if let Some(creds) = store.webauthn_credentials.get_mut(user_id) {
            let original_len = creds.len();
            creds.retain(|c| c.credential_id != credential_id);
            return creds.len() != original_len;
        }
        false
    }
}

impl Default for Storage {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    use crate::config::StorageConfig;
    use crate::types::{UserPool, UserPoolId};

    fn temp_data_file() -> PathBuf {
        std::env::temp_dir().join(format!("cognitox-storage-{}.json", uuid::Uuid::new_v4()))
    }

    #[test]
    fn test_memory_backend_describe() {
        let storage = Storage::new();
        assert_eq!(storage.backend_description(), "memory (no persistence)");
    }

    #[tokio::test]
    async fn test_persistence_roundtrip() {
        let path = temp_data_file();

        let config = StorageConfig::persistent(path.clone());
        let storage = Storage::with_config(config).unwrap();
        let now = Utc::now();
        let pool = UserPool {
            id: UserPoolId::new_local(),
            name: "persisted-pool".to_string(),
            creation_date: now,
            last_modified_date: now,
            account_recovery_setting: None,
            admin_create_user_config: None,
            alias_attributes: None,
            auto_verified_attributes: None,
            deletion_protection: None,
            device_configuration: None,
            email_configuration: None,
            email_verification_message: None,
            email_verification_subject: None,
            lambda_config: None,
            mfa_configuration: None,
            sms_mfa_configuration: None,
            software_token_mfa_configuration: None,
            email_mfa_configuration: None,
            webauthn_configuration: None,
            policies: None,
            schema_attributes: None,
            sms_authentication_message: None,
            sms_configuration: None,
            sms_verification_message: None,
            user_attribute_update_settings: None,
            user_pool_add_ons: None,
            user_pool_tags: None,
            user_pool_tier: None,
            username_attributes: None,
            username_configuration: None,
            verification_message_template: None,
        };
        storage.create_user_pool(pool).await;
        storage.flush_persistence().await.unwrap();

        let loaded = Storage::with_config(StorageConfig::persistent(path.clone())).unwrap();
        let pools = loaded.list_user_pools().await;
        assert_eq!(pools.len(), 1);
        assert_eq!(pools[0].name, "persisted-pool");
        assert_eq!(loaded.backend_description(), "persistent (file)");

        let _ = fs::remove_file(path);
    }

    #[tokio::test]
    async fn test_persistence_roundtrip_compat() {
        let path = temp_data_file();

        let storage = Storage::try_with_data_file(Some(path.clone())).unwrap();
        let now = Utc::now();
        let pool = UserPool {
            id: UserPoolId::new_local(),
            name: "compat-pool".to_string(),
            creation_date: now,
            last_modified_date: now,
            account_recovery_setting: None,
            admin_create_user_config: None,
            alias_attributes: None,
            auto_verified_attributes: None,
            deletion_protection: None,
            device_configuration: None,
            email_configuration: None,
            email_verification_message: None,
            email_verification_subject: None,
            lambda_config: None,
            mfa_configuration: None,
            sms_mfa_configuration: None,
            software_token_mfa_configuration: None,
            email_mfa_configuration: None,
            webauthn_configuration: None,
            policies: None,
            schema_attributes: None,
            sms_authentication_message: None,
            sms_configuration: None,
            sms_verification_message: None,
            user_attribute_update_settings: None,
            user_pool_add_ons: None,
            user_pool_tags: None,
            user_pool_tier: None,
            username_attributes: None,
            username_configuration: None,
            verification_message_template: None,
        };
        storage.create_user_pool(pool).await;
        storage.flush_persistence().await.unwrap();

        let loaded = Storage::try_with_data_file(Some(path.clone())).unwrap();
        let pools = loaded.list_user_pools().await;
        assert_eq!(pools.len(), 1);
        assert_eq!(pools[0].name, "compat-pool");

        let _ = fs::remove_file(path);
    }

    #[test]
    fn test_invalid_persistence_file_fails() {
        let path = temp_data_file();
        fs::write(&path, "{not valid json").unwrap();

        let result = Storage::with_config(StorageConfig::persistent(path.clone()));
        assert!(result.is_err());

        let _ = fs::remove_file(path);
    }

    #[test]
    fn test_null_backend_load_returns_default() {
        let backend = NullBackend;
        let state = backend.load().unwrap();
        assert!(state.pool_store.user_pools.is_empty());
        assert!(state.principal_store.users.is_empty());
    }

    #[test]
    fn test_null_backend_save_is_noop() {
        let backend = NullBackend;
        let state = PersistedStorageState::default();
        assert!(backend.save(&state).is_ok());
    }

    #[test]
    fn test_null_backend_no_flush_interval() {
        let backend = NullBackend;
        assert!(backend.flush_interval().is_none());
    }

    #[test]
    fn test_file_backend_load_missing_file_returns_default() {
        let backend = FileBackend {
            data_file: PathBuf::from("/tmp/cognitox-nonexistent-file.json"),
            flush_interval: Duration::from_millis(500),
        };
        let state = backend.load().unwrap();
        assert!(state.pool_store.user_pools.is_empty());
    }

    #[test]
    fn test_file_backend_has_flush_interval() {
        let backend = FileBackend {
            data_file: PathBuf::from("/tmp/test.json"),
            flush_interval: Duration::from_millis(1000),
        };
        assert_eq!(backend.flush_interval(), Some(Duration::from_millis(1000)));
    }

    #[test]
    fn test_file_backend_save_and_load_roundtrip() {
        let path = temp_data_file();
        let backend = FileBackend {
            data_file: path.clone(),
            flush_interval: Duration::from_millis(500),
        };

        let mut state = PersistedStorageState::default();
        let now = Utc::now();
        let pool = UserPool {
            id: UserPoolId::new_local(),
            name: "backend-test-pool".to_string(),
            creation_date: now,
            last_modified_date: now,
            account_recovery_setting: None,
            admin_create_user_config: None,
            alias_attributes: None,
            auto_verified_attributes: None,
            deletion_protection: None,
            device_configuration: None,
            email_configuration: None,
            email_verification_message: None,
            email_verification_subject: None,
            lambda_config: None,
            mfa_configuration: None,
            sms_mfa_configuration: None,
            software_token_mfa_configuration: None,
            email_mfa_configuration: None,
            webauthn_configuration: None,
            policies: None,
            schema_attributes: None,
            sms_authentication_message: None,
            sms_configuration: None,
            sms_verification_message: None,
            user_attribute_update_settings: None,
            user_pool_add_ons: None,
            user_pool_tags: None,
            user_pool_tier: None,
            username_attributes: None,
            username_configuration: None,
            verification_message_template: None,
        };
        state.pool_store.user_pools.insert(pool.id.clone(), pool);
        backend.save(&state).unwrap();

        let loaded = backend.load().unwrap();
        assert_eq!(loaded.pool_store.user_pools.len(), 1);
        let has_pool = loaded
            .pool_store
            .user_pools
            .values()
            .any(|p| p.name == "backend-test-pool");
        assert!(has_pool);

        let _ = fs::remove_file(path);
    }

    #[tokio::test]
    async fn test_memory_mode_flush_is_noop() {
        let storage = Storage::new();
        // flush on memory backend should succeed silently
        assert!(storage.flush_persistence().await.is_ok());
    }

    #[test]
    fn test_try_with_data_file_none_is_memory() {
        let storage = Storage::try_with_data_file(None).unwrap();
        assert_eq!(storage.backend_description(), "memory (no persistence)");
    }

    #[test]
    fn test_try_with_data_file_some_is_persistent() {
        let path = temp_data_file();
        let storage = Storage::try_with_data_file(Some(path.clone())).unwrap();
        assert_eq!(storage.backend_description(), "persistent (file)");
        let _ = fs::remove_file(path);
    }

    #[test]
    fn test_storage_debug_format() {
        let storage = Storage::new();
        let debug = format!("{:?}", storage);
        assert!(debug.contains("memory (no persistence)"));
    }
}
