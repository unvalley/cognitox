//! In-memory storage for Cognito entities with optional file persistence.
//!
//! This module provides thread-safe in-memory storage for user pools, clients, and users.
//! If `DATA_FILE` is set, state is loaded from/saved to that file.

use std::{
    collections::{HashMap, HashSet},
    fs,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::RwLock;
use tracing::error;

use crate::types::{
    AuthEvent, AuthorizationCode, BrandingId, ClientId, ConfirmationCode, Device, DomainPrefix,
    Group, GroupName, IdentityProvider, ManagedLoginBranding, PasswordResetCode, RefreshToken,
    ResourceServer, TermsDocument, UiCustomization, User, UserId, UserImportJob, UserPool,
    UserPoolClient, UserPoolDomain, UserPoolId, WebAuthnCredential,
};

#[derive(Debug, Clone)]
pub struct Storage {
    inner: Arc<RwLock<StorageInner>>,
    persistence: Option<Arc<PersistenceConfig>>,
}

#[derive(Debug, Serialize, Deserialize, Default)]
struct StorageInner {
    user_pools: HashMap<UserPoolId, UserPool>,
    user_pool_clients: HashMap<ClientId, UserPoolClient>,
    user_pool_domains: HashMap<DomainPrefix, UserPoolDomain>,
    user_pool_id_to_domain: HashMap<UserPoolId, DomainPrefix>,
    identity_providers: HashMap<(UserPoolId, String), IdentityProvider>,
    resource_servers: HashMap<(UserPoolId, String), ResourceServer>,
    managed_login_brandings: HashMap<BrandingId, ManagedLoginBranding>,
    user_pool_brandings: HashMap<UserPoolId, BrandingId>,
    client_brandings: HashMap<ClientId, BrandingId>,
    users: HashMap<UserId, User>,
    devices: HashMap<(UserId, String), Device>,
    confirmation_codes: HashMap<UserId, ConfirmationCode>,
    refresh_tokens: HashMap<String, RefreshToken>,
    software_token_sessions: HashMap<String, (UserId, String)>,
    user_auth_factors: HashMap<UserId, Vec<String>>,
    auth_events: HashMap<String, AuthEvent>,
    user_auth_event_index: HashMap<UserId, Vec<String>>,
    authorization_codes: HashMap<String, AuthorizationCode>,
    username_index: HashMap<(UserPoolId, String), UserId>,
    groups: HashMap<(UserPoolId, GroupName), Group>,
    user_groups: HashMap<UserId, Vec<GroupName>>,
    password_reset_codes: HashMap<UserId, PasswordResetCode>,
    user_import_jobs: HashMap<String, UserImportJob>,
    terms_documents: HashMap<String, TermsDocument>,
    terms_name_index: HashMap<(UserPoolId, ClientId, String), String>,
    ui_customizations: HashMap<(UserPoolId, Option<ClientId>), UiCustomization>,
    risk_configurations: HashMap<(UserPoolId, Option<ClientId>), Value>,
    log_delivery_configurations: HashMap<UserPoolId, Vec<Value>>,
    webauthn_credentials: HashMap<UserId, Vec<WebAuthnCredential>>,
    webauthn_registration_challenges: HashMap<UserId, String>,
}

#[derive(Debug)]
struct PersistenceConfig {
    data_file: PathBuf,
}

#[derive(Debug, Serialize, Deserialize)]
struct PersistedSnapshot {
    version: u32,
    encoding: String,
    payload: String,
}

impl PersistedSnapshot {
    const CURRENT_VERSION: u32 = 1;
    const CURRENT_ENCODING: &'static str = "bincode+base64";
}

impl Storage {
    pub fn new() -> Self {
        Self::try_new().expect("Failed to initialize storage")
    }

    pub fn try_new() -> Result<Self, String> {
        let data_file = std::env::var("DATA_FILE").ok().map(PathBuf::from);
        Self::try_with_data_file(data_file)
    }

    pub fn try_with_data_file(data_file: Option<PathBuf>) -> Result<Self, String> {
        let persistence = data_file.map(|data_file| Arc::new(PersistenceConfig { data_file }));
        let initial_inner = if let Some(config) = &persistence {
            Self::load_from_file(&config.data_file)?
        } else {
            StorageInner::default()
        };

        let storage = Self {
            inner: Arc::new(RwLock::new(initial_inner)),
            persistence,
        };
        storage.start_auto_persist_loop();
        Ok(storage)
    }

    fn start_auto_persist_loop(&self) {
        let Some(config) = &self.persistence else {
            return;
        };

        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            return;
        };

        let inner = Arc::downgrade(&self.inner);
        let data_file = config.data_file.clone();
        handle.spawn(async move {
            let mut last_snapshot: Option<Vec<u8>> = None;
            loop {
                tokio::time::sleep(Duration::from_millis(500)).await;
                let Some(inner) = inner.upgrade() else {
                    break;
                };
                let snapshot = {
                    let inner = inner.read().await;
                    match Storage::encode_snapshot(&inner) {
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

                if let Err(e) = Storage::write_snapshot_file(&data_file, &snapshot) {
                    error!("Failed to persist storage snapshot to {:?}: {e}", data_file);
                    continue;
                }

                last_snapshot = Some(snapshot);
            }
        });
    }

    fn load_from_file(path: &Path) -> Result<StorageInner, String> {
        match fs::read_to_string(path) {
            Ok(content) => Self::decode_snapshot(&content),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(StorageInner::default()),
            Err(e) => Err(format!("Failed to read data file {:?}: {}", path, e)),
        }
    }

    fn decode_snapshot(content: &str) -> Result<StorageInner, String> {
        let snapshot: PersistedSnapshot =
            serde_json::from_str(content).map_err(|e| format!("Invalid JSON snapshot: {e}"))?;

        if snapshot.version != PersistedSnapshot::CURRENT_VERSION {
            return Err(format!(
                "Unsupported snapshot version: {}",
                snapshot.version
            ));
        }

        if snapshot.encoding != PersistedSnapshot::CURRENT_ENCODING {
            return Err(format!(
                "Unsupported snapshot encoding: {}",
                snapshot.encoding
            ));
        }

        let payload = BASE64_STANDARD
            .decode(snapshot.payload.as_bytes())
            .map_err(|e| format!("Invalid snapshot payload encoding: {e}"))?;

        bincode::deserialize::<StorageInner>(&payload)
            .map_err(|e| format!("Failed to deserialize snapshot payload: {e}"))
    }

    fn encode_snapshot(inner: &StorageInner) -> Result<Vec<u8>, String> {
        let payload = bincode::serialize(inner)
            .map_err(|e| format!("Failed to serialize storage state: {e}"))?;
        let snapshot = PersistedSnapshot {
            version: PersistedSnapshot::CURRENT_VERSION,
            encoding: PersistedSnapshot::CURRENT_ENCODING.to_string(),
            payload: BASE64_STANDARD.encode(payload),
        };

        serde_json::to_vec_pretty(&snapshot).map_err(|e| format!("Failed to encode snapshot: {e}"))
    }

    fn write_snapshot_file(path: &Path, data: &[u8]) -> Result<(), String> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| {
                format!("Failed to create persistence directory {:?}: {}", parent, e)
            })?;
        }

        let tmp_path = path.with_extension("tmp");
        fs::write(&tmp_path, data)
            .map_err(|e| format!("Failed to write temp snapshot {:?}: {}", tmp_path, e))?;
        fs::rename(&tmp_path, path)
            .map_err(|e| format!("Failed to atomically move snapshot to {:?}: {}", path, e))
    }

    pub async fn flush_persistence(&self) -> Result<(), String> {
        let Some(config) = &self.persistence else {
            return Ok(());
        };
        let snapshot = {
            let inner = self.inner.read().await;
            Self::encode_snapshot(&inner)?
        };
        Self::write_snapshot_file(&config.data_file, &snapshot)
    }

    pub fn persistence_path(&self) -> Option<&Path> {
        self.persistence
            .as_ref()
            .map(|config| config.data_file.as_path())
    }

    // ==================== User Pool Operations ====================

    // ==================== User Pool Operations ====================

    pub async fn create_user_pool(&self, pool: UserPool) -> UserPool {
        let mut inner = self.inner.write().await;
        inner.user_pools.insert(pool.id.clone(), pool.clone());
        pool
    }

    pub async fn get_user_pool(&self, id: &UserPoolId) -> Option<UserPool> {
        let inner = self.inner.read().await;
        inner.user_pools.get(id).cloned()
    }

    pub async fn delete_user_pool(&self, id: &UserPoolId) -> Option<UserPool> {
        let mut inner = self.inner.write().await;
        let pool = inner.user_pools.remove(id)?;

        // Remove domain and reverse index entries for this pool.
        inner
            .user_pool_domains
            .retain(|_, domain| &domain.user_pool_id != id);
        inner
            .user_pool_id_to_domain
            .retain(|pool_id, _| pool_id != id);

        // Remove pool-scoped clients and keep track of their IDs for downstream cleanup.
        let client_ids: HashSet<ClientId> = inner
            .user_pool_clients
            .iter()
            .filter(|(_, client)| &client.user_pool_id == id)
            .map(|(client_id, _)| client_id.clone())
            .collect();
        inner
            .user_pool_clients
            .retain(|client_id, _| !client_ids.contains(client_id));

        // Remove pool-scoped entities.
        inner
            .identity_providers
            .retain(|(pool_id, _), _| pool_id != id);
        inner
            .resource_servers
            .retain(|(pool_id, _), _| pool_id != id);
        inner.groups.retain(|(pool_id, _), _| pool_id != id);
        inner
            .user_import_jobs
            .retain(|_, job| &job.user_pool_id != id);
        inner
            .ui_customizations
            .retain(|(pool_id, _), _| pool_id != id);
        inner
            .risk_configurations
            .retain(|(pool_id, _), _| pool_id != id);
        inner.log_delivery_configurations.remove(id);

        // Remove terms and associated indexes.
        let terms_ids: HashSet<String> = inner
            .terms_documents
            .iter()
            .filter(|(_, terms)| &terms.user_pool_id == id)
            .map(|(terms_id, _)| terms_id.clone())
            .collect();
        inner
            .terms_documents
            .retain(|terms_id, _| !terms_ids.contains(terms_id));
        inner
            .terms_name_index
            .retain(|(pool_id, _, _), terms_id| pool_id != id && !terms_ids.contains(terms_id));

        // Remove managed login branding for the pool and any clients that were removed.
        let branding_ids: HashSet<BrandingId> = inner
            .managed_login_brandings
            .iter()
            .filter(|(_, branding)| &branding.user_pool_id == id)
            .map(|(branding_id, _)| branding_id.clone())
            .collect();
        inner
            .managed_login_brandings
            .retain(|branding_id, _| !branding_ids.contains(branding_id));
        inner
            .user_pool_brandings
            .retain(|pool_id, branding_id| pool_id != id && !branding_ids.contains(branding_id));
        inner.client_brandings.retain(|client_id, branding_id| {
            !client_ids.contains(client_id) && !branding_ids.contains(branding_id)
        });

        // Remove users in this pool using the same cleanup semantics as DeleteUser.
        let user_ids: Vec<UserId> = inner
            .users
            .values()
            .filter(|user| &user.user_pool_id == id)
            .map(|user| user.id)
            .collect();
        let user_id_set: HashSet<UserId> = user_ids.iter().copied().collect();
        for user_id in user_ids {
            Self::remove_user_records(&mut inner, &user_id);
        }

        // Remove authorization codes tied to deleted users or clients.
        inner.authorization_codes.retain(|_, code| {
            !user_id_set.contains(&code.user_id) && !client_ids.contains(&code.client_id)
        });

        Some(pool)
    }

    pub async fn list_user_pools(&self) -> Vec<UserPool> {
        let inner = self.inner.read().await;
        inner.user_pools.values().cloned().collect()
    }

    pub async fn update_user_pool(&self, pool: UserPool) -> Option<UserPool> {
        let mut inner = self.inner.write().await;
        if let std::collections::hash_map::Entry::Occupied(mut e) =
            inner.user_pools.entry(pool.id.clone())
        {
            e.insert(pool.clone());
            Some(pool)
        } else {
            None
        }
    }

    // ==================== User Pool Client Operations ====================

    pub async fn create_user_pool_client(&self, client: UserPoolClient) -> UserPoolClient {
        let mut inner = self.inner.write().await;
        inner
            .user_pool_clients
            .insert(client.client_id.clone(), client.clone());
        client
    }

    pub async fn get_user_pool_client(&self, client_id: &ClientId) -> Option<UserPoolClient> {
        let inner = self.inner.read().await;
        inner.user_pool_clients.get(client_id).cloned()
    }

    pub async fn delete_user_pool_client(&self, client_id: &ClientId) -> Option<UserPoolClient> {
        let mut inner = self.inner.write().await;
        inner.user_pool_clients.remove(client_id)
    }

    pub async fn list_user_pool_clients(&self, user_pool_id: &UserPoolId) -> Vec<UserPoolClient> {
        let inner = self.inner.read().await;
        inner
            .user_pool_clients
            .values()
            .filter(|c| &c.user_pool_id == user_pool_id)
            .cloned()
            .collect()
    }

    pub async fn update_user_pool_client(&self, client: UserPoolClient) -> Option<UserPoolClient> {
        let mut inner = self.inner.write().await;
        if let std::collections::hash_map::Entry::Occupied(mut e) =
            inner.user_pool_clients.entry(client.client_id.clone())
        {
            e.insert(client.clone());
            Some(client)
        } else {
            None
        }
    }

    // ==================== User Pool Domain Operations ====================

    pub async fn create_user_pool_domain(&self, domain: UserPoolDomain) -> UserPoolDomain {
        let mut inner = self.inner.write().await;
        inner
            .user_pool_id_to_domain
            .insert(domain.user_pool_id.clone(), domain.domain.clone());
        inner
            .user_pool_domains
            .insert(domain.domain.clone(), domain.clone());
        domain
    }

    pub async fn get_user_pool_domain(&self, domain: &DomainPrefix) -> Option<UserPoolDomain> {
        let inner = self.inner.read().await;
        inner.user_pool_domains.get(domain).cloned()
    }

    pub async fn get_user_pool_domain_by_user_pool_id(
        &self,
        user_pool_id: &UserPoolId,
    ) -> Option<UserPoolDomain> {
        let inner = self.inner.read().await;
        let domain_prefix = inner.user_pool_id_to_domain.get(user_pool_id)?;
        inner.user_pool_domains.get(domain_prefix).cloned()
    }

    pub async fn update_user_pool_domain(&self, domain: UserPoolDomain) -> Option<UserPoolDomain> {
        let mut inner = self.inner.write().await;
        if let std::collections::hash_map::Entry::Occupied(mut e) =
            inner.user_pool_domains.entry(domain.domain.clone())
        {
            e.insert(domain.clone());
            Some(domain)
        } else {
            None
        }
    }

    pub async fn delete_user_pool_domain(&self, domain: &DomainPrefix) -> Option<UserPoolDomain> {
        let mut inner = self.inner.write().await;
        if let Some(removed) = inner.user_pool_domains.remove(domain) {
            inner.user_pool_id_to_domain.remove(&removed.user_pool_id);
            Some(removed)
        } else {
            None
        }
    }

    // ==================== Identity Provider Operations ====================

    pub async fn create_identity_provider(&self, provider: IdentityProvider) -> IdentityProvider {
        let mut inner = self.inner.write().await;
        inner.identity_providers.insert(
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
        let inner = self.inner.read().await;
        inner
            .identity_providers
            .get(&(user_pool_id.clone(), provider_name.to_string()))
            .cloned()
    }

    pub async fn get_identity_provider_by_identifier(
        &self,
        user_pool_id: &UserPoolId,
        identifier: &str,
    ) -> Option<IdentityProvider> {
        let inner = self.inner.read().await;
        inner
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
        let inner = self.inner.read().await;
        inner
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
        let mut inner = self.inner.write().await;
        let key = (
            provider.user_pool_id.clone(),
            provider.provider_name.clone(),
        );
        if let std::collections::hash_map::Entry::Occupied(mut e) =
            inner.identity_providers.entry(key)
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
        let mut inner = self.inner.write().await;
        inner
            .identity_providers
            .remove(&(user_pool_id.clone(), provider_name.to_string()))
    }

    // ==================== Resource Server Operations ====================

    pub async fn create_resource_server(&self, resource_server: ResourceServer) -> ResourceServer {
        let mut inner = self.inner.write().await;
        inner.resource_servers.insert(
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
        let inner = self.inner.read().await;
        inner
            .resource_servers
            .get(&(user_pool_id.clone(), identifier.to_string()))
            .cloned()
    }

    pub async fn list_resource_servers(&self, user_pool_id: &UserPoolId) -> Vec<ResourceServer> {
        let inner = self.inner.read().await;
        inner
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
        let mut inner = self.inner.write().await;
        let key = (
            resource_server.user_pool_id.clone(),
            resource_server.identifier.clone(),
        );
        if let std::collections::hash_map::Entry::Occupied(mut e) =
            inner.resource_servers.entry(key)
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
        let mut inner = self.inner.write().await;
        inner
            .resource_servers
            .remove(&(user_pool_id.clone(), identifier.to_string()))
    }

    // ==================== User Operations ====================

    pub async fn create_user(&self, user: User) -> User {
        let mut inner = self.inner.write().await;
        inner
            .username_index
            .insert((user.user_pool_id.clone(), user.username.clone()), user.id);
        inner.users.insert(user.id, user.clone());
        user
    }

    pub async fn get_user(&self, id: &UserId) -> Option<User> {
        let inner = self.inner.read().await;
        inner.users.get(id).cloned()
    }

    pub async fn get_user_by_username(
        &self,
        user_pool_id: &UserPoolId,
        username: &str,
    ) -> Option<User> {
        let inner = self.inner.read().await;
        let user_id = inner
            .username_index
            .get(&(user_pool_id.clone(), username.to_string()))?;
        inner.users.get(user_id).cloned()
    }

    pub async fn update_user(&self, user: User) -> Option<User> {
        let mut inner = self.inner.write().await;
        if let std::collections::hash_map::Entry::Occupied(mut e) = inner.users.entry(user.id) {
            e.insert(user.clone());
            Some(user)
        } else {
            None
        }
    }

    pub async fn delete_user(&self, id: &UserId) -> Option<User> {
        let mut inner = self.inner.write().await;
        Self::remove_user_records(&mut inner, id)
    }

    pub async fn list_users(&self, user_pool_id: &UserPoolId) -> Vec<User> {
        let inner = self.inner.read().await;
        inner
            .users
            .values()
            .filter(|u| &u.user_pool_id == user_pool_id)
            .cloned()
            .collect()
    }

    // ==================== Device Operations ====================

    pub async fn put_device(&self, device: Device) -> Device {
        let mut inner = self.inner.write().await;
        inner
            .devices
            .insert((device.user_id, device.device_key.clone()), device.clone());
        device
    }

    pub async fn get_device_for_user(&self, user_id: &UserId, device_key: &str) -> Option<Device> {
        let inner = self.inner.read().await;
        inner
            .devices
            .get(&(*user_id, device_key.to_string()))
            .cloned()
    }

    pub async fn list_devices_for_user(&self, user_id: &UserId) -> Vec<Device> {
        let inner = self.inner.read().await;
        inner
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
        let mut inner = self.inner.write().await;
        inner.devices.remove(&(*user_id, device_key.to_string()))
    }

    pub async fn update_device_for_user(&self, device: Device) -> Option<Device> {
        let mut inner = self.inner.write().await;
        let key = (device.user_id, device.device_key.clone());
        if let std::collections::hash_map::Entry::Occupied(mut e) = inner.devices.entry(key) {
            e.insert(device.clone());
            Some(device)
        } else {
            None
        }
    }

    /// Confirm a user by updating their status to Confirmed
    pub async fn confirm_user(&self, user_id: &UserId) {
        let mut inner = self.inner.write().await;
        if let Some(user) = inner.users.get_mut(user_id) {
            user.user_status = crate::types::UserStatus::Confirmed;
            user.last_modified_date = chrono::Utc::now();
        }
        // Also remove the confirmation code
        inner.confirmation_codes.remove(user_id);
    }

    /// Set the password for a user
    pub async fn set_user_password(&self, user_id: &UserId, password_hash: &str) {
        let mut inner = self.inner.write().await;
        if let Some(user) = inner.users.get_mut(user_id) {
            user.password_hash = password_hash.to_string();
            user.last_modified_date = chrono::Utc::now();
        }
    }

    // ==================== Confirmation Code Operations ====================

    pub async fn save_confirmation_code(&self, code: ConfirmationCode) {
        let mut inner = self.inner.write().await;
        inner.confirmation_codes.insert(code.user_id, code);
    }

    pub async fn get_confirmation_code(&self, user_id: &UserId) -> Option<ConfirmationCode> {
        let inner = self.inner.read().await;
        inner.confirmation_codes.get(user_id).cloned()
    }

    pub async fn delete_confirmation_code(&self, user_id: &UserId) {
        let mut inner = self.inner.write().await;
        inner.confirmation_codes.remove(user_id);
    }

    // ==================== Refresh Token Operations ====================

    pub async fn save_refresh_token(&self, token: RefreshToken) {
        let mut inner = self.inner.write().await;
        inner.refresh_tokens.insert(token.token.clone(), token);
    }

    pub async fn get_refresh_token(&self, token: &str) -> Option<RefreshToken> {
        let inner = self.inner.read().await;
        inner.refresh_tokens.get(token).cloned()
    }

    pub async fn delete_refresh_token(&self, token: &str) {
        let mut inner = self.inner.write().await;
        inner.refresh_tokens.remove(token);
    }

    pub async fn delete_refresh_tokens_for_user(&self, user_id: &UserId) {
        let mut inner = self.inner.write().await;
        inner.refresh_tokens.retain(|_, v| &v.user_id != user_id);
    }

    // ==================== Software Token MFA Operations ====================

    pub async fn save_software_token_session(
        &self,
        session: String,
        user_id: &UserId,
        secret: String,
    ) {
        let mut inner = self.inner.write().await;
        inner
            .software_token_sessions
            .insert(session, (*user_id, secret));
    }

    pub async fn get_software_token_session(&self, session: &str) -> Option<(UserId, String)> {
        let inner = self.inner.read().await;
        inner.software_token_sessions.get(session).cloned()
    }

    pub async fn delete_software_token_session(&self, session: &str) {
        let mut inner = self.inner.write().await;
        inner.software_token_sessions.remove(session);
    }

    pub async fn add_user_auth_factor(&self, user_id: &UserId, factor: &str) {
        let mut inner = self.inner.write().await;
        let factors = inner.user_auth_factors.entry(*user_id).or_default();
        if !factors.iter().any(|existing| existing == factor) {
            factors.push(factor.to_string());
        }
    }

    pub async fn list_user_auth_factors(&self, user_id: &UserId) -> Vec<String> {
        let inner = self.inner.read().await;
        inner
            .user_auth_factors
            .get(user_id)
            .cloned()
            .unwrap_or_default()
    }

    // ==================== Auth Event Operations ====================

    pub async fn create_auth_event(&self, event: AuthEvent) -> AuthEvent {
        let mut inner = self.inner.write().await;
        inner
            .user_auth_event_index
            .entry(event.user_id)
            .or_default()
            .push(event.event_id.clone());
        inner
            .auth_events
            .insert(event.event_id.clone(), event.clone());
        event
    }

    pub async fn get_auth_event(&self, event_id: &str) -> Option<AuthEvent> {
        let inner = self.inner.read().await;
        inner.auth_events.get(event_id).cloned()
    }

    pub async fn update_auth_event(&self, event: AuthEvent) -> Option<AuthEvent> {
        let mut inner = self.inner.write().await;
        if let std::collections::hash_map::Entry::Occupied(mut e) =
            inner.auth_events.entry(event.event_id.clone())
        {
            e.insert(event.clone());
            Some(event)
        } else {
            None
        }
    }

    pub async fn list_auth_events_for_user(&self, user_id: &UserId) -> Vec<AuthEvent> {
        let inner = self.inner.read().await;
        inner
            .user_auth_event_index
            .get(user_id)
            .map(|ids| {
                ids.iter()
                    .filter_map(|id| inner.auth_events.get(id))
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    // ==================== Group Operations ====================

    pub async fn create_group(&self, group: Group) -> Group {
        let mut inner = self.inner.write().await;
        inner.groups.insert(
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
        let inner = self.inner.read().await;
        inner
            .groups
            .get(&(user_pool_id.clone(), group_name.clone()))
            .cloned()
    }

    pub async fn update_group(&self, group: Group) -> Option<Group> {
        let mut inner = self.inner.write().await;
        let key = (group.user_pool_id.clone(), group.group_name.clone());
        if let std::collections::hash_map::Entry::Occupied(mut e) = inner.groups.entry(key) {
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
        let mut inner = self.inner.write().await;
        inner
            .groups
            .remove(&(user_pool_id.clone(), group_name.clone()))
    }

    pub async fn list_groups(&self, user_pool_id: &UserPoolId) -> Vec<Group> {
        let inner = self.inner.read().await;
        inner
            .groups
            .values()
            .filter(|g| &g.user_pool_id == user_pool_id)
            .cloned()
            .collect()
    }

    // ==================== User Group Membership Operations ====================

    pub async fn add_user_to_group(&self, user_id: &UserId, group_name: &GroupName) {
        let mut inner = self.inner.write().await;
        inner
            .user_groups
            .entry(*user_id)
            .or_default()
            .push(group_name.clone());
    }

    pub async fn remove_user_from_group(&self, user_id: &UserId, group_name: &GroupName) {
        let mut inner = self.inner.write().await;
        if let Some(groups) = inner.user_groups.get_mut(user_id) {
            groups.retain(|g| g != group_name);
        }
    }

    pub async fn get_groups_for_user(&self, user_id: &UserId) -> Vec<GroupName> {
        let inner = self.inner.read().await;
        inner.user_groups.get(user_id).cloned().unwrap_or_default()
    }

    pub async fn get_users_in_group(
        &self,
        user_pool_id: &UserPoolId,
        group_name: &GroupName,
    ) -> Vec<User> {
        let inner = self.inner.read().await;
        inner
            .user_groups
            .iter()
            .filter(|(_, groups)| groups.contains(group_name))
            .filter_map(|(user_id, _)| inner.users.get(user_id))
            .filter(|user| &user.user_pool_id == user_pool_id)
            .cloned()
            .collect()
    }

    // ==================== Password Reset Code Operations ====================

    pub async fn save_password_reset_code(&self, code: PasswordResetCode) {
        let mut inner = self.inner.write().await;
        inner.password_reset_codes.insert(code.user_id, code);
    }

    pub async fn get_password_reset_code(&self, user_id: &UserId) -> Option<PasswordResetCode> {
        let inner = self.inner.read().await;
        inner.password_reset_codes.get(user_id).cloned()
    }

    pub async fn delete_password_reset_code(&self, user_id: &UserId) {
        let mut inner = self.inner.write().await;
        inner.password_reset_codes.remove(user_id);
    }

    // ==================== Authorization Code Operations ====================

    pub async fn save_authorization_code(&self, code: AuthorizationCode) {
        let mut inner = self.inner.write().await;
        inner.authorization_codes.insert(code.code.clone(), code);
    }

    pub async fn get_authorization_code(&self, code: &str) -> Option<AuthorizationCode> {
        let inner = self.inner.read().await;
        inner.authorization_codes.get(code).cloned()
    }

    pub async fn delete_authorization_code(&self, code: &str) -> Option<AuthorizationCode> {
        let mut inner = self.inner.write().await;
        inner.authorization_codes.remove(code)
    }

    // ==================== Managed Login Branding Operations ====================

    pub async fn create_managed_login_branding(
        &self,
        branding: ManagedLoginBranding,
    ) -> ManagedLoginBranding {
        let mut inner = self.inner.write().await;

        // Index by user pool
        inner
            .user_pool_brandings
            .insert(branding.user_pool_id.clone(), branding.branding_id.clone());

        // Index by client if specified
        if let Some(ref client_id) = branding.client_id {
            inner
                .client_brandings
                .insert(client_id.clone(), branding.branding_id.clone());
        }

        inner
            .managed_login_brandings
            .insert(branding.branding_id.clone(), branding.clone());
        branding
    }

    pub async fn get_managed_login_branding(
        &self,
        branding_id: &BrandingId,
    ) -> Option<ManagedLoginBranding> {
        let inner = self.inner.read().await;
        inner.managed_login_brandings.get(branding_id).cloned()
    }

    pub async fn get_managed_login_branding_by_user_pool(
        &self,
        user_pool_id: &UserPoolId,
    ) -> Option<ManagedLoginBranding> {
        let inner = self.inner.read().await;
        let branding_id = inner.user_pool_brandings.get(user_pool_id)?;
        inner.managed_login_brandings.get(branding_id).cloned()
    }

    pub async fn get_managed_login_branding_by_client(
        &self,
        client_id: &ClientId,
    ) -> Option<ManagedLoginBranding> {
        let inner = self.inner.read().await;
        let branding_id = inner.client_brandings.get(client_id)?;
        inner.managed_login_brandings.get(branding_id).cloned()
    }

    pub async fn update_managed_login_branding(
        &self,
        branding: ManagedLoginBranding,
    ) -> Option<ManagedLoginBranding> {
        let mut inner = self.inner.write().await;
        if let std::collections::hash_map::Entry::Occupied(mut e) = inner
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
        let mut inner = self.inner.write().await;
        if let Some(branding) = inner.managed_login_brandings.remove(branding_id) {
            inner.user_pool_brandings.remove(&branding.user_pool_id);
            if let Some(ref client_id) = branding.client_id {
                inner.client_brandings.remove(client_id);
            }
            Some(branding)
        } else {
            None
        }
    }

    // ==================== User Import Job Operations ====================

    pub async fn create_user_import_job(&self, job: UserImportJob) -> UserImportJob {
        let mut inner = self.inner.write().await;
        inner
            .user_import_jobs
            .insert(job.job_id.clone(), job.clone());
        job
    }

    pub async fn get_user_import_job(&self, job_id: &str) -> Option<UserImportJob> {
        let inner = self.inner.read().await;
        inner.user_import_jobs.get(job_id).cloned()
    }

    pub async fn list_user_import_jobs(&self, user_pool_id: &UserPoolId) -> Vec<UserImportJob> {
        let inner = self.inner.read().await;
        inner
            .user_import_jobs
            .values()
            .filter(|job| &job.user_pool_id == user_pool_id)
            .cloned()
            .collect()
    }

    pub async fn update_user_import_job(&self, job: UserImportJob) -> Option<UserImportJob> {
        let mut inner = self.inner.write().await;
        if let std::collections::hash_map::Entry::Occupied(mut e) =
            inner.user_import_jobs.entry(job.job_id.clone())
        {
            e.insert(job.clone());
            Some(job)
        } else {
            None
        }
    }

    // ==================== Terms Operations ====================

    pub async fn create_terms(&self, terms: TermsDocument) -> TermsDocument {
        let mut inner = self.inner.write().await;
        inner.terms_name_index.insert(
            (
                terms.user_pool_id.clone(),
                terms.client_id.clone(),
                terms.terms_name.clone(),
            ),
            terms.terms_id.clone(),
        );
        inner
            .terms_documents
            .insert(terms.terms_id.clone(), terms.clone());
        terms
    }

    pub async fn get_terms_by_id(&self, terms_id: &str) -> Option<TermsDocument> {
        let inner = self.inner.read().await;
        inner.terms_documents.get(terms_id).cloned()
    }

    pub async fn get_terms_by_name(
        &self,
        user_pool_id: &UserPoolId,
        client_id: &ClientId,
        terms_name: &str,
    ) -> Option<TermsDocument> {
        let inner = self.inner.read().await;
        let id = inner.terms_name_index.get(&(
            user_pool_id.clone(),
            client_id.clone(),
            terms_name.to_string(),
        ))?;
        inner.terms_documents.get(id).cloned()
    }

    pub async fn list_terms(&self, user_pool_id: &UserPoolId) -> Vec<TermsDocument> {
        let inner = self.inner.read().await;
        inner
            .terms_documents
            .values()
            .filter(|terms| &terms.user_pool_id == user_pool_id)
            .cloned()
            .collect()
    }

    pub async fn update_terms(&self, terms: TermsDocument) -> Option<TermsDocument> {
        let mut inner = self.inner.write().await;
        if let std::collections::hash_map::Entry::Occupied(mut e) =
            inner.terms_documents.entry(terms.terms_id.clone())
        {
            e.insert(terms.clone());
            inner.terms_name_index.insert(
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
        let mut inner = self.inner.write().await;
        let terms = inner.terms_documents.get(terms_id)?.clone();
        if &terms.user_pool_id != user_pool_id {
            return None;
        }
        inner.terms_name_index.remove(&(
            terms.user_pool_id.clone(),
            terms.client_id.clone(),
            terms.terms_name.clone(),
        ));
        inner.terms_documents.remove(terms_id)
    }

    // ==================== UI Customization Operations ====================

    pub async fn set_ui_customization(&self, customization: UiCustomization) -> UiCustomization {
        let mut inner = self.inner.write().await;
        inner.ui_customizations.insert(
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
        let inner = self.inner.read().await;
        let key = (user_pool_id.clone(), client_id.cloned());
        if let Some(found) = inner.ui_customizations.get(&key) {
            return Some(found.clone());
        }
        if client_id.is_some() {
            return inner
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
        let mut inner = self.inner.write().await;
        inner
            .risk_configurations
            .insert((user_pool_id.clone(), client_id.cloned()), value);
    }

    pub async fn get_risk_configuration(
        &self,
        user_pool_id: &UserPoolId,
        client_id: Option<&ClientId>,
    ) -> Option<Value> {
        let inner = self.inner.read().await;
        let key = (user_pool_id.clone(), client_id.cloned());
        if let Some(found) = inner.risk_configurations.get(&key) {
            return Some(found.clone());
        }
        if client_id.is_some() {
            return inner
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
        let mut inner = self.inner.write().await;
        inner
            .log_delivery_configurations
            .insert(user_pool_id.clone(), log_configurations);
    }

    pub async fn get_log_delivery_configuration(
        &self,
        user_pool_id: &UserPoolId,
    ) -> Option<Vec<Value>> {
        let inner = self.inner.read().await;
        inner.log_delivery_configurations.get(user_pool_id).cloned()
    }

    // ==================== WebAuthn Operations ====================

    pub async fn save_webauthn_challenge(&self, user_id: &UserId, challenge: String) {
        let mut inner = self.inner.write().await;
        inner
            .webauthn_registration_challenges
            .insert(*user_id, challenge);
    }

    pub async fn get_webauthn_challenge(&self, user_id: &UserId) -> Option<String> {
        let inner = self.inner.read().await;
        inner.webauthn_registration_challenges.get(user_id).cloned()
    }

    pub async fn delete_webauthn_challenge(&self, user_id: &UserId) {
        let mut inner = self.inner.write().await;
        inner.webauthn_registration_challenges.remove(user_id);
    }

    pub async fn add_webauthn_credential(
        &self,
        user_id: &UserId,
        credential: WebAuthnCredential,
    ) -> WebAuthnCredential {
        let mut inner = self.inner.write().await;
        let creds = inner.webauthn_credentials.entry(*user_id).or_default();
        creds.retain(|c| c.credential_id != credential.credential_id);
        creds.push(credential.clone());
        credential
    }

    pub async fn list_webauthn_credentials(&self, user_id: &UserId) -> Vec<WebAuthnCredential> {
        let inner = self.inner.read().await;
        inner
            .webauthn_credentials
            .get(user_id)
            .cloned()
            .unwrap_or_default()
    }

    pub async fn delete_webauthn_credential(&self, user_id: &UserId, credential_id: &str) -> bool {
        let mut inner = self.inner.write().await;
        if let Some(creds) = inner.webauthn_credentials.get_mut(user_id) {
            let original_len = creds.len();
            creds.retain(|c| c.credential_id != credential_id);
            return creds.len() != original_len;
        }
        false
    }

    fn remove_user_records(inner: &mut StorageInner, user_id: &UserId) -> Option<User> {
        let user = inner.users.remove(user_id)?;

        inner
            .username_index
            .remove(&(user.user_pool_id.clone(), user.username.clone()));
        inner.devices.retain(|(id, _), _| id != user_id);
        inner.user_auth_factors.remove(user_id);
        inner
            .software_token_sessions
            .retain(|_, (id, _)| id != user_id);

        if let Some(event_ids) = inner.user_auth_event_index.remove(user_id) {
            for event_id in event_ids {
                inner.auth_events.remove(&event_id);
            }
        }

        inner.confirmation_codes.remove(user_id);
        inner.password_reset_codes.remove(user_id);
        inner
            .refresh_tokens
            .retain(|_, token| &token.user_id != user_id);
        inner.user_groups.remove(user_id);
        inner.webauthn_credentials.remove(user_id);
        inner.webauthn_registration_challenges.remove(user_id);
        inner
            .authorization_codes
            .retain(|_, code| &code.user_id != user_id);

        Some(user)
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
    use chrono::{Duration, Utc};
    use std::fs;
    use uuid::Uuid;

    use crate::types::{
        ClientId, ConfirmationCode, Group, PasswordResetCode, RefreshToken, User, UserPool,
        UserPoolClient, UserPoolDomain, UserPoolId, UserStatus, WebAuthnCredential,
    };

    fn temp_data_file() -> PathBuf {
        std::env::temp_dir().join(format!("cognitox-storage-{}.json", uuid::Uuid::new_v4()))
    }

    #[tokio::test]
    async fn test_persistence_roundtrip() {
        let path = temp_data_file();

        let storage = Storage::try_with_data_file(Some(path.clone())).unwrap();
        let now = Utc::now();
        let pool = UserPool {
            id: UserPoolId::new_local(),
            name: "persisted-pool".to_string(),
            creation_date: now,
            last_modified_date: now,
        };
        storage.create_user_pool(pool).await;
        storage.flush_persistence().await.unwrap();

        let loaded = Storage::try_with_data_file(Some(path.clone())).unwrap();
        let pools = loaded.list_user_pools().await;
        assert_eq!(pools.len(), 1);
        assert_eq!(pools[0].name, "persisted-pool");

        let _ = fs::remove_file(path);
    }

    #[test]
    fn test_invalid_persistence_file_fails() {
        let path = temp_data_file();
        fs::write(&path, "{not valid json").unwrap();

        let result = Storage::try_with_data_file(Some(path.clone()));
        assert!(result.is_err());

        let _ = fs::remove_file(path);
    }

    fn sample_client(pool_id: &UserPoolId, name: &str) -> UserPoolClient {
        let now = Utc::now();
        UserPoolClient {
            client_id: ClientId::generate(),
            user_pool_id: pool_id.clone(),
            client_name: name.to_string(),
            client_secret: None,
            creation_date: now,
            last_modified_date: now,
            allowed_oauth_flows: Vec::new(),
            allowed_oauth_scopes: Vec::new(),
            allowed_oauth_flows_user_pool_client: false,
            callback_urls: Vec::new(),
            logout_urls: Vec::new(),
            default_redirect_uri: None,
            supported_identity_providers: Vec::new(),
            explicit_auth_flows: Vec::new(),
            access_token_validity: None,
            id_token_validity: None,
            refresh_token_validity: None,
            token_validity_units: None,
            enable_token_revocation: true,
            prevent_user_existence_errors: None,
            enable_propagate_additional_user_context_data: false,
        }
    }

    fn sample_user(pool_id: &UserPoolId, username: &str) -> User {
        let now = Utc::now();
        User {
            id: Uuid::new_v4(),
            user_pool_id: pool_id.clone(),
            username: username.to_string(),
            email: Some(format!("{username}@example.com")),
            phone_number: None,
            password_hash: "hashed-password".to_string(),
            enabled: true,
            user_status: UserStatus::Confirmed,
            attributes: Vec::new(),
            creation_date: now,
            last_modified_date: now,
        }
    }

    #[tokio::test]
    async fn test_delete_user_cleans_related_records() {
        let storage = Storage::new();
        let now = Utc::now();
        let pool_id = UserPoolId::new_local();
        let client = sample_client(&pool_id, "client");
        let user = sample_user(&pool_id, "alice");
        let refresh_token = Uuid::new_v4().to_string();
        let session = "software-session".to_string();
        let group_name = "admins".to_string();

        storage
            .create_user_pool(UserPool {
                id: pool_id.clone(),
                name: "pool".to_string(),
                creation_date: now,
                last_modified_date: now,
            })
            .await;
        storage.create_user_pool_client(client.clone()).await;
        storage.create_user(user.clone()).await;
        storage
            .save_confirmation_code(ConfirmationCode {
                user_id: user.id,
                code: "123456".to_string(),
                expires_at: now + Duration::hours(1),
            })
            .await;
        storage
            .save_password_reset_code(PasswordResetCode {
                user_id: user.id,
                code: "654321".to_string(),
                expires_at: now + Duration::hours(1),
            })
            .await;
        storage
            .save_refresh_token(RefreshToken {
                token: refresh_token.clone(),
                user_id: user.id,
                client_id: client.client_id.clone(),
                expires_at: now + Duration::hours(1),
            })
            .await;
        storage
            .save_software_token_session(session.clone(), &user.id, "secret".to_string())
            .await;
        storage.add_user_to_group(&user.id, &group_name).await;
        storage
            .save_webauthn_challenge(&user.id, "challenge".into())
            .await;
        storage
            .add_webauthn_credential(
                &user.id,
                WebAuthnCredential {
                    credential_id: "cred-1".to_string(),
                    friendly_credential_name: None,
                    relying_party_id: None,
                    created_at: now,
                    authenticator_attachment: None,
                    authenticator_transports: Vec::new(),
                },
            )
            .await;

        storage.delete_user(&user.id).await;

        assert!(storage.get_user(&user.id).await.is_none());
        assert!(
            storage
                .get_user_by_username(&pool_id, &user.username)
                .await
                .is_none()
        );
        assert!(storage.get_confirmation_code(&user.id).await.is_none());
        assert!(storage.get_password_reset_code(&user.id).await.is_none());
        assert!(storage.get_refresh_token(&refresh_token).await.is_none());
        assert!(storage.get_software_token_session(&session).await.is_none());
        assert!(storage.get_groups_for_user(&user.id).await.is_empty());
        assert!(storage.get_webauthn_challenge(&user.id).await.is_none());
        assert!(storage.list_webauthn_credentials(&user.id).await.is_empty());
    }

    #[tokio::test]
    async fn test_delete_user_pool_cascades_related_records() {
        let storage = Storage::new();
        let now = Utc::now();

        let target_pool_id = UserPoolId::new_local();
        let other_pool_id = UserPoolId::new_local();
        let target_client = sample_client(&target_pool_id, "target-client");
        let other_client = sample_client(&other_pool_id, "other-client");
        let target_user = sample_user(&target_pool_id, "alice");
        let other_user = sample_user(&other_pool_id, "bob");
        let target_token = Uuid::new_v4().to_string();
        let group_name = "admins".to_string();

        storage
            .create_user_pool(UserPool {
                id: target_pool_id.clone(),
                name: "target".to_string(),
                creation_date: now,
                last_modified_date: now,
            })
            .await;
        storage
            .create_user_pool(UserPool {
                id: other_pool_id.clone(),
                name: "other".to_string(),
                creation_date: now,
                last_modified_date: now,
            })
            .await;
        storage.create_user_pool_client(target_client.clone()).await;
        storage.create_user_pool_client(other_client.clone()).await;
        storage.create_user(target_user.clone()).await;
        storage.create_user(other_user.clone()).await;
        storage
            .create_group(Group {
                group_name: group_name.clone(),
                user_pool_id: target_pool_id.clone(),
                description: None,
                role_arn: None,
                precedence: None,
                creation_date: now,
                last_modified_date: now,
            })
            .await;
        storage
            .add_user_to_group(&target_user.id, &group_name)
            .await;
        storage
            .create_user_pool_domain(UserPoolDomain {
                domain: "target-domain".to_string(),
                user_pool_id: target_pool_id.clone(),
                status: Default::default(),
                version: None,
                s3_bucket: None,
                cloud_front_distribution: None,
                custom_domain_config: None,
                managed_login_version: None,
            })
            .await;
        storage
            .save_refresh_token(RefreshToken {
                token: target_token.clone(),
                user_id: target_user.id,
                client_id: target_client.client_id.clone(),
                expires_at: now + Duration::hours(1),
            })
            .await;

        storage.delete_user_pool(&target_pool_id).await.unwrap();

        assert!(storage.get_user_pool(&target_pool_id).await.is_none());
        assert!(storage.get_user_pool(&other_pool_id).await.is_some());

        assert!(
            storage
                .list_user_pool_clients(&target_pool_id)
                .await
                .is_empty()
        );
        assert_eq!(
            storage.list_user_pool_clients(&other_pool_id).await.len(),
            1
        );

        assert!(storage.list_users(&target_pool_id).await.is_empty());
        assert!(storage.get_user(&target_user.id).await.is_none());
        assert!(storage.get_user(&other_user.id).await.is_some());

        assert!(storage.list_groups(&target_pool_id).await.is_empty());
        assert!(
            storage
                .get_groups_for_user(&target_user.id)
                .await
                .is_empty()
        );
        assert!(
            storage
                .get_user_pool_domain_by_user_pool_id(&target_pool_id)
                .await
                .is_none()
        );
        assert!(storage.get_refresh_token(&target_token).await.is_none());
    }
}
