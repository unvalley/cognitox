//! In-memory storage for Cognito entities with optional file persistence.
//!
//! This module provides thread-safe in-memory storage for user pools, clients, and users.
//! If `DATA_FILE` is set, state is loaded from/saved to that file.

use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::error;

use crate::types::{
    AuthorizationCode, BrandingId, ClientId, ConfirmationCode, DomainPrefix, Group, GroupName,
    ManagedLoginBranding, PasswordResetCode, RefreshToken, User, UserId, UserPool, UserPoolClient,
    UserPoolDomain, UserPoolId,
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
    managed_login_brandings: HashMap<BrandingId, ManagedLoginBranding>,
    user_pool_brandings: HashMap<UserPoolId, BrandingId>,
    client_brandings: HashMap<ClientId, BrandingId>,
    users: HashMap<UserId, User>,
    confirmation_codes: HashMap<UserId, ConfirmationCode>,
    refresh_tokens: HashMap<String, RefreshToken>,
    authorization_codes: HashMap<String, AuthorizationCode>,
    username_index: HashMap<(UserPoolId, String), UserId>,
    groups: HashMap<(UserPoolId, GroupName), Group>,
    user_groups: HashMap<UserId, Vec<GroupName>>,
    password_reset_codes: HashMap<UserId, PasswordResetCode>,
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
        inner.user_pools.remove(id)
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
        if let Some(user) = inner.users.remove(id) {
            inner
                .username_index
                .remove(&(user.user_pool_id.clone(), user.username.clone()));
            Some(user)
        } else {
            None
        }
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

    use crate::types::{UserPool, UserPoolId};

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
}
