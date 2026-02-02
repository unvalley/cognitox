//! In-memory storage for Cognito entities
//!
//! This module provides thread-safe in-memory storage for user pools, clients, and users.
//! For production use, this could be replaced with a persistent database.

use std::{collections::HashMap, sync::Arc};

use tokio::sync::RwLock;

use crate::types::{
    ClientId, ConfirmationCode, RefreshToken, User, UserId, UserPool, UserPoolClient, UserPoolId,
};

#[derive(Debug, Clone)]
pub struct Storage {
    inner: Arc<RwLock<StorageInner>>,
}

#[derive(Debug, Default)]
struct StorageInner {
    user_pools: HashMap<UserPoolId, UserPool>,
    user_pool_clients: HashMap<ClientId, UserPoolClient>,
    users: HashMap<UserId, User>,
    confirmation_codes: HashMap<UserId, ConfirmationCode>,
    refresh_tokens: HashMap<String, RefreshToken>,
    username_index: HashMap<(UserPoolId, String), UserId>,
}

impl Storage {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(StorageInner::default())),
        }
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
}

impl Default for Storage {
    fn default() -> Self {
        Self::new()
    }
}
