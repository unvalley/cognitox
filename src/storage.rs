//! In-memory storage for Cognito entities
//!
//! This module provides thread-safe in-memory storage for user pools, clients, and users.
//! For production use, this could be replaced with a persistent database.

use std::{collections::HashMap, sync::Arc};

use serde_json::Value;
use tokio::sync::RwLock;

use crate::types::{
    AuthorizationCode, BrandingId, ClientId, ConfirmationCode, Device, DomainPrefix, Group,
    GroupName, IdentityProvider, ManagedLoginBranding, PasswordResetCode, RefreshToken,
    ResourceServer, TermsDocument, UiCustomization, User, UserId, UserImportJob, UserPool,
    UserPoolClient, UserPoolDomain, UserPoolId, WebAuthnCredential,
};

#[derive(Debug, Clone)]
pub struct Storage {
    inner: Arc<RwLock<StorageInner>>,
}

#[derive(Debug, Default)]
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
        if let Some(user) = inner.users.remove(id) {
            inner
                .username_index
                .remove(&(user.user_pool_id.clone(), user.username.clone()));
            inner.devices.retain(|(user_id, _), _| user_id != id);
            inner.user_auth_factors.remove(id);
            inner
                .software_token_sessions
                .retain(|_, (user_id, _)| user_id != id);
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
}

impl Default for Storage {
    fn default() -> Self {
        Self::new()
    }
}
