//! Shared helper functions for user domain

use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::jwt;

pub fn generate_confirmation_code() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    format!("{:06}", rng.gen_range(0..1000000))
}

pub fn hash_password(password: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    format!("{:x}", hasher.finalize())
}

pub fn mask_email(email: &str) -> String {
    if let Some((local, domain)) = email.split_once('@') {
        if local.len() > 2 {
            format!("{}***@{}", &local[..2], domain)
        } else {
            format!("***@{}", domain)
        }
    } else {
        "***".to_string()
    }
}

/// Extract user ID from access token (JWT)
pub fn extract_user_id_from_token(token: &str) -> Option<Uuid> {
    jwt::extract_user_id_from_token(token)
}
