//! Shared helper functions for user domain

use sha2::{Digest, Sha256};
use uuid::Uuid;

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

pub fn generate_tokens(user_id: &Uuid, client_id: &str) -> (String, String, String) {
    let access_token = format!("access_{}_{}_{}", user_id, client_id, Uuid::new_v4());
    let id_token = format!("id_{}_{}_{}", user_id, client_id, Uuid::new_v4());
    let refresh_token = format!("refresh_{}_{}_{}", user_id, client_id, Uuid::new_v4());
    (access_token, id_token, refresh_token)
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

pub fn extract_user_id_from_token(token: &str) -> Option<Uuid> {
    let parts: Vec<&str> = token.split('_').collect();
    if parts.len() >= 2 && parts[0] == "access" {
        Uuid::parse_str(parts[1]).ok()
    } else {
        None
    }
}
