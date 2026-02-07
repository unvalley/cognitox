//! Shared helper functions for user domain

use uuid::Uuid;

use crate::jwt;

/// Default bcrypt cost factor (4 for fast testing, use 12+ in production)
const BCRYPT_COST: u32 = 4;

pub fn generate_confirmation_code() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    format!("{:06}", rng.gen_range(0..1000000))
}

/// Hash password using bcrypt with automatic salt generation
pub fn hash_password(password: &str) -> String {
    bcrypt::hash(password, BCRYPT_COST).expect("Failed to hash password")
}

/// Verify password against bcrypt hash
pub fn verify_password(password: &str, hash: &str) -> bool {
    bcrypt::verify(password, hash).unwrap_or(false)
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
