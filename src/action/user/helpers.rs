//! Shared helper functions for user domain

use uuid::Uuid;

use crate::jwt;

/// Default bcrypt cost factor (4 for fast testing, use 12+ in production)
const BCRYPT_COST: u32 = 4;

/// Generate a secure confirmation code
/// Uses 20 alphanumeric characters for high entropy (~119 bits)
/// Format: XXXX-XXXX-XXXX-XXXX-XXXX for readability
pub fn generate_confirmation_code() -> String {
    use rand::Rng;
    const CHARSET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789"; // Excludes confusing chars: 0/O, 1/I/L
    let mut rng = rand::thread_rng();

    let code: String = (0..20)
        .map(|_| {
            let idx = rng.gen_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect();

    // Format as XXXX-XXXX-XXXX-XXXX-XXXX for readability
    format!(
        "{}-{}-{}-{}-{}",
        &code[0..4],
        &code[4..8],
        &code[8..12],
        &code[12..16],
        &code[16..20]
    )
}

/// Normalize a confirmation code by removing dashes and converting to uppercase
pub fn normalize_confirmation_code(code: &str) -> String {
    code.chars()
        .filter(|c| c.is_alphanumeric())
        .collect::<String>()
        .to_uppercase()
}

/// Hash password using bcrypt with automatic salt generation
pub fn hash_password(password: &str) -> Result<String, String> {
    bcrypt::hash(password, BCRYPT_COST).map_err(|e| format!("Failed to hash password: {}", e))
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

/// Verify access token signature and extract user ID
/// Returns the user ID if the token is valid, or an error message if validation fails
pub fn verify_and_extract_user_id(token: &str) -> Result<Uuid, String> {
    let token_data = jwt::verify_access_token(token)?;
    Uuid::parse_str(&token_data.claims.sub)
        .map_err(|e| format!("Invalid user ID in token: {}", e))
}
