//! Secure Remote Password as Amazon Cognito uses it for `USER_SRP_AUTH`.
//!
//! Cognito runs SRP-6a over the 3072-bit MODP group of RFC 3526 with
//! SHA-256, derives a 16 byte key with HKDF (`Caldera Derived Key`), and has
//! the client prove knowledge of it by signing the `PASSWORD_VERIFIER`
//! challenge. The arithmetic and the hex padding rules follow the public
//! client implementations (`amazon-cognito-identity-js`, Amplify).

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use hmac::{Hmac, Mac};
use rand::RngCore;
use rsa::BigUint;
use sha2::{Digest, Sha256};
use std::sync::OnceLock;

type HmacSha256 = Hmac<Sha256>;

/// RFC 3526 group 15 prime.
const N_HEX: &str = concat!(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1",
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD",
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245",
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED",
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D",
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F",
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D",
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B",
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9",
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510",
    "15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64",
    "ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7",
    "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B",
    "F12FFA06D98A0864D87602733EC86A64521F2B18177B200C",
    "BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31",
    "43DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF",
);

const G: u32 = 2;
const DERIVED_KEY_INFO: &[u8] = b"Caldera Derived Key";
const DERIVED_KEY_LEN: usize = 16;

struct Group {
    n: BigUint,
    g: BigUint,
    k: BigUint,
}

fn group() -> &'static Group {
    static GROUP: OnceLock<Group> = OnceLock::new();
    GROUP.get_or_init(|| {
        let n = parse_hex(N_HEX).expect("the SRP prime is valid hex");
        let g = BigUint::from(G);
        let k = hash_hex(&format!("{}{}", pad_hex(&n), pad_hex(&g)));
        Group { n, g, k }
    })
}

fn parse_hex(value: &str) -> Option<BigUint> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    BigUint::parse_bytes(value.as_bytes(), 16)
}

/// Hex encoding of a non-negative integer the way the Cognito clients pad
/// it: an even number of digits, with a leading zero byte when the top bit
/// is set so the value stays positive as a two's complement number.
fn pad_hex(value: &BigUint) -> String {
    let hex = value.to_str_radix(16);
    if hex.len() % 2 == 1 {
        format!("0{hex}")
    } else if matches!(hex.as_bytes()[0], b'8'..=b'9' | b'a'..=b'f') {
        format!("00{hex}")
    } else {
        hex
    }
}

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    hex.as_bytes()
        .chunks(2)
        .map(|pair| {
            let digits = std::str::from_utf8(pair).unwrap_or("0");
            u8::from_str_radix(digits, 16).unwrap_or(0)
        })
        .collect()
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// SHA-256 over the bytes a hex string encodes, as an integer.
fn hash_hex(hex: &str) -> BigUint {
    BigUint::from_bytes_be(&Sha256::digest(hex_to_bytes(hex)))
}

/// The `poolName` SRP input: the user pool ID without its region prefix.
pub fn pool_name(user_pool_id: &str) -> &str {
    user_pool_id
        .split_once('_')
        .map_or(user_pool_id, |(_, name)| name)
}

fn private_key(pool_name: &str, user_id_for_srp: &str, password: &str, salt: &BigUint) -> BigUint {
    let identity_hash = bytes_to_hex(&Sha256::digest(
        format!("{pool_name}{user_id_for_srp}:{password}").as_bytes(),
    ));
    hash_hex(&format!("{}{identity_hash}", pad_hex(salt)))
}

/// What the server keeps instead of the password.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswordVerifier {
    /// Hex salt, sent to the client as `SALT`.
    pub salt: String,
    /// Hex `g^x mod N`.
    pub verifier: String,
}

/// Derive the SRP verifier for a password.
///
/// `user_id_for_srp` is the value the server later sends as
/// `USER_ID_FOR_SRP`; the client hashes the password under that name.
pub fn generate_verifier(
    user_pool_id: &str,
    user_id_for_srp: &str,
    password: &str,
) -> PasswordVerifier {
    let mut salt_bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut salt_bytes);
    let salt = BigUint::from_bytes_be(&salt_bytes);
    verifier_with_salt(user_pool_id, user_id_for_srp, password, &salt)
}

fn verifier_with_salt(
    user_pool_id: &str,
    user_id_for_srp: &str,
    password: &str,
    salt: &BigUint,
) -> PasswordVerifier {
    let group = group();
    let x = private_key(pool_name(user_pool_id), user_id_for_srp, password, salt);
    PasswordVerifier {
        salt: pad_hex(salt),
        verifier: group.g.modpow(&x, &group.n).to_str_radix(16),
    }
}

/// The server half of one SRP exchange.
#[derive(Debug, Clone)]
pub struct ServerEphemeral {
    /// Hex secret `b`; never leaves the server.
    pub private: String,
    /// Hex `B = k*v + g^b mod N`, sent to the client as `SRP_B`.
    pub public: String,
}

/// Start an exchange for a stored verifier.
pub fn server_ephemeral(verifier: &str) -> Option<ServerEphemeral> {
    let group = group();
    let verifier = parse_hex(verifier)?;
    loop {
        let mut secret = [0u8; 64];
        rand::thread_rng().fill_bytes(&mut secret);
        let private = BigUint::from_bytes_be(&secret);
        let public = (&group.k * &verifier + group.g.modpow(&private, &group.n)) % &group.n;
        if public != BigUint::from(0u32) {
            return Some(ServerEphemeral {
                private: private.to_str_radix(16),
                public: public.to_str_radix(16),
            });
        }
    }
}

/// Whether `SRP_A` is a usable client public value (`A mod N != 0`).
pub fn is_valid_client_public(srp_a: &str) -> bool {
    parse_hex(srp_a).is_some_and(|a| a % &group().n != BigUint::from(0u32))
}

/// Everything the server knows when the client answers `PASSWORD_VERIFIER`.
pub struct PasswordClaim<'a> {
    pub user_pool_id: &'a str,
    pub user_id_for_srp: &'a str,
    pub verifier: &'a str,
    pub client_public: &'a str,
    pub server_private: &'a str,
    pub server_public: &'a str,
    pub secret_block: &'a str,
    pub timestamp: &'a str,
}

impl PasswordClaim<'_> {
    /// The `PASSWORD_CLAIM_SIGNATURE` a client that knows the password sends.
    pub fn expected_signature(&self) -> Option<String> {
        let group = group();
        let a = parse_hex(self.client_public)?;
        let b_public = parse_hex(self.server_public)?;
        let b_private = parse_hex(self.server_private)?;
        let verifier = parse_hex(self.verifier)?;
        if &a % &group.n == BigUint::from(0u32) {
            return None;
        }

        let u = hash_hex(&format!("{}{}", pad_hex(&a), pad_hex(&b_public)));
        if u == BigUint::from(0u32) {
            return None;
        }
        // S = (A * v^u)^b mod N
        let session = (a * verifier.modpow(&u, &group.n) % &group.n).modpow(&b_private, &group.n);
        let key = derive_key(
            &hex_to_bytes(&pad_hex(&session)),
            &hex_to_bytes(&pad_hex(&u)),
        );

        let secret_block = BASE64_STANDARD.decode(self.secret_block).ok()?;
        let mut mac = HmacSha256::new_from_slice(&key).ok()?;
        mac.update(pool_name(self.user_pool_id).as_bytes());
        mac.update(self.user_id_for_srp.as_bytes());
        mac.update(&secret_block);
        mac.update(self.timestamp.as_bytes());
        Some(BASE64_STANDARD.encode(mac.finalize().into_bytes()))
    }

    /// Constant-time comparison of the client's signature with the expected one.
    pub fn verify(&self, signature: &str) -> bool {
        let Some(expected) = self.expected_signature() else {
            return false;
        };
        let (Ok(expected), Ok(provided)) = (
            BASE64_STANDARD.decode(expected),
            BASE64_STANDARD.decode(signature),
        ) else {
            return false;
        };
        expected.len() == provided.len()
            && expected
                .iter()
                .zip(&provided)
                .fold(0u8, |diff, (left, right)| diff | (left ^ right))
                == 0
    }
}

/// HKDF-SHA256 with Cognito's fixed info string, truncated to 16 bytes.
fn derive_key(input_key_material: &[u8], salt: &[u8]) -> Vec<u8> {
    let mut extract = HmacSha256::new_from_slice(salt).expect("HMAC accepts any key length");
    extract.update(input_key_material);
    let pseudo_random_key = extract.finalize().into_bytes();

    let mut expand =
        HmacSha256::new_from_slice(&pseudo_random_key).expect("HMAC accepts any key length");
    expand.update(DERIVED_KEY_INFO);
    expand.update(&[1]);
    expand.finalize().into_bytes()[..DERIVED_KEY_LEN].to_vec()
}

/// A fresh opaque `SECRET_BLOCK`.
pub fn generate_secret_block() -> String {
    let mut block = [0u8; 96];
    rand::thread_rng().fill_bytes(&mut block);
    BASE64_STANDARD.encode(block)
}

/// The client half of the exchange, for tests.
///
/// Written from the published client algorithm (`S = (B - k*g^x)^(a + u*x)`)
/// rather than by reusing the server code path, so the two sides check each
/// other.
#[cfg(test)]
pub(crate) mod client {
    use super::*;

    pub(crate) struct SrpClient {
        private: BigUint,
        public: BigUint,
    }

    impl SrpClient {
        pub(crate) fn new() -> Self {
            let mut secret = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut secret);
            let private = BigUint::from_bytes_be(&secret);
            let public = group().g.modpow(&private, &group().n);
            Self { private, public }
        }

        /// `SRP_A`
        pub(crate) fn public_hex(&self) -> String {
            self.public.to_str_radix(16)
        }

        /// `PASSWORD_CLAIM_SIGNATURE` for the `ChallengeParameters` of a
        /// `PASSWORD_VERIFIER` challenge.
        pub(crate) fn signature(
            &self,
            user_pool_id: &str,
            password: &str,
            parameters: &serde_json::Value,
            timestamp: &str,
        ) -> String {
            let parameter = |name: &str| parameters[name].as_str().unwrap();
            let user_id_for_srp = parameter("USER_ID_FOR_SRP");
            let secret_block = parameter("SECRET_BLOCK");

            let group = group();
            let b_public = parse_hex(parameter("SRP_B")).unwrap();
            let salt = parse_hex(parameter("SALT")).unwrap();

            let u = hash_hex(&format!("{}{}", pad_hex(&self.public), pad_hex(&b_public)));
            let x = private_key(pool_name(user_pool_id), user_id_for_srp, password, &salt);
            let g_x = group.g.modpow(&x, &group.n);
            let base = (&b_public + &group.n * &group.k - &group.k * g_x) % &group.n;
            let session = base.modpow(&(&self.private + &u * x), &group.n);
            let key = derive_key(
                &hex_to_bytes(&pad_hex(&session)),
                &hex_to_bytes(&pad_hex(&u)),
            );

            let mut mac = HmacSha256::new_from_slice(&key).unwrap();
            mac.update(pool_name(user_pool_id).as_bytes());
            mac.update(user_id_for_srp.as_bytes());
            mac.update(&BASE64_STANDARD.decode(secret_block).unwrap());
            mac.update(timestamp.as_bytes());
            BASE64_STANDARD.encode(mac.finalize().into_bytes())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::client::SrpClient;
    use super::*;

    const POOL_ID: &str = "us-east-1_AbCdEfGhI";
    const USERNAME: &str = "alice";
    const PASSWORD: &str = "Corr3ct-horse";
    const TIMESTAMP: &str = "Thu Nov 19 03:04:05 UTC 2026";

    fn exchange(sign_in_password: &str) -> bool {
        let stored = generate_verifier(POOL_ID, USERNAME, PASSWORD);
        let server = server_ephemeral(&stored.verifier).unwrap();
        let secret_block = generate_secret_block();

        let client = SrpClient::new();
        let signature = client.signature(
            POOL_ID,
            sign_in_password,
            &serde_json::json!({
                "USER_ID_FOR_SRP": USERNAME,
                "SALT": stored.salt,
                "SRP_B": server.public,
                "SECRET_BLOCK": secret_block,
            }),
            TIMESTAMP,
        );

        PasswordClaim {
            user_pool_id: POOL_ID,
            user_id_for_srp: USERNAME,
            verifier: &stored.verifier,
            client_public: &client.public_hex(),
            server_private: &server.private,
            server_public: &server.public,
            secret_block: &secret_block,
            timestamp: TIMESTAMP,
        }
        .verify(&signature)
    }

    #[test]
    fn correct_password_is_accepted() {
        for _ in 0..4 {
            assert!(exchange(PASSWORD));
        }
    }

    #[test]
    fn wrong_password_is_rejected() {
        assert!(!exchange("Wr0ng-horse"));
    }

    #[test]
    fn multiplier_matches_the_published_clients() {
        // k = H(00 || N || 02), the constant every Cognito SRP client derives.
        assert_eq!(
            group().k.to_str_radix(16),
            "538282c4354742d7cbbde2359fcf67f9f5b3a6b08791e5011b43b8a5b66d9ee6"
        );
    }

    #[test]
    fn pad_hex_follows_the_client_rules() {
        assert_eq!(pad_hex(&BigUint::from(0x7fu32)), "7f");
        assert_eq!(pad_hex(&BigUint::from(0x80u32)), "0080");
        assert_eq!(pad_hex(&BigUint::from(0xabcu32)), "0abc");
    }

    #[test]
    fn zero_client_public_is_refused() {
        assert!(!is_valid_client_public("0"));
        assert!(!is_valid_client_public(N_HEX));
        assert!(!is_valid_client_public("not-hex"));
        assert!(is_valid_client_public("abcdef"));
    }

    #[test]
    fn pool_name_drops_the_region() {
        assert_eq!(pool_name("us-east-1_AbCdEfGhI"), "AbCdEfGhI");
        assert_eq!(pool_name("local"), "local");
    }
}
