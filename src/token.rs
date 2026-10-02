use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use secrecy::{ExposeSecret, SecretString};
use sha2::{Digest, Sha256};

use crate::error::RevttyError;

const TOKEN_BYTES: usize = 32;

pub struct SecretToken {
    value: SecretString,
}

impl SecretToken {
    pub fn generate(prefix: &str) -> Result<Self, RevttyError> {
        if prefix.is_empty() || !prefix.bytes().all(|byte| byte.is_ascii_alphanumeric()) {
            return Err(RevttyError::message(
                "token prefix must contain only ASCII letters and digits",
            ));
        }

        let mut bytes = [0_u8; TOKEN_BYTES];
        getrandom::fill(&mut bytes)
            .map_err(|error| RevttyError::runtime("generate secure random token", error))?;

        let encoded = URL_SAFE_NO_PAD.encode(bytes);
        Ok(Self {
            value: format!("{prefix}_{encoded}").into(),
        })
    }

    pub fn expose(&self) -> &str {
        self.value.expose_secret()
    }

    pub fn hash(&self) -> [u8; 32] {
        hash_token(self.expose())
    }
}

pub fn hash_token(token: &str) -> [u8; 32] {
    let digest = Sha256::digest(token.as_bytes());
    digest.into()
}

#[cfg(test)]
mod tests {
    use super::{SecretToken, hash_token};

    #[test]
    fn generated_tokens_are_unique_and_prefixed() {
        let first = SecretToken::generate("rve").expect("first token");
        let second = SecretToken::generate("rve").expect("second token");

        assert!(first.expose().starts_with("rve_"));
        assert!(second.expose().starts_with("rve_"));
        assert_ne!(first.expose(), second.expose());
        assert_ne!(first.hash(), second.hash());
    }

    #[test]
    fn token_hash_is_deterministic() {
        assert_eq!(hash_token("token"), hash_token("token"));
        assert_ne!(hash_token("token"), hash_token("other"));
    }
}
