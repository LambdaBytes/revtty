//! Pairing codes. `revtty pair` wraps the relay's single-use enrollment token with a secret S
//! that only the operator and the target's administrator see: the relay never receives it.
//! With S the agent checks that the relay enrolled it for the operator who paired it, and
//! proves its host key to that operator, so that a relay compromised at enrollment can
//! neither authorize a key of its own on the agent nor have the operator pin another key.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hmac::{Hmac, KeyInit, Mac};
use secrecy::{ExposeSecret, SecretString};
use sha2::Sha256;

use crate::error::RevttyError;
use crate::token::SecretToken;

/// Format version of a code. Its parts are joined with '.', which appears neither in
/// base64url nor in the token prefixes, so a code is never mistaken for a plain token.
const CODE_PREFIX: &str = "rvp1";
const SECRET_PREFIX: &str = "rvk";
const ENROLLMENT_TOKEN_PREFIX: &str = "rve_";
const SECRET_LEN: usize = 32;
const MAC_LEN: usize = 32;
const OPERATOR_CONTEXT: &[u8] = b"revtty pairing operator v1\0";
const HOST_KEY_CONTEXT: &[u8] = b"revtty pairing host-key v1\0";

/// The pairing secret S, `rvk_` and the base64url of 32 random bytes, which key the HMACs.
pub struct PairingSecret {
    value: SecretString,
}

impl PairingSecret {
    pub fn generate() -> Result<Self, RevttyError> {
        Self::parse(SecretToken::generate(SECRET_PREFIX)?.expose())
    }

    /// Never quotes `encoded` in its errors.
    pub fn parse(encoded: &str) -> Result<Self, RevttyError> {
        if decode_secret(encoded).is_none() {
            return Err(RevttyError::message("invalid pairing secret"));
        }
        Ok(Self {
            value: encoded.to_owned().into(),
        })
    }

    pub fn expose(&self) -> &str {
        self.value.expose_secret()
    }

    /// Vouches that the agent `agent_name` is enrolled for the operator key whose SHA-256
    /// fingerprint is `operator_fingerprint`.
    pub fn operator_tag(
        &self,
        agent_name: &str,
        operator_fingerprint: &str,
    ) -> Result<String, RevttyError> {
        Ok(encode_mac(
            self.operator_mac(agent_name, operator_fingerprint)?,
        ))
    }

    pub fn operator_tag_matches(
        &self,
        agent_name: &str,
        operator_fingerprint: &str,
        tag: &str,
    ) -> Result<bool, RevttyError> {
        Ok(mac_matches(
            self.operator_mac(agent_name, operator_fingerprint)?,
            tag,
        ))
    }

    /// Proves, to whoever holds S, the agent host key whose SHA-256 fingerprint is
    /// `host_key_fingerprint`.
    pub fn host_key_proof(&self, host_key_fingerprint: &str) -> Result<String, RevttyError> {
        Ok(encode_mac(self.host_key_mac(host_key_fingerprint)?))
    }

    pub fn host_key_proof_matches(
        &self,
        host_key_fingerprint: &str,
        proof: &str,
    ) -> Result<bool, RevttyError> {
        Ok(mac_matches(self.host_key_mac(host_key_fingerprint)?, proof))
    }

    fn operator_mac(
        &self,
        agent_name: &str,
        operator_fingerprint: &str,
    ) -> Result<Hmac<Sha256>, RevttyError> {
        let mut mac = self.mac(OPERATOR_CONTEXT)?;
        // Agent names never contain NUL, so the separator keeps name and key apart.
        mac.update(agent_name.as_bytes());
        mac.update(b"\0");
        mac.update(operator_fingerprint.as_bytes());
        Ok(mac)
    }

    fn host_key_mac(&self, host_key_fingerprint: &str) -> Result<Hmac<Sha256>, RevttyError> {
        let mut mac = self.mac(HOST_KEY_CONTEXT)?;
        mac.update(host_key_fingerprint.as_bytes());
        Ok(mac)
    }

    fn mac(&self, context: &[u8]) -> Result<Hmac<Sha256>, RevttyError> {
        let key = decode_secret(self.expose())
            .ok_or_else(|| RevttyError::message("invalid pairing secret"))?;
        let mut mac = Hmac::<Sha256>::new_from_slice(&key)
            .map_err(|error| RevttyError::runtime("initialize pairing HMAC", error))?;
        mac.update(context);
        Ok(mac)
    }
}

/// `rvp1.TOKEN.S.TAG`: the relay's enrollment token, S, and the operator tag for the agent
/// name and operator it was made for.
pub struct PairingCode {
    token: SecretString,
    secret: PairingSecret,
    operator_tag: String,
}

impl PairingCode {
    pub fn new(
        token: &str,
        secret: PairingSecret,
        agent_name: &str,
        operator_fingerprint: &str,
    ) -> Result<Self, RevttyError> {
        if !is_enrollment_token(token) {
            return Err(RevttyError::message(
                "the enrollment token is not one `revtty relay enroll` prints",
            ));
        }
        let operator_tag = secret.operator_tag(agent_name, operator_fingerprint)?;
        Ok(Self {
            token: token.to_owned().into(),
            secret,
            operator_tag,
        })
    }

    /// Never quotes `code` in its errors: it carries S.
    pub fn parse(code: &str) -> Result<Self, RevttyError> {
        let invalid = || {
            RevttyError::message("invalid pairing code; copy the whole code `revtty pair` printed")
        };
        let mut parts = code.trim().split('.');
        let (Some(CODE_PREFIX), Some(token), Some(secret), Some(operator_tag), None) = (
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
        ) else {
            return Err(invalid());
        };
        if !is_enrollment_token(token) || !is_mac(operator_tag) {
            return Err(invalid());
        }
        let secret = PairingSecret::parse(secret).map_err(|_| invalid())?;

        Ok(Self {
            token: token.to_owned().into(),
            secret,
            operator_tag: operator_tag.to_owned(),
        })
    }

    pub fn encode(&self) -> String {
        format!(
            "{CODE_PREFIX}.{}.{}.{}",
            self.token.expose_secret(),
            self.secret.expose(),
            self.operator_tag
        )
    }

    pub fn token(&self) -> &str {
        self.token.expose_secret()
    }

    pub fn secret(&self) -> &PairingSecret {
        &self.secret
    }

    /// Whether the code was made for this agent name and operator key.
    pub fn vouches_for(
        &self,
        agent_name: &str,
        operator_fingerprint: &str,
    ) -> Result<bool, RevttyError> {
        self.secret
            .operator_tag_matches(agent_name, operator_fingerprint, &self.operator_tag)
    }
}

/// Whether `value` has the shape of a tag or proof (base64url of 32 bytes); the relay checks
/// it to bound what it stores, since it cannot verify one.
pub fn is_mac(value: &str) -> bool {
    URL_SAFE_NO_PAD
        .decode(value)
        .is_ok_and(|bytes| bytes.len() == MAC_LEN)
}

fn is_enrollment_token(token: &str) -> bool {
    token
        .strip_prefix(ENROLLMENT_TOKEN_PREFIX)
        .is_some_and(|rest| {
            !rest.is_empty()
                && rest
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        })
}

fn decode_secret(encoded: &str) -> Option<[u8; SECRET_LEN]> {
    let encoded = encoded.strip_prefix(SECRET_PREFIX)?.strip_prefix('_')?;
    URL_SAFE_NO_PAD.decode(encoded).ok()?.try_into().ok()
}

fn encode_mac(mac: Hmac<Sha256>) -> String {
    URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
}

fn mac_matches(mac: Hmac<Sha256>, encoded: &str) -> bool {
    // Constant-time comparison.
    URL_SAFE_NO_PAD
        .decode(encoded)
        .is_ok_and(|tag| mac.verify_slice(&tag).is_ok())
}

#[cfg(test)]
mod tests {
    use super::{PairingCode, PairingSecret, is_mac};
    use crate::token::SecretToken;

    const OPERATOR: &str = "SHA256:operator-fingerprint";
    const HOST: &str = "SHA256:host-fingerprint";

    fn token() -> String {
        SecretToken::generate("rve")
            .expect("enrollment token")
            .expose()
            .to_owned()
    }

    fn secret() -> PairingSecret {
        PairingSecret::generate().expect("pairing secret")
    }

    #[test]
    fn a_code_round_trips_and_vouches_only_for_its_name_and_operator() {
        let token = token();
        let code = PairingCode::new(&token, secret(), "store-042", OPERATOR).expect("code");
        let encoded = code.encode();
        assert!(encoded.starts_with("rvp1."), "{encoded}");

        let parsed = PairingCode::parse(&format!(" {encoded}\n")).expect("parse code");
        assert_eq!(parsed.token(), token);
        assert_eq!(parsed.secret().expose(), code.secret().expose());
        assert!(
            parsed
                .vouches_for("store-042", OPERATOR)
                .expect("verify tag")
        );
        assert!(
            !parsed
                .vouches_for("store-043", OPERATOR)
                .expect("verify tag")
        );
        assert!(
            !parsed
                .vouches_for("store-042", "SHA256:another-operator")
                .expect("verify tag")
        );

        // The same name and operator under another secret.
        let other = PairingCode::new(&token, secret(), "store-042", OPERATOR).expect("code");
        let forged = format!(
            "rvp1.{token}.{}.{}",
            other.secret().expose(),
            encoded.rsplit('.').next().expect("tag")
        );
        assert!(
            !PairingCode::parse(&forged)
                .expect("parse forged code")
                .vouches_for("store-042", OPERATOR)
                .expect("verify tag")
        );
    }

    #[test]
    fn a_host_key_proof_holds_only_for_its_secret_and_key() {
        let secret = secret();
        let proof = secret.host_key_proof(HOST).expect("proof");
        assert!(is_mac(&proof));

        assert!(secret.host_key_proof_matches(HOST, &proof).expect("verify"));
        assert!(
            !secret
                .host_key_proof_matches("SHA256:other-host", &proof)
                .expect("verify")
        );
        assert!(
            !super::PairingSecret::generate()
                .expect("other secret")
                .host_key_proof_matches(HOST, &proof)
                .expect("verify")
        );
        assert!(
            !secret
                .host_key_proof_matches(HOST, "not base64!")
                .expect("verify")
        );
        // The tag of the operator is not a proof of any host key.
        let tag = secret.operator_tag("store-042", OPERATOR).expect("tag");
        assert!(!secret.host_key_proof_matches(HOST, &tag).expect("verify"));
    }

    #[test]
    fn malformed_codes_are_refused_without_quoting_them() {
        let token = token();
        let code = PairingCode::new(&token, secret(), "store-042", OPERATOR).expect("code");
        let encoded = code.encode();
        let secret = code.secret().expose().to_owned();
        let tag = encoded.rsplit('.').next().expect("tag").to_owned();

        for malformed in [
            String::new(),
            token.clone(),
            format!("rvp1.{token}.{secret}"),
            format!("rvp2.{token}.{secret}.{tag}"),
            format!("{encoded}.extra"),
            format!("rvp1.rva_{}.{secret}.{tag}", &token[4..]),
            format!("rvp1.{token}.rvs_{}.{tag}", &secret[4..]),
            format!("rvp1.{token}.{}.{tag}", &secret[..secret.len() - 2]),
            format!("rvp1.{token}.{secret}.{}", &tag[..tag.len() - 2]),
        ] {
            let error = PairingCode::parse(&malformed)
                .err()
                .unwrap_or_else(|| panic!("accepted {malformed}"));
            let text = error.to_string();
            assert!(
                !text.contains(&secret[4..]) && !text.contains(&token[4..]),
                "{text}"
            );
        }

        assert!(
            PairingCode::new(
                "rvp1.not.a.token",
                super::PairingSecret::generate().expect("secret"),
                "store-042",
                OPERATOR
            )
            .is_err()
        );
    }
}
