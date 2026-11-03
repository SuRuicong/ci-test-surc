//! 对应 tools/license-issuer/src/core/key-policy.ts 的 daemon 侧子集。
//! kid 分级命名（DESIGN.md §3.1）：agentos-{dev|test|prod}-yyyy-qN。

use crate::constants::LICENSE_ALG;
use crate::error::{AgentosError, AgentosResult};
use regex::Regex;
use std::sync::OnceLock;

fn key_id_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^agentos-(dev|test|prod)-\d{4}-q[1-4]$").unwrap())
}

#[derive(Debug, Clone)]
pub struct PublicKeyMetadata {
    pub kid: String,
    pub alg: String,
    pub public_key_pem: String,
    pub production: bool,
}

pub fn parse_key_environment(kid: &str) -> Option<String> {
    let caps = key_id_re().captures(kid)?;
    Some(caps.get(1).unwrap().as_str().to_string())
}

pub fn assert_valid_key_id(kid: &str) -> AgentosResult<()> {
    if !key_id_re().is_match(kid) {
        return Err(AgentosError::new(
            "ERR_INVALID_KEY_ID",
            "Key id must match agentos-{dev|test|prod}-yyyy-qN.",
        ));
    }
    Ok(())
}

pub fn public_key_metadata(kid: &str, public_key_pem: &str) -> AgentosResult<PublicKeyMetadata> {
    assert_valid_key_id(kid)?;
    Ok(PublicKeyMetadata {
        kid: kid.to_string(),
        alg: LICENSE_ALG.to_string(),
        public_key_pem: public_key_pem.to_string(),
        production: parse_key_environment(kid).as_deref() == Some("prod"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kid_policy() {
        assert!(public_key_metadata("agentos-dev-2026-q4", "pem").unwrap().production == false);
        assert!(public_key_metadata("agentos-prod-2026-q4", "pem").unwrap().production);
        assert!(public_key_metadata("bad-kid", "pem").is_err());
    }
}
