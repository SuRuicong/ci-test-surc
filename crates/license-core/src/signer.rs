//! 对应 tools/license-issuer/src/core/signer.ts 的验签侧：
//! 签名输入三行式 + Ed25519 验签（公钥为 SPKI PEM，签名为 base64url）。

use crate::constants::LICENSE_SCHEMA;
use crate::error::{AgentosError, AgentosResult};
use crate::jsonfmt::canonical_json;
use base64::engine::general_purpose::{STANDARD as B64, URL_SAFE_NO_PAD as B64URL};
use base64::Engine;
use ed25519_dalek::{Signature, VerifyingKey};
use serde_json::Value;

/// 签名输入三行式：`${LICENSE_SCHEMA}\n${kid}\n${canonicalJson(payload)}`，LF 分隔、无尾换行。
pub fn signing_input(kid: &str, payload: &Value) -> String {
    format!("{LICENSE_SCHEMA}\n{kid}\n{}", canonical_json(payload))
}

/// Ed25519 SPKI DER 固定 12 字节前缀（1.3.101.112），后跟 32 字节裸公钥。
const SPKI_ED25519_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

/// 从 SPKI PEM 提取 32 字节 Ed25519 裸公钥（等价 node:crypto createPublicKey 对 SPKI 的解析）。
pub fn ed25519_pubkey_from_pem(pem: &str) -> Option<[u8; 32]> {
    let b64: String = pem
        .lines()
        .map(str::trim)
        .filter(|l| !l.starts_with("-----") && !l.is_empty())
        .collect();
    let der = B64.decode(b64).ok()?;
    if der.len() == SPKI_ED25519_PREFIX.len() + 32 && der[..12] == SPKI_ED25519_PREFIX {
        let mut key = [0u8; 32];
        key.copy_from_slice(&der[12..]);
        Some(key)
    } else {
        None
    }
}

fn decode_signature_base64url(sig: &str) -> Option<Vec<u8>> {
    B64URL.decode(sig).ok()
}

/// assertSignatureValid：任何解析/验签失败都归一为 ERR_SIGNATURE_VERIFY_FAILED（同 TS 的 try/catch）。
pub fn assert_signature_valid(
    kid: &str,
    payload: &Value,
    signature_b64url: &str,
    public_key_pem: &str,
) -> AgentosResult<()> {
    let ok = (|| -> Option<bool> {
        let key_bytes = ed25519_pubkey_from_pem(public_key_pem)?;
        let verifying_key = VerifyingKey::from_bytes(&key_bytes).ok()?;
        let sig_bytes = decode_signature_base64url(signature_b64url)?;
        let signature = Signature::from_slice(&sig_bytes).ok()?;
        let input = signing_input(kid, payload);
        Some(
            verifying_key
                .verify_strict(input.as_bytes(), &signature)
                .is_ok(),
        )
    })()
    .unwrap_or(false);
    if !ok {
        return Err(AgentosError::new(
            "ERR_SIGNATURE_VERIFY_FAILED",
            "License signature verification failed.",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::json;

    /// 与 TS 版互操作的核心：用 dalek 本地签名，验证 signing_input + verify 链路自洽。
    #[test]
    fn sign_then_verify_roundtrip() {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let vk = sk.verifying_key();
        // 手工拼 SPKI PEM（前缀 + 32 字节公钥）
        let mut der = SPKI_ED25519_PREFIX.to_vec();
        der.extend_from_slice(&vk.to_bytes());
        let b64 = B64.encode(der);
        let mut pem = String::from("-----BEGIN PUBLIC KEY-----\n");
        for chunk in b64.as_bytes().chunks(64) {
            pem.push_str(std::str::from_utf8(chunk).unwrap());
            pem.push('\n');
        }
        pem.push_str("-----END PUBLIC KEY-----\n");

        let payload = json!({"b": 1, "a": "x"});
        let kid = "agentos-dev-2026-q4";
        let input = signing_input(kid, &payload);
        let sig = sk.sign(input.as_bytes());
        let sig_b64url = B64URL.encode(sig.to_bytes());
        assert!(assert_signature_valid(kid, &payload, &sig_b64url, &pem).is_ok());

        // 篡改 payload → 拒签
        let tampered = json!({"b": 1, "a": "y"});
        let err = assert_signature_valid(kid, &tampered, &sig_b64url, &pem).unwrap_err();
        assert_eq!(err.code, "ERR_SIGNATURE_VERIFY_FAILED");
    }

    #[test]
    fn signing_input_format() {
        let payload = json!({"k": "v"});
        assert_eq!(
            signing_input("agentos-dev-2026-q4", &payload),
            "agentos-license/v1\nagentos-dev-2026-q4\n{\"k\":\"v\"}"
        );
    }
}
