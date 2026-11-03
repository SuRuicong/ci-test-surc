//! 对应 tools/license-issuer/src/core/verifier.ts（daemon 侧调用形态：
//! production=false、allowExpired=false、无 rejectLicenseKinds、不跳时效检查）。

use crate::error::{AgentosError, AgentosResult};
use crate::key_policy::PublicKeyMetadata;
use crate::schema::{parse_license_envelope_shape, require_payload, LicensePayload};
use crate::signer::assert_signature_valid;
use crate::time::{is_before_not_before, is_expired};
use serde_json::Value;

#[derive(Debug, Clone)]
pub struct VerifiedLicense {
    /// 未解析的 envelope 原始 payload 值（canonical JSON 输入用它）。
    pub raw_payload: Value,
    pub payload: LicensePayload,
    /// envelope.signature（checker 用它派生账本 HMAC 密钥，DESIGN §2.3）。
    pub signature: String,
    pub expired: bool,
}

/// 验证流程（沿用参考实现的两阶段顺序）：
/// 1. 验 envelope 外壳（payload 不解析）→ 2. kid 匹配 → 3. 验签 →
/// 4. 验签通过后才解析 payload → 5. 时效检查（skip_temporal_checks=true 时跳过，
///    对应 checker 按水印语义单独判时效的用法）。
pub fn verify_license_object(
    value: &Value,
    public_key: &PublicKeyMetadata,
    now_ms: i64,
    skip_temporal_checks: bool,
) -> AgentosResult<VerifiedLicense> {
    let shape = match parse_license_envelope_shape(value) {
        Ok(s) => s,
        Err(_errors) => {
            return Err(AgentosError::new(
                "ERR_INVALID_LICENSE",
                "License envelope is invalid.",
            ));
        }
    };

    if shape.kid != public_key.kid {
        return Err(AgentosError::new(
            "ERR_UNKNOWN_KEY_ID",
            "Public key metadata kid does not match license kid.",
        ));
    }

    assert_signature_valid(
        &shape.kid,
        &shape.payload,
        &shape.signature,
        &public_key.public_key_pem,
    )?;
    let payload = require_payload(&shape.payload)?;

    let mut expired = false;
    if !skip_temporal_checks {
        if is_before_not_before(&payload.not_before, now_ms) {
            return Err(AgentosError::new(
                "ERR_LICENSE_NOT_YET_VALID",
                "License is not valid yet (notBefore in the future).",
            ));
        }
        expired = is_expired(&payload.expires_at, now_ms);
        if expired {
            return Err(AgentosError::new(
                "ERR_LICENSE_EXPIRED",
                "License is expired.",
            ));
        }
    }

    Ok(VerifiedLicense {
        raw_payload: shape.payload,
        payload,
        signature: shape.signature,
        expired,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signer::signing_input;
    use base64::engine::general_purpose::{STANDARD as B64, URL_SAFE_NO_PAD as B64URL};
    use base64::Engine;
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::json;

    const KID: &str = "agentos-dev-2026-q4";
    const SPKI_ED25519_PREFIX: [u8; 12] = [
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 00,
    ];

    /// 本地签名构造合法 envelope（与 signer.rs 测试同源的 SPKI PEM 拼法）。
    fn signed_envelope(payload: Value) -> (Value, PublicKeyMetadata) {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let vk = sk.verifying_key();
        let mut der = SPKI_ED25519_PREFIX.to_vec();
        der.extend_from_slice(&vk.to_bytes());
        let b64 = B64.encode(der);
        let mut pem = String::from("-----BEGIN PUBLIC KEY-----\n");
        for chunk in b64.as_bytes().chunks(64) {
            pem.push_str(std::str::from_utf8(chunk).unwrap());
            pem.push('\n');
        }
        pem.push_str("-----END PUBLIC KEY-----\n");
        let sig = sk.sign(signing_input(KID, &payload).as_bytes());
        let envelope = json!({
            "schema": "agentos-license/v1",
            "kid": KID,
            "alg": "Ed25519",
            "payload": payload,
            "signature": B64URL.encode(sig.to_bytes())
        });
        let key = PublicKeyMetadata {
            kid: KID.to_string(),
            alg: "Ed25519".to_string(),
            public_key_pem: pem,
            production: false,
        };
        (envelope, key)
    }

    fn payload_with_binding(binding: Value) -> Value {
        json!({
            "product": "agentos",
            "licenseId": "lic-legacy-0001",
            "customer": "旧版客户",
            "edition": "enterprise",
            "licenseKind": "commercial",
            "issuedAt": "2026-11-01T00:00:00+08:00",
            "notBefore": "2026-11-01T00:00:00+08:00",
            "expiresAt": "2027-11-01T00:00:00+08:00",
            "maxRuntimeSeconds": 31622400,
            "binding": binding,
            "features": ["offline"],
            "renewalOf": null
        })
    }

    #[test]
    fn legacy_binding_license_verifies_ok() {
        // codename-spec §7：旧名 binding 的 legacy license 通过 verifyLicenseObject。
        let binding = json!({
            "mode": "machine",
            "required": { "machine-id": format!("sha256:{}", "a".repeat(64)) },
            "optional": [{ "name": "dmi-product-uuid", "sha256": format!("sha256:{}", "b".repeat(64)) }],
            "tolerance": 1
        });
        let (envelope, key) = signed_envelope(payload_with_binding(binding));
        let now_ms = crate::time::parse_iso_millis("2026-12-01T00:00:00Z").unwrap();
        let verified = verify_license_object(&envelope, &key, now_ms, false).unwrap();
        // 解析输出保留输入原名（归一化只在比对边界）。
        assert_eq!(verified.payload.binding.required[0].0, "machine-id");
        assert_eq!(
            verified.payload.binding.optional[0].name,
            "dmi-product-uuid"
        );
    }

    #[test]
    fn codename_binding_license_verifies_ok() {
        let binding = json!({
            "mode": "machine",
            "required": { "c1": format!("sha256:{}", "a".repeat(64)) },
            "optional": [{ "name": "c2", "sha256": format!("sha256:{}", "b".repeat(64)) }],
            "tolerance": 1
        });
        let (envelope, key) = signed_envelope(payload_with_binding(binding));
        let now_ms = crate::time::parse_iso_millis("2026-12-01T00:00:00Z").unwrap();
        let verified = verify_license_object(&envelope, &key, now_ms, false).unwrap();
        assert_eq!(verified.payload.binding.required[0].0, "c1");
    }

    #[test]
    fn dual_name_conflict_license_rejected() {
        // 验签通过但 payload 含归一化冲突 → ERR_INVALID_PAYLOAD。
        let binding = json!({
            "mode": "machine",
            "required": {
                "machine-id": format!("sha256:{}", "a".repeat(64)),
                "c1": format!("sha256:{}", "a".repeat(64))
            },
            "optional": [],
            "tolerance": 1
        });
        let (envelope, key) = signed_envelope(payload_with_binding(binding));
        let now_ms = crate::time::parse_iso_millis("2026-12-01T00:00:00Z").unwrap();
        let err = verify_license_object(&envelope, &key, now_ms, false).unwrap_err();
        assert_eq!(err.code, "ERR_INVALID_PAYLOAD");
    }
}
