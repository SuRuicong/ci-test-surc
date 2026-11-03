//! 对应 tools/license-issuer/src/core/schema.ts 的验签侧子集：
//! parseLicenseEnvelopeShape / parsePayload（requirePayload）/ parseBinding。
//! 错误码与消息文案与 TS 版一致；details（逐条 errors）仅用于调试，不进入 HTTP 响应。
//! ADR-20261102：binding 分量名同时接受代号（c1..c5）与旧名；锚点存在性与重复冲突
//! 在代号空间判定（钉死文案见 codename-spec §4.1）；解析输出保留输入原名。

use crate::constants::{
    is_known_component_name, to_codename, ANCHOR_CODENAME, LICENSE_ALG, LICENSE_SCHEMA, PRODUCT,
};
use crate::error::{AgentosError, AgentosResult};
use crate::time::parse_iso_millis;
use regex::Regex;
use serde_json::Value;
use std::sync::OnceLock;

fn iso_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?(Z|[+-]\d{2}:\d{2})$").unwrap()
    })
}

fn feature_id_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^[a-z0-9][a-z0-9._:-]{0,127}$").unwrap())
}

fn base64url_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^[A-Za-z0-9_-]+$").unwrap())
}

fn sha256_hex_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^[0-9a-f]{64}$").unwrap())
}

pub const LICENSE_KINDS: [&str; 4] = ["commercial", "evaluation", "dev", "test"];

#[derive(Debug, Clone)]
pub struct OptionalBindingComponent {
    pub name: String,
    pub sha256: String,
}

#[derive(Debug, Clone)]
pub struct LicenseBinding {
    pub mode: String,
    /// 必选锚点分量哈希表；键序保留 license 文档序（写回 active.lic 时逐字节还原）。
    pub required: Vec<(String, String)>,
    pub optional: Vec<OptionalBindingComponent>,
    pub tolerance: i64,
}

#[derive(Debug, Clone)]
pub struct LicensePayload {
    pub product: String,
    pub license_id: String,
    pub customer: String,
    pub edition: String,
    pub license_kind: String,
    pub issued_at: String,
    pub not_before: String,
    pub expires_at: String,
    pub max_runtime_seconds: i64,
    pub binding: LicenseBinding,
    pub features: Vec<String>,
    pub renewal_of: Option<String>,
}

#[derive(Debug, Clone)]
pub struct EnvelopeShape {
    pub kid: String,
    /// 未解析的 payload（验签通过后才交给 parse_payload）。
    pub payload: Value,
    pub signature: String,
}

fn strict_keys(map: &serde_json::Map<String, Value>, allowed: &[&str], path: &str, errors: &mut Vec<String>) {
    for key in map.keys() {
        if !allowed.contains(&key.as_str()) {
            errors.push(format!("{path}.{key} is not allowed"));
        }
    }
}

fn string_field(value: Option<&Value>, path: &str, errors: &mut Vec<String>, min: usize, max: usize) -> Option<String> {
    match value {
        Some(Value::String(s)) if s.chars().count() >= min && s.chars().count() <= max => Some(s.clone()),
        // JS length 按 UTF-16 码元计；中文等 BMP 字符与 chars() 一致，足够契约等价。
        _ => {
            errors.push(format!("{path} must be a string of length {min}..{max}"));
            None
        }
    }
}

fn literal_field(value: Option<&Value>, literal: &str, path: &str, errors: &mut Vec<String>) -> Option<String> {
    match value {
        Some(Value::String(s)) if s == literal => Some(s.clone()),
        _ => {
            errors.push(format!("{path} must be {}", serde_json::to_string(literal).unwrap()));
            None
        }
    }
}

fn iso_field(value: Option<&Value>, path: &str, errors: &mut Vec<String>) -> Option<String> {
    match value {
        Some(Value::String(s)) if iso_re().is_match(s) && parse_iso_millis(s).is_some() => Some(s.clone()),
        _ => {
            errors.push(format!("{path} must be an ISO-8601 timestamp with seconds and timezone"));
            None
        }
    }
}

fn sha256_component_field(value: Option<&Value>, path: &str, errors: &mut Vec<String>) -> Option<String> {
    match value {
        Some(Value::String(s))
            if s.starts_with("sha256:") && sha256_hex_re().is_match(&s["sha256:".len()..]) =>
        {
            Some(s.clone())
        }
        _ => {
            errors.push(format!("{path} must be 'sha256:<64 lowercase hex>'"));
            None
        }
    }
}

const ENVELOPE_KEYS: [&str; 5] = ["schema", "kid", "alg", "payload", "signature"];
const PAYLOAD_KEYS: [&str; 12] = [
    "product",
    "licenseId",
    "customer",
    "edition",
    "licenseKind",
    "issuedAt",
    "notBefore",
    "expiresAt",
    "maxRuntimeSeconds",
    "binding",
    "features",
    "renewalOf",
];
const BINDING_KEYS: [&str; 4] = ["mode", "required", "optional", "tolerance"];
const OPTIONAL_COMPONENT_KEYS: [&str; 2] = ["name", "sha256"];

/// 第一阶段：只验 envelope 外壳，payload 保持未解析。
pub fn parse_license_envelope_shape(value: &Value) -> Result<EnvelopeShape, Vec<String>> {
    let mut errors: Vec<String> = Vec::new();
    let map = match value {
        Value::Object(m) => m,
        _ => return Err(vec!["license envelope must be an object".to_string()]),
    };
    strict_keys(map, &ENVELOPE_KEYS, "license", &mut errors);
    let schema = literal_field(map.get("schema"), LICENSE_SCHEMA, "license.schema", &mut errors);
    let kid = string_field(map.get("kid"), "license.kid", &mut errors, 1, 128);
    let alg = literal_field(map.get("alg"), LICENSE_ALG, "license.alg", &mut errors);
    let signature = string_field(map.get("signature"), "license.signature", &mut errors, 16, 4096);
    if let Some(sig) = &signature {
        if !base64url_re().is_match(sig) {
            errors.push("license.signature must be base64url".to_string());
        }
    }
    if !map.contains_key("payload") {
        errors.push("license.payload is required".to_string());
    }
    if !errors.is_empty() || schema.is_none() || kid.is_none() || alg.is_none() || signature.is_none() {
        return Err(errors);
    }
    Ok(EnvelopeShape {
        kid: kid.unwrap(),
        payload: map.get("payload").cloned().unwrap_or(Value::Null),
        signature: signature.unwrap(),
    })
}

fn parse_binding(value: Option<&Value>, errors: &mut Vec<String>) -> Option<LicenseBinding> {
    let map = match value {
        Some(Value::Object(m)) => m,
        _ => {
            errors.push("payload.binding must be an object".to_string());
            return None;
        }
    };
    strict_keys(map, &BINDING_KEYS, "payload.binding", errors);
    match map.get("mode") {
        Some(Value::String(s)) if s == "machine" => {}
        _ => errors.push("payload.binding.mode must be 'machine'".to_string()),
    }
    let mut required: Vec<(String, String)> = Vec::new();
    match map.get("required") {
        Some(Value::Object(req)) => {
            if req.is_empty() || req.len() > 16 {
                errors.push("payload.binding.required must contain 1..16 components".to_string());
            }
            // 归一化到代号空间判定锚点存在性与重复冲突；输出保留输入原名。
            let mut required_codenames: Vec<&str> = Vec::new();
            for (name, hash_value) in req {
                if !is_known_component_name(name) {
                    errors.push(format!("payload.binding.required.{name} is not a known fingerprint component"));
                    continue;
                }
                let codename = to_codename(name);
                if required_codenames.contains(&codename) {
                    errors.push(format!(
                        "payload.binding.required contains duplicate component '{codename}' after codename normalization"
                    ));
                    continue;
                }
                required_codenames.push(codename);
                let path = format!("payload.binding.required.{name}");
                if let Some(hash) = sha256_component_field(Some(hash_value), &path, errors) {
                    required.push((name.clone(), hash));
                }
            }
            if !required_codenames.contains(&ANCHOR_CODENAME) {
                errors.push(format!(
                    "payload.binding.required must contain the anchor component '{ANCHOR_CODENAME}'"
                ));
            }
        }
        _ => errors.push("payload.binding.required must be an object".to_string()),
    }
    let mut optional: Vec<OptionalBindingComponent> = Vec::new();
    let mut optional_codenames: Vec<String> = Vec::new();
    match map.get("optional") {
        Some(Value::Array(arr)) => {
            if arr.len() > 16 {
                errors.push("payload.binding.optional must contain at most 16 components".to_string());
            }
            for (index, item) in arr.iter().enumerate() {
                let item_path = format!("payload.binding.optional[{index}]");
                let obj = match item {
                    Value::Object(o) => o,
                    _ => {
                        errors.push(format!("{item_path} must be an object"));
                        continue;
                    }
                };
                strict_keys(obj, &OPTIONAL_COMPONENT_KEYS, &item_path, errors);
                let name = string_field(obj.get("name"), &format!("{item_path}.name"), errors, 1, 64);
                if let Some(n) = &name {
                    // 与 TS schema.ts 一致：optional 不接受必选锚点（锚点归一化后代号即 c1）。
                    if !is_known_component_name(n) || to_codename(n) == ANCHOR_CODENAME {
                        errors.push(format!("{item_path}.name is not a known fingerprint component"));
                    } else {
                        let codename = to_codename(n);
                        if optional_codenames.iter().any(|c| c == codename) {
                            errors.push(format!(
                                "payload.binding.optional contains duplicate component '{codename}' after codename normalization"
                            ));
                        } else {
                            optional_codenames.push(codename.to_string());
                        }
                    }
                }
                let sha256 = sha256_component_field(obj.get("sha256"), &format!("{item_path}.sha256"), errors);
                if let (Some(n), Some(s)) = (name, sha256) {
                    optional.push(OptionalBindingComponent { name: n, sha256: s });
                }
            }
        }
        _ => errors.push("payload.binding.optional must be an array".to_string()),
    }
    let mut tolerance: i64 = 0;
    match map.get("tolerance") {
        Some(Value::Number(n)) => {
            let as_int = n.as_i64().or_else(|| n.as_u64().map(|u| u as i64));
            match as_int {
                Some(v) if (0..=16).contains(&v) => tolerance = v,
                _ => errors.push("payload.binding.tolerance must be an integer in 0..16".to_string()),
            }
        }
        _ => errors.push("payload.binding.tolerance must be an integer in 0..16".to_string()),
    }
    if !errors.is_empty() {
        return None;
    }
    Some(LicenseBinding {
        mode: "machine".to_string(),
        required,
        optional,
        tolerance,
    })
}

/// 第二阶段（验签通过后）：解析 payload，失败抛 ERR_INVALID_PAYLOAD。
pub fn require_payload(value: &Value) -> AgentosResult<LicensePayload> {
    match parse_payload(value) {
        Ok(p) => Ok(p),
        Err(_errors) => Err(AgentosError::new("ERR_INVALID_PAYLOAD", "License payload is invalid.")),
    }
}

fn parse_payload(value: &Value) -> Result<LicensePayload, Vec<String>> {
    let mut errors: Vec<String> = Vec::new();
    let map = match value {
        Value::Object(m) => m,
        _ => return Err(vec!["payload must be an object".to_string()]),
    };
    strict_keys(map, &PAYLOAD_KEYS, "payload", &mut errors);
    let product = literal_field(map.get("product"), PRODUCT, "payload.product", &mut errors);
    let license_id = string_field(map.get("licenseId"), "payload.licenseId", &mut errors, 1, 128);
    let customer = string_field(map.get("customer"), "payload.customer", &mut errors, 1, 256);
    let edition = string_field(map.get("edition"), "payload.edition", &mut errors, 1, 64);
    let license_kind = match map.get("licenseKind") {
        Some(Value::String(s)) if LICENSE_KINDS.contains(&s.as_str()) => Some(s.clone()),
        _ => {
            errors.push(format!("payload.licenseKind must be one of {}", LICENSE_KINDS.join("|")));
            None
        }
    };
    let issued_at = iso_field(map.get("issuedAt"), "payload.issuedAt", &mut errors);
    let not_before = iso_field(map.get("notBefore"), "payload.notBefore", &mut errors);
    let expires_at = iso_field(map.get("expiresAt"), "payload.expiresAt", &mut errors);
    if let (Some(i), Some(e)) = (&issued_at, &expires_at) {
        if parse_iso_millis(e).unwrap() <= parse_iso_millis(i).unwrap() {
            errors.push("payload.expiresAt must be later than payload.issuedAt".to_string());
        }
    }
    if let (Some(nb), Some(e)) = (&not_before, &expires_at) {
        if parse_iso_millis(nb).unwrap() > parse_iso_millis(e).unwrap() {
            errors.push("payload.notBefore must not be later than payload.expiresAt".to_string());
        }
    }
    let mut max_runtime_seconds: i64 = 0;
    match map.get("maxRuntimeSeconds") {
        Some(Value::Number(n)) => {
            let as_int = n.as_i64().or_else(|| n.as_u64().map(|u| u as i64));
            match as_int {
                Some(v) if v > 0 && v <= 315_576_000 => max_runtime_seconds = v,
                _ => errors.push(
                    "payload.maxRuntimeSeconds must be a positive integer no greater than 315576000".to_string(),
                ),
            }
        }
        _ => errors.push(
            "payload.maxRuntimeSeconds must be a positive integer no greater than 315576000".to_string(),
        ),
    }
    let binding = parse_binding(map.get("binding"), &mut errors);
    let mut features: Vec<String> = Vec::new();
    match map.get("features") {
        Some(Value::Array(arr)) if arr.len() <= 128 => {
            for (index, item) in arr.iter().enumerate() {
                match item {
                    Value::String(s) if feature_id_re().is_match(s) => features.push(s.clone()),
                    _ => errors.push(format!(
                        "payload.features[{index}] must match {}",
                        feature_id_re().as_str()
                    )),
                }
            }
        }
        _ => errors.push("payload.features must be an array of at most 128 items".to_string()),
    }
    let mut renewal_of: Option<String> = None;
    match map.get("renewalOf") {
        Some(Value::Null) => {}
        Some(Value::String(s)) => {
            let len = s.chars().count();
            if !(1..=128).contains(&len) {
                errors.push("payload.renewalOf must be a string of length 1..128".to_string());
            } else {
                renewal_of = Some(s.clone());
            }
        }
        _ => errors.push("payload.renewalOf must be null or a string".to_string()),
    }
    if !errors.is_empty()
        || product.is_none()
        || license_id.is_none()
        || customer.is_none()
        || edition.is_none()
        || license_kind.is_none()
        || issued_at.is_none()
        || not_before.is_none()
        || expires_at.is_none()
        || binding.is_none()
    {
        return Err(errors);
    }
    Ok(LicensePayload {
        product: product.unwrap(),
        license_id: license_id.unwrap(),
        customer: customer.unwrap(),
        edition: edition.unwrap(),
        license_kind: license_kind.unwrap(),
        issued_at: issued_at.unwrap(),
        not_before: not_before.unwrap(),
        expires_at: expires_at.unwrap(),
        max_runtime_seconds,
        binding: binding.unwrap(),
        features,
        renewal_of,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sample_payload() -> Value {
        json!({
            "product": "agentos",
            "licenseId": "lic-2026-0001",
            "customer": "某市公安局",
            "edition": "enterprise",
            "licenseKind": "commercial",
            "issuedAt": "2026-11-01T00:00:00+08:00",
            "notBefore": "2026-11-01T00:00:00+08:00",
            "expiresAt": "2027-11-01T00:00:00+08:00",
            "maxRuntimeSeconds": 31622400,
            "binding": {
                "mode": "machine",
                "required": { "c1": format!("sha256:{}", "a".repeat(64)) },
                "optional": [{ "name": "c2", "sha256": format!("sha256:{}", "b".repeat(64)) }],
                "tolerance": 1
            },
            "features": ["offline"],
            "renewalOf": null
        })
    }

    #[test]
    fn payload_roundtrip_ok() {
        let p = require_payload(&sample_payload()).unwrap();
        assert_eq!(p.license_id, "lic-2026-0001");
        assert_eq!(p.binding.required.len(), 1);
        // 解析输出保留输入原名（代号输入 → 代号输出，不做归一化改写）。
        assert_eq!(p.binding.required[0].0, "c1");
        assert_eq!(p.binding.optional[0].name, "c2");
        assert_eq!(p.binding.tolerance, 1);
        assert_eq!(p.max_runtime_seconds, 31622400);
    }

    #[test]
    fn legacy_binding_names_accepted_and_preserved() {
        // legacy license（旧名 binding）通过 schema 校验，输出保留旧名（归一化只在比对边界）。
        let mut p = sample_payload();
        p["binding"]["required"] = json!({ "machine-id": format!("sha256:{}", "a".repeat(64)) });
        p["binding"]["optional"] =
            json!([{ "name": "dmi-product-uuid", "sha256": format!("sha256:{}", "b".repeat(64)) }]);
        let parsed = require_payload(&p).unwrap();
        assert_eq!(parsed.binding.required[0].0, "machine-id");
        assert_eq!(parsed.binding.optional[0].name, "dmi-product-uuid");
    }

    #[test]
    fn envelope_rejects_unknown_key() {
        let v = json!({
            "schema": "agentos-license/v1",
            "kid": "agentos-dev-2026-q4",
            "alg": "Ed25519",
            "payload": {},
            "signature": "a".repeat(86),
            "extra": 1
        });
        let err = parse_license_envelope_shape(&v).unwrap_err();
        assert!(err.iter().any(|e| e == "license.extra is not allowed"));
    }

    #[test]
    fn binding_requires_anchor() {
        let mut p = sample_payload();
        p["binding"]["required"] = json!({ "cpu": format!("sha256:{}", "c".repeat(64)) });
        // 钉死文案（codename-spec §4.1）：锚点缺失统一报 c1。
        let err = parse_payload(&p).unwrap_err();
        assert!(err
            .iter()
            .any(|e| e == "payload.binding.required must contain the anchor component 'c1'"));
    }

    #[test]
    fn binding_anchor_legacy_name_satisfies_anchor_requirement() {
        // required 用旧名 machine-id 也算含锚点 c1（归一化到代号空间后判定）。
        let mut p = sample_payload();
        p["binding"]["required"] = json!({ "machine-id": format!("sha256:{}", "a".repeat(64)) });
        assert!(require_payload(&p).is_ok());
    }

    #[test]
    fn required_dual_name_conflict_rejected() {
        // required 同时含 machine-id 与 c1 → 归一化后重复，钉死文案拒绝。
        let mut p = sample_payload();
        p["binding"]["required"] = json!({
            "machine-id": format!("sha256:{}", "a".repeat(64)),
            "c1": format!("sha256:{}", "a".repeat(64))
        });
        let err = parse_payload(&p).unwrap_err();
        assert!(err.iter().any(|e| e
            == "payload.binding.required contains duplicate component 'c1' after codename normalization"));
    }

    #[test]
    fn optional_dual_name_conflict_rejected() {
        // optional 双名并存（dmi-product-uuid 与 c2）→ 钉死文案拒绝。
        let mut p = sample_payload();
        p["binding"]["optional"] = json!([
            { "name": "dmi-product-uuid", "sha256": format!("sha256:{}", "b".repeat(64)) },
            { "name": "c2", "sha256": format!("sha256:{}", "b".repeat(64)) }
        ]);
        let err = parse_payload(&p).unwrap_err();
        assert!(err.iter().any(|e| e
            == "payload.binding.optional contains duplicate component 'c2' after codename normalization"));
    }

    #[test]
    fn unknown_component_error_keeps_input_name() {
        // 合法名集合 = 5 代号 ∪ 5 旧名；其余报原文案，名字按输入原样填。
        let mut p = sample_payload();
        p["binding"]["required"] = json!({
            "c1": format!("sha256:{}", "a".repeat(64)),
            "bios-uuid": format!("sha256:{}", "d".repeat(64))
        });
        let err = parse_payload(&p).unwrap_err();
        assert!(err
            .iter()
            .any(|e| e == "payload.binding.required.bios-uuid is not a known fingerprint component"));
    }

    #[test]
    fn optional_rejects_anchor_component() {
        // 与 TS schema.ts 对齐：optional 不接受必选锚点，无论代号 c1 还是旧名 machine-id。
        for anchor in ["c1", "machine-id"] {
            let mut p = sample_payload();
            p["binding"]["optional"] =
                json!([{ "name": anchor, "sha256": format!("sha256:{}", "a".repeat(64)) }]);
            let err = parse_payload(&p).unwrap_err();
            assert!(err
                .iter()
                .any(|e| e == "payload.binding.optional[0].name is not a known fingerprint component"));
        }
    }
}
