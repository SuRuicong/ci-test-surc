//! 对应 tools/license-daemon/src/core/activation.ts：
//! 激活（DESIGN.md §3.3）：验签 → 指纹校验 → 时效预检（verify 内置）→
//! 通过才把 license 原子写入 <stateDir>/active.lic（write-temp-then-rename）。
//! 任一失败抛错且不留半激活状态。

use license_core::binding::match_binding;
use license_core::constants::{LICENSE_ALG, LICENSE_SCHEMA};
use license_core::error::{AgentosError, AgentosResult};
use license_core::jsonfmt::{object_in_order, pretty_json};
use license_core::key_policy::PublicKeyMetadata;
use license_core::schema::LicensePayload;
use license_core::verifier::verify_license_object;
use serde_json::Value;
use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct ActivationResult {
    pub license_id: String,
    pub customer: String,
    pub expires_at: String,
    /// 与 TS ActivationResult.activeLicensePath 对齐的返回字段。
    /// 当前 HTTP 响应契约只用 licenseId/customer/expiresAt（同 TS server.ts），
    /// 该字段供调用方/调试定位落盘路径，bin crate 内暂未被读，故显式豁免 dead_code。
    #[allow(dead_code)]
    pub active_license_path: PathBuf,
}

/// 重建 verified envelope 的 JSON 值，键序与 TS 版 `{...shape, payload}` 一致：
/// schema, kid, alg, payload, signature；payload 内字段按 parsePayload 构造序。
fn envelope_value(shape_kid: &str, shape_signature: &str, payload: &LicensePayload) -> Value {
    let required = Value::Object(
        payload
            .binding
            .required
            .iter()
            .map(|(k, v)| (k.clone(), Value::String(v.clone())))
            .collect(),
    );
    let optional = Value::Array(
        payload
            .binding
            .optional
            .iter()
            .map(|c| {
                object_in_order(vec![
                    ("name", Value::String(c.name.clone())),
                    ("sha256", Value::String(c.sha256.clone())),
                ])
            })
            .collect(),
    );
    let binding = object_in_order(vec![
        ("mode", Value::String(payload.binding.mode.clone())),
        ("required", required),
        ("optional", optional),
        (
            "tolerance",
            Value::Number(serde_json::Number::from(payload.binding.tolerance)),
        ),
    ]);
    let payload_value = object_in_order(vec![
        ("product", Value::String(payload.product.clone())),
        ("licenseId", Value::String(payload.license_id.clone())),
        ("customer", Value::String(payload.customer.clone())),
        ("edition", Value::String(payload.edition.clone())),
        ("licenseKind", Value::String(payload.license_kind.clone())),
        ("issuedAt", Value::String(payload.issued_at.clone())),
        ("notBefore", Value::String(payload.not_before.clone())),
        ("expiresAt", Value::String(payload.expires_at.clone())),
        (
            "maxRuntimeSeconds",
            Value::Number(serde_json::Number::from(payload.max_runtime_seconds)),
        ),
        ("binding", binding),
        (
            "features",
            Value::Array(
                payload
                    .features
                    .iter()
                    .map(|f| Value::String(f.clone()))
                    .collect(),
            ),
        ),
        (
            "renewalOf",
            match &payload.renewal_of {
                Some(s) => Value::String(s.clone()),
                None => Value::Null,
            },
        ),
    ]);
    object_in_order(vec![
        ("schema", Value::String(LICENSE_SCHEMA.to_string())),
        ("kid", Value::String(shape_kid.to_string())),
        ("alg", Value::String(LICENSE_ALG.to_string())),
        ("payload", payload_value),
        ("signature", Value::String(shape_signature.to_string())),
    ])
}

/// Windows 上 fs::rename 不覆盖已存在目标；Node renameSync 覆盖。
/// 用 MoveFileExW(MOVEFILE_REPLACE_EXISTING) 对齐 Node 语义。
#[cfg(windows)]
fn rename_replace(from: &Path, to: &Path) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    extern "system" {
        fn MoveFileExW(existing: *const u16, new: *const u16, flags: u32) -> i32;
    }
    const MOVEFILE_REPLACE_EXISTING: u32 = 0x1;
    let from_w: Vec<u16> = from
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let to_w: Vec<u16> = to
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    if unsafe { MoveFileExW(from_w.as_ptr(), to_w.as_ptr(), MOVEFILE_REPLACE_EXISTING) } == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(not(windows))]
fn rename_replace(from: &Path, to: &Path) -> io::Result<()> {
    std::fs::rename(from, to)
}

fn atomic_write(
    state_dir: &Path,
    tmp_name: &str,
    target_name: &str,
    content: &str,
) -> AgentosResult<PathBuf> {
    let tmp = state_dir.join(tmp_name);
    let target = state_dir.join(target_name);
    std::fs::write(&tmp, content).map_err(|e| {
        AgentosError::new(
            "ERR_STATE_WRITE_FAILED",
            &format!("failed to write {}: {e}", tmp.display()),
        )
    })?;
    rename_replace(&tmp, &target).map_err(|e| {
        AgentosError::new(
            "ERR_STATE_WRITE_FAILED",
            &format!(
                "failed to rename {} -> {}: {e}",
                tmp.display(),
                target.display()
            ),
        )
    })?;
    Ok(target)
}

pub fn activate_license(
    license_value: &Value,
    state_dir: &Path,
    public_key: &PublicKeyMetadata,
    current_components: &HashMap<String, String>,
    now_ms: i64,
) -> AgentosResult<ActivationResult> {
    let verified = verify_license_object(license_value, public_key, now_ms, false)?;
    let payload = &verified.payload;

    let match_result = match_binding(&payload.binding, current_components);
    if !match_result.ok {
        return Err(AgentosError::new(
            "ERR_FINGERPRINT_MISMATCH",
            &format!(
                "Machine fingerprint mismatch: {}.",
                match_result.mismatches.join(", ")
            ),
        ));
    }

    std::fs::create_dir_all(state_dir).map_err(|e| {
        AgentosError::new(
            "ERR_STATE_WRITE_FAILED",
            &format!("failed to create state dir {}: {e}", state_dir.display()),
        )
    })?;

    // 从原始 envelope 值取 kid/signature（保持与输入一致），payload 用解析后的重建。
    let shape_kid = license_value
        .get("kid")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let shape_signature = license_value
        .get("signature")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let envelope = envelope_value(shape_kid, shape_signature, payload);
    let pid = std::process::id();
    let active_path = atomic_write(
        state_dir,
        &format!(".active.lic.{pid}.tmp"),
        "active.lic",
        &(pretty_json(&envelope) + "\n"),
    )?;

    // 续期基线（DESIGN §5.1）：激活时刻快照账本累计值为 base；账本绑定机器指纹而非单张 license。
    // 直接读链尾文件契约（不反向依赖 checker 模块）；无账本/链尾损坏时 base=0。
    let mut base_cumulative: i64 = 0;
    let tip_path = state_dir.join("ledger-tip.json");
    if let Ok(text) = std::fs::read_to_string(&tip_path) {
        if let Ok(Value::Object(tip)) = serde_json::from_str::<Value>(&text) {
            if let Some(Value::Number(n)) = tip.get("cumulative_seconds") {
                if let Some(v) = n.as_i64().or_else(|| n.as_u64().map(|u| u as i64)) {
                    base_cumulative = v;
                }
            }
        }
    }
    let base = object_in_order(vec![
        ("licenseId", Value::String(payload.license_id.clone())),
        (
            "baseCumulativeSeconds",
            Value::Number(serde_json::Number::from(base_cumulative)),
        ),
    ]);
    atomic_write(
        state_dir,
        &format!(".runtime-base.{pid}.tmp"),
        "runtime-base.json",
        &(pretty_json(&base) + "\n"),
    )?;

    Ok(ActivationResult {
        license_id: payload.license_id.clone(),
        customer: payload.customer.clone(),
        expires_at: payload.expires_at.clone(),
        active_license_path: active_path,
    })
}
