//! 对应 tools/license-checker/src/core/checker.ts：
//! status / heartbeat 共用校验管线，退出码即结论：
//! 0=valid / 2=expired / 3=tampered / 4=unlicensed / 5=clock_rollback / 6=fingerprint_mismatch。

use crate::ledger::{
    append_ledger_entry, derive_ledger_key, load_ledger_tip, verify_ledger_chain, LedgerTip, GENESIS_HASH,
};
use crate::pg_ledger::{pg_tip_matches_file, PgLedgerSink};
use chrono::{DateTime, Utc};
use license_core::binding::match_binding;
use license_core::error::{AgentosError, AgentosResult};
use license_core::fingerprint::{collect_fingerprint, ProbeSource};
use license_core::jsonfmt::object_in_order;
use license_core::key_policy::PublicKeyMetadata;
use license_core::schema::LicensePayload;
use license_core::time::parse_iso_millis;
use license_core::verifier::verify_license_object;
use serde_json::Value;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

pub const EXIT_VALID: i32 = 0;
pub const EXIT_EXPIRED: i32 = 2;
pub const EXIT_TAMPERED: i32 = 3;
pub const EXIT_UNLICENSED: i32 = 4;
pub const EXIT_CLOCK_ROLLBACK: i32 = 5;
pub const EXIT_FINGERPRINT_MISMATCH: i32 = 6;

const CLOCK_ROLLBACK_TOLERANCE_MS: i64 = 10 * 60 * 1000; // DESIGN §5.1：回拨 10 分钟阈值
const BASE_FILE: &str = "runtime-base.json";

pub struct CheckerContext<'a> {
    pub state_dir: PathBuf,
    pub public_key: &'a PublicKeyMetadata,
    pub probe: &'a dyn ProbeSource,
    pub instance_id: Option<&'a str>,
    /// 固定当前时间（测试用）；None 用系统时间。
    pub now_ms: Option<i64>,
    /// PG 账本双写 sink（DESIGN §4.5.3）；提供时心跳双写、校验交叉比对两侧链尾。
    pub pg_sink: Option<&'a mut PgLedgerSink>,
}

#[derive(Debug)]
pub struct CheckerResult {
    pub exit_code: i32,
    /// 校验通过时的契约 payload（键序即 stdout JSON 键序）。
    pub payload: Option<Value>,
    pub diagnostics: String,
}

fn fail(exit_code: i32, diagnostics: String) -> CheckerResult {
    CheckerResult {
        exit_code,
        payload: None,
        diagnostics,
    }
}

struct RuntimeBase {
    base_cumulative_seconds: f64,
}

/// 续期基线（DESIGN §5.1）：由 daemon 激活时快照；缺失或 licenseId 不符视为绕过激活通道 → tampered。
fn load_runtime_base(state_dir: &Path, license_id: &str) -> Option<RuntimeBase> {
    let p = state_dir.join(BASE_FILE);
    if !p.exists() {
        return None;
    }
    let text = std::fs::read_to_string(&p).ok()?;
    let v: Value = serde_json::from_str(&text).ok()?;
    if v.get("licenseId")?.as_str()? != license_id {
        return None;
    }
    let base = v.get("baseCumulativeSeconds")?.as_f64()?;
    Some(RuntimeBase {
        base_cumulative_seconds: base,
    })
}

struct EvalOk {
    payload: LicensePayload,
    ledger_key: [u8; 32],
    tip: Option<LedgerTip>,
}

enum Evaluation {
    Ok(Box<EvalOk>),
    Fail(CheckerResult),
}

/// new Date(ms).toISOString() 等价：'YYYY-MM-DDTHH:mm:ss.sssZ'。
fn iso_from_millis(ms: i64) -> String {
    DateTime::<Utc>::from_timestamp_millis(ms)
        .map(|d| d.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string())
        .unwrap_or_default()
}

fn evaluate(ctx: &mut CheckerContext) -> AgentosResult<Evaluation> {
    let now_ms = ctx.now_ms.unwrap_or_else(license_core::time::now_millis);
    let now_iso = iso_from_millis(now_ms);

    // 1. active.lic 存在性
    let lic_path = ctx.state_dir.join("active.lic");
    if !lic_path.exists() {
        return Ok(Evaluation::Fail(fail(
            EXIT_UNLICENSED,
            format!("no active license at {}", lic_path.display()),
        )));
    }

    // 2. 验签 + schema（时效单独按水印语义判定 → skip_temporal_checks）
    let raw_text = std::fs::read_to_string(&lic_path)
        .map_err(|e| AgentosError::new("ERR_STATE_READ_FAILED", &format!("failed to read {}: {e}", lic_path.display())))?;
    let raw: Value = match serde_json::from_str(&raw_text) {
        Ok(v) => v,
        Err(e) => {
            return Ok(Evaluation::Fail(fail(
                EXIT_TAMPERED,
                format!("active license failed verification: {e}"),
            )))
        }
    };
    let verified = match verify_license_object(&raw, ctx.public_key, now_ms, true) {
        Ok(v) => v,
        Err(err) => {
            return Ok(Evaluation::Fail(fail(
                EXIT_TAMPERED,
                format!("active license failed verification: {}: {}", err.code, err.message),
            )))
        }
    };
    let payload = verified.payload;
    let signature = verified.signature;

    // 3. 机器指纹绑定
    let fp = collect_fingerprint(ctx.probe, ctx.instance_id);
    let current: HashMap<String, String> = fp.components.iter().cloned().collect();
    let match_result = match_binding(&payload.binding, &current);
    if !match_result.ok {
        return Ok(Evaluation::Fail(fail(
            EXIT_FINGERPRINT_MISMATCH,
            format!("fingerprint mismatch: {}", match_result.mismatches.join(", ")),
        )));
    }

    // 4. 账本完整性（HMAC 密钥锚定 license 签名 + 机器指纹）
    let ledger_key = derive_ledger_key(&signature, &fp.fingerprint);
    let chain = verify_ledger_chain(&ctx.state_dir, &ledger_key)
        .map_err(|e| AgentosError::new("ERR_LEDGER", &e))?;
    if !chain.ok {
        return Ok(Evaluation::Fail(fail(
            EXIT_TAMPERED,
            format!(
                "ledger chain broken: {}",
                chain.reason.as_deref().unwrap_or("unknown")
            ),
        )));
    }
    let tip = load_ledger_tip(&ctx.state_dir).map_err(|e| AgentosError::new("ERR_LEDGER", &e))?;

    // 4.5 PG/文件链尾交叉验证（DESIGN §5.1：回滚 DB 备份 → tampered）；
    // PG 连接失败抛 ERR_PG_LEDGER（→ CLI 退出码 1）
    if let Some(sink) = ctx.pg_sink.as_deref_mut() {
        let pg_tip = sink.read_tip()?;
        if !pg_tip_matches_file(tip.as_ref(), pg_tip.as_ref()) {
            let fmt = |t: Option<&LedgerTip>| match t {
                Some(t) => format!("{}:{}", t.seq, t.entry_hash),
                None => "null".to_string(),
            };
            return Ok(Evaluation::Fail(fail(
                EXIT_TAMPERED,
                format!(
                    "pg ledger tip mismatch: file={} pg={}",
                    fmt(tip.as_ref()),
                    fmt(pg_tip.as_ref())
                ),
            )));
        }
    }

    // 5. 时钟回拨：当前系统时间 < 水印 - 10 分钟 → 拒服
    if let Some(t) = &tip {
        if let Some(wm) = parse_iso_millis(&t.wall_clock_max) {
            if now_ms < wm - CLOCK_ROLLBACK_TOLERANCE_MS {
                return Ok(Evaluation::Fail(fail(
                    EXIT_CLOCK_ROLLBACK,
                    format!("system clock rolled back below watermark {}", t.wall_clock_max),
                )));
            }
        }
    }

    // 6. 时效：基准取 max(当前系统时间, wall_clock_max)
    let effective_now_ms = match &tip {
        Some(t) if t.wall_clock_max > now_iso => parse_iso_millis(&t.wall_clock_max).unwrap_or(now_ms),
        _ => now_ms,
    };
    if let Some(expires) = parse_iso_millis(&payload.expires_at) {
        if expires <= effective_now_ms {
            return Ok(Evaluation::Fail(fail(
                EXIT_EXPIRED,
                format!("license expired at {}", payload.expires_at),
            )));
        }
    }

    Ok(Evaluation::Ok(Box::new(EvalOk {
        payload,
        ledger_key,
        tip,
    })))
}

fn build_payload(payload: &LicensePayload, tip: Option<&LedgerTip>, state_dir: &Path) -> Option<Value> {
    let cumulative = tip.map(|t| t.cumulative_seconds).unwrap_or(0.0);
    let base = load_runtime_base(state_dir, &payload.license_id)?;
    let used = (cumulative - base.base_cumulative_seconds).max(0.0);
    let remaining = (payload.max_runtime_seconds as f64 - used).floor().max(0.0);
    Some(object_in_order(vec![
        ("status", Value::String("valid".to_string())),
        ("licenseId", Value::String(payload.license_id.clone())),
        ("customer", Value::String(payload.customer.clone())),
        ("expiresAt", Value::String(payload.expires_at.clone())),
        (
            "runtimeRemainingSeconds",
            Value::Number(serde_json::Number::from_f64(remaining).unwrap()),
        ),
        (
            "ledgerTipHash",
            Value::String(
                tip.map(|t| t.entry_hash.clone())
                    .unwrap_or_else(|| GENESIS_HASH.to_string()),
            ),
        ),
    ]))
}

fn quota_check(result_payload: Option<Value>, max_runtime_seconds: i64) -> CheckerResult {
    match result_payload {
        None => fail(
            EXIT_TAMPERED,
            "runtime base missing or does not match active license (activation channel bypassed?)".to_string(),
        ),
        Some(p) => {
            let remaining = p
                .get("runtimeRemainingSeconds")
                .and_then(Value::as_f64)
                .unwrap_or(0.0);
            if remaining <= 0.0 {
                fail(
                    EXIT_EXPIRED,
                    format!("runtime quota exhausted (maxRuntimeSeconds={max_runtime_seconds})"),
                )
            } else {
                CheckerResult {
                    exit_code: EXIT_VALID,
                    payload: Some(p),
                    diagnostics: String::new(), // 调用方填充
                }
            }
        }
    }
}

/// license-checker status：验签 + 指纹 + 双重时效 + 账本完整性，退出码即结论。
pub fn run_status(ctx: &mut CheckerContext) -> AgentosResult<CheckerResult> {
    let evaluated = match evaluate(ctx)? {
        Evaluation::Ok(e) => e,
        Evaluation::Fail(r) => return Ok(r),
    };
    let payload = build_payload(&evaluated.payload, evaluated.tip.as_ref(), &ctx.state_dir);
    let mut result = quota_check(payload, evaluated.payload.max_runtime_seconds);
    if result.exit_code == EXIT_VALID {
        result.diagnostics = "license valid".to_string();
    }
    Ok(result)
}

/// license-checker heartbeat：status 全量校验通过后追加账本条目（单调时钟计量 + PG 双写）。
pub fn run_heartbeat(ctx: &mut CheckerContext, tick_monotonic_ms: f64) -> AgentosResult<CheckerResult> {
    let evaluated = match evaluate(ctx)? {
        Evaluation::Ok(e) => e,
        Evaluation::Fail(r) => return Ok(r),
    };
    let now_ms = ctx.now_ms.unwrap_or_else(license_core::time::now_millis);
    let now_iso = iso_from_millis(now_ms);
    let watermark = evaluated.tip.as_ref().map(|t| t.wall_clock_max.as_str());
    let (entry, tip) = append_ledger_entry(&ctx.state_dir, &evaluated.ledger_key, tick_monotonic_ms, &now_iso, watermark)
        .map_err(|e| AgentosError::new("ERR_LEDGER", &e))?;
    if let Some(sink) = ctx.pg_sink.as_deref_mut() {
        sink.append(&entry)?;
    }
    let payload = build_payload(&evaluated.payload, Some(&tip), &ctx.state_dir);
    let mut result = quota_check(payload, evaluated.payload.max_runtime_seconds);
    if result.exit_code == EXIT_VALID {
        result.diagnostics = "heartbeat recorded".to_string();
    }
    Ok(result)
}
