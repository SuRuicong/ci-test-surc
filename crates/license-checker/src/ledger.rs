//! 对应 tools/license-checker/src/core/ledger.ts：
//! 文件账本（DESIGN §4.5）：HMAC 密钥 = HKDF-SHA256(license 签名, salt = 机器指纹)；
//! O_APPEND JSONL + 文件锁（create_new 自旋，10s 超时）+ 链尾 write-temp-then-rename。

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use license_core::jsonfmt::{canonical_json, compact_json, object_in_order, pretty_json};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

pub const GENESIS_HASH: &str =
    "sha256:0000000000000000000000000000000000000000000000000000000000000000";
const LEDGER_FILE: &str = "ledger.jsonl";
const TIP_FILE: &str = "ledger-tip.json";
const LOCK_FILE: &str = "ledger.lock";
const HKDF_INFO: &[u8] = b"agentos-license-ledger/v1";

#[derive(Debug, Clone)]
pub struct LedgerTip {
    pub seq: i64,
    pub entry_hash: String,
    pub wall_clock_max: String,
    pub cumulative_seconds: f64,
}

#[derive(Debug, Clone)]
pub struct LedgerEntry {
    pub seq: i64,
    pub recorded_at: String,
    pub wall_clock_max: String,
    pub tick_monotonic_ms: f64,
    pub cumulative_seconds: f64,
    pub prev_hash: String,
    pub entry_hash: String,
    pub entry_hmac: String,
}

/// 账本 HMAC 密钥 = HKDF(license 签名, salt = 机器指纹)（DESIGN §2.3/§5.1）。
pub fn derive_ledger_key(license_signature: &str, machine_fingerprint: &str) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(
        Some(machine_fingerprint.as_bytes()),
        license_signature.as_bytes(),
    );
    let mut okm = [0u8; 32];
    hk.expand(HKDF_INFO, &mut okm)
        .expect("32-byte HKDF output is valid");
    okm
}

fn sha256_hex(data: &str) -> String {
    let digest = Sha256::digest(data.as_bytes());
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

/// entry（不含 entry_hash/entry_hmac）的 Value；canonical_json 会排序，键序仅作可读性。
fn entry_base_value(e: &LedgerEntry) -> Value {
    object_in_order(vec![
        ("seq", Value::Number(serde_json::Number::from(e.seq))),
        ("recorded_at", Value::String(e.recorded_at.clone())),
        ("wall_clock_max", Value::String(e.wall_clock_max.clone())),
        (
            "tick_monotonic_ms",
            Value::Number(serde_json::Number::from_f64(e.tick_monotonic_ms).unwrap()),
        ),
        (
            "cumulative_seconds",
            Value::Number(serde_json::Number::from_f64(e.cumulative_seconds).unwrap()),
        ),
        ("prev_hash", Value::String(e.prev_hash.clone())),
    ])
}

/// JSONL 行用的完整 entry Value（键序与 TS JSON.stringify 插入序一致）。
fn entry_full_value(e: &LedgerEntry) -> Value {
    object_in_order(vec![
        ("seq", Value::Number(serde_json::Number::from(e.seq))),
        ("recorded_at", Value::String(e.recorded_at.clone())),
        ("wall_clock_max", Value::String(e.wall_clock_max.clone())),
        (
            "tick_monotonic_ms",
            Value::Number(serde_json::Number::from_f64(e.tick_monotonic_ms).unwrap()),
        ),
        (
            "cumulative_seconds",
            Value::Number(serde_json::Number::from_f64(e.cumulative_seconds).unwrap()),
        ),
        ("prev_hash", Value::String(e.prev_hash.clone())),
        ("entry_hash", Value::String(e.entry_hash.clone())),
        ("entry_hmac", Value::String(e.entry_hmac.clone())),
    ])
}

fn tip_value(t: &LedgerTip) -> Value {
    object_in_order(vec![
        ("seq", Value::Number(serde_json::Number::from(t.seq))),
        ("entry_hash", Value::String(t.entry_hash.clone())),
        ("wall_clock_max", Value::String(t.wall_clock_max.clone())),
        (
            "cumulative_seconds",
            Value::Number(serde_json::Number::from_f64(t.cumulative_seconds).unwrap()),
        ),
    ])
}

fn compute_entry_hash(e: &LedgerEntry) -> String {
    format!(
        "sha256:{}",
        sha256_hex(&canonical_json(&entry_base_value(e)))
    )
}

fn compute_entry_hmac(key: &[u8; 32], entry_hash: &str) -> String {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(entry_hash.as_bytes());
    mac.finalize()
        .into_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn ledger_path(dir: &Path) -> PathBuf {
    dir.join(LEDGER_FILE)
}

fn tip_path(dir: &Path) -> PathBuf {
    dir.join(TIP_FILE)
}

pub fn load_ledger_tip(dir: &Path) -> Result<Option<LedgerTip>, String> {
    let p = tip_path(dir);
    if !p.exists() {
        return Ok(None);
    }
    let text =
        std::fs::read_to_string(&p).map_err(|e| format!("failed to read {}: {e}", p.display()))?;
    let v: Value =
        serde_json::from_str(&text).map_err(|e| format!("invalid JSON in {}: {e}", p.display()))?;
    match tip_from_value(&v) {
        Some(t) => Ok(Some(t)),
        None => Err(format!("malformed tip in {}", p.display())),
    }
}

fn tip_from_value(v: &Value) -> Option<LedgerTip> {
    Some(LedgerTip {
        seq: v.get("seq")?.as_i64()?,
        entry_hash: v.get("entry_hash")?.as_str()?.to_string(),
        wall_clock_max: v.get("wall_clock_max")?.as_str()?.to_string(),
        cumulative_seconds: v.get("cumulative_seconds")?.as_f64()?,
    })
}

fn entry_from_value(v: &Value) -> Option<LedgerEntry> {
    Some(LedgerEntry {
        seq: v.get("seq")?.as_i64()?,
        recorded_at: v.get("recorded_at")?.as_str()?.to_string(),
        wall_clock_max: v.get("wall_clock_max")?.as_str()?.to_string(),
        tick_monotonic_ms: v.get("tick_monotonic_ms")?.as_f64()?,
        cumulative_seconds: v.get("cumulative_seconds")?.as_f64()?,
        prev_hash: v.get("prev_hash")?.as_str()?.to_string(),
        entry_hash: v.get("entry_hash")?.as_str()?.to_string(),
        entry_hmac: v.get("entry_hmac")?.as_str()?.to_string(),
    })
}

/// 文件锁：create_new（Node 'wx'）自旋，50ms 间隔，10s 超时（心跳 60s 一次，竞争极少）。
fn with_lock<T>(dir: &Path, f: impl FnOnce() -> Result<T, String>) -> Result<T, String> {
    let lock_path = dir.join(LOCK_FILE);
    let deadline = Instant::now() + Duration::from_millis(10000);
    let file = loop {
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&lock_path)
        {
            Ok(fh) => break fh,
            Err(_) => {
                if Instant::now() > deadline {
                    return Err(format!("ledger lock timeout: {}", lock_path.display()));
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    };
    let result = f();
    drop(file);
    let _ = std::fs::remove_file(&lock_path);
    result
}

/// Windows 上 fs::rename 不覆盖已存在目标；Node renameSync 覆盖。对齐 Node 语义。
#[cfg(windows)]
fn rename_replace(from: &Path, to: &Path) -> std::io::Result<()> {
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
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(not(windows))]
fn rename_replace(from: &Path, to: &Path) -> std::io::Result<()> {
    std::fs::rename(from, to)
}

fn write_tip_atomic(dir: &Path, tip: &LedgerTip) -> Result<(), String> {
    let tmp = dir.join(format!(".ledger-tip.{}.tmp", std::process::id()));
    let content = pretty_json(&tip_value(tip)) + "\n";
    std::fs::write(&tmp, content).map_err(|e| format!("failed to write {}: {e}", tmp.display()))?;
    rename_replace(&tmp, &tip_path(dir)).map_err(|e| format!("failed to replace tip file: {e}"))
}

/// 追加账本条目：文件锁 + O_APPEND 追加 JSONL + 链尾原子替换（DESIGN §4.5）。
/// watermark：历史水印（只增不减）；wall_clock_max = max(now, watermark)。
pub fn append_ledger_entry(
    dir: &Path,
    key: &[u8; 32],
    tick_monotonic_ms: f64,
    now_iso: &str,
    watermark: Option<&str>,
) -> Result<(LedgerEntry, LedgerTip), String> {
    with_lock(dir, || {
        let prev_tip = load_ledger_tip(dir)?;
        let seq = prev_tip.as_ref().map(|t| t.seq).unwrap_or(0) + 1;
        let prev_hash = prev_tip
            .as_ref()
            .map(|t| t.entry_hash.clone())
            .unwrap_or_else(|| GENESIS_HASH.to_string());
        let cumulative = prev_tip
            .as_ref()
            .map(|t| t.cumulative_seconds)
            .unwrap_or(0.0)
            + tick_monotonic_ms / 1000.0;
        let wall_clock_max = match watermark {
            Some(w) if w > now_iso => w.to_string(),
            _ => now_iso.to_string(),
        };

        let mut entry = LedgerEntry {
            seq,
            recorded_at: now_iso.to_string(),
            wall_clock_max,
            tick_monotonic_ms,
            cumulative_seconds: cumulative,
            prev_hash,
            entry_hash: String::new(),
            entry_hmac: String::new(),
        };
        entry.entry_hash = compute_entry_hash(&entry);
        entry.entry_hmac = compute_entry_hmac(key, &entry.entry_hash);

        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(ledger_path(dir))
            .map_err(|e| format!("failed to open ledger: {e}"))?;
        file.write_all((compact_json(&entry_full_value(&entry)) + "\n").as_bytes())
            .map_err(|e| format!("failed to append ledger: {e}"))?;

        let tip = LedgerTip {
            seq: entry.seq,
            entry_hash: entry.entry_hash.clone(),
            wall_clock_max: entry.wall_clock_max.clone(),
            cumulative_seconds: entry.cumulative_seconds,
        };
        write_tip_atomic(dir, &tip)?;
        Ok((entry, tip))
    })
}

#[derive(Debug, Clone)]
pub struct ChainVerifyResult {
    pub ok: bool,
    pub reason: Option<String>,
}

/// 全链校验：逐条重算 entry_hash/entry_hmac 与 prev 链接，最终必须与链尾文件一致。
pub fn verify_ledger_chain(dir: &Path, key: &[u8; 32]) -> Result<ChainVerifyResult, String> {
    let file = ledger_path(dir);
    let tip = load_ledger_tip(dir)?;
    if !file.exists() {
        return Ok(if tip.is_none() {
            ChainVerifyResult {
                ok: true,
                reason: None,
            }
        } else {
            ChainVerifyResult {
                ok: false,
                reason: Some("ledger.jsonl missing but tip exists".to_string()),
            }
        });
    }
    let content =
        std::fs::read_to_string(&file).map_err(|e| format!("failed to read ledger: {e}"))?;
    let lines: Vec<&str> = content
        .split('\n')
        .filter(|l| !l.trim().is_empty())
        .collect();
    let mut prev_hash = GENESIS_HASH.to_string();
    let mut last: Option<LedgerEntry> = None;
    for (idx, line) in lines.iter().enumerate() {
        let v: Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(_) => {
                return Ok(ChainVerifyResult {
                    ok: false,
                    reason: Some(format!("line {}: invalid JSON", idx + 1)),
                })
            }
        };
        let entry = match entry_from_value(&v) {
            Some(e) => e,
            None => {
                return Ok(ChainVerifyResult {
                    ok: false,
                    reason: Some(format!("line {}: invalid JSON", idx + 1)),
                })
            }
        };
        if entry.seq != idx as i64 + 1 {
            return Ok(ChainVerifyResult {
                ok: false,
                reason: Some(format!("line {}: seq mismatch", idx + 1)),
            });
        }
        if entry.prev_hash != prev_hash {
            return Ok(ChainVerifyResult {
                ok: false,
                reason: Some(format!("line {}: prev_hash broken", idx + 1)),
            });
        }
        let recomputed = compute_entry_hash(&entry);
        if recomputed != entry.entry_hash {
            return Ok(ChainVerifyResult {
                ok: false,
                reason: Some(format!("line {}: entry_hash mismatch", idx + 1)),
            });
        }
        if compute_entry_hmac(key, &entry.entry_hash) != entry.entry_hmac {
            return Ok(ChainVerifyResult {
                ok: false,
                reason: Some(format!("line {}: entry_hmac mismatch", idx + 1)),
            });
        }
        prev_hash = entry.entry_hash.clone();
        last = Some(entry);
    }
    match (&tip, &last) {
        (None, None) => Ok(ChainVerifyResult {
            ok: true,
            reason: None,
        }),
        (None, Some(_)) => Ok(ChainVerifyResult {
            ok: false,
            reason: Some("tip missing but ledger has entries".to_string()),
        }),
        (Some(_), None) => Ok(ChainVerifyResult {
            ok: false,
            reason: Some("tip exists but ledger empty".to_string()),
        }),
        (Some(t), Some(l)) => {
            if t.seq != l.seq
                || t.entry_hash != l.entry_hash
                || t.wall_clock_max != l.wall_clock_max
                || t.cumulative_seconds != l.cumulative_seconds
            {
                Ok(ChainVerifyResult {
                    ok: false,
                    reason: Some("tip does not match ledger tail".to_string()),
                })
            } else {
                Ok(ChainVerifyResult {
                    ok: true,
                    reason: None,
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(tag: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("agentos-ledger-rs-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn hkdf_matches_rfc5869_shape() {
        // 只断言确定性 + 32 字节；与 Node hkdfSync 的互操作由端到端交叉验证覆盖。
        let a = derive_ledger_key("sigA", "fpA");
        let b = derive_ledger_key("sigA", "fpA");
        let c = derive_ledger_key("sigA", "fpB");
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn append_and_verify_roundtrip() {
        let dir = temp_dir("roundtrip");
        let key = derive_ledger_key("sig", "fp");
        let (_e1, t1) =
            append_ledger_entry(&dir, &key, 60000.0, "2026-11-15T00:00:00.000Z", None).unwrap();
        assert_eq!(t1.seq, 1);
        assert_eq!(t1.cumulative_seconds, 60.0);
        let (_e2, t2) = append_ledger_entry(
            &dir,
            &key,
            1500.0,
            "2026-11-15T00:01:00.000Z",
            Some(&t1.wall_clock_max),
        )
        .unwrap();
        assert_eq!(t2.seq, 2);
        assert_eq!(t2.cumulative_seconds, 61.5);
        assert!(verify_ledger_chain(&dir, &key).unwrap().ok);
        // 错误密钥 → hmac 校验失败
        let bad = derive_ledger_key("sig2", "fp");
        assert!(!verify_ledger_chain(&dir, &bad).unwrap().ok);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn tampered_line_breaks_chain() {
        let dir = temp_dir("tamper");
        let key = derive_ledger_key("sig", "fp");
        append_ledger_entry(&dir, &key, 60000.0, "2026-11-15T00:00:00.000Z", None).unwrap();
        // 篡改 cumulative_seconds
        let path = ledger_path(&dir);
        let content = std::fs::read_to_string(&path).unwrap();
        let mut v: Value = serde_json::from_str(content.trim()).unwrap();
        v["cumulative_seconds"] = Value::Number(serde_json::Number::from(1));
        std::fs::write(&path, compact_json(&v) + "\n").unwrap();
        let r = verify_ledger_chain(&dir, &key).unwrap();
        assert!(!r.ok);
        assert!(r.reason.unwrap().contains("entry_hash mismatch"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn jsonl_line_format_is_compact_ordered() {
        let dir = temp_dir("format");
        let key = derive_ledger_key("sig", "fp");
        append_ledger_entry(&dir, &key, 60000.0, "2026-11-15T00:00:00.000Z", None).unwrap();
        let content = std::fs::read_to_string(ledger_path(&dir)).unwrap();
        let line = content.trim_end();
        assert!(line.starts_with("{\"seq\":1,\"recorded_at\":\"2026-11-15T00:00:00.000Z\",\"wall_clock_max\":\"2026-11-15T00:00:00.000Z\",\"tick_monotonic_ms\":60000,\"cumulative_seconds\":60,\"prev_hash\":\"sha256:0000000000000000000000000000000000000000000000000000000000000000\",\"entry_hash\":\"sha256:"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn non_tidy_float_cumulative_still_verifies() {
        // 现场回归：supervisor 传实测间隔（62390ms、60005ms），第二次心跳后 cumulative
        // 会落在 122.39500000000001 这类非整洁浮点；写入后 status/verify 不得自判篡改。
        let dir = temp_dir("float-cumulative");
        let key = derive_ledger_key("sig", "fp");
        let (_e1, t1) =
            append_ledger_entry(&dir, &key, 62390.0, "2026-11-15T00:00:00.000Z", None).unwrap();
        assert_eq!(t1.cumulative_seconds, 62.39);
        let (_e2, t2) = append_ledger_entry(
            &dir,
            &key,
            60005.0,
            "2026-11-15T00:01:02.390Z",
            Some(&t1.wall_clock_max),
        )
        .unwrap();
        assert_eq!(t2.cumulative_seconds, 122.39500000000001);
        let result = verify_ledger_chain(&dir, &key).unwrap();
        assert!(result.ok, "ledger should verify, got: {:?}", result.reason);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
