//! 对应 tools/license-checker/src/cli.ts：
//! agentos-license-checker — 现场无状态 license 校验程序（stdio 通道，spawn-per-call）。
//! 退出码：0=valid / 2=expired / 3=tampered / 4=unlicensed / 5=clock_rollback /
//! 6=fingerprint_mismatch / 1=用法错误、PG 账本故障或其他未分类错误。

mod checker;
mod ledger;
mod pg_ledger;

use checker::{run_heartbeat, run_status, CheckerContext};
use license_core::error::{AgentosError, AgentosResult};
use license_core::fingerprint::SystemProbeSource;
use license_core::jsonfmt::compact_json;
use license_core::key_policy::{public_key_metadata, PublicKeyMetadata};
use pg_ledger::PgLedgerSink;
use std::io::Write;
use std::path::PathBuf;

const USAGE: &str = "agentos-license-checker — 现场无状态 license 校验程序（stdio 通道，spawn-per-call）

Usage:
  agentos-license-checker status    --state-dir <dir> --public-key-file <pem|metadata.json> [--kid <kid>] [--instance-id <id>]
  agentos-license-checker heartbeat --tick-monotonic-ms <n> （其余参数同上）

stdout: 校验通过时输出 {\"status\":\"valid\",\"licenseId\":...,\"runtimeRemainingSeconds\":...,\"ledgerTipHash\":\"...\"}
stderr: 人类可读诊断（脱敏）
退出码: 0=valid / 2=expired / 3=tampered / 4=unlicensed / 5=clock_rollback / 6=fingerprint_mismatch
环境变量: AGENTOS_LICENSE_PG_URL 设置后心跳双写 PG 账本并做链尾交叉验证（PG 故障→退出码 1，走宽限）
";

fn read_arg<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .map(String::as_str)
}

fn load_public_key(file: &str, kid_arg: Option<&str>) -> AgentosResult<PublicKeyMetadata> {
    let text = std::fs::read_to_string(file)
        .map_err(|e| AgentosError::new("ERR_USAGE", &format!("cannot read public key file {file}: {e}")))?;
    let text = text.trim();
    if text.starts_with('{') {
        let meta: serde_json::Value = serde_json::from_str(text)
            .map_err(|e| AgentosError::new("ERR_USAGE", &format!("invalid public-key metadata JSON: {e}")))?;
        let kid = meta.get("kid").and_then(serde_json::Value::as_str);
        let pem = meta.get("publicKeyPem").and_then(serde_json::Value::as_str);
        match (kid, pem) {
            (Some(k), Some(p)) => public_key_metadata(k, p),
            _ => Err(AgentosError::new(
                "ERR_USAGE",
                "public-key metadata JSON must contain kid and publicKeyPem.",
            )),
        }
    } else {
        match kid_arg {
            Some(k) => public_key_metadata(k, text),
            None => Err(AgentosError::new(
                "ERR_USAGE",
                "--kid is required when --public-key-file is a bare PEM.",
            )),
        }
    }
}

/// JS Number(str) 的近似：trim 后空串为 0，其余按十进制浮点解析（失败即 NaN）。
fn js_number(s: &str) -> f64 {
    let t = s.trim();
    if t.is_empty() {
        return 0.0;
    }
    t.parse::<f64>().unwrap_or(f64::NAN)
}

fn run(argv: &[String]) -> AgentosResult<i32> {
    let (command, rest) = match argv.split_first() {
        Some((c, r)) => (c.as_str(), r),
        None => ("", &[][..]),
    };
    if command != "status" && command != "heartbeat" {
        std::io::stderr().write_all(USAGE.as_bytes()).ok();
        return Ok(if command == "--help" || command == "-h" { 0 } else { 1 });
    }
    let state_dir = read_arg(rest, "--state-dir");
    let public_key_file = read_arg(rest, "--public-key-file");
    let (state_dir, public_key_file) = match (state_dir, public_key_file) {
        (Some(s), Some(p)) => (s, p),
        _ => {
            return Err(AgentosError::new(
                "ERR_USAGE",
                "requires --state-dir and --public-key-file.",
            ))
        }
    };

    let public_key = load_public_key(public_key_file, read_arg(rest, "--kid"))?;

    // AGENTOS_LICENSE_PG_URL 设置后心跳双写 PG 账本并做链尾交叉验证。
    let mut pg_sink = match std::env::var("AGENTOS_LICENSE_PG_URL") {
        Ok(url) if !url.is_empty() => Some(PgLedgerSink::connect(&url)?),
        _ => None,
    };

    let probe = SystemProbeSource::new();
    let mut ctx = CheckerContext {
        state_dir: PathBuf::from(state_dir),
        public_key: &public_key,
        probe: &probe,
        instance_id: read_arg(rest, "--instance-id"),
        now_ms: None,
        pg_sink: pg_sink.as_mut(),
    };

    let result = if command == "heartbeat" {
        let tick = match read_arg(rest, "--tick-monotonic-ms") {
            Some(s) => js_number(s),
            None => f64::NAN,
        };
        if !tick.is_finite() || tick < 0.0 {
            return Err(AgentosError::new(
                "ERR_USAGE",
                "heartbeat requires --tick-monotonic-ms <non-negative number>.",
            ));
        }
        run_heartbeat(&mut ctx, tick)?
    } else {
        run_status(&mut ctx)?
    };

    if result.exit_code == 0 {
        if let Some(payload) = &result.payload {
            println!("{}", compact_json(payload));
        }
    } else {
        eprintln!("[license-checker] exit={} {}", result.exit_code, result.diagnostics);
    }
    Ok(result.exit_code)
}

fn main() {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    match run(&argv) {
        Ok(code) => std::process::exit(code),
        Err(err) => {
            eprintln!("[{}] {}", err.code, err.message);
            std::process::exit(1);
        }
    }
}
