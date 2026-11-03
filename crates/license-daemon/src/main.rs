//! 对应 tools/license-daemon/src/cli.ts 全文：
//! agentos-license-daemon CLI（serve 子命令）：加载公钥 → 采集指纹 → 起 HTTP 页面服务。
//! USAGE 文案、启动日志、错误输出格式与 TS 版逐字节一致。

mod activation;
mod http;

use license_core::error::AgentosError;
use license_core::fingerprint::{collect_fingerprint, SystemProbeSource};
use license_core::key_policy::{public_key_metadata, PublicKeyMetadata};
use serde_json::Value;
use std::error::Error;
use std::path::PathBuf;

/// 对应 cli.ts:9-17 USAGE，逐字节（含末尾换行）。
const USAGE: &str = r#"agentos-license-daemon — 现场宿主机 license 服务（HTTP 页面：指纹采集展示 + 上传激活）

Usage:
  agentos-license-daemon serve --state-dir <dir> --public-key-file <pem|metadata.json>
    [--port <n>]            默认 8471
    [--bind <addr>]         默认 127.0.0.1
    [--instance-id <id>]    AgentOS 部署实例 ID（可选分量 c5）
    [--kid <kid>]           public-key-file 为纯 PEM 时必须显式给定 kid
"#;

/// 对应 cli.ts:19-22 readArg：首次出现优先；flag 在末尾无值 → None。
fn read_arg<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .map(|s| s.as_str())
}

/// 对应 cli.ts:24-38 loadPublicKey。
/// 文件读失败 / metadata JSON 语法错在 TS 中是非 AgentosError 直接抛出，
/// Rust 归为非 AgentosError 路径（打印 + exit 1），不要求字节一致。
fn load_public_key(
    file: &str,
    kid_arg: Option<&str>,
) -> Result<PublicKeyMetadata, Box<dyn Error + Send + Sync>> {
    let text = std::fs::read_to_string(file)?;
    let trimmed = text.trim();
    if trimmed.starts_with('{') {
        let meta: Value = serde_json::from_str(trimmed)?;
        // TS `!meta.kid || !meta.publicKeyPem`：要求均为非空字符串。
        let kid = meta
            .get("kid")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty());
        let pem = meta
            .get("publicKeyPem")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty());
        return match (kid, pem) {
            // metadata 分支 publicKeyPem 不 trim。
            (Some(kid), Some(pem)) => Ok(public_key_metadata(kid, pem)?),
            _ => Err(Box::new(AgentosError::new(
                "ERR_USAGE",
                "public-key metadata JSON must contain kid and publicKeyPem.",
            ))),
        };
    }
    match kid_arg.filter(|s| !s.is_empty()) {
        None => Err(Box::new(AgentosError::new(
            "ERR_USAGE",
            "--kid is required when --public-key-file is a bare PEM.",
        ))),
        // 纯 PEM 分支用 trim 后全文。
        Some(kid) => Ok(public_key_metadata(kid, trimmed)?),
    }
}

fn main() {
    std::process::exit(run_cli());
}

/// 对应 cli.ts:68-77 顶层错误处理：AgentosError → stderr `[code] message` exit 1；
/// 其它错误 TS 是 rethrow 打栈，Rust 只能近似（打印 + exit 1）。
fn run_cli() -> i32 {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    match run(&argv) {
        Ok(code) => code,
        Err(e) => {
            if let Some(ae) = e.downcast_ref::<AgentosError>() {
                eprintln!("[{}] {}", ae.code, ae.message);
            } else {
                eprintln!("{e}");
            }
            1
        }
    }
}

/// 对应 cli.ts:40-66 runDaemonCli。
fn run(argv: &[String]) -> Result<i32, Box<dyn Error + Send + Sync>> {
    let command = argv.first().map(|s| s.as_str());
    if command != Some("serve") {
        eprint!("{USAGE}");
        return Ok(if command == Some("--help") || command == Some("-h") {
            0
        } else {
            1
        });
    }
    let rest = &argv[1..];
    // TS `!stateDir || !publicKeyFile`：缺失或空串都算缺参。
    let state_dir = read_arg(rest, "--state-dir").filter(|s| !s.is_empty());
    let public_key_file = read_arg(rest, "--public-key-file").filter(|s| !s.is_empty());
    let (state_dir, public_key_file) = match (state_dir, public_key_file) {
        (Some(s), Some(p)) => (s.to_string(), p.to_string()),
        _ => {
            return Err(Box::new(AgentosError::new(
                "ERR_USAGE",
                "serve requires --state-dir and --public-key-file.",
            )))
        }
    };
    // 偏差说明：TS 对非法 --port 得 NaN → listen(NaN) 抛非 AgentosError（Node 打栈退出 1），
    // 无法逐字节复刻；Rust 解析失败打印错误 exit 1。
    let port: u16 = match read_arg(rest, "--port") {
        Some(p) => p
            .parse::<u16>()
            .map_err(|_| format!("invalid --port value: {p}"))?,
        None => 8471,
    };
    let bind = read_arg(rest, "--bind").unwrap_or("127.0.0.1").to_string();
    let instance_id = read_arg(rest, "--instance-id");
    let public_key = load_public_key(&public_key_file, read_arg(rest, "--kid"))?;

    let fingerprint = collect_fingerprint(&SystemProbeSource::new(), instance_id);
    let anchor_available = fingerprint.anchor_available;
    let anchor = if anchor_available {
        "ok"
    } else {
        "MISSING(c1)"
    };

    let bind_log = bind.clone();
    let state_dir_log = state_dir.clone();
    http::serve(
        http::DaemonContext {
            fingerprint,
            state_dir: PathBuf::from(&state_dir),
            public_key,
        },
        &bind,
        port,
        move || {
            println!(
                "[license-daemon] serving http://{bind_log}:{port} stateDir={state_dir_log} anchor={anchor}"
            );
            if !anchor_available {
                eprintln!(
                    "[license-daemon] WARN: required anchor c1 unavailable; page will show guidance."
                );
            }
        },
    )?;
    Ok(0)
}
