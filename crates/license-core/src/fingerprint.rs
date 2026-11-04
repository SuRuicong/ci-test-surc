//! 对应 tools/license-daemon/src/core/fingerprint-collect.ts + system-probe.ts。
//! 采集机器指纹（DESIGN.md §2.1）：只读固有标识；探测不到标记 'unavailable'，
//! 绝不随机生成替代；必选锚点 machine-id 缺失时 anchorAvailable=false。

use crate::constants::{to_codename, COMPONENT_ORDER, FINGERPRINT_SCHEMA, REQUIRED_ANCHOR_NAME};
use crate::jsonfmt::object_in_order;
use regex::Regex;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::sync::OnceLock;

pub fn sha256_hex(data: &str) -> String {
    let digest = Sha256::digest(data.as_bytes());
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

fn norm(value: &str) -> String {
    // trim_matches('\u{feff}') 对齐 JS String.trim()（JS 会把 BOM 当空白去除，Rust 不会），
    // 保证双实现对同一输入产出同一字符串（现实中 systemd/注册表/IOKit 均不会写出 BOM）。
    value.trim_matches('\u{feff}').trim().to_lowercase()
}

/// trim 后为空按缺失计：不对空串做哈希（sha256('') 是公开常量，会把多台机器的锚点撞成同一个值）。
fn nonempty_norm(s: &str) -> Option<String> {
    if s.trim().is_empty() {
        None
    } else {
        Some(norm(s))
    }
}

/// 探测源抽象：真实环境由 SystemProbeSource 提供，测试注入假数据。
pub trait ProbeSource {
    /// "win32" | "linux" | "darwin"（Node process.platform 语义）
    fn platform(&self) -> &'static str;
    /// 读文件，不存在/不可读返回 None。
    fn read_file(&self, path: &str) -> Option<String>;
    /// 执行只读探测命令，失败/不可用返回 None。
    fn exec(&self, file: &str, args: &[&str]) -> Option<String>;
}

#[derive(Debug, Clone)]
pub struct CollectedFingerprint {
    pub platform: String,
    /// 分量名 → 'sha256:<64hex>' 或 'unavailable'；键序固定为探测插入序。
    pub components: Vec<(String, String)>,
    /// 完整指纹 sha256:<64hex>（固定序拼接的 SHA-256）。
    pub fingerprint: String,
    /// 必选锚点 machine-id 是否可用。
    pub anchor_available: bool,
}

impl CollectedFingerprint {
    pub fn component(&self, name: &str) -> Option<&str> {
        self.components
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }
}

/// /proc/cpuinfo → `${model}|${逻辑核数}`（规范化小写）。
/// ARM 回退：`model name` 缺失时（典型于 ARM64）用 `CPU implementer/part/variant/revision`
/// 组成 `arm {impl}/{part}/{variant}/{revision}`（缺失段填 '-'）；implementer 与 part 均缺 → None。
/// x86 取值路径逐字节不变。
pub fn parse_linux_cpu_info(raw: &str) -> Option<String> {
    let mut model: Option<String> = None;
    let mut implementer: Option<String> = None;
    let mut part: Option<String> = None;
    let mut variant: Option<String> = None;
    let mut revision: Option<String> = None;
    let mut cores = 0u32;
    for line in raw.split('\n') {
        if Regex::new(r"^processor\s*:\s*[0-9]+")
            .unwrap()
            .is_match(line)
        {
            cores += 1;
        }
        if model.is_none() {
            if let Some(caps) = Regex::new(r"^model name\s*:\s*(.+)$")
                .unwrap()
                .captures(line)
            {
                model = Some(caps.get(1).unwrap().as_str().trim().to_string());
            }
        }
        if implementer.is_none() {
            if let Some(caps) = Regex::new(r"^CPU implementer\s*:\s*(.+)$")
                .unwrap()
                .captures(line)
            {
                implementer = Some(caps.get(1).unwrap().as_str().trim().to_string());
            }
        }
        if part.is_none() {
            if let Some(caps) = Regex::new(r"^CPU part\s*:\s*(.+)$").unwrap().captures(line) {
                part = Some(caps.get(1).unwrap().as_str().trim().to_string());
            }
        }
        if variant.is_none() {
            if let Some(caps) = Regex::new(r"^CPU variant\s*:\s*(.+)$")
                .unwrap()
                .captures(line)
            {
                variant = Some(caps.get(1).unwrap().as_str().trim().to_string());
            }
        }
        if revision.is_none() {
            if let Some(caps) = Regex::new(r"^CPU revision\s*:\s*(.+)$")
                .unwrap()
                .captures(line)
            {
                revision = Some(caps.get(1).unwrap().as_str().trim().to_string());
            }
        }
    }
    if cores == 0 {
        return None;
    }
    let model = match model {
        Some(m) => m,
        None => {
            if implementer.is_none() && part.is_none() {
                return None;
            }
            format!(
                "arm {}/{}/{}/{}",
                implementer.as_deref().unwrap_or("-"),
                part.as_deref().unwrap_or("-"),
                variant.as_deref().unwrap_or("-"),
                revision.as_deref().unwrap_or("-")
            )
        }
    };
    Some(format!("{model}|{cores}").to_lowercase())
}

fn machine_guid_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)MachineGuid\s+REG_SZ\s+(\S+)").unwrap())
}

/// reg query 输出中提取 MachineGuid 值。
pub fn parse_machine_guid_reg_output(raw: &str) -> Option<String> {
    machine_guid_re()
        .captures(raw)
        .map(|c| c.get(1).unwrap().as_str().to_string())
}

fn hashed_component(value: Option<&str>, transform: fn(&str) -> Option<String>) -> String {
    match value.and_then(transform) {
        Some(v) => format!("sha256:{}", sha256_hex(&v)),
        None => "unavailable".to_string(),
    }
}

fn probe_linux(source: &dyn ProbeSource) -> Vec<(String, String)> {
    vec![
        (
            REQUIRED_ANCHOR_NAME.to_string(),
            hashed_component(
                source.read_file("/etc/machine-id").as_deref(),
                nonempty_norm,
            ),
        ),
        (
            "dmi-product-uuid".to_string(),
            hashed_component(
                source
                    .read_file("/sys/class/dmi/id/product_uuid")
                    .as_deref(),
                nonempty_norm,
            ),
        ),
        (
            "dmi-product-serial".to_string(),
            hashed_component(
                source
                    .read_file("/sys/class/dmi/id/product_serial")
                    .as_deref(),
                nonempty_norm,
            ),
        ),
        (
            "cpu".to_string(),
            hashed_component(
                source.read_file("/proc/cpuinfo").as_deref(),
                parse_linux_cpu_info,
            ),
        ),
    ]
}

fn probe_windows(source: &dyn ProbeSource) -> Vec<(String, String)> {
    let reg_out = source.exec(
        "reg",
        &[
            "query",
            "HKLM\\SOFTWARE\\Microsoft\\Cryptography",
            "/v",
            "MachineGuid",
        ],
    );
    let guid = reg_out.as_deref().and_then(parse_machine_guid_reg_output);

    let uuid = source.exec(
        "powershell",
        &[
            "-NoProfile",
            "-Command",
            "(Get-CimInstance Win32_ComputerSystemProduct).UUID",
        ],
    );
    let serial = source.exec(
        "powershell",
        &[
            "-NoProfile",
            "-Command",
            "(Get-CimInstance Win32_BIOS).SerialNumber",
        ],
    );
    let cpu = source.exec(
        "powershell",
        &[
            "-NoProfile",
            "-Command",
            "$p=Get-CimInstance Win32_Processor; \"$(($p | Select-Object -First 1).Name)|$(@($p).Count)\"",
        ],
    );

    // TS 语义：exec 结果 trim 后为空串按 unavailable 计（norm('') → sha256('') 不会发生，
    // 因为 TS 里 uuid && uuid.trim() 条件把空串排除了）。
    fn nonempty_norm(s: &str) -> Option<String> {
        if s.trim().is_empty() {
            None
        } else {
            Some(norm(s))
        }
    }

    vec![
        (
            REQUIRED_ANCHOR_NAME.to_string(),
            hashed_component(guid.as_deref(), nonempty_norm),
        ),
        (
            "dmi-product-uuid".to_string(),
            hashed_component(uuid.as_deref(), nonempty_norm),
        ),
        (
            "dmi-product-serial".to_string(),
            hashed_component(serial.as_deref(), nonempty_norm),
        ),
        (
            "cpu".to_string(),
            hashed_component(cpu.as_deref(), nonempty_norm),
        ),
    ]
}

/// macOS 使用平台 UUID 作为必选锚点，序列号作为可选分量。
/// 不复制同一硬件值到多个分量，也不在采集失败时生成替代标识。
fn probe_macos(source: &dyn ProbeSource) -> Vec<(String, String)> {
    let output = source.exec("/usr/sbin/ioreg", &["-rd1", "-c", "IOPlatformExpertDevice"]);
    let property = |name: &str| -> Option<String> {
        let pattern = format!(r#"(?m)^\s*"{}"\s*=\s*"([^"]*)"\s*$"#, regex::escape(name));
        let re = Regex::new(&pattern).ok()?;
        let value = re.captures(output.as_deref()?)?.get(1)?.as_str().trim();
        if value.is_empty() {
            None
        } else {
            Some(norm(value))
        }
    };
    let uuid = property("IOPlatformUUID").filter(|value| {
        static UUID_RE: OnceLock<Regex> = OnceLock::new();
        UUID_RE
            .get_or_init(|| {
                Regex::new(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
                    .unwrap()
            })
            .is_match(value)
            && value != "00000000-0000-0000-0000-000000000000"
    });
    let serial = property("IOPlatformSerialNumber");
    vec![
        (
            REQUIRED_ANCHOR_NAME.to_string(),
            hashed_component(uuid.as_deref(), |s| Some(s.to_string())),
        ),
        ("dmi-product-uuid".to_string(), "unavailable".to_string()),
        (
            "dmi-product-serial".to_string(),
            hashed_component(serial.as_deref(), |s| Some(s.to_string())),
        ),
        ("cpu".to_string(), "unavailable".to_string()),
    ]
}

/// 采集机器指纹：固定序拼接 canonical 文本后取 SHA-256。
pub fn collect_fingerprint(
    source: &dyn ProbeSource,
    instance_id: Option<&str>,
) -> CollectedFingerprint {
    let mut components = match source.platform() {
        "win32" => probe_windows(source),
        "darwin" => probe_macos(source),
        _ => probe_linux(source),
    };
    components.push((
        "agentos-instance-id".to_string(),
        match instance_id.and_then(nonempty_norm) {
            Some(id) => format!("sha256:{}", sha256_hex(&id)),
            None => "unavailable".to_string(),
        },
    ));

    let canonical = COMPONENT_ORDER
        .iter()
        .map(|name| {
            let value = components
                .iter()
                .find(|(k, _)| k == name)
                .map(|(_, v)| v.clone())
                .unwrap_or_else(|| "unavailable".to_string());
            format!("{name}={value}")
        })
        .collect::<Vec<_>>()
        .join("\n");

    let anchor_available = components
        .iter()
        .find(|(k, _)| k == REQUIRED_ANCHOR_NAME)
        .map(|(_, v)| v != "unavailable")
        .unwrap_or(false);

    CollectedFingerprint {
        platform: source.platform().to_string(),
        components,
        fingerprint: format!("sha256:{}", sha256_hex(&canonical)),
        anchor_available,
    }
}

/// 生成可抄送/下载给供应商的指纹文件（只含哈希，不含原始硬件值）。
/// wire 边界（codename-spec §3.1）：components 键为代号 c1..c5，值与槽位顺序不变。
pub fn build_fingerprint_file(fp: &CollectedFingerprint) -> Value {
    let components = Value::Object(
        fp.components
            .iter()
            .map(|(k, v)| (to_codename(k).to_string(), Value::String(v.clone())))
            .collect(),
    );
    object_in_order(vec![
        ("schema", Value::String(FINGERPRINT_SCHEMA.to_string())),
        ("fingerprint", Value::String(fp.fingerprint.clone())),
        ("components", components),
    ])
}

/// 分组展示格式：64 位大写 hex，每 4 字符一组连字符分隔（XXXX-XXXX-…）。
pub fn format_fingerprint_groups(fingerprint: &str) -> String {
    let hex = fingerprint
        .strip_prefix("sha256:")
        .unwrap_or(fingerprint)
        .to_uppercase();
    let mut out = String::new();
    for (i, ch) in hex.chars().enumerate() {
        if i > 0 && i % 4 == 0 {
            out.push('-');
        }
        out.push(ch);
    }
    out
}

/// 真实宿主机探测源：Linux 直读系统文件；Windows reg/CIM；macOS ioreg。
/// 所有探测都是只读；任何失败返回 None，由采集层标记 unavailable。
pub struct SystemProbeSource;

impl SystemProbeSource {
    pub fn new() -> Self {
        SystemProbeSource
    }
}

impl ProbeSource for SystemProbeSource {
    fn platform(&self) -> &'static str {
        if cfg!(windows) {
            "win32"
        } else if cfg!(target_os = "macos") {
            "darwin"
        } else {
            "linux"
        }
    }

    fn read_file(&self, path: &str) -> Option<String> {
        std::fs::read_to_string(path).ok()
    }

    fn exec(&self, file: &str, args: &[&str]) -> Option<String> {
        use std::io::Read;
        use std::process::{Command, Stdio};
        use wait_timeout::ChildExt;

        let mut command = Command::new(file);
        command
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        // windowsHide: 不弹控制台窗口
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            const CREATE_NO_WINDOW: u32 = 0x0800_0000;
            command.creation_flags(CREATE_NO_WINDOW);
        }
        let mut child = command.spawn().ok()?;
        let timeout = std::time::Duration::from_secs(15);
        let status = match child.wait_timeout(timeout).ok()? {
            Some(s) => s,
            None => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        };
        if !status.success() {
            return None;
        }
        let mut buf = Vec::new();
        child.stdout.take()?.read_to_end(&mut buf).ok()?;
        // Node spawnSync({encoding:'utf8'})：非法 UTF-8 以替换字符兜底（lossy 等价）。
        Some(String::from_utf8_lossy(&buf).into_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    const LINUX_MACHINE_ID_RAW: &str = "ABCDEF0123456789ABCDEF0123456789\n";
    const LINUX_MACHINE_ID_NORM: &str = "abcdef0123456789abcdef0123456789";
    const LINUX_UUID_RAW: &str = "4C4C4544-0038-4410-805A-CAC04F385732\n";
    const LINUX_UUID_NORM: &str = "4c4c4544-0038-4410-805a-cac04f385732";
    const LINUX_SERIAL_RAW: &str = "SN-TEST-0001\n";
    const LINUX_SERIAL_NORM: &str = "sn-test-0001";
    const LINUX_CPUINFO: &str = "processor\t: 0\nmodel name\t: Intel(R) Xeon(R) Gold 6248 CPU @ 2.50GHz\nprocessor\t: 1\nmodel name\t: Intel(R) Xeon(R) Gold 6248 CPU @ 2.50GHz\n";
    const LINUX_CPU_NORM: &str = "intel(r) xeon(r) gold 6248 cpu @ 2.50ghz|2";
    const WIN_GUID_RAW: &str = "A1B2C3D4-E5F6-7890-ABCD-EF0123456789";
    const WIN_GUID_NORM: &str = "a1b2c3d4-e5f6-7890-abcd-ef0123456789";

    struct FakeSource {
        platform: &'static str,
        files: HashMap<String, String>,
        machine_guid: Option<String>,
        wmi: HashMap<String, String>,
    }

    impl ProbeSource for FakeSource {
        fn platform(&self) -> &'static str {
            self.platform
        }
        fn read_file(&self, path: &str) -> Option<String> {
            self.files.get(path).cloned()
        }
        fn exec(&self, file: &str, args: &[&str]) -> Option<String> {
            let joined = args.join(" ");
            if file == "/usr/sbin/ioreg" && args == ["-rd1", "-c", "IOPlatformExpertDevice"] {
                return self.wmi.get("ioreg").cloned();
            }
            if file == "reg" && joined.contains("MachineGuid") {
                return self.machine_guid.as_ref().map(|g| {
                    format!("\r\nHKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Cryptography\r\n    MachineGuid    REG_SZ    {g}\r\n\r\n")
                });
            }
            if file == "powershell" {
                for (marker, value) in &self.wmi {
                    if joined.contains(marker) {
                        return Some(format!("{value}\r\n"));
                    }
                }
            }
            None
        }
    }

    #[test]
    fn macos_uses_platform_uuid_as_anchor_and_serial_as_optional_component() {
        let source = FakeSource {
            platform: "darwin",
            files: HashMap::new(),
            machine_guid: None,
            wmi: HashMap::from([("ioreg".into(), "    \"IOPlatformUUID\" = \"A1B2C3D4-E5F6-7890-ABCD-EF0123456789\"\n    \"IOPlatformSerialNumber\" = \"Serial-123\"\n".into())]),
        };
        let a = collect_fingerprint(&source, Some("inst-abc"));
        let b = collect_fingerprint(&source, Some("inst-abc"));
        assert!(a.anchor_available);
        assert_eq!(
            a.component("machine-id"),
            Some(format!("sha256:{}", sha256_hex(WIN_GUID_NORM)).as_str())
        );
        assert_eq!(
            a.component("dmi-product-serial"),
            Some(format!("sha256:{}", sha256_hex("serial-123")).as_str())
        );
        assert_eq!(a.component("dmi-product-uuid"), Some("unavailable"));
        assert_eq!(a.component("cpu"), Some("unavailable"));
        assert_eq!(a.fingerprint, b.fingerprint);
        let text = crate::jsonfmt::compact_json(&build_fingerprint_file(&a));
        assert!(!text.contains("A1B2C3D4"));
        assert!(!text.contains("Serial-123"));
    }

    #[test]
    fn macos_missing_or_invalid_uuid_cannot_be_an_anchor() {
        for uuid in [
            None,
            Some(""),
            Some("garbage"),
            Some("00000000-0000-0000-0000-000000000000"),
        ] {
            let mut wmi = HashMap::new();
            if let Some(uuid) = uuid {
                wmi.insert("ioreg".into(), format!("\"IOPlatformUUID\" = \"{uuid}\"\n"));
            }
            let source = FakeSource {
                platform: "darwin",
                files: HashMap::new(),
                machine_guid: None,
                wmi,
            };
            let fp = collect_fingerprint(&source, None);
            assert!(!fp.anchor_available, "invalid UUID accepted: {uuid:?}");
            assert_eq!(fp.component("machine-id"), Some("unavailable"));
        }
    }

    fn full_linux_source() -> FakeSource {
        FakeSource {
            platform: "linux",
            files: HashMap::from([
                (
                    "/etc/machine-id".to_string(),
                    LINUX_MACHINE_ID_RAW.to_string(),
                ),
                (
                    "/sys/class/dmi/id/product_uuid".to_string(),
                    LINUX_UUID_RAW.to_string(),
                ),
                (
                    "/sys/class/dmi/id/product_serial".to_string(),
                    LINUX_SERIAL_RAW.to_string(),
                ),
                ("/proc/cpuinfo".to_string(), LINUX_CPUINFO.to_string()),
            ]),
            machine_guid: None,
            wmi: HashMap::new(),
        }
    }

    #[test]
    fn linux_full_components_normalized_hashes() {
        let fp = collect_fingerprint(&full_linux_source(), Some("inst-abc-123"));
        assert_eq!(
            fp.component("machine-id"),
            Some(format!("sha256:{}", sha256_hex(LINUX_MACHINE_ID_NORM)).as_str())
        );
        assert_eq!(
            fp.component("dmi-product-uuid"),
            Some(format!("sha256:{}", sha256_hex(LINUX_UUID_NORM)).as_str())
        );
        assert_eq!(
            fp.component("dmi-product-serial"),
            Some(format!("sha256:{}", sha256_hex(LINUX_SERIAL_NORM)).as_str())
        );
        assert_eq!(
            fp.component("cpu"),
            Some(format!("sha256:{}", sha256_hex(LINUX_CPU_NORM)).as_str())
        );
        assert_eq!(
            fp.component("agentos-instance-id"),
            Some(format!("sha256:{}", sha256_hex("inst-abc-123")).as_str())
        );
        assert!(fp.anchor_available);
    }

    #[test]
    fn linux_missing_machine_id_marks_unavailable() {
        let source = FakeSource {
            platform: "linux",
            files: HashMap::from([
                (
                    "/sys/class/dmi/id/product_uuid".to_string(),
                    LINUX_UUID_RAW.to_string(),
                ),
                ("/proc/cpuinfo".to_string(), LINUX_CPUINFO.to_string()),
            ]),
            machine_guid: None,
            wmi: HashMap::new(),
        };
        let fp = collect_fingerprint(&source, None);
        assert_eq!(fp.component("machine-id"), Some("unavailable"));
        assert!(!fp.anchor_available);
    }

    #[test]
    fn linux_blank_machine_id_is_unavailable_not_empty_hash() {
        // 空文件/纯空白内容不得哈希成 sha256('') 常量锚点（绑定穿透场景）。
        for content in ["", "\n", "   \r\n"] {
            let source = FakeSource {
                platform: "linux",
                files: HashMap::from([("/etc/machine-id".to_string(), content.to_string())]),
                machine_guid: None,
                wmi: HashMap::new(),
            };
            let fp = collect_fingerprint(&source, None);
            assert_eq!(
                fp.component("machine-id"),
                Some("unavailable"),
                "blank anchor accepted: {content:?}"
            );
            assert!(!fp.anchor_available);
        }
    }

    #[test]
    fn linux_blank_dmi_components_and_instance_id_are_unavailable() {
        let source = FakeSource {
            platform: "linux",
            files: HashMap::from([
                (
                    "/etc/machine-id".to_string(),
                    LINUX_MACHINE_ID_RAW.to_string(),
                ),
                (
                    "/sys/class/dmi/id/product_uuid".to_string(),
                    "  \n".to_string(),
                ),
                (
                    "/sys/class/dmi/id/product_serial".to_string(),
                    "\n".to_string(),
                ),
            ]),
            machine_guid: None,
            wmi: HashMap::new(),
        };
        let fp = collect_fingerprint(&source, Some("   "));
        assert_eq!(fp.component("dmi-product-uuid"), Some("unavailable"));
        assert_eq!(fp.component("dmi-product-serial"), Some("unavailable"));
        assert_eq!(fp.component("agentos-instance-id"), Some("unavailable"));
        assert!(fp.anchor_available);
    }

    #[test]
    fn linux_arm64_cpuinfo_without_model_name_uses_arm_fallback() {
        // ARM64 /proc/cpuinfo 通常无 model name；用 implementer/part/variant/revision 组成稳定型号。
        // 与 TS parseLinuxCpuInfo 相同输入必须得到相同规范化串。
        const ARM64_CPUINFO: &str = "processor\t: 0\nBogoMIPS\t: 38.40\nFeatures\t: fp asimd evtstrm aes pmull sha1 sha2 crc32\nCPU implementer\t: 0x41\nCPU architecture: 8\nCPU variant\t: 0x0\nCPU part\t: 0xd03\nCPU revision\t: 4\nprocessor\t: 1\nCPU implementer\t: 0x41\nCPU variant\t: 0x0\nCPU part\t: 0xd03\nCPU revision\t: 4\n";
        let source = FakeSource {
            platform: "linux",
            files: HashMap::from([
                (
                    "/etc/machine-id".to_string(),
                    LINUX_MACHINE_ID_RAW.to_string(),
                ),
                ("/proc/cpuinfo".to_string(), ARM64_CPUINFO.to_string()),
            ]),
            machine_guid: None,
            wmi: HashMap::new(),
        };
        let fp = collect_fingerprint(&source, None);
        assert_eq!(
            parse_linux_cpu_info(ARM64_CPUINFO).as_deref(),
            Some("arm 0x41/0xd03/0x0/4|2")
        );
        assert_eq!(
            fp.component("cpu"),
            Some(format!("sha256:{}", sha256_hex("arm 0x41/0xd03/0x0/4|2")).as_str())
        );
    }

    #[test]
    fn linux_cpuinfo_without_model_and_arm_fields_is_unavailable() {
        const BARE_CPUINFO: &str = "processor\t: 0\nprocessor\t: 1\n";
        assert_eq!(parse_linux_cpu_info(BARE_CPUINFO), None);
    }

    #[test]
    fn linux_cpuinfo_model_name_takes_priority_over_arm_fields() {
        // model name 与 ARM 字段同时存在时以 model name 为准（x86 取值路径冻结）。
        const MIXED: &str = "processor\t: 0\nmodel name\t: Some x86 CPU\nCPU implementer\t: 0x41\nCPU part\t: 0xd03\n";
        assert_eq!(
            parse_linux_cpu_info(MIXED).as_deref(),
            Some("some x86 cpu|1")
        );
    }

    #[test]
    fn linux_arm_fallback_blank_field_value_stays_empty_segment() {
        // 字段存在但值为空白：捕获后 trim 为空串段（区别于缺失段的 '-'）；与 TS 同输入同输出，钉死防漂移。
        const BLANK_FIELD: &str = "processor\t: 0\nCPU implementer\t: 0x41\nCPU part\t: \n";
        assert_eq!(
            parse_linux_cpu_info(BLANK_FIELD).as_deref(),
            Some("arm 0x41//-/-|1")
        );
    }

    #[test]
    fn blank_instance_id_string_is_unavailable() {
        let source = FakeSource {
            platform: "linux",
            files: HashMap::from([(
                "/etc/machine-id".to_string(),
                LINUX_MACHINE_ID_RAW.to_string(),
            )]),
            machine_guid: None,
            wmi: HashMap::new(),
        };
        let fp = collect_fingerprint(&source, Some(""));
        assert_eq!(fp.component("agentos-instance-id"), Some("unavailable"));
    }

    #[test]
    fn windows_registry_and_wmi_parsing() {
        let source = FakeSource {
            platform: "win32",
            files: HashMap::new(),
            machine_guid: Some(WIN_GUID_RAW.to_string()),
            wmi: HashMap::from([
                (
                    "Win32_ComputerSystemProduct".to_string(),
                    LINUX_UUID_NORM.to_uppercase(),
                ),
                ("Win32_BIOS".to_string(), LINUX_SERIAL_NORM.to_uppercase()),
                (
                    "Win32_Processor".to_string(),
                    "Intel(R) Xeon(R) Gold 6248 CPU @ 2.50GHz|2".to_string(),
                ),
            ]),
        };
        let fp = collect_fingerprint(&source, None);
        assert_eq!(
            fp.component("machine-id"),
            Some(format!("sha256:{}", sha256_hex(WIN_GUID_NORM)).as_str())
        );
        assert_eq!(
            fp.component("dmi-product-uuid"),
            Some(format!("sha256:{}", sha256_hex(LINUX_UUID_NORM)).as_str())
        );
        assert_eq!(
            fp.component("cpu"),
            Some(format!("sha256:{}", sha256_hex(LINUX_CPU_NORM)).as_str())
        );
        assert!(fp.anchor_available);
    }

    #[test]
    fn windows_failed_probes_mark_unavailable() {
        let source = FakeSource {
            platform: "win32",
            files: HashMap::new(),
            machine_guid: Some(WIN_GUID_RAW.to_string()),
            wmi: HashMap::new(),
        };
        let fp = collect_fingerprint(&source, None);
        assert_eq!(fp.component("dmi-product-uuid"), Some("unavailable"));
        assert_eq!(fp.component("cpu"), Some("unavailable"));
    }

    #[test]
    fn fingerprint_deterministic_and_grouped() {
        let a = collect_fingerprint(&full_linux_source(), None);
        let b = collect_fingerprint(&full_linux_source(), None);
        assert_eq!(a.fingerprint, b.fingerprint);
        assert!(Regex::new(r"^sha256:[0-9a-f]{64}$")
            .unwrap()
            .is_match(&a.fingerprint));
        let grouped = format_fingerprint_groups(&a.fingerprint);
        assert!(Regex::new(r"^([0-9A-F]{4}-){15}[0-9A-F]{4}$")
            .unwrap()
            .is_match(&grouped));
    }

    #[test]
    fn fingerprint_file_schema_and_no_raw_values() {
        let fp = collect_fingerprint(&full_linux_source(), None);
        let file = build_fingerprint_file(&fp);
        assert_eq!(
            file["schema"],
            Value::String(FINGERPRINT_SCHEMA.to_string())
        );
        assert_eq!(file["fingerprint"], Value::String(fp.fingerprint.clone()));
        let serialized = crate::jsonfmt::canonical_json(&file);
        assert!(!serialized.contains(LINUX_MACHINE_ID_RAW.trim()));
        assert!(!serialized.contains(LINUX_UUID_RAW.trim()));
    }

    #[test]
    fn fingerprint_file_uses_codename_keys() {
        // codename-spec §3.1：components 键为代号 c1..c5，值与槽位顺序不变；
        // 键序按探测插入序（preserve_order）→ c1,c2,c3,c4,c5。
        let fp = collect_fingerprint(&full_linux_source(), Some("inst-abc-123"));
        let file = build_fingerprint_file(&fp);
        let components = file["components"].as_object().unwrap();
        let keys: Vec<&str> = components.keys().map(String::as_str).collect();
        assert_eq!(keys, vec!["c1", "c2", "c3", "c4", "c5"]);
        // 值与内部名槽位一一对应（c1 对应 machine-id 槽位的值）。
        assert_eq!(
            components["c1"],
            Value::String(fp.component("machine-id").unwrap().to_string())
        );
        assert_eq!(
            components["c4"],
            Value::String(fp.component("cpu").unwrap().to_string())
        );
        // wire 产物不再出现旧名。
        let serialized = crate::jsonfmt::compact_json(&file);
        for legacy in COMPONENT_ORDER {
            assert!(
                !serialized.contains(legacy),
                "fingerprint file leaks {legacy}"
            );
        }
        // 整机指纹值不受代号化影响。
        assert_eq!(file["fingerprint"], Value::String(fp.fingerprint.clone()));
    }
}
