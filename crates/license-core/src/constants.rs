//! 对应 tools/license-issuer/src/core/constants.ts。

pub const LICENSE_SCHEMA: &str = "agentos-license/v1";
pub const LICENSE_ALG: &str = "Ed25519";
pub const PRODUCT: &str = "agentos";
pub const FINGERPRINT_SCHEMA: &str = "agentos-fingerprint/v1";

/// 可选指纹分量目录（binding.optional 的 name 白名单）。
pub const OPTIONAL_COMPONENT_NAMES: [&str; 4] = [
    "dmi-product-uuid",
    "dmi-product-serial",
    "cpu",
    "agentos-instance-id",
];

/// 必选锚点分量名（binding.required 必须包含）。
pub const REQUIRED_ANCHOR_NAME: &str = "machine-id";

/// 固定分量顺序（完整指纹拼接与展示共用）。
pub const COMPONENT_ORDER: [&str; 5] = [
    "machine-id",
    "dmi-product-uuid",
    "dmi-product-serial",
    "cpu",
    "agentos-instance-id",
];

/// 指纹分量代号映射（ADR-20261102 / codename-spec §0）：内部名（旧名）→ 代号。
/// 代号只出现在 wire 边界（fingerprint.json 键、license binding、页面与日志）；
/// 指纹 canonical 拼接继续用内部名，整机指纹值跨版本不变。
pub const COMPONENT_CODENAMES: [(&str, &str); 5] = [
    ("machine-id", "c1"),
    ("dmi-product-uuid", "c2"),
    ("dmi-product-serial", "c3"),
    ("cpu", "c4"),
    ("agentos-instance-id", "c5"),
];

/// 必选锚点的代号（binding.required 归一化到代号空间后必须包含）。
pub const ANCHOR_CODENAME: &str = "c1";

/// 内部名 → 代号；已是代号或未知名 → 原样返回（对应 TS toCodename）。
pub fn to_codename(name: &str) -> &str {
    COMPONENT_CODENAMES
        .iter()
        .find(|(internal, _)| *internal == name)
        .map(|(_, codename)| *codename)
        .unwrap_or(name)
}

/// 代号 → 内部名；已是内部名或未知名 → 原样返回（对应 TS toInternalName）。
pub fn to_internal_name(name: &str) -> &str {
    COMPONENT_CODENAMES
        .iter()
        .find(|(_, codename)| *codename == name)
        .map(|(internal, _)| *internal)
        .unwrap_or(name)
}

/// schema 校验的合法分量名集合 = 5 个代号 ∪ 5 个内部名（codename-spec §4.1）。
pub fn is_known_component_name(name: &str) -> bool {
    COMPONENT_ORDER.contains(&name) || COMPONENT_CODENAMES.iter().any(|(_, c)| *c == name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codename_roundtrip_and_passthrough() {
        // 5 项映射双向对应。
        for (internal, codename) in COMPONENT_CODENAMES {
            assert_eq!(to_codename(internal), codename);
            assert_eq!(to_internal_name(codename), internal);
        }
        // 已是代号/旧名 → 原样返回；未知名 → 原样返回。
        assert_eq!(to_codename("c1"), "c1");
        assert_eq!(to_internal_name("machine-id"), "machine-id");
        assert_eq!(to_codename("unknown-x"), "unknown-x");
        assert_eq!(to_internal_name("unknown-x"), "unknown-x");
        assert_eq!(ANCHOR_CODENAME, "c1");
        assert_eq!(to_codename(REQUIRED_ANCHOR_NAME), ANCHOR_CODENAME);
    }

    #[test]
    fn known_name_set_is_dual() {
        for (internal, codename) in COMPONENT_CODENAMES {
            assert!(is_known_component_name(internal));
            assert!(is_known_component_name(codename));
        }
        assert!(!is_known_component_name("bios-uuid"));
    }
}
