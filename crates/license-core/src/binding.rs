//! 对应 tools/license-daemon/src/core/binding-match.ts：
//! 必选锚点逐一匹配（不受 tolerance 影响）；可选分量至多容忍 tolerance 项不匹配，
//! 运行侧探测不到（缺失/unavailable/空串）按不匹配计。
//! ADR-20261102：比对前把 binding 与运行侧分量名都归一化到代号空间（c1..c5），
//! mismatches 返回代号（未知名原样）；旧名 license 因此在比对边界全兼容。

use crate::constants::to_codename;
use crate::schema::LicenseBinding;
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct BindingMatchResult {
    pub ok: bool,
    pub mismatches: Vec<String>,
}

pub fn match_binding(binding: &LicenseBinding, current_components: &HashMap<String, String>) -> BindingMatchResult {
    // 运行侧采集用内部名；归一化到代号空间后与 binding（代号或旧名均可）比较。
    let current: HashMap<String, String> = current_components
        .iter()
        .map(|(k, v)| (to_codename(k).to_string(), v.clone()))
        .collect();
    let mut mismatches: Vec<String> = Vec::new();
    for (name, expected) in &binding.required {
        let codename = to_codename(name);
        if current.get(codename) != Some(expected) {
            mismatches.push(codename.to_string());
        }
    }
    if !mismatches.is_empty() {
        return BindingMatchResult { ok: false, mismatches };
    }
    let mut optional_mismatches = 0i64;
    for comp in &binding.optional {
        let codename = to_codename(&comp.name);
        let current_value = current.get(codename);
        let matched = matches!(current_value, Some(c) if !c.is_empty() && c != "unavailable" && *c == comp.sha256);
        if !matched {
            optional_mismatches += 1;
            mismatches.push(codename.to_string());
        }
    }
    BindingMatchResult {
        ok: optional_mismatches <= binding.tolerance,
        mismatches,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::OptionalBindingComponent;

    /// 新格式 binding：required/optional 全为代号（issuer bindingFromFingerprint 新产出）。
    fn binding() -> LicenseBinding {
        LicenseBinding {
            mode: "machine".to_string(),
            required: vec![("c1".to_string(), "sha256:".to_string() + &"a".repeat(64))],
            optional: vec![OptionalBindingComponent {
                name: "c2".to_string(),
                sha256: "sha256:".to_string() + &"b".repeat(64),
            }],
            tolerance: 1,
        }
    }

    /// legacy binding：旧名（旧版 issuer 签发的 license）。
    fn legacy_binding() -> LicenseBinding {
        LicenseBinding {
            mode: "machine".to_string(),
            required: vec![("machine-id".to_string(), "sha256:".to_string() + &"a".repeat(64))],
            optional: vec![OptionalBindingComponent {
                name: "dmi-product-uuid".to_string(),
                sha256: "sha256:".to_string() + &"b".repeat(64),
            }],
            tolerance: 1,
        }
    }

    /// 运行侧采集的分量恒为内部名（fingerprint.rs 采集不变）。
    fn current(entries: &[(&str, &str)]) -> HashMap<String, String> {
        entries.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    fn full_current() -> HashMap<String, String> {
        current(&[
            ("machine-id", &format!("sha256:{}", "a".repeat(64))),
            ("dmi-product-uuid", &format!("sha256:{}", "b".repeat(64))),
        ])
    }

    #[test]
    fn anchor_mismatch_fails_regardless_of_tolerance() {
        let b = binding();
        let c = current(&[("machine-id", &format!("sha256:{}", "f".repeat(64)))]);
        let r = match_binding(&b, &c);
        assert!(!r.ok);
        // mismatches 返回代号。
        assert_eq!(r.mismatches, vec!["c1"]);
    }

    #[test]
    fn optional_within_tolerance_ok() {
        let b = binding();
        let c = current(&[
            ("machine-id", &format!("sha256:{}", "a".repeat(64))),
            ("dmi-product-uuid", "unavailable"),
        ]);
        let r = match_binding(&b, &c);
        assert!(r.ok);
        assert_eq!(r.mismatches, vec!["c2"]);
    }

    #[test]
    fn optional_beyond_tolerance_fails() {
        let mut b = binding();
        b.tolerance = 0;
        let c = current(&[("machine-id", &format!("sha256:{}", "a".repeat(64)))]);
        let r = match_binding(&b, &c);
        assert!(!r.ok);
        assert_eq!(r.mismatches, vec!["c2"]);
    }

    #[test]
    fn codename_binding_matches_internal_name_components() {
        // 新格式 binding（代号）对当前采集（内部名）匹配成功。
        let r = match_binding(&binding(), &full_current());
        assert!(r.ok);
        assert!(r.mismatches.is_empty());
    }

    #[test]
    fn legacy_binding_matches_internal_name_components() {
        // legacy license（旧名 binding）对当前采集（内部名）匹配成功（codename-spec §4.2）。
        let r = match_binding(&legacy_binding(), &full_current());
        assert!(r.ok);
        assert!(r.mismatches.is_empty());
    }

    #[test]
    fn legacy_binding_mismatch_reports_codename() {
        // legacy binding 不匹配时 mismatches 仍返回代号。
        let b = legacy_binding();
        let c = current(&[
            ("machine-id", &format!("sha256:{}", "a".repeat(64))),
            ("dmi-product-uuid", "unavailable"),
        ]);
        let r = match_binding(&b, &c);
        assert!(r.ok); // tolerance=1 内容忍
        assert_eq!(r.mismatches, vec!["c2"]);
    }

    #[test]
    fn unknown_names_pass_through_normalization() {
        // 未知名不归一化（原样参与比较，自然不匹配）。
        let mut b = binding();
        b.optional.push(OptionalBindingComponent {
            name: "mystery".to_string(),
            sha256: "sha256:".to_string() + &"c".repeat(64),
        });
        let r = match_binding(&b, &full_current());
        assert!(r.mismatches.contains(&"mystery".to_string()));
    }
}
