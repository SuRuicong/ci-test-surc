//! 对应 tools/license-issuer/src/core/time.ts 的验签侧子集（毫秒精度比较）。
//! ISO 串先经 schema 层的 ISO_RE 校验，这里只需 RFC3339 解析（与 Date.parse 对合法输入等价）。

use chrono::{DateTime, Utc};

/// 'YYYY-MM-DDTHH:mm:ss(.f)?(Z|±hh:mm)' → Unix 毫秒；非法返回 None（对应 Date.parse → NaN）。
pub fn parse_iso_millis(s: &str) -> Option<i64> {
    DateTime::parse_from_rfc3339(s).ok().map(|d| d.timestamp_millis())
}

pub fn now_millis() -> i64 {
    Utc::now().timestamp_millis()
}

/// isBeforeNotBefore：now < notBefore
pub fn is_before_not_before(not_before: &str, now_ms: i64) -> bool {
    match parse_iso_millis(not_before) {
        Some(t) => now_ms < t,
        None => false,
    }
}

/// isExpired：now > expiresAt
pub fn is_expired(expires_at: &str, now_ms: i64) -> bool {
    match parse_iso_millis(expires_at) {
        Some(t) => now_ms > t,
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_offset_and_z() {
        let a = parse_iso_millis("2026-11-01T00:00:00+08:00").unwrap();
        let b = parse_iso_millis("2026-10-31T16:00:00Z").unwrap();
        assert_eq!(a, b);
        assert!(parse_iso_millis("2026-13-01T00:00:00Z").is_none());
    }

    #[test]
    fn expiry_semantics() {
        let now = parse_iso_millis("2026-11-15T00:00:00Z").unwrap();
        assert!(!is_expired("2027-11-01T00:00:00+08:00", now));
        assert!(is_expired("2026-01-01T00:00:00Z", now));
        assert!(is_before_not_before("2027-01-01T00:00:00Z", now));
    }
}
