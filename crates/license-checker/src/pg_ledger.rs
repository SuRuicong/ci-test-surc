//! 对应 tools/license-checker/src/core/pg-ledger.ts：
//! PG 账本双写（DESIGN §4.5.3/§5.1）。AGENTOS_LICENSE_PG_URL 设置时心跳双写
//! license_runtime_ledger（表结构见 apps/web/lib/db/schema.ts:410），
//! 每次校验把 PG 链尾与文件链尾交叉比对；不一致 → 退出码 3。
//! 连接/读写失败抛 ERR_PG_LEDGER（CLI 映射退出码 1，AgentOS 侧按宽限处理）。

use crate::ledger::{LedgerEntry, LedgerTip};
use license_core::error::{AgentosError, AgentosResult};

pub struct PgLedgerSink {
    client: postgres::Client,
}

fn wrap<T>(op: &str, result: Result<T, postgres::Error>) -> AgentosResult<T> {
    result.map_err(|e| AgentosError::new("ERR_PG_LEDGER", &format!("pg ledger {op} failed: {e}")))
}

impl PgLedgerSink {
    pub fn connect(url: &str) -> AgentosResult<Self> {
        let client = wrap("connect", postgres::Client::connect(url, postgres::NoTls))?;
        Ok(PgLedgerSink { client })
    }

    pub fn append(&mut self, entry: &LedgerEntry) -> AgentosResult<()> {
        let seq = entry.seq as i32;
        wrap(
            "append",
            self.client.execute(
                "INSERT INTO license_runtime_ledger \
                 (seq, recorded_at, wall_clock_max, tick_monotonic_ms, cumulative_seconds, prev_hash, entry_hash, entry_hmac) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
                &[
                    &seq,
                    &entry.recorded_at,
                    &entry.wall_clock_max,
                    &entry.tick_monotonic_ms,
                    &entry.cumulative_seconds,
                    &entry.prev_hash,
                    &entry.entry_hash,
                    &entry.entry_hmac,
                ],
            ),
        )?;
        Ok(())
    }

    pub fn read_tip(&mut self) -> AgentosResult<Option<LedgerTip>> {
        let rows = wrap(
            "readTip",
            self.client.query(
                "SELECT seq, entry_hash, wall_clock_max, cumulative_seconds \
                 FROM license_runtime_ledger ORDER BY seq DESC LIMIT 1",
                &[],
            ),
        )?;
        Ok(rows.first().map(|row| LedgerTip {
            seq: row.get::<_, i32>(0) as i64,
            entry_hash: row.get(1),
            wall_clock_max: row.get(2),
            cumulative_seconds: row.get(3),
        }))
    }
}

/// 文件链尾与 PG 链尾交叉比对；两侧都为空（尚无心跳）视为一致。
pub fn pg_tip_matches_file(file_tip: Option<&LedgerTip>, pg_tip: Option<&LedgerTip>) -> bool {
    match (file_tip, pg_tip) {
        (None, None) => true,
        (Some(f), Some(p)) => {
            f.seq == p.seq
                && f.entry_hash == p.entry_hash
                && f.wall_clock_max == p.wall_clock_max
                && f.cumulative_seconds == p.cumulative_seconds
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tip(seq: i64, hash: &str, wc: &str, cum: f64) -> LedgerTip {
        LedgerTip {
            seq,
            entry_hash: hash.to_string(),
            wall_clock_max: wc.to_string(),
            cumulative_seconds: cum,
        }
    }

    #[test]
    fn both_empty_match() {
        assert!(pg_tip_matches_file(None, None));
    }

    #[test]
    fn one_side_missing_mismatches() {
        let t = tip(1, "sha256:aa", "2026-11-15T00:00:00.000Z", 60.0);
        assert!(!pg_tip_matches_file(Some(&t), None));
        assert!(!pg_tip_matches_file(None, Some(&t)));
    }

    #[test]
    fn identical_tips_match() {
        let a = tip(2, "sha256:bb", "2026-11-15T00:01:00.000Z", 61.5);
        let b = tip(2, "sha256:bb", "2026-11-15T00:01:00.000Z", 61.5);
        assert!(pg_tip_matches_file(Some(&a), Some(&b)));
    }

    #[test]
    fn rolled_back_seq_mismatches() {
        let a = tip(3, "sha256:cc", "2026-11-15T00:02:00.000Z", 120.0);
        let b = tip(2, "sha256:bb", "2026-11-15T00:01:00.000Z", 61.5);
        assert!(!pg_tip_matches_file(Some(&a), Some(&b)));
    }
}
