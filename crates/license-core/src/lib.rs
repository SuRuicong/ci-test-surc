//! AgentOS License 共享核心（Rust）。
//! 模块与 TS 侧的对应关系：
//! - error       ↔ tools/license-issuer/src/core/errors.ts
//! - constants   ↔ tools/license-issuer/src/core/constants.ts
//! - jsonfmt     ↔ JS JSON.stringify / canonical-json.ts（字节级兼容序列化）
//! - schema      ↔ tools/license-issuer/src/core/schema.ts（验签侧子集）
//! - time        ↔ tools/license-issuer/src/core/time.ts
//! - key_policy  ↔ tools/license-issuer/src/core/key-policy.ts（公钥侧子集）
//! - signer      ↔ tools/license-issuer/src/core/signer.ts（验签子集）
//! - verifier    ↔ tools/license-issuer/src/core/verifier.ts
//! - binding     ↔ tools/license-daemon/src/core/binding-match.ts
//! - fingerprint ↔ tools/license-daemon/src/core/fingerprint-collect.ts + system-probe.ts

pub mod binding;
pub mod constants;
pub mod error;
pub mod fingerprint;
pub mod jsonfmt;
pub mod key_policy;
pub mod schema;
pub mod signer;
pub mod time;
pub mod verifier;
