//! AgentosError：对应 tools/license-issuer/src/core/errors.ts。
//! 错误码（code）是对外契约，HTTP 422 响应只暴露 code + message。

use std::fmt;

#[derive(Debug, Clone)]
pub struct AgentosError {
    pub code: String,
    pub message: String,
}

impl AgentosError {
    pub fn new(code: &str, message: &str) -> Self {
        AgentosError {
            code: code.to_string(),
            message: message.to_string(),
        }
    }
}

impl fmt::Display for AgentosError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}", self.code, self.message)
    }
}

impl std::error::Error for AgentosError {}

pub type AgentosResult<T> = Result<T, AgentosError>;
