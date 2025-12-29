//! Error types for mdns-filter.

use thiserror::Error;

/// Errors that can occur during mDNS operations.
#[derive(Error, Debug)]
pub enum Error {
    /// Failed to parse an mDNS packet.
    #[error("failed to parse mDNS packet: {0}")]
    ParseError(String),

    /// Invalid configuration.
    #[error("invalid configuration: {0}")]
    ConfigError(String),

    /// Network I/O error.
    #[error("network error: {0}")]
    NetworkError(#[from] std::io::Error),

    /// Invalid IP address or CIDR.
    #[error("invalid IP/CIDR: {0}")]
    InvalidIp(String),

    /// Invalid pattern syntax.
    #[error("invalid pattern: {0}")]
    InvalidPattern(String),

    /// Interface not found.
    #[error("interface not found: {0}")]
    InterfaceNotFound(String),

    /// YAML parsing error.
    #[error("YAML error: {0}")]
    YamlError(#[from] serde_yaml::Error),

    /// Regex compilation error.
    #[error("regex error: {0}")]
    RegexError(#[from] regex::Error),
}

/// Result type alias for mdns-filter operations.
pub type Result<T> = std::result::Result<T, Error>;
