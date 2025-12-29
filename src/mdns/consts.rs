//! Constants and enums for mDNS operations.

use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;

/// Package name.
pub const PACKAGE: &str = "mdns-filter";

/// mDNS multicast address.
pub const MULTICAST_ADDRESS: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);

/// mDNS port.
pub const MDNS_PORT: u16 = 5353;

/// Maximum packet size for mDNS.
pub const PACKET_SIZE: usize = 65536;

/// DNS record types relevant to mDNS.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[allow(clippy::upper_case_acronyms)]
pub enum RecordType {
    A,
    NS,
    CNAME,
    SOA,
    PTR,
    HINFO,
    MX,
    TXT,
    AAAA,
    SRV,
    NSEC,
    ANY,
    /// Unknown record type with raw value.
    #[serde(untagged)]
    Unknown(u16),
}

impl RecordType {
    /// Convert from a raw u16 value.
    pub fn from_u16(value: u16) -> Self {
        match value {
            1 => RecordType::A,
            2 => RecordType::NS,
            5 => RecordType::CNAME,
            6 => RecordType::SOA,
            12 => RecordType::PTR,
            13 => RecordType::HINFO,
            15 => RecordType::MX,
            16 => RecordType::TXT,
            28 => RecordType::AAAA,
            33 => RecordType::SRV,
            47 => RecordType::NSEC,
            255 => RecordType::ANY,
            _ => RecordType::Unknown(value),
        }
    }

    /// Convert to raw u16 value.
    pub fn to_u16(self) -> u16 {
        match self {
            RecordType::A => 1,
            RecordType::NS => 2,
            RecordType::CNAME => 5,
            RecordType::SOA => 6,
            RecordType::PTR => 12,
            RecordType::HINFO => 13,
            RecordType::MX => 15,
            RecordType::TXT => 16,
            RecordType::AAAA => 28,
            RecordType::SRV => 33,
            RecordType::NSEC => 47,
            RecordType::ANY => 255,
            RecordType::Unknown(v) => v,
        }
    }

    /// Get human-readable name for the record type.
    pub fn name(&self) -> String {
        match self {
            RecordType::A => "A".to_string(),
            RecordType::NS => "NS".to_string(),
            RecordType::CNAME => "CNAME".to_string(),
            RecordType::SOA => "SOA".to_string(),
            RecordType::PTR => "PTR".to_string(),
            RecordType::HINFO => "HINFO".to_string(),
            RecordType::MX => "MX".to_string(),
            RecordType::TXT => "TXT".to_string(),
            RecordType::AAAA => "AAAA".to_string(),
            RecordType::SRV => "SRV".to_string(),
            RecordType::NSEC => "NSEC".to_string(),
            RecordType::ANY => "ANY".to_string(),
            RecordType::Unknown(v) => format!("TYPE{}", v),
        }
    }
}

impl From<u16> for RecordType {
    fn from(value: u16) -> Self {
        Self::from_u16(value)
    }
}

impl From<RecordType> for u16 {
    fn from(value: RecordType) -> Self {
        value.to_u16()
    }
}

/// Section of DNS message where a record appears.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RecordSection {
    Question,
    Answer,
    Authority,
    Additional,
}

/// Action to take when a filter rule matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FilterAction {
    #[default]
    Allow,
    Deny,
}

/// Log level for filter rule logging.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    #[default]
    #[serde(rename = "none")]
    Off,
    Debug,
    Info,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_record_type_from_u16() {
        assert_eq!(RecordType::from_u16(1), RecordType::A);
        assert_eq!(RecordType::from_u16(12), RecordType::PTR);
        assert_eq!(RecordType::from_u16(16), RecordType::TXT);
        assert_eq!(RecordType::from_u16(9999), RecordType::Unknown(9999));
    }

    #[test]
    fn test_record_type_to_u16() {
        assert_eq!(RecordType::A.to_u16(), 1);
        assert_eq!(RecordType::PTR.to_u16(), 12);
        assert_eq!(RecordType::Unknown(9999).to_u16(), 9999);
    }

    #[test]
    fn test_record_type_name() {
        assert_eq!(RecordType::A.name(), "A");
        assert_eq!(RecordType::PTR.name(), "PTR");
        assert_eq!(RecordType::Unknown(9999).name(), "TYPE9999");
    }
}
