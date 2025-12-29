//! mdns-filter - A filtering mDNS repeater.
//!
//! This library provides functionality for parsing, filtering, and repeating
//! mDNS (multicast DNS) packets between network interfaces.

pub mod config;
pub mod error;
pub mod filter;
pub mod mdns;
pub mod net;

pub use config::{FilterConfig, FilterMatch, FilterRule, MatchMode};
pub use error::{Error, Result};
pub use filter::{CompiledPattern, FilterEngine, PatternMatcher};
pub use mdns::{
    DnsRecord, FilterAction, LogLevel, MdnsParser, ParsedMdnsPacket, RecordSection, RecordType,
    MDNS_PORT, MULTICAST_ADDRESS, PACKAGE, PACKET_SIZE,
};
pub use net::{create_multicast_socket, InterfaceInfo, InterfaceSocket};
