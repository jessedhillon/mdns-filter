//! mDNS packet types and parsing.

pub mod consts;
pub mod packet;

pub use consts::{
    FilterAction, LogLevel, RecordSection, RecordType, MDNS_PORT, MULTICAST_ADDRESS, PACKAGE,
    PACKET_SIZE,
};
pub use packet::{DnsRecord, ParsedMdnsPacket};
