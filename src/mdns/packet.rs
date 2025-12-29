//! mDNS packet data types.

use std::collections::HashMap;
use std::net::Ipv4Addr;

use crate::mdns::consts::{RecordSection, RecordType};

/// Represents a single DNS resource record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsRecord {
    /// Full DNS name (e.g., "Google-Cast-Group-xxx._googlecast._tcp.local").
    pub name: String,
    /// Record type (A, PTR, TXT, etc.).
    pub record_type: RecordType,
    /// Record class (typically 1 for IN).
    pub record_class: u16,
    /// Time-to-live in seconds.
    pub ttl: u32,
    /// Raw record data.
    pub rdata: Vec<u8>,

    // Parsed fields for convenience
    /// Instance name (e.g., "Google-Cast-Group-xxx").
    pub instance: Option<String>,
    /// Service type (e.g., "_googlecast._tcp").
    pub service: Option<String>,
    /// Domain (e.g., "local").
    pub domain: String,

    /// For TXT records: parsed key-value pairs.
    pub txt_records: HashMap<String, String>,
}

impl DnsRecord {
    /// Create a new DNS record with minimal fields.
    pub fn new(name: String, record_type: RecordType, record_class: u16) -> Self {
        Self {
            name,
            record_type,
            record_class,
            ttl: 0,
            rdata: Vec::new(),
            instance: None,
            service: None,
            domain: "local".to_string(),
            txt_records: HashMap::new(),
        }
    }

    /// Get human-readable record type name.
    pub fn type_name(&self) -> String {
        self.record_type.name()
    }

    /// Check if record type matches pattern (e.g., "PTR", "TXT", "*").
    pub fn matches_type(&self, type_pattern: &str) -> bool {
        if type_pattern == "*" {
            return true;
        }
        self.type_name().eq_ignore_ascii_case(type_pattern)
    }
}

impl Default for DnsRecord {
    fn default() -> Self {
        Self {
            name: String::new(),
            record_type: RecordType::A,
            record_class: 1,
            ttl: 0,
            rdata: Vec::new(),
            instance: None,
            service: None,
            domain: "local".to_string(),
            txt_records: HashMap::new(),
        }
    }
}

/// Represents a parsed mDNS packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedMdnsPacket {
    // Header fields
    /// Transaction ID.
    pub transaction_id: u16,
    /// Raw flags field.
    pub flags: u16,
    /// Whether this is a response (vs query).
    pub is_response: bool,
    /// Whether the response is authoritative.
    pub is_authoritative: bool,
    /// Whether the message is truncated.
    pub is_truncated: bool,

    // Records by section
    /// Question records.
    pub questions: Vec<DnsRecord>,
    /// Answer records.
    pub answers: Vec<DnsRecord>,
    /// Authority records.
    pub authorities: Vec<DnsRecord>,
    /// Additional records.
    pub additionals: Vec<DnsRecord>,

    /// Source IP address.
    pub src_ip: Option<Ipv4Addr>,
}

impl ParsedMdnsPacket {
    /// Create a new empty packet.
    pub fn new(transaction_id: u16, flags: u16) -> Self {
        Self {
            transaction_id,
            flags,
            is_response: (flags & 0x8000) != 0,
            is_authoritative: (flags & 0x0400) != 0,
            is_truncated: (flags & 0x0200) != 0,
            questions: Vec::new(),
            answers: Vec::new(),
            authorities: Vec::new(),
            additionals: Vec::new(),
            src_ip: None,
        }
    }

    /// Get all records with their sections.
    pub fn all_records(&self) -> Vec<(RecordSection, &DnsRecord)> {
        let mut result = Vec::new();
        for rec in &self.questions {
            result.push((RecordSection::Question, rec));
        }
        for rec in &self.answers {
            result.push((RecordSection::Answer, rec));
        }
        for rec in &self.authorities {
            result.push((RecordSection::Authority, rec));
        }
        for rec in &self.additionals {
            result.push((RecordSection::Additional, rec));
        }
        result
    }

    /// Total number of records in the packet.
    pub fn record_count(&self) -> usize {
        self.questions.len() + self.answers.len() + self.authorities.len() + self.additionals.len()
    }

    /// Format packet as a human-readable summary (similar to tcpdump).
    pub fn format_summary(&self) -> String {
        let mut parts = Vec::new();

        // Source
        if let Some(ip) = self.src_ip {
            parts.push(format!("from {}", ip));
        }

        // Message type
        if self.is_response {
            let mut flags = Vec::new();
            if self.is_authoritative {
                flags.push("authoritative");
            }
            if self.is_truncated {
                flags.push("truncated");
            }
            let flag_str = if flags.is_empty() {
                String::new()
            } else {
                format!(" ({})", flags.join(", "))
            };
            parts.push(format!("response{}", flag_str));
        } else {
            parts.push("query".to_string());
        }

        // Record counts
        let mut counts = Vec::new();
        if !self.questions.is_empty() {
            counts.push(format!("{}q", self.questions.len()));
        }
        if !self.answers.is_empty() {
            counts.push(format!("{}an", self.answers.len()));
        }
        if !self.authorities.is_empty() {
            counts.push(format!("{}ns", self.authorities.len()));
        }
        if !self.additionals.is_empty() {
            counts.push(format!("{}ar", self.additionals.len()));
        }
        if !counts.is_empty() {
            parts.push(format!("[{}]", counts.join("/")));
        }

        // Key records (answers are most interesting)
        let mut record_strs = Vec::new();
        for record in self.answers.iter().take(3) {
            let type_name = record.type_name();
            if let (Some(instance), Some(service)) = (&record.instance, &record.service) {
                record_strs.push(format!(
                    "{} {}.{}.{}",
                    type_name, instance, service, record.domain
                ));
            } else if let Some(service) = &record.service {
                record_strs.push(format!("{} {}.{}", type_name, service, record.domain));
            } else {
                record_strs.push(format!("{} {}", type_name, record.name));
            }
        }

        if record_strs.is_empty() {
            // Fall back to questions if no answers
            for record in self.questions.iter().take(3) {
                let type_name = record.type_name();
                record_strs.push(format!("{}? {}", type_name, record.name));
            }
        }

        if !record_strs.is_empty() {
            parts.push(format!(": {}", record_strs.join(", ")));
            if self.answers.len() > 3 {
                parts.push(format!(" (+{} more)", self.answers.len() - 3));
            }
        }

        parts.join(" ")
    }

    /// Format packet with full details of all records.
    pub fn format_detailed(&self) -> String {
        let mut lines = Vec::new();

        // Header
        let msg_type = if self.is_response {
            "Response"
        } else {
            "Query"
        };
        lines.push(format!(
            "mDNS {} from {}",
            msg_type,
            self.src_ip
                .map_or("unknown".to_string(), |ip| ip.to_string())
        ));
        lines.push(format!(
            "  Flags: AA={}, TC={}",
            self.is_authoritative, self.is_truncated
        ));

        fn format_records(lines: &mut Vec<String>, section_name: &str, records: &[DnsRecord]) {
            if records.is_empty() {
                return;
            }
            lines.push(format!("  {}:", section_name));
            for record in records {
                let type_name = record.type_name();
                if let Some(instance) = &record.instance {
                    lines.push(format!(
                        "    {}: {}.{}.{}",
                        type_name,
                        instance,
                        record.service.as_deref().unwrap_or(""),
                        record.domain
                    ));
                } else {
                    lines.push(format!("    {}: {}", type_name, record.name));
                }
                for (key, value) in &record.txt_records {
                    lines.push(format!("      TXT: {}={}", key, value));
                }
            }
        }

        format_records(&mut lines, "Questions", &self.questions);
        format_records(&mut lines, "Answers", &self.answers);
        format_records(&mut lines, "Authority", &self.authorities);
        format_records(&mut lines, "Additional", &self.additionals);

        lines.join("\n")
    }
}

impl Default for ParsedMdnsPacket {
    fn default() -> Self {
        Self::new(0, 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dns_record_matches_type() {
        let record = DnsRecord {
            record_type: RecordType::PTR,
            ..Default::default()
        };

        assert!(record.matches_type("PTR"));
        assert!(record.matches_type("ptr"));
        assert!(record.matches_type("*"));
        assert!(!record.matches_type("TXT"));
    }

    #[test]
    fn test_packet_all_records() {
        let mut packet = ParsedMdnsPacket::default();
        packet.questions.push(DnsRecord::default());
        packet.answers.push(DnsRecord::default());
        packet.answers.push(DnsRecord::default());

        let all = packet.all_records();
        assert_eq!(all.len(), 3);
        assert_eq!(all[0].0, RecordSection::Question);
        assert_eq!(all[1].0, RecordSection::Answer);
        assert_eq!(all[2].0, RecordSection::Answer);
    }

    #[test]
    fn test_packet_record_count() {
        let mut packet = ParsedMdnsPacket::default();
        packet.questions.push(DnsRecord::default());
        packet.answers.push(DnsRecord::default());
        packet.authorities.push(DnsRecord::default());
        packet.additionals.push(DnsRecord::default());

        assert_eq!(packet.record_count(), 4);
    }
}
