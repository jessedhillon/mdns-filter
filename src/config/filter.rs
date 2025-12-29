//! Filter rule definitions and configuration.

use std::net::Ipv4Addr;
use std::path::Path;

use ipnet::Ipv4Net;
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::filter::PatternMatcher;
use crate::mdns::{DnsRecord, FilterAction, LogLevel, ParsedMdnsPacket, RecordSection, RecordType};

/// Defines matching criteria for a filter rule.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FilterMatch {
    /// Source IP or CIDR pattern.
    #[serde(default)]
    pub src_ip: Option<String>,

    /// Match queries (true) or responses (false).
    #[serde(default)]
    pub is_query: Option<bool>,

    /// Match authoritative responses.
    #[serde(default)]
    pub is_authoritative: Option<bool>,

    /// Service type pattern (e.g., "_googlecast._tcp").
    #[serde(default)]
    pub service: Option<String>,

    /// Instance name pattern (e.g., "Google-Cast-*").
    #[serde(default)]
    pub instance: Option<String>,

    /// Full DNS name pattern.
    #[serde(default)]
    pub name: Option<String>,

    /// Record type: PTR, SRV, TXT, A, AAAA, or *.
    #[serde(default)]
    pub record_type: Option<String>,

    /// Record section: question, answer, authority, additional.
    #[serde(default)]
    pub section: Option<RecordSection>,

    /// Pattern to match against TXT record content.
    #[serde(default)]
    pub txt_contains: Option<String>,
}

impl FilterMatch {
    /// Validate and parse src_ip as IPv4 network.
    pub fn get_network(&self) -> Result<Option<Ipv4Net>> {
        match &self.src_ip {
            Some(ip_str) => {
                // Try parsing as CIDR first, then as single IP
                if ip_str.contains('/') {
                    ip_str
                        .parse::<Ipv4Net>()
                        .map(Some)
                        .map_err(|_| Error::InvalidIp(ip_str.clone()))
                } else {
                    ip_str
                        .parse::<Ipv4Addr>()
                        .map(|ip| Some(Ipv4Net::new(ip, 32).unwrap()))
                        .map_err(|_| Error::InvalidIp(ip_str.clone()))
                }
            }
            None => Ok(None),
        }
    }

    /// Check if a record matches all specified criteria.
    pub fn matches_record(
        &self,
        section: RecordSection,
        record: &DnsRecord,
        packet: &ParsedMdnsPacket,
    ) -> bool {
        // IP matching
        if let Some(ref ip_str) = self.src_ip {
            if let Some(src_ip) = packet.src_ip {
                match self.get_network() {
                    Ok(Some(network)) => {
                        if !network.contains(&src_ip) {
                            return false;
                        }
                    }
                    Ok(None) => {}
                    Err(_) => {
                        // Invalid IP pattern, log and don't match
                        tracing::warn!("Invalid IP pattern: {}", ip_str);
                        return false;
                    }
                }
            }
        }

        // Message-level matching
        if let Some(is_query) = self.is_query {
            if is_query == packet.is_response {
                return false;
            }
        }

        if let Some(is_auth) = self.is_authoritative {
            if is_auth != packet.is_authoritative {
                return false;
            }
        }

        // Section matching
        if let Some(ref match_section) = self.section {
            if *match_section != section {
                return false;
            }
        }

        // Record type matching
        if let Some(ref type_pattern) = self.record_type {
            if !record.matches_type(type_pattern) {
                return false;
            }
        }

        // Service matching
        if let Some(ref pattern) = self.service {
            if !PatternMatcher::matches(record.service.as_deref(), pattern) {
                return false;
            }
        }

        // Instance matching
        if let Some(ref pattern) = self.instance {
            if !PatternMatcher::matches(record.instance.as_deref(), pattern) {
                return false;
            }
        }

        // Name matching
        if let Some(ref pattern) = self.name {
            if !PatternMatcher::matches(Some(&record.name), pattern) {
                return false;
            }
        }

        // TXT record content matching
        if let Some(ref pattern) = self.txt_contains {
            if record.record_type != RecordType::TXT {
                return false;
            }

            // Match against any key or value in TXT records
            let mut matched = false;
            for (key, value) in &record.txt_records {
                if PatternMatcher::matches(Some(key), pattern) {
                    matched = true;
                    break;
                }
                if PatternMatcher::matches(Some(value), pattern) {
                    matched = true;
                    break;
                }
                // Also match "key=value" format
                let kv = format!("{}={}", key, value);
                if PatternMatcher::matches(Some(&kv), pattern) {
                    matched = true;
                    break;
                }
            }
            if !matched {
                return false;
            }
        }

        true
    }
}

/// A single filter rule with match criteria and action.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FilterRule {
    /// Human-readable rule name.
    pub name: String,

    /// Matching criteria.
    #[serde(rename = "match")]
    pub match_criteria: FilterMatch,

    /// Action: allow or deny.
    pub action: FilterAction,

    /// Logging level for this rule.
    #[serde(default)]
    pub log: LogLevel,

    /// Match mode: "any" (default) or "all".
    #[serde(default = "default_match_mode")]
    pub match_mode: MatchMode,
}

fn default_match_mode() -> MatchMode {
    MatchMode::Any
}

/// How to match records within a packet.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MatchMode {
    /// Match if any record matches the criteria.
    #[default]
    Any,
    /// Match only if all records match the criteria.
    All,
}

/// Complete filter configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FilterConfig {
    /// Action when no rules match.
    #[serde(default)]
    pub default_action: FilterAction,

    /// Ordered list of filter rules (first match wins).
    #[serde(default)]
    pub rules: Vec<FilterRule>,
}

impl Default for FilterConfig {
    fn default() -> Self {
        Self {
            default_action: FilterAction::Allow,
            rules: Vec::new(),
        }
    }
}

impl FilterConfig {
    /// Load configuration from a YAML file.
    pub fn from_yaml_file(path: &Path) -> Result<Self> {
        let contents = std::fs::read_to_string(path)?;
        let config: FilterConfig = serde_yaml::from_str(&contents)?;
        Ok(config)
    }

    /// Create configuration from CLI patterns.
    ///
    /// Patterns are in format: "field:pattern" or "field:pattern,field2:pattern2"
    pub fn from_cli_patterns(
        allow_patterns: &[String],
        deny_patterns: &[String],
        default_deny: bool,
    ) -> Result<Self> {
        let mut rules = Vec::new();

        // Add deny rules first (higher priority)
        for (idx, pattern) in deny_patterns.iter().enumerate() {
            rules.push(FilterRule {
                name: format!("cli-deny-{}", idx),
                match_criteria: Self::parse_pattern(pattern)?,
                action: FilterAction::Deny,
                log: LogLevel::Debug,
                match_mode: MatchMode::Any,
            });
        }

        // Then allow rules
        for (idx, pattern) in allow_patterns.iter().enumerate() {
            rules.push(FilterRule {
                name: format!("cli-allow-{}", idx),
                match_criteria: Self::parse_pattern(pattern)?,
                action: FilterAction::Allow,
                log: LogLevel::Debug,
                match_mode: MatchMode::Any,
            });
        }

        Ok(Self {
            default_action: if default_deny {
                FilterAction::Deny
            } else {
                FilterAction::Allow
            },
            rules,
        })
    }

    /// Parse a CLI pattern string into FilterMatch.
    fn parse_pattern(pattern: &str) -> Result<FilterMatch> {
        let mut match_criteria = FilterMatch::default();

        for part in pattern.split(',') {
            let (field, value) = part.split_once(':').ok_or_else(|| {
                Error::ConfigError(format!(
                    "Invalid pattern format: {} (expected field:value)",
                    part
                ))
            })?;

            let field = field.trim().to_lowercase();
            let value = value.trim().to_string();

            match field.as_str() {
                "instance" => match_criteria.instance = Some(value),
                "service" => match_criteria.service = Some(value),
                "name" => match_criteria.name = Some(value),
                "type" | "record_type" => match_criteria.record_type = Some(value),
                "src_ip" | "ip" => match_criteria.src_ip = Some(value),
                "section" => {
                    match_criteria.section = Some(match value.to_lowercase().as_str() {
                        "question" => RecordSection::Question,
                        "answer" => RecordSection::Answer,
                        "authority" => RecordSection::Authority,
                        "additional" => RecordSection::Additional,
                        _ => {
                            return Err(Error::ConfigError(format!("Invalid section: {}", value)));
                        }
                    });
                }
                "txt" | "txt_contains" => match_criteria.txt_contains = Some(value),
                _ => {
                    return Err(Error::ConfigError(format!(
                        "Unknown filter field: {}",
                        field
                    )));
                }
            }
        }

        Ok(match_criteria)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn make_record(name: &str, record_type: RecordType) -> DnsRecord {
        DnsRecord {
            name: name.to_string(),
            record_type,
            record_class: 1,
            ttl: 4500,
            rdata: Vec::new(),
            instance: None,
            service: None,
            domain: "local".to_string(),
            txt_records: HashMap::new(),
        }
    }

    fn make_packet(is_response: bool, src_ip: Option<Ipv4Addr>) -> ParsedMdnsPacket {
        ParsedMdnsPacket {
            transaction_id: 0,
            flags: if is_response { 0x8400 } else { 0 },
            is_response,
            is_authoritative: is_response,
            is_truncated: false,
            questions: Vec::new(),
            answers: Vec::new(),
            authorities: Vec::new(),
            additionals: Vec::new(),
            src_ip,
        }
    }

    // FilterMatch tests
    #[test]
    fn test_match_empty_criteria() {
        let criteria = FilterMatch::default();
        let record = make_record("test.local", RecordType::A);
        let packet = make_packet(true, None);

        assert!(criteria.matches_record(RecordSection::Answer, &record, &packet));
    }

    #[test]
    fn test_match_service_pattern() {
        let criteria = FilterMatch {
            service: Some("_googlecast.*".to_string()),
            ..Default::default()
        };

        let mut record = make_record("_googlecast._tcp.local", RecordType::PTR);
        record.service = Some("_googlecast._tcp".to_string());
        let packet = make_packet(true, None);

        assert!(criteria.matches_record(RecordSection::Answer, &record, &packet));
    }

    #[test]
    fn test_match_instance_pattern() {
        let criteria = FilterMatch {
            instance: Some("Google-Cast-*".to_string()),
            ..Default::default()
        };

        let mut record = make_record("test", RecordType::PTR);
        record.instance = Some("Google-Cast-Group-abc123".to_string());
        let packet = make_packet(true, None);

        assert!(criteria.matches_record(RecordSection::Answer, &record, &packet));
    }

    #[test]
    fn test_match_record_type() {
        let criteria = FilterMatch {
            record_type: Some("PTR".to_string()),
            ..Default::default()
        };

        let ptr_record = make_record("test", RecordType::PTR);
        let txt_record = make_record("test", RecordType::TXT);
        let packet = make_packet(true, None);

        assert!(criteria.matches_record(RecordSection::Answer, &ptr_record, &packet));
        assert!(!criteria.matches_record(RecordSection::Answer, &txt_record, &packet));
    }

    #[test]
    fn test_match_section() {
        let criteria = FilterMatch {
            section: Some(RecordSection::Answer),
            ..Default::default()
        };

        let record = make_record("test", RecordType::A);
        let packet = make_packet(true, None);

        assert!(criteria.matches_record(RecordSection::Answer, &record, &packet));
        assert!(!criteria.matches_record(RecordSection::Question, &record, &packet));
    }

    #[test]
    fn test_match_is_query() {
        let criteria = FilterMatch {
            is_query: Some(true),
            ..Default::default()
        };

        let record = make_record("test", RecordType::A);
        let query_packet = make_packet(false, None);
        let response_packet = make_packet(true, None);

        assert!(criteria.matches_record(RecordSection::Question, &record, &query_packet));
        assert!(!criteria.matches_record(RecordSection::Answer, &record, &response_packet));
    }

    #[test]
    fn test_match_src_ip() {
        let criteria = FilterMatch {
            src_ip: Some("192.168.1.0/24".to_string()),
            ..Default::default()
        };

        let record = make_record("test", RecordType::A);
        let packet_in_range = make_packet(true, Some(Ipv4Addr::new(192, 168, 1, 100)));
        let packet_out_of_range = make_packet(true, Some(Ipv4Addr::new(192, 168, 2, 100)));

        assert!(criteria.matches_record(RecordSection::Answer, &record, &packet_in_range));
        assert!(!criteria.matches_record(RecordSection::Answer, &record, &packet_out_of_range));
    }

    #[test]
    fn test_match_txt_contains() {
        let criteria = FilterMatch {
            txt_contains: Some("*Living*".to_string()),
            ..Default::default()
        };

        let mut record = make_record("test", RecordType::TXT);
        record
            .txt_records
            .insert("fn".to_string(), "Living Room".to_string());
        let packet = make_packet(true, None);

        assert!(criteria.matches_record(RecordSection::Answer, &record, &packet));
    }

    // FilterConfig tests
    #[test]
    fn test_parse_cli_pattern_single() {
        let config =
            FilterConfig::from_cli_patterns(&["instance:Google-Cast-*".to_string()], &[], false)
                .unwrap();

        assert_eq!(config.rules.len(), 1);
        assert_eq!(config.rules[0].action, FilterAction::Allow);
        assert_eq!(
            config.rules[0].match_criteria.instance,
            Some("Google-Cast-*".to_string())
        );
    }

    #[test]
    fn test_parse_cli_pattern_multiple_fields() {
        let config = FilterConfig::from_cli_patterns(
            &["instance:Google-*,service:_googlecast._tcp".to_string()],
            &[],
            false,
        )
        .unwrap();

        assert_eq!(config.rules.len(), 1);
        assert_eq!(
            config.rules[0].match_criteria.instance,
            Some("Google-*".to_string())
        );
        assert_eq!(
            config.rules[0].match_criteria.service,
            Some("_googlecast._tcp".to_string())
        );
    }

    #[test]
    fn test_deny_rules_first() {
        let config = FilterConfig::from_cli_patterns(
            &["instance:Allow-*".to_string()],
            &["instance:Deny-*".to_string()],
            false,
        )
        .unwrap();

        assert_eq!(config.rules.len(), 2);
        assert_eq!(config.rules[0].action, FilterAction::Deny);
        assert_eq!(config.rules[1].action, FilterAction::Allow);
    }

    #[test]
    fn test_default_deny() {
        let config = FilterConfig::from_cli_patterns(&[], &[], true).unwrap();
        assert_eq!(config.default_action, FilterAction::Deny);
    }

    #[test]
    fn test_yaml_deserialization() {
        let yaml = r#"
default_action: deny
rules:
  - name: allow-chromecast
    match:
      service: "_googlecast._tcp"
      instance: "Google-Cast-*"
    action: allow
    log: info
    match_mode: any
"#;

        let config: FilterConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.default_action, FilterAction::Deny);
        assert_eq!(config.rules.len(), 1);
        assert_eq!(config.rules[0].name, "allow-chromecast");
        assert_eq!(
            config.rules[0].match_criteria.service,
            Some("_googlecast._tcp".to_string())
        );
    }
}
