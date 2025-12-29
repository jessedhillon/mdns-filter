//! Filter engine for evaluating packets against rules.

use tracing::{debug, info};

use crate::config::filter::{FilterConfig, MatchMode};
use crate::mdns::{FilterAction, ParsedMdnsPacket};

/// Evaluates filter rules against mDNS packets.
pub struct FilterEngine {
    config: FilterConfig,
}

impl FilterEngine {
    /// Create a new filter engine with the given configuration.
    pub fn new(config: FilterConfig) -> Self {
        Self { config }
    }

    /// Evaluate a packet against all rules.
    ///
    /// Returns (action, rule_name) where rule_name is None if default action was used.
    pub fn evaluate(&self, packet: &ParsedMdnsPacket) -> (FilterAction, Option<String>) {
        let all_records = packet.all_records();

        if all_records.is_empty() {
            // Empty packet - use default action
            return (self.config.default_action, None);
        }

        for rule in &self.config.rules {
            let matched = match rule.match_mode {
                MatchMode::Any => {
                    // Match if any record matches
                    all_records.iter().any(|(section, record)| {
                        rule.match_criteria.matches_record(*section, record, packet)
                    })
                }
                MatchMode::All => {
                    // Match only if all records match
                    all_records.iter().all(|(section, record)| {
                        rule.match_criteria.matches_record(*section, record, packet)
                    })
                }
            };

            if matched {
                // Log if configured
                match rule.log {
                    crate::mdns::LogLevel::Debug => {
                        debug!(
                            rule = %rule.name,
                            action = ?rule.action,
                            src = ?packet.src_ip,
                            "Rule matched"
                        );
                    }
                    crate::mdns::LogLevel::Info => {
                        info!(
                            rule = %rule.name,
                            action = ?rule.action,
                            src = ?packet.src_ip,
                            "Rule matched"
                        );
                    }
                    crate::mdns::LogLevel::Off => {}
                }

                return (rule.action, Some(rule.name.clone()));
            }
        }

        // No rule matched - use default action
        (self.config.default_action, None)
    }

    /// Get a reference to the configuration.
    pub fn config(&self) -> &FilterConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::filter::{FilterMatch, FilterRule};
    use crate::mdns::{DnsRecord, LogLevel, RecordType};
    use std::collections::HashMap;
    use std::net::Ipv4Addr;

    fn make_record(instance: Option<&str>, service: Option<&str>) -> DnsRecord {
        DnsRecord {
            name: "test.local".to_string(),
            record_type: RecordType::PTR,
            record_class: 1,
            ttl: 4500,
            rdata: Vec::new(),
            instance: instance.map(|s| s.to_string()),
            service: service.map(|s| s.to_string()),
            domain: "local".to_string(),
            txt_records: HashMap::new(),
        }
    }

    fn make_packet(answers: Vec<DnsRecord>, src_ip: Option<Ipv4Addr>) -> ParsedMdnsPacket {
        ParsedMdnsPacket {
            transaction_id: 0,
            flags: 0x8400,
            is_response: true,
            is_authoritative: true,
            is_truncated: false,
            questions: Vec::new(),
            answers,
            authorities: Vec::new(),
            additionals: Vec::new(),
            src_ip,
        }
    }

    #[test]
    fn test_empty_packet_uses_default() {
        let config = FilterConfig {
            default_action: FilterAction::Deny,
            rules: vec![],
        };
        let engine = FilterEngine::new(config);
        let packet = make_packet(vec![], None);

        let (action, rule_name) = engine.evaluate(&packet);
        assert_eq!(action, FilterAction::Deny);
        assert!(rule_name.is_none());
    }

    #[test]
    fn test_no_rules_uses_default() {
        let config = FilterConfig {
            default_action: FilterAction::Allow,
            rules: vec![],
        };
        let engine = FilterEngine::new(config);
        let packet = make_packet(vec![make_record(None, None)], None);

        let (action, rule_name) = engine.evaluate(&packet);
        assert_eq!(action, FilterAction::Allow);
        assert!(rule_name.is_none());
    }

    #[test]
    fn test_matching_rule_returns_action() {
        let config = FilterConfig {
            default_action: FilterAction::Deny,
            rules: vec![FilterRule {
                name: "allow-chromecast".to_string(),
                match_criteria: FilterMatch {
                    instance: Some("Google-Cast-*".to_string()),
                    ..Default::default()
                },
                action: FilterAction::Allow,
                log: LogLevel::Off,
                match_mode: MatchMode::Any,
            }],
        };
        let engine = FilterEngine::new(config);

        let record = make_record(Some("Google-Cast-Group-123"), Some("_googlecast._tcp"));
        let packet = make_packet(vec![record], None);

        let (action, rule_name) = engine.evaluate(&packet);
        assert_eq!(action, FilterAction::Allow);
        assert_eq!(rule_name, Some("allow-chromecast".to_string()));
    }

    #[test]
    fn test_first_match_wins() {
        let config = FilterConfig {
            default_action: FilterAction::Allow,
            rules: vec![
                FilterRule {
                    name: "deny-all-cast".to_string(),
                    match_criteria: FilterMatch {
                        instance: Some("*Cast*".to_string()),
                        ..Default::default()
                    },
                    action: FilterAction::Deny,
                    log: LogLevel::Off,
                    match_mode: MatchMode::Any,
                },
                FilterRule {
                    name: "allow-google-cast".to_string(),
                    match_criteria: FilterMatch {
                        instance: Some("Google-Cast-*".to_string()),
                        ..Default::default()
                    },
                    action: FilterAction::Allow,
                    log: LogLevel::Off,
                    match_mode: MatchMode::Any,
                },
            ],
        };
        let engine = FilterEngine::new(config);

        let record = make_record(Some("Google-Cast-Group-123"), None);
        let packet = make_packet(vec![record], None);

        let (action, rule_name) = engine.evaluate(&packet);
        // First rule matches, even though second would also match
        assert_eq!(action, FilterAction::Deny);
        assert_eq!(rule_name, Some("deny-all-cast".to_string()));
    }

    #[test]
    fn test_match_mode_any() {
        let config = FilterConfig {
            default_action: FilterAction::Deny,
            rules: vec![FilterRule {
                name: "allow-chromecast".to_string(),
                match_criteria: FilterMatch {
                    instance: Some("Google-Cast-*".to_string()),
                    ..Default::default()
                },
                action: FilterAction::Allow,
                log: LogLevel::Off,
                match_mode: MatchMode::Any,
            }],
        };
        let engine = FilterEngine::new(config);

        // One matching, one not matching - should match with "any"
        let record1 = make_record(Some("Google-Cast-Group-123"), None);
        let record2 = make_record(Some("WiiM-Pro"), None);
        let packet = make_packet(vec![record1, record2], None);

        let (action, _) = engine.evaluate(&packet);
        assert_eq!(action, FilterAction::Allow);
    }

    #[test]
    fn test_match_mode_all() {
        let config = FilterConfig {
            default_action: FilterAction::Deny,
            rules: vec![FilterRule {
                name: "allow-all-chromecast".to_string(),
                match_criteria: FilterMatch {
                    instance: Some("Google-Cast-*".to_string()),
                    ..Default::default()
                },
                action: FilterAction::Allow,
                log: LogLevel::Off,
                match_mode: MatchMode::All,
            }],
        };
        let engine = FilterEngine::new(config);

        // One matching, one not matching - should NOT match with "all"
        let record1 = make_record(Some("Google-Cast-Group-123"), None);
        let record2 = make_record(Some("WiiM-Pro"), None);
        let packet = make_packet(vec![record1, record2], None);

        let (action, rule_name) = engine.evaluate(&packet);
        assert_eq!(action, FilterAction::Deny);
        assert!(rule_name.is_none());
    }

    #[test]
    fn test_match_mode_all_succeeds() {
        let config = FilterConfig {
            default_action: FilterAction::Deny,
            rules: vec![FilterRule {
                name: "allow-all-chromecast".to_string(),
                match_criteria: FilterMatch {
                    instance: Some("Google-Cast-*".to_string()),
                    ..Default::default()
                },
                action: FilterAction::Allow,
                log: LogLevel::Off,
                match_mode: MatchMode::All,
            }],
        };
        let engine = FilterEngine::new(config);

        // Both records match
        let record1 = make_record(Some("Google-Cast-Group-123"), None);
        let record2 = make_record(Some("Google-Cast-Audio-456"), None);
        let packet = make_packet(vec![record1, record2], None);

        let (action, rule_name) = engine.evaluate(&packet);
        assert_eq!(action, FilterAction::Allow);
        assert_eq!(rule_name, Some("allow-all-chromecast".to_string()));
    }
}
