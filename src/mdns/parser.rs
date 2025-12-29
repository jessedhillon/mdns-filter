//! mDNS packet parsing.
//!
//! Parses raw DNS/mDNS packet bytes into structured data.

use std::collections::HashMap;
use std::net::Ipv4Addr;

use crate::error::{Error, Result};
use crate::mdns::{DnsRecord, ParsedMdnsPacket, RecordType};

/// Maximum number of compression pointer jumps to prevent infinite loops.
const MAX_JUMPS: usize = 10;

/// Parser for mDNS/DNS packets.
pub struct MdnsParser;

impl MdnsParser {
    /// Parse a DNS name from packet data, handling compression.
    ///
    /// DNS names can contain compression pointers (2 bytes starting with 0xC0)
    /// that reference earlier positions in the packet.
    ///
    /// Returns the parsed name and the new offset after the name.
    pub fn parse_name(data: &[u8], offset: usize) -> Result<(String, usize)> {
        let mut labels: Vec<String> = Vec::new();
        let mut current_offset = offset;
        let mut jumped = false;
        let mut jump_count = 0;

        loop {
            if jump_count >= MAX_JUMPS {
                return Err(Error::ParseError("Too many compression jumps".to_string()));
            }

            if current_offset >= data.len() {
                break;
            }

            let length = data[current_offset] as usize;

            // End of name
            if length == 0 {
                current_offset += 1;
                break;
            }

            // Compression pointer: top 2 bits are 11
            if (length & 0xC0) == 0xC0 {
                if current_offset + 1 >= data.len() {
                    return Err(Error::ParseError(
                        "Truncated compression pointer".to_string(),
                    ));
                }

                let pointer = ((length & 0x3F) << 8) | (data[current_offset + 1] as usize);

                if !jumped {
                    jumped = true;
                }

                current_offset = pointer;
                jump_count += 1;
                continue;
            }

            // Regular label
            current_offset += 1;
            if current_offset + length > data.len() {
                return Err(Error::ParseError(
                    "Label extends past end of data".to_string(),
                ));
            }

            let label = String::from_utf8_lossy(&data[current_offset..current_offset + length]);
            labels.push(label.into_owned());
            current_offset += length;
        }

        let name = labels.join(".");
        // If we jumped, we need to find where the name actually ends in the original data
        let final_offset = if jumped {
            Self::find_end_offset(data, offset)?
        } else {
            current_offset
        };

        Ok((name, final_offset))
    }

    /// Find the end offset of a name, accounting for compression.
    fn find_end_offset(data: &[u8], offset: usize) -> Result<usize> {
        let mut current = offset;

        while current < data.len() {
            let length = data[current] as usize;

            if length == 0 {
                return Ok(current + 1);
            }

            if (length & 0xC0) == 0xC0 {
                // Compression pointer is 2 bytes, then we're done
                return Ok(current + 2);
            }

            current += 1 + length;
        }

        Err(Error::ParseError("Unterminated name".to_string()))
    }

    /// Parse an mDNS service name into (instance, service, domain).
    ///
    /// Examples:
    /// - `"Google-Cast-Group-xxx._googlecast._tcp.local"`
    ///   → `(Some("Google-Cast-Group-xxx"), Some("_googlecast._tcp"), "local")`
    /// - `"_googlecast._tcp.local"`
    ///   → `(None, Some("_googlecast._tcp"), "local")`
    /// - `"somehost.local"`
    ///   → `(None, None, "local")`
    pub fn parse_service_name(name: &str) -> (Option<String>, Option<String>, String) {
        let parts: Vec<&str> = name.split('.').collect();

        // Find service type pattern: _name._tcp or _name._udp
        let mut service_start = None;
        for (idx, part) in parts.iter().enumerate() {
            if part.starts_with('_') && idx + 1 < parts.len() {
                let next_part = parts[idx + 1];
                if next_part == "_tcp" || next_part == "_udp" {
                    service_start = Some(idx);
                    break;
                }
            }
        }

        let Some(service_idx) = service_start else {
            // No service pattern found
            let domain = parts
                .last()
                .map(|s| s.to_string())
                .unwrap_or_else(|| "local".to_string());
            return (None, None, domain);
        };

        let instance = if service_idx > 0 {
            Some(parts[..service_idx].join("."))
        } else {
            None
        };

        let service = format!("{}.{}", parts[service_idx], parts[service_idx + 1]);

        let domain = if service_idx + 2 < parts.len() {
            parts[service_idx + 2..].join(".")
        } else {
            "local".to_string()
        };

        (instance, Some(service), domain)
    }

    /// Parse TXT record data into key-value pairs.
    ///
    /// TXT records contain length-prefixed strings in "key=value" format.
    pub fn parse_txt_record(rdata: &[u8]) -> HashMap<String, String> {
        let mut result = HashMap::new();
        let mut offset = 0;

        while offset < rdata.len() {
            let length = rdata[offset] as usize;
            offset += 1;

            if length == 0 || offset + length > rdata.len() {
                break;
            }

            let txt = String::from_utf8_lossy(&rdata[offset..offset + length]);
            offset += length;

            if let Some((key, value)) = txt.split_once('=') {
                result.insert(key.to_string(), value.to_string());
            } else {
                // Flag-style TXT record (no value)
                result.insert(txt.into_owned(), String::new());
            }
        }

        result
    }

    /// Parse a complete mDNS packet.
    pub fn parse(data: &[u8], src_ip: Option<Ipv4Addr>) -> Result<ParsedMdnsPacket> {
        if data.len() < 12 {
            return Err(Error::ParseError(
                "Packet too short for DNS header".to_string(),
            ));
        }

        // Parse header
        let transaction_id = u16::from_be_bytes([data[0], data[1]]);
        let flags = u16::from_be_bytes([data[2], data[3]]);
        let qdcount = u16::from_be_bytes([data[4], data[5]]) as usize;
        let ancount = u16::from_be_bytes([data[6], data[7]]) as usize;
        let nscount = u16::from_be_bytes([data[8], data[9]]) as usize;
        let arcount = u16::from_be_bytes([data[10], data[11]]) as usize;

        let is_response = (flags & 0x8000) != 0;
        let is_authoritative = (flags & 0x0400) != 0;
        let is_truncated = (flags & 0x0200) != 0;

        let mut offset = 12;
        let mut questions = Vec::with_capacity(qdcount);

        // Parse questions
        for _ in 0..qdcount {
            if offset >= data.len() {
                break;
            }

            let (name, new_offset) = Self::parse_name(data, offset)?;
            offset = new_offset;

            if offset + 4 > data.len() {
                break;
            }

            let qtype = u16::from_be_bytes([data[offset], data[offset + 1]]);
            let qclass = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
            offset += 4;

            let (instance, service, domain) = Self::parse_service_name(&name);

            questions.push(DnsRecord {
                name,
                record_type: RecordType::from_u16(qtype),
                record_class: qclass,
                ttl: 0,
                rdata: Vec::new(),
                instance,
                service,
                domain,
                txt_records: HashMap::new(),
            });
        }

        // Parse resource records helper
        let parse_rr = |data: &[u8], offset: &mut usize, count: usize| -> Result<Vec<DnsRecord>> {
            let mut records = Vec::with_capacity(count);

            for _ in 0..count {
                if *offset >= data.len() {
                    break;
                }

                let (name, new_offset) = Self::parse_name(data, *offset)?;
                *offset = new_offset;

                if *offset + 10 > data.len() {
                    break;
                }

                let rtype = u16::from_be_bytes([data[*offset], data[*offset + 1]]);
                let rclass = u16::from_be_bytes([data[*offset + 2], data[*offset + 3]]);
                let ttl = u32::from_be_bytes([
                    data[*offset + 4],
                    data[*offset + 5],
                    data[*offset + 6],
                    data[*offset + 7],
                ]);
                let rdlength = u16::from_be_bytes([data[*offset + 8], data[*offset + 9]]) as usize;
                *offset += 10;

                if *offset + rdlength > data.len() {
                    break;
                }

                let rdata = data[*offset..*offset + rdlength].to_vec();
                let rdata_start = *offset;
                *offset += rdlength;

                let (mut instance, mut service, domain) = Self::parse_service_name(&name);

                // Parse TXT records
                let txt_records = if rtype == RecordType::TXT.to_u16() {
                    Self::parse_txt_record(&rdata)
                } else {
                    HashMap::new()
                };

                // For PTR records, parse the target for instance/service
                if rtype == RecordType::PTR.to_u16() && !rdata.is_empty() {
                    if let Ok((target_name, _)) = Self::parse_name(data, rdata_start) {
                        let (ptr_instance, ptr_service, _) = Self::parse_service_name(&target_name);
                        if ptr_instance.is_some() && instance.is_none() {
                            instance = ptr_instance;
                        }
                        if ptr_service.is_some() && service.is_none() {
                            service = ptr_service;
                        }
                    }
                }

                records.push(DnsRecord {
                    name,
                    record_type: RecordType::from_u16(rtype),
                    record_class: rclass,
                    ttl,
                    rdata,
                    instance,
                    service,
                    domain,
                    txt_records,
                });
            }

            Ok(records)
        };

        let answers = parse_rr(data, &mut offset, ancount)?;
        let authorities = parse_rr(data, &mut offset, nscount)?;
        let additionals = parse_rr(data, &mut offset, arcount)?;

        Ok(ParsedMdnsPacket {
            transaction_id,
            flags,
            is_response,
            is_authoritative,
            is_truncated,
            questions,
            answers,
            authorities,
            additionals,
            src_ip,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test parse_name with simple names
    #[test]
    fn test_parse_name_simple() {
        // "local" = 5 'l' 'o' 'c' 'a' 'l' 0
        let data = b"\x05local\x00";
        let (name, offset) = MdnsParser::parse_name(data, 0).unwrap();
        assert_eq!(name, "local");
        assert_eq!(offset, 7);
    }

    #[test]
    fn test_parse_name_multiple_labels() {
        // "_googlecast._tcp.local"
        let data = b"\x0b_googlecast\x04_tcp\x05local\x00";
        let (name, offset) = MdnsParser::parse_name(data, 0).unwrap();
        assert_eq!(name, "_googlecast._tcp.local");
        assert_eq!(offset, data.len());
    }

    #[test]
    fn test_parse_name_with_compression() {
        // Build packet with compression pointer
        // Offset 0: "\x05local\x00" (7 bytes)
        // Offset 7: "\x03foo\xC0\x00" (5 bytes: length + "foo" + 2-byte pointer)
        let data = b"\x05local\x00\x03foo\xC0\x00";
        let (name, offset) = MdnsParser::parse_name(data, 7).unwrap();
        assert_eq!(name, "foo.local");
        assert_eq!(offset, 13); // After the compression pointer (7 + 1 + 3 + 2)
    }

    // Test parse_service_name
    #[test]
    fn test_parse_service_name_full() {
        let (instance, service, domain) =
            MdnsParser::parse_service_name("Google-Cast-Group-xxx._googlecast._tcp.local");
        assert_eq!(instance, Some("Google-Cast-Group-xxx".to_string()));
        assert_eq!(service, Some("_googlecast._tcp".to_string()));
        assert_eq!(domain, "local");
    }

    #[test]
    fn test_parse_service_name_no_instance() {
        let (instance, service, domain) = MdnsParser::parse_service_name("_googlecast._tcp.local");
        assert_eq!(instance, None);
        assert_eq!(service, Some("_googlecast._tcp".to_string()));
        assert_eq!(domain, "local");
    }

    #[test]
    fn test_parse_service_name_no_service() {
        let (instance, service, domain) = MdnsParser::parse_service_name("somehost.local");
        assert_eq!(instance, None);
        assert_eq!(service, None);
        assert_eq!(domain, "local");
    }

    #[test]
    fn test_parse_service_name_udp() {
        let (instance, service, domain) = MdnsParser::parse_service_name("printer._ipp._udp.local");
        assert_eq!(instance, Some("printer".to_string()));
        assert_eq!(service, Some("_ipp._udp".to_string()));
        assert_eq!(domain, "local");
    }

    // Test parse_txt_record
    #[test]
    fn test_parse_txt_record_single() {
        // "fn=Living Room" = 14 bytes, length prefix = 1
        let data = b"\x0efn=Living Room";
        let result = MdnsParser::parse_txt_record(data);
        assert_eq!(result.get("fn"), Some(&"Living Room".to_string()));
    }

    #[test]
    fn test_parse_txt_record_multiple() {
        // Two TXT strings: "fn=Living Room" and "md=Chromecast"
        let data = b"\x0efn=Living Room\x0dmd=Chromecast";
        let result = MdnsParser::parse_txt_record(data);
        assert_eq!(result.get("fn"), Some(&"Living Room".to_string()));
        assert_eq!(result.get("md"), Some(&"Chromecast".to_string()));
    }

    #[test]
    fn test_parse_txt_record_flag() {
        // Flag without value: "enabled"
        let data = b"\x07enabled";
        let result = MdnsParser::parse_txt_record(data);
        assert_eq!(result.get("enabled"), Some(&String::new()));
    }

    // Test full packet parsing
    #[test]
    fn test_parse_query_packet() {
        // Simple mDNS query for _googlecast._tcp.local
        #[rustfmt::skip]
        let packet: &[u8] = &[
            // Header
            0x00, 0x00, // Transaction ID
            0x00, 0x00, // Flags (query)
            0x00, 0x01, // Questions: 1
            0x00, 0x00, // Answers: 0
            0x00, 0x00, // Authority: 0
            0x00, 0x00, // Additional: 0
            // Question: _googlecast._tcp.local PTR
            0x0b, b'_', b'g', b'o', b'o', b'g', b'l', b'e', b'c', b'a', b's', b't',
            0x04, b'_', b't', b'c', b'p',
            0x05, b'l', b'o', b'c', b'a', b'l',
            0x00, // End of name
            0x00, 0x0c, // Type: PTR
            0x00, 0x01, // Class: IN
        ];

        let result = MdnsParser::parse(packet, None).unwrap();

        assert!(!result.is_response);
        assert_eq!(result.questions.len(), 1);
        assert_eq!(result.questions[0].name, "_googlecast._tcp.local");
        assert_eq!(result.questions[0].record_type, RecordType::PTR);
        assert_eq!(
            result.questions[0].service,
            Some("_googlecast._tcp".to_string())
        );
    }

    #[test]
    fn test_parse_response_packet() {
        // Simple mDNS response
        #[rustfmt::skip]
        let packet: &[u8] = &[
            // Header
            0x00, 0x00, // Transaction ID
            0x84, 0x00, // Flags (response, authoritative)
            0x00, 0x00, // Questions: 0
            0x00, 0x01, // Answers: 1
            0x00, 0x00, // Authority: 0
            0x00, 0x00, // Additional: 0
            // Answer: _googlecast._tcp.local PTR -> Device._googlecast._tcp.local
            0x0b, b'_', b'g', b'o', b'o', b'g', b'l', b'e', b'c', b'a', b's', b't',
            0x04, b'_', b't', b'c', b'p',
            0x05, b'l', b'o', b'c', b'a', b'l',
            0x00, // End of name
            0x00, 0x0c, // Type: PTR
            0x80, 0x01, // Class: IN with cache-flush
            0x00, 0x00, 0x11, 0x94, // TTL: 4500
            0x00, 0x09, // RDLENGTH: 9
            // RDATA: Device (pointer to _googlecast._tcp.local)
            0x06, b'D', b'e', b'v', b'i', b'c', b'e',
            0xc0, 0x0c, // Compression pointer to offset 12
        ];

        let result = MdnsParser::parse(packet, None).unwrap();

        assert!(result.is_response);
        assert!(result.is_authoritative);
        assert_eq!(result.answers.len(), 1);
        assert_eq!(result.answers[0].name, "_googlecast._tcp.local");
        assert_eq!(result.answers[0].record_type, RecordType::PTR);
        assert_eq!(result.answers[0].ttl, 4500);
        // Instance should be parsed from PTR target
        assert_eq!(result.answers[0].instance, Some("Device".to_string()));
    }

    #[test]
    fn test_parse_packet_too_short() {
        let packet = &[0x00, 0x00, 0x00];
        assert!(MdnsParser::parse(packet, None).is_err());
    }

    #[test]
    fn test_parse_with_src_ip() {
        #[rustfmt::skip]
        let packet: &[u8] = &[
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        let src = Ipv4Addr::new(192, 168, 1, 100);
        let result = MdnsParser::parse(packet, Some(src)).unwrap();
        assert_eq!(result.src_ip, Some(src));
    }
}
