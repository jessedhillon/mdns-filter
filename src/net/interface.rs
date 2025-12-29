//! Network interface information and discovery.

use std::net::Ipv4Addr;

use ipnet::Ipv4Net;
use nix::ifaddrs::getifaddrs;

use crate::error::{Error, Result};

/// Network interface information.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterfaceInfo {
    /// Interface name (e.g., "eth0", "wlan0").
    pub ifname: String,
    /// IPv4 address assigned to the interface.
    pub addr: Ipv4Addr,
    /// Network mask.
    pub mask: Ipv4Addr,
    /// Network (computed from addr and mask).
    pub network: Ipv4Net,
}

impl InterfaceInfo {
    /// Create InterfaceInfo from name, address, and mask.
    pub fn new(ifname: String, addr: Ipv4Addr, mask: Ipv4Addr) -> Self {
        let prefix_len = mask.octets().iter().map(|b| b.count_ones()).sum::<u32>() as u8;
        let network =
            Ipv4Net::new(addr, prefix_len).unwrap_or_else(|_| Ipv4Net::new(addr, 32).unwrap());

        Self {
            ifname,
            addr,
            mask,
            network,
        }
    }

    /// Look up interface information by name.
    pub fn from_name(ifname: &str) -> Result<Self> {
        let addrs = getifaddrs().map_err(|e| Error::NetworkError(std::io::Error::other(e)))?;

        for ifaddr in addrs {
            if ifaddr.interface_name != ifname {
                continue;
            }

            // Get IPv4 address
            let Some(addr) = ifaddr.address else {
                continue;
            };
            let Some(addr_in) = addr.as_sockaddr_in() else {
                continue;
            };
            let ip_addr = addr_in.ip();

            // Skip loopback and link-local
            if ip_addr.is_loopback() || ip_addr.is_link_local() {
                continue;
            }

            // Get netmask
            let mask = ifaddr
                .netmask
                .and_then(|m| m.as_sockaddr_in().map(|s| s.ip()))
                .unwrap_or(Ipv4Addr::new(255, 255, 255, 0));

            return Ok(Self::new(ifname.to_string(), ip_addr, mask));
        }

        Err(Error::InterfaceNotFound(ifname.to_string()))
    }

    /// List all network interfaces with IPv4 addresses.
    pub fn list_all() -> Result<Vec<Self>> {
        let addrs = getifaddrs().map_err(|e| Error::NetworkError(std::io::Error::other(e)))?;

        let mut interfaces = Vec::new();
        let mut seen_names = std::collections::HashSet::new();

        for ifaddr in addrs {
            if seen_names.contains(&ifaddr.interface_name) {
                continue;
            }

            let Some(addr) = ifaddr.address else {
                continue;
            };
            let Some(addr_in) = addr.as_sockaddr_in() else {
                continue;
            };
            let ip_addr = addr_in.ip();

            // Skip loopback
            if ip_addr.is_loopback() {
                continue;
            }

            let mask = ifaddr
                .netmask
                .and_then(|m| m.as_sockaddr_in().map(|s| s.ip()))
                .unwrap_or(Ipv4Addr::new(255, 255, 255, 0));

            seen_names.insert(ifaddr.interface_name.clone());
            interfaces.push(Self::new(ifaddr.interface_name, ip_addr, mask));
        }

        Ok(interfaces)
    }
}

impl std::fmt::Display for InterfaceInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "dev {} addr {} mask {} net {}",
            self.ifname, self.addr, self.mask, self.network
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_interface_info_new() {
        let info = InterfaceInfo::new(
            "eth0".to_string(),
            Ipv4Addr::new(192, 168, 1, 100),
            Ipv4Addr::new(255, 255, 255, 0),
        );

        assert_eq!(info.ifname, "eth0");
        assert_eq!(info.addr, Ipv4Addr::new(192, 168, 1, 100));
        assert_eq!(info.mask, Ipv4Addr::new(255, 255, 255, 0));
        assert_eq!(info.network.prefix_len(), 24);
    }

    #[test]
    fn test_interface_info_display() {
        let info = InterfaceInfo::new(
            "eth0".to_string(),
            Ipv4Addr::new(192, 168, 1, 100),
            Ipv4Addr::new(255, 255, 255, 0),
        );

        let display = format!("{}", info);
        assert!(display.contains("eth0"));
        assert!(display.contains("192.168.1.100"));
    }

    #[test]
    fn test_list_all_interfaces() {
        // This test may pass or fail depending on system configuration
        // Just ensure it doesn't panic
        let result = InterfaceInfo::list_all();
        assert!(result.is_ok());
    }

    #[test]
    fn test_interface_not_found() {
        let result = InterfaceInfo::from_name("nonexistent_interface_xyz");
        assert!(result.is_err());
        match result {
            Err(Error::InterfaceNotFound(name)) => {
                assert_eq!(name, "nonexistent_interface_xyz");
            }
            _ => panic!("Expected InterfaceNotFound error"),
        }
    }
}
