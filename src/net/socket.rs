//! Multicast socket creation and management.

use std::net::{Ipv4Addr, SocketAddrV4};

use socket2::{Domain, Protocol, Socket, Type};

use crate::error::Result;
use crate::mdns::{MDNS_PORT, MULTICAST_ADDRESS};
use crate::net::InterfaceInfo;

/// Create a multicast UDP socket bound to an interface.
///
/// The socket is configured for:
/// - UDP multicast reception on the mDNS address (224.0.0.251:5353)
/// - Bound to the specific interface
/// - Multicast loop disabled (don't receive our own packets)
/// - Address reuse enabled (multiple listeners)
pub fn create_multicast_socket(interface: &InterfaceInfo) -> Result<Socket> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;

    // Allow address reuse
    socket.set_reuse_address(true)?;

    // On Linux, also set SO_REUSEPORT
    #[cfg(target_os = "linux")]
    socket.set_reuse_port(true)?;

    // Bind to the mDNS port on all interfaces
    let bind_addr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, MDNS_PORT);
    socket.bind(&bind_addr.into())?;

    // Join the mDNS multicast group on this interface
    socket.join_multicast_v4(&MULTICAST_ADDRESS, &interface.addr)?;

    // Disable multicast loopback
    socket.set_multicast_loop_v4(false)?;

    // Set multicast interface for outgoing packets
    socket.set_multicast_if_v4(&interface.addr)?;

    // Set non-blocking mode for async operation
    socket.set_nonblocking(true)?;

    Ok(socket)
}

/// Runtime wrapper combining interface info with its socket.
pub struct InterfaceSocket {
    /// Interface information.
    pub info: InterfaceInfo,
    /// The UDP socket bound to this interface.
    pub socket: Socket,
}

impl InterfaceSocket {
    /// Create a new interface socket.
    pub fn new(info: InterfaceInfo) -> Result<Self> {
        let socket = create_multicast_socket(&info)?;
        Ok(Self { info, socket })
    }

    /// Get the interface name.
    pub fn ifname(&self) -> &str {
        &self.info.ifname
    }

    /// Get the interface address.
    pub fn addr(&self) -> Ipv4Addr {
        self.info.addr
    }
}

impl std::fmt::Display for InterfaceSocket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.info)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Note: These tests require network capabilities and may fail
    // in restricted environments (containers, sandboxes, etc.)

    #[test]
    fn test_interface_socket_display() {
        // Just test display formatting without actually creating a socket
        let info = InterfaceInfo::new(
            "eth0".to_string(),
            Ipv4Addr::new(192, 168, 1, 100),
            Ipv4Addr::new(255, 255, 255, 0),
        );

        let display = format!("{}", info);
        assert!(display.contains("eth0"));
    }

    // Socket creation tests are commented out as they require
    // CAP_NET_RAW or root privileges on most systems
    /*
    #[test]
    fn test_create_multicast_socket() {
        let info = InterfaceInfo::new(
            "lo".to_string(),
            Ipv4Addr::new(127, 0, 0, 1),
            Ipv4Addr::new(255, 0, 0, 0),
        );

        let result = create_multicast_socket(&info);
        // May fail due to permissions
        if let Ok(socket) = result {
            assert!(socket.local_addr().is_ok());
        }
    }
    */
}
