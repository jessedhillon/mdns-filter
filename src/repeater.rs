//! Main mDNS repeater/filter orchestration logic.

use std::net::{Ipv4Addr, SocketAddrV4};
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use socket2::{Domain, Protocol, Socket, Type};
use tokio::io::unix::AsyncFd;
use tokio::io::Interest;
use tracing::{debug, error, info, warn};

use crate::config::FilterConfig;
use crate::error::Result;
use crate::filter::FilterEngine;
use crate::mdns::{FilterAction, MdnsParser, MDNS_PORT, MULTICAST_ADDRESS, PACKET_SIZE};
use crate::net::InterfaceInfo;

/// Configuration for the mDNS repeater.
#[derive(Debug, Clone)]
pub struct RepeaterConfig {
    /// Network interfaces to bridge (minimum 2).
    pub interfaces: Vec<String>,
    /// Dry run mode - don't actually forward packets.
    pub dry_run: bool,
    /// Filter configuration.
    pub filter_config: FilterConfig,
}

/// Interface with its send socket.
struct InterfaceSocket {
    info: InterfaceInfo,
    socket: Socket,
}

/// Main mDNS repeater.
pub struct MdnsRepeater {
    config: RepeaterConfig,
    filter_engine: FilterEngine,
    shutdown_flag: Arc<AtomicBool>,
}

impl MdnsRepeater {
    /// Create a new repeater with the given configuration.
    pub fn new(config: RepeaterConfig) -> Self {
        let filter_engine = FilterEngine::new(config.filter_config.clone());
        Self {
            config,
            filter_engine,
            shutdown_flag: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Create the main receiving socket for mDNS multicast.
    fn create_recv_socket(&self) -> Result<Socket> {
        let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;

        socket.set_reuse_address(true)?;
        #[cfg(target_os = "linux")]
        socket.set_reuse_port(true)?;

        // Bind to mDNS port on all interfaces
        let bind_addr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, MDNS_PORT);
        socket.bind(&bind_addr.into())?;

        // Enable multicast loop to receive our own packets (for debugging)
        socket.set_multicast_loop_v4(true)?;

        socket.set_nonblocking(true)?;

        Ok(socket)
    }

    /// Create a send socket for a specific interface.
    fn create_send_socket(&self, recv_socket: &Socket, ifname: &str) -> Result<InterfaceSocket> {
        let info = InterfaceInfo::from_name(ifname)?;

        let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;

        socket.set_reuse_address(true)?;
        #[cfg(target_os = "linux")]
        socket.set_reuse_port(true)?;

        // Bind to interface address
        let bind_addr = SocketAddrV4::new(info.addr, MDNS_PORT);
        socket.bind(&bind_addr.into())?;

        // Set multicast interface for outgoing packets
        socket.set_multicast_if_v4(&info.addr)?;

        // Join multicast group on recv socket for this interface
        recv_socket.join_multicast_v4(&MULTICAST_ADDRESS, &info.addr)?;

        // Set TTL for multicast packets
        socket.set_multicast_ttl_v4(255)?;
        socket.set_multicast_loop_v4(true)?;

        socket.set_nonblocking(true)?;

        info!("{}", info);

        Ok(InterfaceSocket { info, socket })
    }

    /// Check if packet originated from one of our configured networks.
    fn is_from_our_network(&self, from_addr: Ipv4Addr, interfaces: &[InterfaceSocket]) -> bool {
        interfaces
            .iter()
            .any(|iface| iface.info.network.contains(&from_addr))
    }

    /// Check if packet is from one of our own interface addresses (loopback).
    fn is_loopback(&self, from_addr: Ipv4Addr, interfaces: &[InterfaceSocket]) -> bool {
        interfaces.iter().any(|iface| iface.info.addr == from_addr)
    }

    /// Get the source network for an address.
    fn get_source_network(
        &self,
        from_addr: Ipv4Addr,
        interfaces: &[InterfaceSocket],
    ) -> Option<ipnet::Ipv4Net> {
        for iface in interfaces {
            if iface.info.network.contains(&from_addr) {
                return Some(iface.info.network);
            }
        }
        None
    }

    /// Handle a received packet.
    async fn handle_packet(
        &self,
        data: &[u8],
        from_addr: Ipv4Addr,
        interfaces: &[InterfaceSocket],
    ) {
        // Basic network checks
        if !self.is_from_our_network(from_addr, interfaces) {
            debug!("Ignoring packet from {} (not from our network)", from_addr);
            return;
        }

        if self.is_loopback(from_addr, interfaces) {
            return; // Silently ignore our own packets
        }

        // Parse the packet
        let packet = MdnsParser::parse(data, Some(from_addr)).ok();

        // Evaluate with filter engine
        let (should_forward, reason) = if !self.config.filter_config.rules.is_empty() {
            if let Some(ref pkt) = packet {
                let (action, rule_name) = self.filter_engine.evaluate(pkt);
                let reason = if let Some(name) = rule_name {
                    format!("rule '{}': {:?}", name, action)
                } else {
                    format!("no rule matched, default: {:?}", action)
                };
                (action == FilterAction::Allow, reason)
            } else {
                let action = self.config.filter_config.default_action;
                (
                    action == FilterAction::Allow,
                    format!("parse failed, default: {:?}", action),
                )
            }
        } else {
            (true, "allowed (no filters)".to_string())
        };

        // Format packet summary
        let packet_summary = if let Some(ref pkt) = packet {
            pkt.format_summary()
        } else {
            format!("{} bytes from {}", data.len(), from_addr)
        };

        // Handle denied packets
        if !should_forward {
            info!("DENY: {} ({})", packet_summary, reason);
            return;
        }

        // Get target interfaces (all except source network)
        let source_net = self.get_source_network(from_addr, interfaces);
        let target_ifaces: Vec<_> = interfaces
            .iter()
            .filter(|iface| Some(iface.info.network) != source_net)
            .collect();
        let target_names: Vec<_> = target_ifaces
            .iter()
            .map(|i| i.info.ifname.as_str())
            .collect();

        // Dry run mode
        if self.config.dry_run {
            info!(
                "WOULD FORWARD: {} -> [{}] ({})",
                packet_summary,
                target_names.join(", "),
                reason
            );
            if let Some(ref pkt) = packet {
                debug!("\n{}", pkt.format_detailed());
            }
            return;
        }

        // Actually forward
        info!(
            "FORWARD: {} -> [{}] ({})",
            packet_summary,
            target_names.join(", "),
            reason
        );

        let dest_addr = SocketAddrV4::new(MULTICAST_ADDRESS, MDNS_PORT);
        for iface in target_ifaces {
            match iface.socket.send_to(data, &dest_addr.into()) {
                Ok(sent) if sent != data.len() => {
                    error!(
                        "Partial send to {}: expected {}, sent {}",
                        iface.info.ifname,
                        data.len(),
                        sent
                    );
                }
                Err(err) => {
                    error!("Send error on {}: {}", iface.info.ifname, err);
                }
                Ok(_) => {}
            }
        }
    }

    /// Log the filter configuration.
    fn log_filter_config(&self) {
        let fc = &self.config.filter_config;
        info!("Filter default action: {:?}", fc.default_action);
        for rule in &fc.rules {
            info!("  Rule '{}': {:?}", rule.name, rule.action);
        }
    }

    /// Main entry point - runs the repeater.
    pub async fn run(&self) -> Result<i32> {
        // Log mode
        if self.config.dry_run {
            info!("DRY RUN MODE - packets will not actually be forwarded");
        }

        // Log content filters
        if !self.config.filter_config.rules.is_empty() {
            self.log_filter_config();
        }

        // Create sockets
        let recv_socket = self.create_recv_socket()?;
        let mut interface_sockets = Vec::new();

        for ifname in &self.config.interfaces {
            match self.create_send_socket(&recv_socket, ifname) {
                Ok(iface_sock) => interface_sockets.push(iface_sock),
                Err(err) => {
                    error!("Failed to create socket for {}: {}", ifname, err);
                    return Ok(1);
                }
            }
        }

        // Set up signal handling
        let shutdown = self.shutdown_flag.clone();
        tokio::spawn(async move {
            if let Ok(()) = tokio::signal::ctrl_c().await {
                info!("Received shutdown signal");
                shutdown.store(true, Ordering::SeqCst);
            }
        });

        // Convert to async fd
        let async_fd = AsyncFd::new(recv_socket.as_raw_fd())?;

        let mut buf = vec![std::mem::MaybeUninit::<u8>::uninit(); PACKET_SIZE];

        info!("Listening for mDNS packets...");

        // Main receive loop
        while !self.shutdown_flag.load(Ordering::SeqCst) {
            // Wait for readability
            let mut guard = match async_fd.ready(Interest::READABLE).await {
                Ok(guard) => guard,
                Err(err) => {
                    if !self.shutdown_flag.load(Ordering::SeqCst) {
                        error!("Poll error: {}", err);
                    }
                    continue;
                }
            };

            // Try to read
            match recv_socket.recv_from(&mut buf) {
                Ok((len, addr)) => {
                    guard.clear_ready();
                    if let Some(addr_in) = addr.as_socket_ipv4() {
                        // Safety: recv_from initialized len bytes
                        let data: &[u8] =
                            unsafe { std::slice::from_raw_parts(buf.as_ptr() as *const u8, len) };
                        self.handle_packet(data, *addr_in.ip(), &interface_sockets)
                            .await;
                    }
                }
                Err(ref err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    guard.clear_ready();
                    continue;
                }
                Err(err) => {
                    guard.clear_ready();
                    if !self.shutdown_flag.load(Ordering::SeqCst) {
                        warn!("Receive error: {}", err);
                    }
                }
            }
        }

        info!("Shutting down...");
        Ok(0)
    }
}
