"""Main mDNS repeater/filter orchestration logic."""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import signal
import socket
import struct
import sys
import types
import typing as t

import pydantic as p

from mdns_filter import const
from mdns_filter.const import FilterAction
from mdns_filter.filter import FilterEngine
from mdns_filter.mdns import ParsedMDNSPacket
from mdns_filter.net import get_interface_info, InterfaceInfo, InterfaceSocket
from mdns_filter.parse import MDNSParser
from mdns_filter.rules import FilterConfig

logger = logging.getLogger(const.Package)


class RepeaterConfig(p.BaseModel):
    """Main configuration for the mDNS repeater."""

    model_config = p.ConfigDict(extra="forbid")

    interfaces: t.Annotated[
        list[str],
        p.Field(min_length=2, description="Network interfaces to bridge"),
    ]
    dry_run: bool = False
    filter_config: FilterConfig = p.Field(default_factory=FilterConfig)


class MDNSRepeater:
    """Main mDNS repeater class."""

    def __init__(self, config: RepeaterConfig) -> None:
        self.config = config
        self.filter_engine = FilterEngine(config.filter_config)

        self.server_socket: socket.socket | None = None
        self.interface_sockets: list[InterfaceSocket] = []
        self.shutdown_flag = False

    def _create_recv_socket(self) -> socket.socket:
        """Create the main receiving socket for mDNS multicast."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)

        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            except AttributeError:
                pass

            sock.bind(("", const.MdnsPort))
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 1)

            try:
                sock.setsockopt(socket.IPPROTO_IP, const.IP_PKTINFO, 1)
            except OSError:
                pass

            sock.setblocking(False)
            return sock

        except Exception:
            sock.close()
            raise

    def _create_send_socket(self, recv_sock: socket.socket, ifname: str) -> InterfaceSocket:
        """Create a sending socket bound to a specific interface."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)

        try:
            try:
                sock.setsockopt(socket.SOL_SOCKET, const.SO_BINDTODEVICE, ifname.encode("utf-8"))
            except OSError as err:
                logger.warning("SO_BINDTODEVICE failed for %s: %s (may need root)", ifname, err)

            addr, mask = get_interface_info(sock, ifname)

            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            except AttributeError:
                pass

            sock.bind((str(addr), const.MdnsPort))
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(str(addr)))

            mreq = struct.pack("4s4s", socket.inet_aton(const.MdnsAddr), socket.inet_aton(str(addr)))
            recv_sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 1)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)

            sock.setblocking(False)

            info = InterfaceInfo.from_interface(ifname, addr, mask)
            iface_sock = InterfaceSocket(info, sock)
            logger.info("%s", iface_sock)
            return iface_sock

        except Exception:
            sock.close()
            raise

    def _send_packet(self, sock: socket.socket, data: bytes) -> int:
        """Send a packet to the mDNS multicast address."""
        return sock.sendto(data, (const.MdnsAddr, const.MdnsPort))

    def _is_from_our_network(self, from_addr: ipaddress.IPv4Address) -> bool:
        """Check if packet originated from one of our configured networks."""
        return any(from_addr in iface.network for iface in self.interface_sockets)

    def _is_loopback(self, from_addr: ipaddress.IPv4Address) -> bool:
        """Check if packet is from one of our own interface addresses."""
        return any(from_addr == iface.addr for iface in self.interface_sockets)

    def _evaluate_packet(
        self, from_addr: ipaddress.IPv4Address, data: bytes
    ) -> tuple[bool, ParsedMDNSPacket | None, str]:
        """
        Evaluate whether a packet should be forwarded.

        Returns:
            Tuple of (should_forward, parsed_packet, reason)
            - should_forward: True if packet should be forwarded
            - parsed_packet: Parsed mDNS packet (if parsing succeeded)
            - reason: Human-readable reason for the decision
        """
        # Basic network checks
        if not self._is_from_our_network(from_addr):
            return False, None, "not from our network"

        if self._is_loopback(from_addr):
            return False, None, "loopback (our own packet)"

        # Parse the packet
        packet = MDNSParser.parse(data, from_addr)

        # Content-based filtering
        if self.config.filter_config.rules:
            if packet is None:
                action = self.config.filter_config.default_action
                reason = f"parse failed, using default: {action.value}"
            else:
                action, rule_name = self.filter_engine.evaluate(packet)
                if rule_name:
                    reason = f"rule '{rule_name}': {action.value}"
                else:
                    reason = f"no rule matched, default: {action.value}"

            if action == FilterAction.Deny:
                return False, packet, reason
            else:
                return True, packet, reason

        # No content filtering configured - allow
        return True, packet, "allowed (no filters)"

    def _get_source_network(self, from_addr: ipaddress.IPv4Address) -> ipaddress.IPv4Network | None:
        """Get the network from which a packet originated."""
        for iface in self.interface_sockets:
            if from_addr in iface.network:
                return iface.network
        return None

    async def _handle_packet(self, data: bytes, from_addr: tuple[str, int]) -> None:
        """Handle a received mDNS packet."""
        addr = ipaddress.IPv4Address(from_addr[0])

        # Evaluate the packet
        should_forward, packet, reason = self._evaluate_packet(addr, data)

        # Format packet summary for logging
        if packet:
            packet_summary = packet.format_summary()
        else:
            packet_summary = f"{len(data)} bytes from {addr}"

        # Handle denied packets
        if not should_forward:
            logger.info("DENY: %s (%s)", packet_summary, reason)
            return

        # Get target interfaces
        source_net = self._get_source_network(addr)
        target_ifaces = [iface for iface in self.interface_sockets if iface.network != source_net]
        target_names = [iface.ifname for iface in target_ifaces]

        # Dry run mode - just log what would happen
        if self.config.dry_run:
            logger.info(
                "WOULD FORWARD: %s -> [%s] (%s)",
                packet_summary,
                ", ".join(target_names),
                reason,
            )
            if packet:
                logger.debug("\n%s", packet.format_detailed())
            return

        # Actually forward the packet
        logger.info("FORWARD: %s -> [%s] (%s)", packet_summary, ", ".join(target_names), reason)

        for iface in target_ifaces:
            try:
                sent = self._send_packet(iface.sockfd, data)
                if sent != len(data):
                    logger.error("Partial send to %s: expected %d, sent %d", iface.ifname, len(data), sent)
            except OSError as err:
                logger.error("Send error on %s: %s", iface.ifname, err)

    async def _receive_loop(self) -> None:
        """Main receive loop using asyncio."""
        assert self.server_socket is not None
        loop = asyncio.get_event_loop()

        while not self.shutdown_flag:
            try:
                future = loop.sock_recvfrom(self.server_socket, const.PacketSize)
                try:
                    data, from_addr = await asyncio.wait_for(future, timeout=10.0)
                    await self._handle_packet(data, from_addr)
                except asyncio.TimeoutError:
                    continue
            except OSError as err:
                if not self.shutdown_flag:
                    logger.error("Receive error: %s", err)
                    await asyncio.sleep(1)

    def _signal_handler(self, signum: int, frame: types.FrameType | None) -> None:
        """Handle shutdown signals."""
        logger.info("Received signal %d, shutting down...", signum)
        self.shutdown_flag = True

    def _setup_logging(self) -> None:
        """Configure logging to stderr."""
        logging.basicConfig(
            level=logging.DEBUG,
            format=f"{const.Package}: %(message)s",
            stream=sys.stderr,
        )

    def _cleanup(self) -> None:
        """Clean up resources on shutdown."""
        if self.server_socket:
            self.server_socket.close()

        for iface in self.interface_sockets:
            iface.sockfd.close()

        logger.info("Exit.")

    def _log_filter_config(self) -> None:
        """Log the active filter configuration."""
        fc = self.config.filter_config
        logger.info("Filter default action: %s", fc.default_action.value)
        for rule in fc.rules:
            logger.info("  Rule '%s': %s", rule.name, rule.action.value)

    def run(self) -> int:
        """Main entry point."""
        self._setup_logging()

        # Log mode
        if self.config.dry_run:
            logger.info("DRY RUN MODE - packets will not actually be forwarded")

        # Log content filters
        if self.config.filter_config.rules:
            self._log_filter_config()

        try:
            self.server_socket = self._create_recv_socket()

            for ifname in self.config.interfaces:
                iface_sock = self._create_send_socket(self.server_socket, ifname)
                self.interface_sockets.append(iface_sock)

        except OSError as err:
            logger.error("Failed to create sockets: %s", err)
            self._cleanup()
            return 1

        signal.signal(signal.SIGTERM, self._signal_handler)
        signal.signal(signal.SIGINT, self._signal_handler)

        try:
            asyncio.run(self._receive_loop())
        except KeyboardInterrupt:
            pass
        finally:
            logger.info("Shutting down...")
            self._cleanup()

        return 0
