"""Network models and utilities."""

from __future__ import annotations

import fcntl
import ipaddress
import logging
import socket
import struct

import pydantic as p

from mdns_filter import const

logger = logging.getLogger(const.Package)


class InterfaceInfo(p.BaseModel):
    """Network interface information (without socket, which can't be serialized)."""

    model_config = p.ConfigDict(frozen=True)

    ifname: str
    addr: ipaddress.IPv4Address
    mask: ipaddress.IPv4Address
    network: ipaddress.IPv4Network

    @classmethod
    def from_interface(cls, ifname: str, addr: ipaddress.IPv4Address, mask: ipaddress.IPv4Address) -> "InterfaceInfo":
        """Create from interface name and address info."""
        prefix_len = bin(int(mask)).count("1")
        network = ipaddress.IPv4Network(f"{addr}/{prefix_len}", strict=False)
        return cls(ifname=ifname, addr=addr, mask=mask, network=network)

    def __str__(self) -> str:
        return f"dev {self.ifname} addr {self.addr} mask {self.mask} net {self.network}"


class InterfaceSocket:
    """Wrapper for interface info with its socket (runtime object)."""

    def __init__(self, info: InterfaceInfo, sockfd: socket.socket) -> None:
        self.info = info
        self.sockfd = sockfd

    @property
    def ifname(self) -> str:
        return self.info.ifname

    @property
    def addr(self) -> ipaddress.IPv4Address:
        return self.info.addr

    @property
    def network(self) -> ipaddress.IPv4Network:
        return self.info.network

    def __str__(self) -> str:
        return str(self.info)


def get_interface_info(sock: socket.socket, ifname: str) -> tuple[ipaddress.IPv4Address, ipaddress.IPv4Address]:
    """Get IP address and netmask for an interface using ioctl."""
    SIOCGIFADDR = 0x8915
    SIOCGIFNETMASK = 0x891B

    ifreq = struct.pack("256s", ifname.encode("utf-8")[:15])

    try:
        result = fcntl.ioctl(sock.fileno(), SIOCGIFNETMASK, ifreq)
        mask = ipaddress.IPv4Address(socket.inet_ntoa(result[20:24]))
    except OSError as err:
        logger.error("Failed to get netmask for %s: %s", ifname, err)
        raise

    try:
        result = fcntl.ioctl(sock.fileno(), SIOCGIFADDR, ifreq)
        addr = ipaddress.IPv4Address(socket.inet_ntoa(result[20:24]))
    except OSError as err:
        logger.error("Failed to get address for %s: %s", ifname, err)
        raise

    return addr, mask
