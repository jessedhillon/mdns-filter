"""Tests for mdns_filter.net module."""

from __future__ import annotations

import ipaddress
import socket
from unittest.mock import MagicMock

from mdns_filter.net import InterfaceInfo, InterfaceSocket


class TestInterfaceInfo:
    """Tests for InterfaceInfo model."""

    def test_from_interface_basic(self) -> None:
        info = InterfaceInfo.from_interface(
            ifname="eth0",
            addr=ipaddress.IPv4Address("192.168.1.100"),
            mask=ipaddress.IPv4Address("255.255.255.0"),
        )
        assert info.ifname == "eth0"
        assert info.addr == ipaddress.IPv4Address("192.168.1.100")
        assert info.mask == ipaddress.IPv4Address("255.255.255.0")
        assert info.network == ipaddress.IPv4Network("192.168.1.0/24")

    def test_from_interface_slash_16(self) -> None:
        info = InterfaceInfo.from_interface(
            ifname="wlan0",
            addr=ipaddress.IPv4Address("10.0.50.25"),
            mask=ipaddress.IPv4Address("255.255.0.0"),
        )
        assert info.network == ipaddress.IPv4Network("10.0.0.0/16")

    def test_from_interface_slash_8(self) -> None:
        info = InterfaceInfo.from_interface(
            ifname="lo",
            addr=ipaddress.IPv4Address("127.0.0.1"),
            mask=ipaddress.IPv4Address("255.0.0.0"),
        )
        assert info.network == ipaddress.IPv4Network("127.0.0.0/8")

    def test_from_interface_slash_32(self) -> None:
        info = InterfaceInfo.from_interface(
            ifname="ppp0",
            addr=ipaddress.IPv4Address("10.0.0.1"),
            mask=ipaddress.IPv4Address("255.255.255.255"),
        )
        assert info.network == ipaddress.IPv4Network("10.0.0.1/32")

    def test_str_representation(self) -> None:
        info = InterfaceInfo.from_interface(
            ifname="eth0",
            addr=ipaddress.IPv4Address("192.168.1.100"),
            mask=ipaddress.IPv4Address("255.255.255.0"),
        )
        result = str(info)
        assert "dev eth0" in result
        assert "addr 192.168.1.100" in result
        assert "mask 255.255.255.0" in result
        assert "net 192.168.1.0/24" in result

    def test_frozen_model(self) -> None:
        info = InterfaceInfo.from_interface(
            ifname="eth0",
            addr=ipaddress.IPv4Address("192.168.1.100"),
            mask=ipaddress.IPv4Address("255.255.255.0"),
        )
        try:
            info.ifname = "wlan0"  # type: ignore[misc]
            raise AssertionError("Should have raised an error")
        except Exception:
            pass  # Expected


class TestInterfaceSocket:
    """Tests for InterfaceSocket wrapper."""

    def test_properties(self) -> None:
        info = InterfaceInfo.from_interface(
            ifname="eth0",
            addr=ipaddress.IPv4Address("192.168.1.100"),
            mask=ipaddress.IPv4Address("255.255.255.0"),
        )
        mock_socket = MagicMock(spec=socket.socket)

        iface_sock = InterfaceSocket(info, mock_socket)

        assert iface_sock.ifname == "eth0"
        assert iface_sock.addr == ipaddress.IPv4Address("192.168.1.100")
        assert iface_sock.network == ipaddress.IPv4Network("192.168.1.0/24")
        assert iface_sock.sockfd is mock_socket

    def test_str_representation(self) -> None:
        info = InterfaceInfo.from_interface(
            ifname="wlan0",
            addr=ipaddress.IPv4Address("10.0.0.50"),
            mask=ipaddress.IPv4Address("255.255.255.0"),
        )
        mock_socket = MagicMock(spec=socket.socket)

        iface_sock = InterfaceSocket(info, mock_socket)
        result = str(iface_sock)

        assert "dev wlan0" in result
        assert "addr 10.0.0.50" in result

    def test_info_accessible(self) -> None:
        info = InterfaceInfo.from_interface(
            ifname="eth0",
            addr=ipaddress.IPv4Address("192.168.1.100"),
            mask=ipaddress.IPv4Address("255.255.255.0"),
        )
        mock_socket = MagicMock(spec=socket.socket)

        iface_sock = InterfaceSocket(info, mock_socket)

        assert iface_sock.info is info
        assert iface_sock.info.ifname == "eth0"
