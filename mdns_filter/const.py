"""Constants and enums for mdns-filter."""

import enum

Package = "mdns-filter"
MdnsAddr = "224.0.0.251"
MdnsPort = 5353
PacketSize = 65536

# Socket options that may not be in the socket module
SO_BINDTODEVICE = 25
IP_PKTINFO = 8


class RecordType(enum.IntEnum):
    """DNS record types relevant to mDNS."""

    A = 1
    NS = 2
    CNAME = 5
    SOA = 6
    PTR = 12
    HINFO = 13
    MX = 15
    TXT = 16
    AAAA = 28
    SRV = 33
    NSEC = 47
    ANY = 255

    @classmethod
    def from_int(cls, value: int) -> "RecordType | int":
        """Convert int to RecordType, returning int if unknown."""
        try:
            return cls(value)
        except ValueError:
            return value


class RecordSection(enum.StrEnum):
    """Section of DNS message where a record appears."""

    Question = "question"
    Answer = "answer"
    Authority = "authority"
    Additional = "additional"


class FilterAction(enum.StrEnum):
    """Action to take when a filter rule matches."""

    Allow = "allow"
    Deny = "deny"


class LogLevel(enum.StrEnum):
    """Log level for filter rule logging."""

    Off = "none"
    Debug = "debug"
    Info = "info"
