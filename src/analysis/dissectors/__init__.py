"""Protocol dissectors package."""

from ..protocol_dissector import registry
from .ethernet import EthernetDissector
from .ipv4 import IPv4Dissector
from .ipv6 import IPv6Dissector
from .tcp import TCPDissector
from .udp import UDPDissector
from .icmp import ICMPDissector


# Register all dissectors
def register_all():
    """Register all available dissectors."""
    registry.register(EthernetDissector())
    registry.register(IPv4Dissector())
    registry.register(IPv6Dissector())
    registry.register(TCPDissector())
    registry.register(UDPDissector())
    registry.register(ICMPDissector())


# Auto-register on import
register_all()


__all__ = [
    'registry',
    'EthernetDissector',
    'IPv4Dissector',
    'IPv6Dissector',
    'TCPDissector',
    'UDPDissector',
    'ICMPDissector',
]