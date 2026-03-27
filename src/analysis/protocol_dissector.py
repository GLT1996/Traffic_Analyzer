"""Base classes for protocol dissectors."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any, Tuple


class Layer(Enum):
    """Protocol layer enumeration."""
    LINK = 1        # Ethernet, etc.
    NETWORK = 2     # IP, IPv6
    TRANSPORT = 3   # TCP, UDP
    APPLICATION = 4 # HTTP, DNS, etc.


@dataclass
class FieldSpec:
    """Specification for a protocol field."""
    name: str
    offset: int         # Bit offset from start of header
    size: int           # Size in bits
    data_type: type     # int, str, bytes, etc.
    display_format: str = "normal"  # normal, hex, binary, ip, mac

    def extract(self, data: bytes) -> Any:
        """Extract the field value from data."""
        byte_offset = self.offset // 8
        bit_offset = self.offset % 8

        # Calculate how many bytes we need
        total_bits = bit_offset + self.size
        bytes_needed = (total_bits + 7) // 8
        bytes_needed = max(bytes_needed, 1)

        if byte_offset + bytes_needed > len(data):
            return None

        # Extract bytes
        chunk = data[byte_offset:byte_offset + bytes_needed]

        # Convert to integer
        value = int.from_bytes(chunk, byteorder='big')

        # Shift and mask
        shift = (bytes_needed * 8) - bit_offset - self.size
        value = (value >> shift) & ((1 << self.size) - 1)

        # Convert to appropriate type
        if self.data_type == int:
            return value
        elif self.data_type == str:
            return str(value)
        elif self.data_type == bytes:
            return data[byte_offset:byte_offset + (self.size // 8)]

        return value


@dataclass
class DissectionResult:
    """Result of protocol dissection."""
    protocol: str
    fields: Dict[str, Any]
    raw_data: bytes
    payload: bytes = b""
    next_protocol: Optional[str] = None
    summary: str = ""
    warnings: List[str] = field(default_factory=list)


class ProtocolDissector(ABC):
    """Abstract base class for protocol dissectors."""

    @property
    @abstractmethod
    def protocol_name(self) -> str:
        """Human-readable protocol name."""
        pass

    @property
    @abstractmethod
    def layer(self) -> Layer:
        """Protocol layer this dissector handles."""
        pass

    @property
    def fields(self) -> List[FieldSpec]:
        """List of field specifications."""
        return []

    @property
    def port_ranges(self) -> List[Tuple[int, int]]:
        """Default port ranges for this protocol (for heuristics)."""
        return []

    @abstractmethod
    def can_dissect(self, data: bytes, context: Dict[str, Any]) -> bool:
        """Check if this dissector can handle the data."""
        pass

    @abstractmethod
    def dissect(self, data: bytes, context: Dict[str, Any]) -> DissectionResult:
        """Parse the protocol and return structured data."""
        pass

    def _parse_fields(self, data: bytes) -> Dict[str, Any]:
        """Parse all defined fields from data."""
        result = {}
        for field_spec in self.fields:
            value = field_spec.extract(data)
            if value is not None:
                result[field_spec.name] = value
        return result

    def _format_value(self, value: Any, format_type: str) -> str:
        """Format a value for display."""
        if format_type == "hex":
            if isinstance(value, int):
                return f"0x{value:x}"
            elif isinstance(value, bytes):
                return value.hex()
        elif format_type == "ip":
            if isinstance(value, int):
                return self._int_to_ip(value)
        elif format_type == "mac":
            if isinstance(value, int):
                return self._int_to_mac(value)
        return str(value)

    @staticmethod
    def _int_to_ip(value: int) -> str:
        """Convert integer to IP address string."""
        return f"{(value >> 24) & 0xFF}.{(value >> 16) & 0xFF}.{(value >> 8) & 0xFF}.{value & 0xFF}"

    @staticmethod
    def _int_to_mac(value: int) -> str:
        """Convert integer to MAC address string."""
        return ":".join(f"{(value >> (40 - i * 8)) & 0xFF:02x}" for i in range(6))


class DissectorRegistry:
    """Registry for protocol dissectors."""

    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._dissectors = {}
            cls._instance._port_map = {}
        return cls._instance

    def register(self, dissector: ProtocolDissector):
        """Register a protocol dissector."""
        name = dissector.protocol_name.lower()
        self._dissectors[name] = dissector

        # Register port-based detection
        for start, end in dissector.port_ranges:
            for port in range(start, end + 1):
                self._port_map[port] = name

    def get(self, protocol_name: str) -> Optional[ProtocolDissector]:
        """Get a dissector by protocol name."""
        return self._dissectors.get(protocol_name.lower())

    def get_by_port(self, port: int) -> Optional[ProtocolDissector]:
        """Get a dissector by port number."""
        name = self._port_map.get(port)
        if name:
            return self._dissectors.get(name)
        return None

    def get_all(self) -> List[ProtocolDissector]:
        """Get all registered dissectors."""
        return list(self._dissectors.values())

    def get_by_layer(self, layer: Layer) -> List[ProtocolDissector]:
        """Get dissectors for a specific layer."""
        return [d for d in self._dissectors.values() if d.layer == layer]


# Global registry
registry = DissectorRegistry()