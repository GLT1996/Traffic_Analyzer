"""Lightweight packet model."""

from dataclasses import dataclass
from datetime import datetime


@dataclass
class Packet:
    """Minimal packet data."""
    index: int
    timestamp: float
    length: int
    raw_data: bytes = b""
    payload: bytes = b""  # Application layer data
    src_ip: str = ""
    dst_ip: str = ""
    src_port: int = 0
    dst_port: int = 0
    protocol: str = ""
    process_name: str = ""  # Process associated with this packet

    @property
    def time_str(self) -> str:
        return datetime.fromtimestamp(self.timestamp).strftime("%H:%M:%S.%f")[:-3]

    @property
    def info_str(self) -> str:
        if self.src_port:
            return f"{self.protocol} {self.src_ip}:{self.src_port} → {self.dst_ip}:{self.dst_port}"
        return f"{self.protocol} {self.src_ip} → {self.dst_ip}"

    @property
    def payload_size(self) -> int:
        return len(self.payload)