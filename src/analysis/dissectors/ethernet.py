"""Ethernet protocol dissector."""

from ..protocol_dissector import (
    ProtocolDissector, DissectionResult, Layer, FieldSpec
)


class EthernetDissector(ProtocolDissector):
    """Dissector for Ethernet (Layer 2) protocol."""

    ETHERTYPE_IP = 0x0800
    ETHERTYPE_IPV6 = 0x86DD
    ETHERTYPE_ARP = 0x0806

    ETHERTYPE_MAP = {
        0x0800: "IPv4",
        0x86DD: "IPv6",
        0x0806: "ARP",
        0x8035: "RARP",
        0x8100: "VLAN",
        0x88CC: "LLDP",
    }

    @property
    def protocol_name(self) -> str:
        return "Ethernet"

    @property
    def layer(self) -> Layer:
        return Layer.LINK

    @property
    def fields(self) -> list:
        return [
            FieldSpec("dst_mac", 0, 48, int, "mac"),
            FieldSpec("src_mac", 48, 48, int, "mac"),
            FieldSpec("ethertype", 96, 16, int, "hex"),
        ]

    def can_dissect(self, data: bytes, context: dict) -> bool:
        """Ethernet is always the first layer for network captures."""
        return len(data) >= 14

    def dissect(self, data: bytes, context: dict) -> DissectionResult:
        if len(data) < 14:
            return DissectionResult(
                protocol=self.protocol_name,
                fields={},
                raw_data=data,
                warnings=["Truncated Ethernet frame"]
            )

        fields = self._parse_fields(data)

        # Get ethertype
        ethertype = fields.get("ethertype", 0)

        # Format MAC addresses
        dst_mac = fields.get("dst_mac", 0)
        src_mac = fields.get("src_mac", 0)
        fields["dst_mac_str"] = self._format_mac(dst_mac)
        fields["src_mac_str"] = self._format_mac(src_mac)

        # Determine next protocol
        next_protocol = self.ETHERTYPE_MAP.get(ethertype, f"Unknown(0x{ethertype:04x})")

        # Payload starts after Ethernet header (14 bytes)
        payload = data[14:]

        return DissectionResult(
            protocol=self.protocol_name,
            fields=fields,
            raw_data=data[:14],
            payload=payload,
            next_protocol=next_protocol,
            summary=f"{fields['src_mac_str']} → {fields['dst_mac_str']}, Type: {next_protocol}"
        )

    def _format_mac(self, value: int) -> str:
        """Format MAC address."""
        return ":".join(f"{(value >> (40 - i * 8)) & 0xFF:02x}" for i in range(6))