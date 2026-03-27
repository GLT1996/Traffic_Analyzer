"""IPv4 protocol dissector."""

from ..protocol_dissector import (
    ProtocolDissector, DissectionResult, Layer, FieldSpec
)


class IPv4Dissector(ProtocolDissector):
    """Dissector for IPv4 protocol."""

    PROTOCOL_MAP = {
        1: "ICMP",
        2: "IGMP",
        6: "TCP",
        17: "UDP",
        41: "IPv6",
        47: "GRE",
        50: "ESP",
        51: "AH",
        89: "OSPF",
        132: "SCTP",
    }

    @property
    def protocol_name(self) -> str:
        return "IPv4"

    @property
    def layer(self) -> Layer:
        return Layer.NETWORK

    @property
    def fields(self) -> list:
        return [
            FieldSpec("version", 0, 4, int),
            FieldSpec("ihl", 4, 4, int),  # Header length in 32-bit words
            FieldSpec("dscp", 8, 6, int),
            FieldSpec("ecn", 14, 2, int),
            FieldSpec("total_length", 16, 16, int),
            FieldSpec("identification", 32, 16, int, "hex"),
            FieldSpec("flags", 48, 3, int),
            FieldSpec("fragment_offset", 51, 13, int),
            FieldSpec("ttl", 64, 8, int),
            FieldSpec("protocol", 72, 8, int),
            FieldSpec("checksum", 80, 16, int, "hex"),
            FieldSpec("src_ip", 96, 32, int, "ip"),
            FieldSpec("dst_ip", 128, 32, int, "ip"),
        ]

    def can_dissect(self, data: bytes, context: dict) -> bool:
        if len(data) < 20:
            return False
        version = (data[0] >> 4) & 0x0F
        return version == 4

    def dissect(self, data: bytes, context: dict) -> DissectionResult:
        if len(data) < 20:
            return DissectionResult(
                protocol=self.protocol_name,
                fields={},
                raw_data=data,
                warnings=["Truncated IPv4 header"]
            )

        fields = self._parse_fields(data)

        # Format IP addresses
        src_ip = fields.get("src_ip", 0)
        dst_ip = fields.get("dst_ip", 0)
        fields["src_ip_str"] = self._int_to_ip(src_ip)
        fields["dst_ip_str"] = self._int_to_ip(dst_ip)

        # Get header length
        ihl = fields.get("ihl", 5)
        header_length = ihl * 4

        if header_length < 20:
            return DissectionResult(
                protocol=self.protocol_name,
                fields=fields,
                raw_data=data[:header_length],
                warnings=[f"Invalid header length: {header_length}"]
            )

        # Flags
        flags = fields.get("flags", 0)
        fields["flags_str"] = self._format_flags(flags)

        # Protocol
        protocol = fields.get("protocol", 0)
        next_protocol = self.PROTOCOL_MAP.get(protocol, f"Unknown({protocol})")
        fields["protocol_str"] = next_protocol

        # Payload
        payload = data[header_length:]

        return DissectionResult(
            protocol=self.protocol_name,
            fields=fields,
            raw_data=data[:header_length],
            payload=payload,
            next_protocol=next_protocol,
            summary=f"{fields['src_ip_str']} → {fields['dst_ip_str']}, TTL: {fields.get('ttl', 0)}, Proto: {next_protocol}"
        )

    def _format_flags(self, flags: int) -> str:
        """Format IPv4 flags."""
        flag_names = []
        if flags & 0x04:  # Reserved
            flag_names.append("R")
        if flags & 0x02:  # Don't Fragment
            flag_names.append("DF")
        if flags & 0x01:  # More Fragments
            flag_names.append("MF")
        return ",".join(flag_names) if flag_names else "None"