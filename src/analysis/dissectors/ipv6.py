"""IPv6 protocol dissector."""

from ..protocol_dissector import (
    ProtocolDissector, DissectionResult, Layer, FieldSpec
)


class IPv6Dissector(ProtocolDissector):
    """Dissector for IPv6 protocol."""

    NEXT_HEADER_MAP = {
        0: "Hop-by-Hop",
        6: "TCP",
        17: "UDP",
        41: "IPv6",
        43: "Routing",
        44: "Fragment",
        50: "ESP",
        51: "AH",
        58: "ICMPv6",
        59: "No Next Header",
        60: "Destination Options",
    }

    @property
    def protocol_name(self) -> str:
        return "IPv6"

    @property
    def layer(self) -> Layer:
        return Layer.NETWORK

    @property
    def fields(self) -> list:
        return [
            FieldSpec("version", 0, 4, int),
            FieldSpec("traffic_class", 4, 8, int),
            FieldSpec("flow_label", 12, 20, int, "hex"),
            FieldSpec("payload_length", 32, 16, int),
            FieldSpec("next_header", 48, 8, int),
            FieldSpec("hop_limit", 56, 8, int),
            FieldSpec("src_ip", 64, 128, bytes),
            FieldSpec("dst_ip", 192, 128, bytes),
        ]

    def can_dissect(self, data: bytes, context: dict) -> bool:
        if len(data) < 40:
            return False
        version = (data[0] >> 4) & 0x0F
        return version == 6

    def dissect(self, data: bytes, context: dict) -> DissectionResult:
        if len(data) < 40:
            return DissectionResult(
                protocol=self.protocol_name,
                fields={},
                raw_data=data,
                warnings=["Truncated IPv6 header"]
            )

        fields = self._parse_fields(data)

        # Format IPv6 addresses
        src_ip_bytes = fields.get("src_ip", b"")
        dst_ip_bytes = fields.get("dst_ip", b"")
        fields["src_ip_str"] = self._format_ipv6(src_ip_bytes)
        fields["dst_ip_str"] = self._format_ipv6(dst_ip_bytes)

        # Next header
        next_header = fields.get("next_header", 0)
        next_protocol = self.NEXT_HEADER_MAP.get(next_header, f"Unknown({next_header})")
        fields["next_header_str"] = next_protocol

        # Payload
        payload = data[40:]

        return DissectionResult(
            protocol=self.protocol_name,
            fields=fields,
            raw_data=data[:40],
            payload=payload,
            next_protocol=next_protocol,
            summary=f"{fields['src_ip_str']} → {fields['dst_ip_str']}, Hop: {fields.get('hop_limit', 0)}, Next: {next_protocol}"
        )

    def _format_ipv6(self, addr: bytes) -> str:
        """Format IPv6 address."""
        if len(addr) != 16:
            return "Invalid"

        # Convert to hex groups
        groups = []
        for i in range(0, 16, 2):
            group = (addr[i] << 8) | addr[i + 1]
            groups.append(f"{group:x}")

        # Find longest run of zeros for compression
        best_start = 0
        best_len = 0
        current_start = 0
        current_len = 0

        for i, group in enumerate(groups):
            if group == "0":
                if current_len == 0:
                    current_start = i
                current_len += 1
                if current_len > best_len:
                    best_start = current_start
                    best_len = current_len
            else:
                current_len = 0

        # Compress
        if best_len >= 2:
            compressed = groups[:best_start] + [""] + groups[best_start + best_len:]
            return ":".join(compressed)
        else:
            return ":".join(groups)