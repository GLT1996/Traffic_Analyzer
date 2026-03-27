"""ICMP protocol dissector."""

from ..protocol_dissector import (
    ProtocolDissector, DissectionResult, Layer, FieldSpec
)


class ICMPDissector(ProtocolDissector):
    """Dissector for ICMP protocol."""

    TYPE_MAP = {
        0: "Echo Reply",
        3: "Destination Unreachable",
        4: "Source Quench",
        5: "Redirect",
        8: "Echo Request",
        9: "Router Advertisement",
        10: "Router Solicitation",
        11: "Time Exceeded",
        12: "Parameter Problem",
        13: "Timestamp Request",
        14: "Timestamp Reply",
        17: "Address Mask Request",
        18: "Address Mask Reply",
    }

    UNREACHABLE_CODES = {
        0: "Network Unreachable",
        1: "Host Unreachable",
        2: "Protocol Unreachable",
        3: "Port Unreachable",
        4: "Fragmentation Needed",
        5: "Source Route Failed",
        6: "Network Unknown",
        7: "Host Unknown",
        9: "Network Prohibited",
        10: "Host Prohibited",
        11: "TOS Network Unreachable",
        12: "TOS Host Unreachable",
        13: "Communication Prohibited",
        14: "Host Precedence Violation",
        15: "Precedence Cutoff",
    }

    @property
    def protocol_name(self) -> str:
        return "ICMP"

    @property
    def layer(self) -> Layer:
        return Layer.TRANSPORT

    @property
    def fields(self) -> list:
        return [
            FieldSpec("type", 0, 8, int),
            FieldSpec("code", 8, 8, int),
            FieldSpec("checksum", 16, 16, int, "hex"),
            FieldSpec("rest_of_header", 32, 32, int, "hex"),
        ]

    def can_dissect(self, data: bytes, context: dict) -> bool:
        return context.get("protocol") == "ICMP" or len(data) >= 8

    def dissect(self, data: bytes, context: dict) -> DissectionResult:
        if len(data) < 8:
            return DissectionResult(
                protocol=self.protocol_name,
                fields={},
                raw_data=data,
                warnings=["Truncated ICMP header"]
            )

        fields = self._parse_fields(data)

        icmp_type = fields.get("type", 0)
        code = fields.get("code", 0)

        # Get type name
        type_name = self.TYPE_MAP.get(icmp_type, f"Unknown({icmp_type})")
        fields["type_str"] = type_name

        # Get code description for Destination Unreachable
        if icmp_type == 3:
            fields["code_str"] = self.UNREACHABLE_CODES.get(code, f"Unknown Code({code})")

        # For Echo Request/Reply, extract ID and Sequence
        if icmp_type in (0, 8):
            fields["id"] = (fields.get("rest_of_header", 0) >> 16) & 0xFFFF
            fields["sequence"] = fields.get("rest_of_header", 0) & 0xFFFF

        # Payload
        payload = data[8:]

        # Build summary
        summary = f"{type_name}"
        if icmp_type == 3:
            summary += f" ({fields.get('code_str', f'code {code}')})"
        elif icmp_type in (0, 8):
            summary += f" id={fields.get('id', 0)} seq={fields.get('sequence', 0)}"

        return DissectionResult(
            protocol=self.protocol_name,
            fields=fields,
            raw_data=data[:8],
            payload=payload,
            next_protocol=None,
            summary=summary
        )