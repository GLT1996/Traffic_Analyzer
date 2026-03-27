"""UDP protocol dissector."""

from ..protocol_dissector import (
    ProtocolDissector, DissectionResult, Layer, FieldSpec
)


class UDPDissector(ProtocolDissector):
    """Dissector for UDP protocol."""

    PORT_MAP = {
        53: "DNS",
        67: "DHCP-Server",
        68: "DHCP-Client",
        69: "TFTP",
        123: "NTP",
        161: "SNMP",
        162: "SNMP-Trap",
        500: "IKE",
        514: "Syslog",
        1701: "L2TP",
        4500: "IKE-NAT",
        5353: "mDNS",
    }

    @property
    def protocol_name(self) -> str:
        return "UDP"

    @property
    def layer(self) -> Layer:
        return Layer.TRANSPORT

    @property
    def fields(self) -> list:
        return [
            FieldSpec("src_port", 0, 16, int),
            FieldSpec("dst_port", 16, 16, int),
            FieldSpec("length", 32, 16, int),
            FieldSpec("checksum", 48, 16, int, "hex"),
        ]

    @property
    def port_ranges(self) -> list:
        return [(53, 53), (67, 68), (123, 123), (161, 162), (5353, 5353)]

    def can_dissect(self, data: bytes, context: dict) -> bool:
        return context.get("protocol") == "UDP" or len(data) >= 8

    def dissect(self, data: bytes, context: dict) -> DissectionResult:
        if len(data) < 8:
            return DissectionResult(
                protocol=self.protocol_name,
                fields={},
                raw_data=data,
                warnings=["Truncated UDP header"]
            )

        fields = self._parse_fields(data)

        src_port = fields.get("src_port", 0)
        dst_port = fields.get("dst_port", 0)
        length = fields.get("length", 0)

        # Get service names
        src_service = self.PORT_MAP.get(src_port, "")
        dst_service = self.PORT_MAP.get(dst_port, "")
        fields["src_service"] = src_service
        fields["dst_service"] = dst_service

        # Determine next protocol
        next_protocol = None
        if dst_port == 53 or src_port == 53:
            next_protocol = "DNS"
        elif dst_port == 123 or src_port == 123:
            next_protocol = "NTP"
        elif dst_port in (67, 68) or src_port in (67, 68):
            next_protocol = "DHCP"

        # Payload
        payload = data[8:]

        # Build summary
        summary = f"{src_port}"
        if src_service:
            summary += f" ({src_service})"
        summary += f" → {dst_port}"
        if dst_service:
            summary += f" ({dst_service})"
        summary += f" Len={length}"

        return DissectionResult(
            protocol=self.protocol_name,
            fields=fields,
            raw_data=data[:8],
            payload=payload,
            next_protocol=next_protocol,
            summary=summary
        )