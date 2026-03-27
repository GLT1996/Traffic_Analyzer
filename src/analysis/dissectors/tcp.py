"""TCP protocol dissector."""

from ..protocol_dissector import (
    ProtocolDissector, DissectionResult, Layer, FieldSpec
)


class TCPDissector(ProtocolDissector):
    """Dissector for TCP protocol."""

    # Common ports
    PORT_MAP = {
        20: "FTP-DATA",
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",  # TCP DNS
        80: "HTTP",
        110: "POP3",
        143: "IMAP",
        443: "HTTPS",
        465: "SMTPS",
        993: "IMAPS",
        995: "POP3S",
        1433: "MSSQL",
        1521: "Oracle",
        3306: "MySQL",
        3389: "RDP",
        5432: "PostgreSQL",
        6379: "Redis",
        8080: "HTTP-Alt",
        8443: "HTTPS-Alt",
        27017: "MongoDB",
    }

    @property
    def protocol_name(self) -> str:
        return "TCP"

    @property
    def layer(self) -> Layer:
        return Layer.TRANSPORT

    @property
    def fields(self) -> list:
        return [
            FieldSpec("src_port", 0, 16, int),
            FieldSpec("dst_port", 16, 16, int),
            FieldSpec("seq_num", 32, 32, int, "hex"),
            FieldSpec("ack_num", 64, 32, int, "hex"),
            FieldSpec("data_offset", 96, 4, int),
            FieldSpec("reserved", 100, 3, int),
            FieldSpec("ns", 103, 1, int),
            FieldSpec("cwr", 104, 1, int),
            FieldSpec("ece", 105, 1, int),
            FieldSpec("urg", 106, 1, int),
            FieldSpec("ack", 107, 1, int),
            FieldSpec("psh", 108, 1, int),
            FieldSpec("rst", 109, 1, int),
            FieldSpec("syn", 110, 1, int),
            FieldSpec("fin", 111, 1, int),
            FieldSpec("window", 112, 16, int),
            FieldSpec("checksum", 128, 16, int, "hex"),
            FieldSpec("urgent_ptr", 144, 16, int),
        ]

    @property
    def port_ranges(self) -> list:
        return [(20, 21), (22, 22), (80, 80), (443, 443), (8080, 8080)]

    def can_dissect(self, data: bytes, context: dict) -> bool:
        # Check if context indicates TCP
        return context.get("protocol") == "TCP" or len(data) >= 20

    def dissect(self, data: bytes, context: dict) -> DissectionResult:
        if len(data) < 20:
            return DissectionResult(
                protocol=self.protocol_name,
                fields={},
                raw_data=data,
                warnings=["Truncated TCP header"]
            )

        fields = self._parse_fields(data)

        # Get header length
        data_offset = fields.get("data_offset", 5)
        header_length = data_offset * 4

        if header_length < 20 or header_length > len(data):
            header_length = 20

        # Format ports
        src_port = fields.get("src_port", 0)
        dst_port = fields.get("dst_port", 0)

        # Get service names
        src_service = self.PORT_MAP.get(src_port, "")
        dst_service = self.PORT_MAP.get(dst_port, "")
        fields["src_service"] = src_service
        fields["dst_service"] = dst_service

        # Format flags
        flags = self._get_flags(fields)
        fields["flags_str"] = flags

        # Determine next protocol based on port
        next_protocol = None
        if dst_port in self.PORT_MAP:
            next_protocol = self.PORT_MAP[dst_port]
        elif src_port in self.PORT_MAP:
            next_protocol = self.PORT_MAP[src_port]

        # Payload
        payload = data[header_length:]

        # Build summary
        summary = f"{src_port}"
        if src_service:
            summary += f" ({src_service})"
        summary += f" → {dst_port}"
        if dst_service:
            summary += f" ({dst_service})"
        summary += f" [{flags}] Seq={fields.get('seq_num', 0)}, Ack={fields.get('ack_num', 0)}, Win={fields.get('window', 0)}"

        return DissectionResult(
            protocol=self.protocol_name,
            fields=fields,
            raw_data=data[:header_length],
            payload=payload,
            next_protocol=next_protocol,
            summary=summary
        )

    def _get_flags(self, fields: dict) -> str:
        """Get TCP flags string."""
        flag_chars = []
        if fields.get("fin"):
            flag_chars.append("F")
        if fields.get("syn"):
            flag_chars.append("S")
        if fields.get("rst"):
            flag_chars.append("R")
        if fields.get("psh"):
            flag_chars.append("P")
        if fields.get("ack"):
            flag_chars.append("A")
        if fields.get("urg"):
            flag_chars.append("U")
        if fields.get("ece"):
            flag_chars.append("E")
        if fields.get("cwr"):
            flag_chars.append("C")
        return "".join(flag_chars) if flag_chars else "."