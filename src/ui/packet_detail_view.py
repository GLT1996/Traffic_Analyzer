"""Packet detail view with hex display."""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QSplitter, QTextEdit, QTreeWidget, QTreeWidgetItem
)
from PyQt6.QtCore import Qt

from ..models.packet import Packet


class PacketDetailView(QWidget):
    """Detailed packet info with hex view."""

    def __init__(self):
        super().__init__()
        self._init_ui()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(4, 4, 4, 4)

        # Splitter for info and hex
        splitter = QSplitter(Qt.Orientation.Vertical)

        # Info tree
        self._tree = QTreeWidget()
        self._tree.setHeaderLabel("Packet Details")
        self._tree.setStyleSheet("""
            QTreeWidget { background: #1e1e1e; color: #d4d4d4; border: 1px solid #3d3d3d; }
            QTreeWidget::item:selected { background: #4a90d9; }
        """)
        splitter.addWidget(self._tree)

        # Payload view
        self._payload_view = QTextEdit()
        self._payload_view.setReadOnly(True)
        self._payload_view.setStyleSheet("""
            QTextEdit { background: #0d1117; color: #58a6ff; font-family: Consolas; font-size: 11px; }
        """)
        splitter.addWidget(self._payload_view)

        splitter.setSizes([180, 220])
        layout.addWidget(splitter)

    def set_packet(self, p: Packet):
        """Display packet details."""
        self._tree.clear()
        self._payload_view.clear()

        if not p:
            return

        # Build info tree
        root = QTreeWidgetItem([f"Frame {p.index}"])
        root.setExpanded(True)

        # Basic info
        QTreeWidgetItem(root, [f"Time: {p.time_str}"])
        QTreeWidgetItem(root, [f"Length: {p.length} bytes"])
        QTreeWidgetItem(root, [f"Protocol: {p.protocol or 'Unknown'}"])

        # Addresses
        addr_item = QTreeWidgetItem(root, ["Addresses"])
        if p.src_ip:
            src_text = f"{p.src_ip}:{p.src_port}" if p.src_port else p.src_ip
            QTreeWidgetItem(addr_item, [f"Source: {src_text}"])
        if p.dst_ip:
            dst_text = f"{p.dst_ip}:{p.dst_port}" if p.dst_port else p.dst_ip
            QTreeWidgetItem(addr_item, [f"Destination: {dst_text}"])
        addr_item.setExpanded(True)

        # Protocol layers
        if p.raw_data:
            self._parse_protocol_layers(root, p.raw_data)

        # Payload info
        if p.payload:
            payload_item = QTreeWidgetItem(root, ["Payload"])
            QTreeWidgetItem(payload_item, [f"Size: {len(p.payload)} bytes"])
            QTreeWidgetItem(payload_item, [f"Preview: {self._preview(p.payload)}"])
            payload_item.setExpanded(True)

        self._tree.addTopLevelItem(root)

        # Show payload in detail
        self._show_payload(p)

    def _preview(self, data: bytes, max_len: int = 50) -> str:
        """Get short preview of payload."""
        if not data:
            return "(empty)"

        # Check if it looks like text
        try:
            text = data.decode('utf-8', errors='strict')
            printable = sum(1 for c in text if c.isprintable() or c in '\n\r\t ')
            ratio = printable / len(text) if text else 0

            if ratio > 0.8:  # Mostly printable = text
                preview = ''.join(c if c.isprintable() or c in '\n\r\t' else '·' for c in text[:max_len])
                return f"[Text] {preview}"
            else:
                # Check for TLS/SSL
                if len(data) >= 3:
                    if data[0] == 0x16 and data[1] == 0x03:  # TLS handshake
                        return f"[TLS/SSL Encrypted] {data[:10].hex()}..."
                    elif data[0] == 0x17 and data[1] == 0x03:  # TLS application data
                        return f"[TLS Application Data] {data[:10].hex()}..."

                return f"[Binary] {data[:max_len//2].hex()}"
        except:
            # Not valid UTF-8
            return f"[Binary] {data[:max_len//2].hex()}"

    def _parse_protocol_layers(self, root: QTreeWidgetItem, data: bytes):
        """Parse and display protocol layers."""
        offset = 0

        # Ethernet header (14 bytes) - if present
        if len(data) >= 14:
            eth_item = QTreeWidgetItem(root, ["Ethernet II"])

            dst_mac = data[0:6].hex(':').upper()
            src_mac = data[6:12].hex(':').upper()
            ethertype = int.from_bytes(data[12:14], 'big')

            QTreeWidgetItem(eth_item, [f"Dst MAC: {dst_mac}"])
            QTreeWidgetItem(eth_item, [f"Src MAC: {src_mac}"])
            QTreeWidgetItem(eth_item, [f"Type: 0x{ethertype:04x}"])

            eth_item.setExpanded(True)
            offset = 14

        # IP header
        if len(data) >= offset + 20:
            ip_first = data[offset]
            version = (ip_first >> 4) & 0x0F

            if version == 4:
                ip_item = QTreeWidgetItem(root, ["IPv4"])

                ihl = (ip_first & 0x0F) * 4
                total_len = int.from_bytes(data[offset+2:offset+4], 'big')
                ttl = data[offset+8]
                proto = data[offset+9]
                src_ip = ".".join(str(b) for b in data[offset+12:offset+16])
                dst_ip = ".".join(str(b) for b in data[offset+16:offset+20])

                QTreeWidgetItem(ip_item, [f"Version: 4"])
                QTreeWidgetItem(ip_item, [f"Header Length: {ihl} bytes"])
                QTreeWidgetItem(ip_item, [f"Total Length: {total_len}"])
                QTreeWidgetItem(ip_item, [f"TTL: {ttl}"])
                QTreeWidgetItem(ip_item, [f"Protocol: {proto}"])
                QTreeWidgetItem(ip_item, [f"Source: {src_ip}"])
                QTreeWidgetItem(ip_item, [f"Destination: {dst_ip}"])

                ip_item.setExpanded(True)
                offset += ihl

                # TCP/UDP
                if proto == 6 and len(data) >= offset + 20:  # TCP
                    tcp_item = QTreeWidgetItem(root, ["TCP"])
                    src_port = int.from_bytes(data[offset:offset+2], 'big')
                    dst_port = int.from_bytes(data[offset+2:offset+4], 'big')
                    seq = int.from_bytes(data[offset+4:offset+8], 'big')
                    ack = int.from_bytes(data[offset+8:offset+12], 'big')
                    data_offset = (data[offset+12] >> 4) * 4
                    flags = data[offset+13]

                    QTreeWidgetItem(tcp_item, [f"Src Port: {src_port}"])
                    QTreeWidgetItem(tcp_item, [f"Dst Port: {dst_port}"])
                    QTreeWidgetItem(tcp_item, [f"Seq: {seq}"])
                    QTreeWidgetItem(tcp_item, [f"Ack: {ack}"])
                    QTreeWidgetItem(tcp_item, [f"Header Length: {data_offset} bytes"])

                    flag_str = self._parse_tcp_flags(flags)
                    QTreeWidgetItem(tcp_item, [f"Flags: {flag_str}"])

                    tcp_item.setExpanded(True)

                elif proto == 17 and len(data) >= offset + 8:  # UDP
                    udp_item = QTreeWidgetItem(root, ["UDP"])
                    src_port = int.from_bytes(data[offset:offset+2], 'big')
                    dst_port = int.from_bytes(data[offset+2:offset+4], 'big')
                    udp_len = int.from_bytes(data[offset+4:offset+6], 'big')

                    QTreeWidgetItem(udp_item, [f"Src Port: {src_port}"])
                    QTreeWidgetItem(udp_item, [f"Dst Port: {dst_port}"])
                    QTreeWidgetItem(udp_item, [f"Length: {udp_len}"])

                    udp_item.setExpanded(True)

    def _parse_tcp_flags(self, flags: int) -> str:
        """Parse TCP flags byte."""
        names = []
        if flags & 0x01: names.append("FIN")
        if flags & 0x02: names.append("SYN")
        if flags & 0x04: names.append("RST")
        if flags & 0x08: names.append("PSH")
        if flags & 0x10: names.append("ACK")
        if flags & 0x20: names.append("URG")
        return ", ".join(names) if names else "None"

    def _show_payload(self, p: Packet):
        """Show payload with multiple views."""
        if not p.payload:
            if p.raw_data:
                self._show_hex(p.raw_data)
            else:
                self._payload_view.setText("No data")
            return

        lines = []
        lines.append("═" * 60)
        lines.append(f"PAYLOAD ({len(p.payload)} bytes)")
        lines.append("═" * 60)

        # Detect content type
        content_type = self._detect_content(p.payload)
        lines.append(f"\nType: {content_type}")

        # Check if encrypted
        if content_type in ["TLS/SSL Encrypted", "TLS Application Data", "Binary Data"]:
            lines.append("\n⚠ This appears to be encrypted data (normal for HTTPS)")
            lines.append("\n[HEX VIEW - First 256 bytes]")
            lines.append("-" * 40)
            data = p.payload[:256]
            for i in range(0, len(data), 16):
                chunk = data[i:i+16]
                hex_str = " ".join(f"{b:02x}" for b in chunk)
                ascii_str = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
                lines.append(f"{i:04x}  {hex_str.ljust(47)}  |{ascii_str}|")
            if len(p.payload) > 256:
                lines.append(f"\n... {len(p.payload) - 256} more bytes")
        else:
            # Try to decode as text
            try:
                text = p.payload.decode('utf-8', errors='replace')
                lines.append("\n[TEXT VIEW]")
                lines.append("-" * 40)
                lines.append(text[:2000])
            except:
                lines.append("\n[HEX VIEW]")
                lines.append("-" * 40)
                data = p.payload[:256]
                for i in range(0, len(data), 16):
                    chunk = data[i:i+16]
                    hex_str = " ".join(f"{b:02x}" for b in chunk)
                    ascii_str = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
                    lines.append(f"{i:04x}  {hex_str.ljust(47)}  |{ascii_str}|")

        self._payload_view.setText("\n".join(lines))

    def _detect_content(self, data: bytes) -> str:
        """Detect the type of content in payload."""
        if not data:
            return "Empty"

        if len(data) >= 2:
            # TLS/SSL detection
            if data[0] == 0x16 and data[1] == 0x03:
                return "TLS/SSL Handshake"
            if data[0] == 0x17 and data[1] == 0x03:
                return "TLS Application Data"
            if data[0] == 0x15 and data[1] == 0x03:
                return "TLS Alert"

        # Check if mostly printable
        try:
            text = data.decode('utf-8', errors='strict')
            printable = sum(1 for c in text if c.isprintable() or c in '\n\r\t ')
            ratio = printable / len(text) if text else 0
            if ratio > 0.8:
                # Check for common protocols
                if text.startswith('GET ') or text.startswith('POST '):
                    return "HTTP Request"
                if text.startswith('HTTP/'):
                    return "HTTP Response"
                if text.startswith('{') or text.startswith('['):
                    return "JSON"
                return "Plain Text"
        except:
            pass

        return "Binary Data"

    def _show_hex(self, data: bytes):
        """Show hex dump of raw data."""
        if not data:
            self._payload_view.setText("No data")
            return

        lines = ["[RAW DATA - HEX VIEW]", "-" * 40]

        for i in range(0, min(len(data), 512), 16):
            chunk = data[i:i+16]
            hex_str = " ".join(f"{b:02x}" for b in chunk)
            hex_str = hex_str.ljust(47)
            ascii_str = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            lines.append(f"{i:06x}  {hex_str}  |{ascii_str}|")

        self._payload_view.setText("\n".join(lines))

    def clear(self):
        self._tree.clear()
        self._payload_view.clear()