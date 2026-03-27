"""Hex viewer widget for displaying packet data."""

from PyQt6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QLabel, QScrollBar
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QFont, QColor, QPalette, QTextCharFormat, QTextCursor


class HexViewer(QWidget):
    """Widget for displaying hex dump of packet data."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._data = b""
        self._bytes_per_line = 16
        self._highlight_range = (-1, -1)
        self._init_ui()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        # Header
        header_layout = QHBoxLayout()
        header = QLabel("Offset    00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F   ASCII")
        header.setFont(QFont("Consolas", 9))
        header.setStyleSheet("color: #888; padding: 4px; background: #2d2d2d;")
        header_layout.addWidget(header)
        header_layout.addStretch()
        layout.addLayout(header_layout)

        # Hex content
        self._content_label = QLabel()
        self._content_label.setFont(QFont("Consolas", 9))
        self._content_label.setStyleSheet("""
            QLabel {
                background-color: #1e1e1e;
                color: #d4d4d4;
                padding: 8px;
                border: 1px solid #3d3d3d;
            }
        """)
        self._content_label.setWordWrap(True)
        self._content_label.setAlignment(Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignLeft)

        layout.addWidget(self._content_label, 1)
        self.setLayout(layout)

    def set_data(self, data: bytes):
        """Set the data to display."""
        self._data = data
        self._update_display()

    def highlight_range(self, start: int, end: int):
        """Highlight a range of bytes."""
        self._highlight_range = (start, end)
        self._update_display()

    def clear_highlight(self):
        """Clear highlighting."""
        self._highlight_range = (-1, -1)
        self._update_display()

    def _update_display(self):
        """Update the hex display."""
        if not self._data:
            self._content_label.setText("<i>No data</i>")
            return

        lines = []
        data = self._data
        bpl = self._bytes_per_line

        for i in range(0, len(data), bpl):
            chunk = data[i:i + bpl]

            # Offset
            offset = f"{i:08x}"

            # Hex bytes
            hex_parts = []
            for j, b in enumerate(chunk):
                idx = i + j
                byte_str = f"{b:02x}"
                # Check if this byte should be highlighted
                start, end = self._highlight_range
                if start <= idx < end:
                    hex_parts.append(f'<span style="background-color: #4a90d9; color: white;">{byte_str}</span>')
                else:
                    hex_parts.append(byte_str)

            # Split into two groups of 8
            hex_part1 = " ".join(hex_parts[:8])
            hex_part2 = " ".join(hex_parts[8:]) if len(hex_parts) > 8 else ""

            if hex_part2:
                hex_str = f"{hex_part1}  {hex_part2}"
            else:
                hex_str = hex_part1

            # Pad hex string for alignment
            hex_str = hex_str.ljust(47)

            # ASCII
            ascii_chars = []
            for j, b in enumerate(chunk):
                idx = i + j
                char = chr(b) if 32 <= b < 127 else "."
                start, end = self._highlight_range
                if start <= idx < end:
                    ascii_chars.append(f'<span style="background-color: #4a90d9; color: white;">{char}</span>')
                else:
                    ascii_chars.append(char)
            ascii_str = "".join(ascii_chars)

            lines.append(f"<pre>{offset}  {hex_str}  {ascii_str}</pre>")

        self._content_label.setText("<br>".join(lines))

    def clear(self):
        """Clear the display."""
        self._data = b""
        self._content_label.setText("")