"""Simple statistics panel."""

from PyQt6.QtWidgets import QWidget, QVBoxLayout, QLabel, QGroupBox
from PyQt6.QtCore import QTimer
from collections import Counter

from ..models.packet import Packet


class StatisticsPanel(QWidget):
    """Lightweight stats display."""

    def __init__(self):
        super().__init__()
        self._packets = 0
        self._bytes = 0
        self._protos = Counter()

        layout = QVBoxLayout(self)

        # Summary
        g1 = QGroupBox("Summary")
        l1 = QVBoxLayout(g1)
        self._sum_label = QLabel("Packets: 0 | Bytes: 0")
        l1.addWidget(self._sum_label)
        layout.addWidget(g1)

        # Protocols
        g2 = QGroupBox("Protocols")
        l2 = QVBoxLayout(g2)
        self._proto_label = QLabel("-")
        l2.addWidget(self._proto_label)
        layout.addWidget(g2)

        layout.addStretch()

        # Update timer
        self._timer = QTimer()
        self._timer.timeout.connect(self._refresh)
        self._timer.start(1000)

    def add_packet(self, p: Packet):
        self._packets += 1
        self._bytes += p.length
        if p.protocol:
            self._protos[p.protocol] += 1

    def _refresh(self):
        self._sum_label.setText(f"Packets: {self._packets:,} | Bytes: {self._fmt(self._bytes)}")
        if self._protos:
            lines = [f"{k}: {v}" for k, v in self._protos.most_common(5)]
            self._proto_label.setText("\n".join(lines))

    def _fmt(self, n):
        for u in ['B', 'KB', 'MB', 'GB']:
            if n < 1024:
                return f"{n:.1f}{u}"
            n /= 1024
        return f"{n:.1f}TB"

    def clear(self):
        self._packets = 0
        self._bytes = 0
        self._protos.clear()
        self._sum_label.setText("Packets: 0 | Bytes: 0")
        self._proto_label.setText("-")