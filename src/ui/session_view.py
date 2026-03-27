"""Simple session view."""

from PyQt6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton
from PyQt6.QtCore import QTimer
from collections import defaultdict

from ..models.packet import Packet


class SessionView(QWidget):
    """Minimal session tracking."""

    def __init__(self):
        super().__init__()
        self._sessions = defaultdict(lambda: {"packets": 0, "bytes": 0})

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        h = QHBoxLayout()
        self._label = QLabel("Sessions: 0")
        h.addWidget(self._label)
        h.addStretch()
        layout.addLayout(h)

        self._display = QLabel("-")
        self._display.setWordWrap(True)
        layout.addWidget(self._display)

        self._timer = QTimer()
        self._timer.timeout.connect(self._refresh)
        self._timer.start(2000)

    def process_packet(self, p: Packet):
        if p.src_ip and p.dst_ip:
            key = f"{p.src_ip} → {p.dst_ip}"
            self._sessions[key]["packets"] += 1
            self._sessions[key]["bytes"] += p.length

    def _refresh(self):
        self._label.setText(f"Sessions: {len(self._sessions)}")
        if self._sessions:
            top = sorted(self._sessions.items(), key=lambda x: -x[1]["packets"])[:5]
            lines = [f"{k}: {v['packets']} pkts" for k, v in top]
            self._display.setText("\n".join(lines))

    def _clear_sessions(self):
        self._sessions.clear()
        self._label.setText("Sessions: 0")
        self._display.setText("-")