"""Main window - Simplified for stability."""

import sys
from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QSplitter, QToolBar, QStatusBar, QComboBox,
    QLabel, QPushButton, QMessageBox, QFileDialog,
    QApplication, QLineEdit, QTabWidget
)
from PyQt6.QtCore import Qt, QTimer

from ..capture.interface_manager import InterfaceManager
from ..capture.packet_capture import PacketCapture
from ..capture.bpf_compiler import BPFCompiler
from ..capture.process_manager import process_manager
from ..models.packet import Packet
from ..core.export_manager import ExportManager
from .packet_list_view import PacketListView
from .packet_detail_view import PacketDetailView
from .statistics_panel import StatisticsPanel
from .session_view import SessionView


class MainWindow(QMainWindow):
    """Simplified main window for stability."""

    def __init__(self):
        super().__init__()

        self._interface_manager = InterfaceManager()
        self._capture = PacketCapture()
        self._running = False

        self._init_ui()
        self._populate_interfaces()

        # UI update timer - simple polling
        self._timer = QTimer()
        self._timer.timeout.connect(self._update_ui)
        self._timer.start(500)  # 500ms

    def _init_ui(self):
        self.setWindowTitle("Network Traffic Analyzer")
        self.setMinimumSize(1100, 700)
        self.setStyleSheet("""
            QMainWindow, QWidget { background: #1e1e1e; color: #d4d4d4; }
            QComboBox, QLineEdit { background: #2d2d2d; border: 1px solid #3d3d3d; padding: 4px; }
            QPushButton { background: #2d2d2d; border: 1px solid #3d3d3d; padding: 6px 12px; border-radius: 4px; }
            QPushButton:hover { background: #3d3d3d; }
            QPushButton:disabled { background: #1d1d1d; color: #666; }
            QTabWidget::pane { border: 1px solid #3d3d3d; }
            QTabBar::tab { background: #2d2d2d; padding: 6px 12px; }
        """)

        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)
        layout.setContentsMargins(8, 8, 8, 8)

        # Controls
        row1 = QHBoxLayout()
        row1.addWidget(QLabel("Interface:"))
        self._iface_combo = QComboBox()
        self._iface_combo.setMinimumWidth(200)
        row1.addWidget(self._iface_combo)

        row1.addWidget(QLabel("Process:"))
        self._process_combo = QComboBox()
        self._process_combo.setMinimumWidth(150)
        self._process_combo.addItem("All Processes", "")
        row1.addWidget(self._process_combo)

        self._refresh_proc_btn = QPushButton("Refresh")
        self._refresh_proc_btn.clicked.connect(self._refresh_processes)
        row1.addWidget(self._refresh_proc_btn)
        self._process_combo.currentIndexChanged.connect(self._on_process_changed)

        row1.addWidget(QLabel("Filter:"))
        self._filter_input = QLineEdit()
        self._filter_input.setPlaceholderText("tcp port 80")
        row1.addWidget(self._filter_input)
        row1.addStretch()
        layout.addLayout(row1)

        # Buttons
        row2 = QHBoxLayout()
        self._start_btn = QPushButton("▶ Start")
        self._start_btn.clicked.connect(self._start)
        row2.addWidget(self._start_btn)

        self._stop_btn = QPushButton("⏹ Stop")
        self._stop_btn.setEnabled(False)
        self._stop_btn.clicked.connect(self._stop)
        row2.addWidget(self._stop_btn)

        self._clear_btn = QPushButton("Clear")
        self._clear_btn.clicked.connect(self._clear)
        row2.addWidget(self._clear_btn)

        row2.addStretch()
        self._stats = QLabel("Packets: 0")
        row2.addWidget(self._stats)
        layout.addLayout(row2)

        # Content
        splitter = QSplitter(Qt.Orientation.Horizontal)

        # Left: packets
        self._packet_list = PacketListView()
        # Connect packet selection to detail view
        self._packet_list.packet_selected.connect(self._on_packet_selected)
        splitter.addWidget(self._packet_list)

        # Right: info
        right = QTabWidget()
        self._packet_detail = PacketDetailView()
        right.addTab(self._packet_detail, "Detail")

        self._stats_panel = StatisticsPanel()
        right.addTab(self._stats_panel, "Stats")

        splitter.addWidget(right)
        splitter.setSizes([700, 400])
        layout.addWidget(splitter, 1)

        # Status
        self.setStatusBar(QStatusBar())
        self.statusBar().showMessage("Ready")

        # Toolbar
        toolbar = QToolBar()
        self.addToolBar(toolbar)
        toolbar.addAction("Export PCAP", self._export)

    def _on_packet_selected(self, packet):
        """Handle packet selection - update detail view."""
        self._packet_detail.set_packet(packet)

    def _populate_interfaces(self):
        self._iface_combo.clear()
        ifaces = self._interface_manager.get_active_interfaces()
        if not ifaces:
            ifaces = self._interface_manager.get_interfaces()

        for i in ifaces:
            self._iface_combo.addItem(i.display_name, i.name)

        if not ifaces:
            self.statusBar().showMessage("No interfaces - install Npcap?")
            self._start_btn.setEnabled(False)

    def _refresh_processes(self):
        """Refresh the process dropdown list."""
        current = self._process_combo.currentData()
        self._process_combo.clear()
        self._process_combo.addItem("All Processes", "")

        processes = process_manager.get_all_processes()
        for proc in processes:
            self._process_combo.addItem(proc, proc)

        # Restore previous selection if still available
        if current:
            idx = self._process_combo.findData(current)
            if idx >= 0:
                self._process_combo.setCurrentIndex(idx)

        self.statusBar().showMessage(f"Found {len(processes)} processes with network activity")

    def _on_process_changed(self):
        """Handle process selection change."""
        process_name = self._process_combo.currentData()
        self._packet_list.set_process_filter(process_name)
        if process_name:
            self.statusBar().showMessage(f"Filtering: {process_name}")
        else:
            self.statusBar().showMessage("Showing all processes")

    def _start(self):
        iface = self._iface_combo.currentData()
        if not iface:
            QMessageBox.warning(self, "Error", "Select interface")
            return

        bpf = self._filter_input.text().strip()

        if self._capture.start_capture(iface, bpf):
            self._running = True
            self._start_btn.setEnabled(False)
            self._stop_btn.setEnabled(True)
            self._iface_combo.setEnabled(False)
            self._process_combo.setEnabled(False)
            self._refresh_proc_btn.setEnabled(False)
            self._filter_input.setEnabled(False)
            self.statusBar().showMessage(f"Capturing on {iface}...")
        else:
            QMessageBox.critical(self, "Error", "Failed to start capture")

    def _stop(self):
        self._capture.stop_capture()
        self._running = False
        self._start_btn.setEnabled(True)
        self._stop_btn.setEnabled(False)
        self._iface_combo.setEnabled(True)
        self._process_combo.setEnabled(True)
        self._refresh_proc_btn.setEnabled(True)
        self._filter_input.setEnabled(True)

        stats = self._capture.get_stats()
        self.statusBar().showMessage(f"Stopped - {stats['packets']} packets")

    def _clear(self):
        self._packet_list.clear_packets()
        self._packet_list.set_process_filter("")  # Clear process filter
        self._packet_detail.clear()
        self._stats_panel.clear()
        self._stats.setText("Packets: 0")
        self._process_combo.setCurrentIndex(0)  # Reset to "All Processes"

    def _update_ui(self):
        """Called by timer - poll for new packets."""
        if not self._running:
            return

        # Get new packets
        packets = self._capture.get_new_packets()
        if not packets:
            return

        # Add to list (batch)
        self._packet_list.add_packets_batch(packets)

        # Update stats
        stats = self._capture.get_stats()
        self._stats.setText(f"Packets: {stats['packets']:,} | {self._fmt(stats['bytes'])}")

        # Update stats panel (sampling)
        for p in packets[::5]:
            self._stats_panel.add_packet(p)

        # Auto-scroll occasionally
        if stats['packets'] % 100 == 0:
            self._packet_list._table.scrollToBottom()

    def _export(self):
        path, _ = QFileDialog.getSaveFileName(self, "Export", "", "PCAP (*.pcap)")
        if path:
            if self._capture.save_to_pcap(path):
                self.statusBar().showMessage(f"Saved to {path}")

    def _fmt(self, n):
        for u in ['B', 'KB', 'MB', 'GB']:
            if n < 1024:
                return f"{n:.1f}{u}"
            n /= 1024
        return f"{n:.1f}TB"

    def closeEvent(self, e):
        if self._running:
            self._capture.stop_capture()
        self._timer.stop()
        e.accept()


def main():
    app = QApplication(sys.argv)
    app.setApplicationName("Traffic Analyzer")
    MainWindow().show()
    sys.exit(app.exec())