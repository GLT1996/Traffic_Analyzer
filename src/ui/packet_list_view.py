"""Simple packet list - optimized for speed."""

from PyQt6.QtWidgets import QWidget, QVBoxLayout, QTableView, QHeaderView, QAbstractItemView
from PyQt6.QtCore import Qt, QAbstractTableModel, QModelIndex, pyqtSignal, QSortFilterProxyModel
from PyQt6.QtGui import QFont, QColor
from collections import deque
from typing import List

from ..models.packet import Packet


class PacketModel(QAbstractTableModel):
    """Fast model with fixed-size buffer."""
    HEADERS = ["No.", "Time", "Source", "Dest", "Proto", "Len", "Process"]
    MAX = 400

    def __init__(self):
        super().__init__()
        self._data = deque(maxlen=self.MAX)

    def rowCount(self, p=QModelIndex()):
        return len(self._data)

    def columnCount(self, p=QModelIndex()):
        return 7

    def data(self, idx, role=Qt.ItemDataRole.DisplayRole):
        if not idx.isValid() or idx.row() >= len(self._data):
            return None

        p = self._data[idx.row()]
        c = idx.column()

        if role == Qt.ItemDataRole.DisplayRole:
            if c == 0: return str(p.index)
            if c == 1: return p.time_str
            if c == 2: return f"{p.src_ip}:{p.src_port}" if p.src_port else p.src_ip
            if c == 3: return f"{p.dst_ip}:{p.dst_port}" if p.dst_port else p.dst_ip
            if c == 4: return p.protocol
            if c == 5: return str(p.length)
            if c == 6: return p.process_name or "-"

        if role == Qt.ItemDataRole.FontRole:
            return QFont("Consolas", 9)

        if role == Qt.ItemDataRole.BackgroundRole:
            proto = (p.protocol or "").lower()
            if "tcp" in proto: return QColor("#1a3a1a")
            if "udp" in proto: return QColor("#1a1a3a")

        return None

    def headerData(self, s, o, role=Qt.ItemDataRole.DisplayRole):
        if role == Qt.ItemDataRole.DisplayRole and o == Qt.Orientation.Horizontal:
            return self.HEADERS[s]

    def add_batch(self, packets: List[Packet]):
        """Add packets with single update."""
        if not packets:
            return

        # Remove old if needed
        overflow = len(self._data) + len(packets) - self.MAX
        if overflow > 0:
            to_remove = min(overflow, len(self._data))
            if to_remove > 0:
                self.beginRemoveRows(QModelIndex(), 0, to_remove - 1)
                for _ in range(to_remove):
                    self._data.popleft()
                self.endRemoveRows()

        # Add new
        start = len(self._data)
        self.beginInsertRows(QModelIndex(), start, start + len(packets) - 1)
        self._data.extend(packets)
        self.endInsertRows()

    def get(self, row):
        return self._data[row] if 0 <= row < len(self._data) else None

    def clear(self):
        self.beginResetModel()
        self._data.clear()
        self.endResetModel()


class ProcessFilterProxy(QSortFilterProxyModel):
    """Proxy model for filtering by process name."""

    def __init__(self):
        super().__init__()
        self._filter_process = ""

    def set_process_filter(self, process_name: str):
        """Set the process name filter."""
        self._filter_process = process_name.lower() if process_name else ""
        self.invalidateFilter()

    def filterAcceptsRow(self, source_row, source_parent):
        """Check if row should be shown."""
        if not self._filter_process:
            return True

        source_model = self.sourceModel()
        if not source_model:
            return True

        packet = source_model.get(source_row)
        if not packet:
            return True

        return packet.process_name.lower() == self._filter_process

    def get_packet(self, proxy_row):
        """Get packet from proxy row."""
        source_row = self.mapToSource(self.index(proxy_row, 0)).row()
        source_model = self.sourceModel()
        if source_model:
            return source_model.get(source_row)
        return None


class PacketListView(QWidget):
    packet_selected = pyqtSignal(object)

    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        # Source model stores all packets
        self._source_model = PacketModel()

        # Proxy model handles filtering
        self._proxy_model = ProcessFilterProxy()
        self._proxy_model.setSourceModel(self._source_model)

        self._table = QTableView()
        self._table.setModel(self._proxy_model)  # Use proxy model
        self._table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._table.setAlternatingRowColors(True)
        self._table.setStyleSheet("""
            QTableView { background: #1e1e1e; color: #d4d4d4; }
            QHeaderView::section { background: #2d2d2d; padding: 4px; border: none; }
        """)

        h = self._table.horizontalHeader()
        h.setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed)
        h.setSectionResizeMode(1, QHeaderView.ResizeMode.Fixed)
        h.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        h.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        h.setSectionResizeMode(4, QHeaderView.ResizeMode.Fixed)
        h.setSectionResizeMode(5, QHeaderView.ResizeMode.Fixed)
        h.setSectionResizeMode(6, QHeaderView.ResizeMode.Interactive)

        self._table.setColumnWidth(0, 50)
        self._table.setColumnWidth(1, 80)
        self._table.setColumnWidth(4, 50)
        self._table.setColumnWidth(5, 50)
        self._table.setColumnWidth(6, 100)

        self._table.selectionModel().currentRowChanged.connect(self._on_sel)
        layout.addWidget(self._table)

    def _on_sel(self, cur, prev):
        # Get packet from proxy row
        proxy_row = cur.row()
        p = self._proxy_model.get_packet(proxy_row)
        if p:
            self.packet_selected.emit(p)

    def add_packets_batch(self, packets):
        self._source_model.add_batch(packets)

    def set_process_filter(self, process_name: str):
        """Filter displayed packets by process name - works immediately."""
        self._proxy_model.set_process_filter(process_name)

    def clear_packets(self):
        self._source_model.clear()
        self._proxy_model.set_process_filter("")  # Clear filter too