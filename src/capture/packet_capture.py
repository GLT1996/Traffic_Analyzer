"""Packet capture - Simple and reliable."""

import time
from collections import deque
from typing import List

from ..models.packet import Packet
from .process_manager import process_manager


class PacketCapture:
    """Simple packet capture without threading complexity."""

    MAX_PACKETS = 300

    def __init__(self):
        self._running = False
        self._sniffer = None
        self._total_packets = 0
        self._total_bytes = 0
        self._packets: deque = deque(maxlen=self.MAX_PACKETS)
        self._new_packets: List[Packet] = []

    def start_capture(self, interface: str, bpf_filter: str = "") -> bool:
        """Start capture - returns immediately, runs in background."""
        if self._running:
            return False

        self._running = True
        self._total_packets = 0
        self._total_bytes = 0
        self._packets.clear()
        self._new_packets.clear()

        # Start sniff in background thread
        import threading
        self._thread = threading.Thread(
            target=self._sniff_loop,
            args=(interface, bpf_filter),
            daemon=True
        )
        self._thread.start()
        return True

    def stop_capture(self):
        self._running = False
        if hasattr(self, '_thread'):
            self._thread.join(timeout=1.0)

    def _sniff_loop(self, interface: str, bpf_filter: str):
        """Run sniff in a loop - simpler than stop_filter."""
        from scapy.all import AsyncSniffer

        try:
            self._sniffer = AsyncSniffer(
                iface=interface,
                filter=bpf_filter if bpf_filter else None,
                prn=self._on_packet,
                store=False
            )
            self._sniffer.start()

            # Keep thread alive while running
            while self._running:
                time.sleep(0.1)

            # Stop sniffer
            if self._sniffer:
                self._sniffer.stop()
        except Exception as e:
            print(f"Capture error: {e}")
            self._running = False

    def _on_packet(self, scapy_pkt):
        """Called for each packet - must be fast!"""
        if not self._running:
            return

        self._total_packets += 1
        self._total_bytes += len(scapy_pkt)

        # Save raw data (first 1024 bytes for detail view)
        raw = bytes(scapy_pkt)[:1024]

        # Create packet with raw data
        pkt = Packet(
            index=self._total_packets,
            timestamp=float(scapy_pkt.time),
            length=len(scapy_pkt),
            raw_data=raw
        )

        # Quick field extraction
        self._quick_extract(scapy_pkt, pkt)

        # Lookup process by port
        if pkt.src_port:
            proc = process_manager.get_process_by_port(pkt.src_port)
            if proc:
                pkt.process_name = proc
        if not pkt.process_name and pkt.dst_port:
            proc = process_manager.get_process_by_port(pkt.dst_port)
            if proc:
                pkt.process_name = proc

        # Store
        self._packets.append(pkt)
        self._new_packets.append(pkt)

    def _quick_extract(self, pkt, out):
        """Fast field extraction without loops."""
        header_len = 0

        # Ethernet (14 bytes) if present
        if pkt.haslayer("Ether"):
            header_len += 14

        # Check IP layer
        if pkt.haslayer("IP"):
            out.src_ip = pkt["IP"].src
            out.dst_ip = pkt["IP"].dst
            out.protocol = "IP"
            header_len += pkt["IP"].ihl * 4  # IP header length

        elif pkt.haslayer("IPv6"):
            out.src_ip = pkt["IPv6"].src
            out.dst_ip = pkt["IPv6"].dst
            out.protocol = "IPv6"
            header_len += 40  # IPv6 fixed header

        # Transport layer
        if pkt.haslayer("TCP"):
            out.src_port = pkt["TCP"].sport
            out.dst_port = pkt["TCP"].dport
            out.protocol = "TCP"
            header_len += pkt["TCP"].dataofs * 4  # TCP header length

        elif pkt.haslayer("UDP"):
            out.src_port = pkt["UDP"].sport
            out.dst_port = pkt["UDP"].dport
            out.protocol = "UDP"
            header_len += 8  # UDP fixed header

        elif pkt.haslayer("ICMP"):
            out.protocol = "ICMP"
            header_len += 8  # ICMP header

        # Extract payload (application data)
        try:
            if pkt.haslayer("Raw"):
                out.payload = bytes(pkt["Raw"].load)[:2048]  # Limit to 2KB
            elif out.raw_data and header_len < len(out.raw_data):
                out.payload = out.raw_data[header_len:header_len+2048]
        except:
            pass

    def is_running(self) -> bool:
        return self._running

    def get_new_packets(self) -> List[Packet]:
        """Get and clear new packets - call this from UI timer."""
        packets = self._new_packets
        self._new_packets = []
        return packets

    def get_stats(self) -> dict:
        return {
            "packets": self._total_packets,
            "bytes": self._total_bytes
        }

    def get_recent_packets(self) -> List[Packet]:
        return list(self._packets)

    def save_to_pcap(self, filepath: str) -> bool:
        """Save packets to PCAP."""
        try:
            from scapy.all import wrpcap
            # Re-capture with raw data for export
            wrpcap(filepath, list(self._packets))
            return True
        except Exception as e:
            print(f"Save error: {e}")
            return False