"""Export manager for saving captured data."""

import json
import csv
from datetime import datetime
from typing import List

from ..models.packet import Packet


class ExportManager:
    """Handles exporting captured data."""

    @staticmethod
    def to_pcap(packets: List[Packet], filepath: str) -> bool:
        """Export packets to PCAP format."""
        try:
            from scapy.all import wrpcap, Ether
            scapy_packets = []

            for packet in packets:
                if packet.raw_data:
                    try:
                        scapy_packets.append(Ether(packet.raw_data))
                    except:
                        pass

            if scapy_packets:
                wrpcap(filepath, scapy_packets)
            return True
        except Exception as e:
            print(f"Error exporting PCAP: {e}")
            return False

    @staticmethod
    def to_json(packets: List[Packet], filepath: str) -> bool:
        """Export packets to JSON format."""
        try:
            data = []
            for p in packets:
                data.append({
                    "index": p.index,
                    "timestamp": p.timestamp,
                    "time": p.time_str,
                    "length": p.length,
                    "src_ip": p.src_ip,
                    "dst_ip": p.dst_ip,
                    "src_port": p.src_port,
                    "dst_port": p.dst_port,
                    "protocol": p.protocol,
                    "info": p.info_str
                })

            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2)
            return True
        except Exception as e:
            print(f"Error exporting JSON: {e}")
            return False

    @staticmethod
    def to_csv(packets: List[Packet], filepath: str) -> bool:
        """Export packets to CSV format."""
        try:
            with open(filepath, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow([
                    "No.", "Time", "Source IP", "Src Port",
                    "Dest IP", "Dst Port", "Protocol", "Length"
                ])

                for p in packets:
                    writer.writerow([
                        p.index, p.time_str, p.src_ip, p.src_port,
                        p.dst_ip, p.dst_port, p.protocol, p.length
                    ])
            return True
        except Exception as e:
            print(f"Error exporting CSV: {e}")
            return False

    @staticmethod
    def to_summary(packets: List[Packet], filepath: str) -> bool:
        """Export session summary."""
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write("Network Traffic Summary\n")
                f.write("=" * 40 + "\n\n")
                f.write(f"Total Packets: {len(packets)}\n")

                if packets:
                    total_bytes = sum(p.length for p in packets)
                    f.write(f"Total Bytes: {total_bytes:,}\n")

                    # Protocol breakdown
                    protocols = {}
                    for p in packets:
                        protocols[p.protocol] = protocols.get(p.protocol, 0) + 1

                    f.write("\nProtocols:\n")
                    for proto, count in sorted(protocols.items(), key=lambda x: -x[1]):
                        f.write(f"  {proto}: {count}\n")

            return True
        except Exception as e:
            print(f"Error exporting summary: {e}")
            return False