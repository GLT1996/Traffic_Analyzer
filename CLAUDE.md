# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

Network Traffic Analyzer - A Windows desktop application for learning network protocols and analyzing traffic patterns. Built with Python, PyQt6, and Scapy.

## Commands

```bash
# Install dependencies
pip install -r requirements.txt

# Run the application
python run.py

# Run directly
python -m src.main
```

**Requirements:**
- Npcap must be installed (https://npcap.com/) with WinPcap compatibility mode
- Administrator privileges recommended for packet capture

## Architecture

```
src/
├── capture/                    # Packet capture layer
│   ├── interface_manager.py    # Network interface enumeration
│   ├── packet_capture.py       # Scapy-based capture engine (threaded)
│   └── bpf_compiler.py         # BPF filter utilities & presets
│
├── analysis/                   # Protocol analysis layer
│   ├── protocol_dissector.py   # Base dissector class & registry
│   ├── session_tracker.py      # TCP/UDP session tracking
│   ├── pattern_analyzer.py     # Unknown protocol pattern detection
│   └── dissectors/             # Protocol-specific dissectors
│       ├── ethernet.py
│       ├── ipv4.py
│       ├── ipv6.py
│       ├── tcp.py
│       ├── udp.py
│       └── icmp.py
│
├── core/                       # Application logic
│   └── export_manager.py       # PCAP/JSON/CSV export
│
├── ui/                         # PyQt6 interface
│   ├── main_window.py          # Main application window
│   ├── packet_list_view.py     # Packet table with filtering
│   ├── packet_detail_view.py   # Protocol tree + hex view
│   ├── statistics_panel.py     # Real-time traffic graphs
│   ├── session_view.py         # Session list widget
│   └── widgets/
│       └── hex_viewer.py       # Hex/ASCII display widget
│
└── models/                     # Data models
    └── packet.py               # Packet & Session dataclasses
```

## Key Classes

| Class | File | Description |
|-------|------|-------------|
| `PacketCapture` | capture/packet_capture.py | Threaded capture engine using Scapy |
| `InterfaceManager` | capture/interface_manager.py | Network interface enumeration |
| `ProtocolDissector` | analysis/protocol_dissector.py | Abstract base for protocol dissectors |
| `DissectorRegistry` | analysis/protocol_dissector.py | Singleton registry for dissectors |
| `SessionTracker` | analysis/session_tracker.py | TCP state machine, UDP session tracking |
| `PatternAnalyzer` | analysis/pattern_analyzer.py | Detects protocol structures |
| `ExportManager` | core/export_manager.py | Multi-format export (PCAP/JSON/CSV) |
| `Packet` | models/packet.py | Dataclass with layers, hex view |
| `Session` | models/packet.py | 5-tuple session with stats |

## Features

- **Real-time capture** with BPF filtering
- **Protocol dissection**: Ethernet, IPv4, IPv6, TCP, UDP, ICMP
- **Session tracking**: TCP state machine, bidirectional flow analysis
- **Statistics**: Traffic rate graphs, protocol distribution, top talkers
- **Pattern analysis**: Detect length-prefixed fields, delimiters, fixed headers
- **Export**: PCAP, JSON, CSV formats

## Extending

To add a new protocol dissector:

1. Create a new file in `src/analysis/dissectors/`
2. Subclass `ProtocolDissector`
3. Implement `can_dissect()` and `dissect()` methods
4. Register in `dissectors/__init__.py`