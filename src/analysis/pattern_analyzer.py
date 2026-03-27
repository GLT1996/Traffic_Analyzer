"""Pattern analyzer for unknown protocol detection."""

from dataclasses import dataclass
from typing import List, Dict, Tuple, Optional
from collections import Counter, defaultdict
import struct

from ..models.packet import Packet


@dataclass
class PatternMatch:
    """Represents a detected pattern in data."""
    offset: int
    size: int
    pattern_type: str
    description: str
    confidence: float
    examples: List[bytes]


class PatternAnalyzer:
    """Analyzes packet data to detect protocol patterns."""

    def __init__(self):
        self._min_pattern_length = 4
        self._max_pattern_length = 16
        self._min_occurrences = 3

    def analyze_packets(self, packets: List[Packet]) -> Dict:
        """
        Analyze a list of packets for patterns.

        Returns a dictionary with analysis results.
        """
        if not packets:
            return {"error": "No packets to analyze"}

        results = {
            "total_packets": len(packets),
            "size_distribution": self._analyze_sizes(packets),
            "byte_frequency": self._analyze_byte_frequency(packets),
            "common_patterns": self._find_common_patterns(packets),
            "structure_hints": self._detect_structure(packets),
            "timing_analysis": self._analyze_timing(packets),
        }

        return results

    def _analyze_sizes(self, packets: List[Packet]) -> Dict:
        """Analyze packet size distribution."""
        sizes = [p.length for p in packets]

        if not sizes:
            return {}

        size_counter = Counter(sizes)

        return {
            "min": min(sizes),
            "max": max(sizes),
            "average": sum(sizes) / len(sizes),
            "most_common": size_counter.most_common(5),
            "distribution": {
                "small (< 100)": len([s for s in sizes if s < 100]),
                "medium (100-500)": len([s for s in sizes if 100 <= s < 500]),
                "large (500-1500)": len([s for s in sizes if 500 <= s < 1500]),
                "jumbo (> 1500)": len([s for s in sizes if s >= 1500]),
            }
        }

    def _analyze_byte_frequency(self, packets: List[Packet]) -> Dict:
        """Analyze byte value frequency across all packets."""
        byte_counts = Counter()

        for packet in packets:
            for byte in packet.raw_data:
                byte_counts[byte] += 1

        total_bytes = sum(byte_counts.values())

        # Calculate entropy
        import math
        entropy = 0
        for count in byte_counts.values():
            if count > 0:
                p = count / total_bytes
                entropy -= p * math.log2(p)

        return {
            "entropy": entropy,
            "entropy_max": 8.0,  # Max entropy for byte
            "is_encrypted": entropy > 7.5,  # High entropy suggests encryption
            "most_common_bytes": byte_counts.most_common(10),
            "null_byte_ratio": byte_counts[0] / total_bytes if total_bytes > 0 else 0,
        }

    def _find_common_patterns(self, packets: List[Packet]) -> List[Dict]:
        """Find common byte patterns across packets."""
        patterns = Counter()

        for packet in packets:
            data = packet.raw_data

            # Extract all substrings of various lengths
            for length in range(self._min_pattern_length, min(self._max_pattern_length + 1, len(data) + 1)):
                for i in range(len(data) - length + 1):
                    pattern = data[i:i + length]
                    patterns[(pattern, i)] += 1

        # Filter patterns that occur frequently
        common = []
        seen = set()

        for (pattern, offset), count in patterns.most_common(50):
            if count < self._min_occurrences:
                break

            # Skip if we've seen this pattern already
            if pattern in seen:
                continue
            seen.add(pattern)

            common.append({
                "pattern": pattern.hex(),
                "offset": offset,
                "occurrences": count,
                "length": len(pattern),
                "ascii_safe": all(32 <= b < 127 for b in pattern),
                "ascii_repr": "".join(chr(b) if 32 <= b < 127 else "." for b in pattern),
            })

        return common[:20]

    def _detect_structure(self, packets: List[Packet]) -> List[Dict]:
        """Detect potential protocol structures."""
        hints = []

        if len(packets) < 3:
            return hints

        # Check for length-prefixed messages
        length_prefix_hints = self._detect_length_prefix(packets)
        hints.extend(length_prefix_hints)

        # Check for fixed headers
        header_hints = self._detect_fixed_header(packets)
        hints.extend(header_hints)

        # Check for delimiters
        delimiter_hints = self._detect_delimiters(packets)
        hints.extend(delimiter_hints)

        return hints

    def _detect_length_prefix(self, packets: List[Packet]) -> List[Dict]:
        """Detect length-prefixed fields."""
        hints = []

        # Check first few bytes as length indicators
        for offset in range(min(4, len(packets[0].raw_data) if packets else 0)):
            for size in [1, 2, 4]:
                matches = 0
                total = 0

                for packet in packets[:50]:  # Check first 50 packets
                    data = packet.raw_data
                    if len(data) < offset + size:
                        continue

                    total += 1

                    # Try to interpret as length
                    if size == 1:
                        length = data[offset]
                    elif size == 2:
                        length = struct.unpack('>H', data[offset:offset + 2])[0]
                    else:
                        length = struct.unpack('>I', data[offset:offset + 4])[0]

                    # Check if length makes sense
                    expected_payload = len(data) - offset - size
                    if abs(length - expected_payload) <= 10:  # Allow some tolerance
                        matches += 1

                if total > 0 and matches / total > 0.7:
                    hints.append({
                        "type": "length_prefix",
                        "offset": offset,
                        "size": size,
                        "confidence": matches / total,
                        "description": f"Possible {size}-byte length field at offset {offset}",
                    })

        return hints

    def _detect_fixed_header(self, packets: List[Packet]) -> List[Dict]:
        """Detect fixed header patterns."""
        hints = []

        if len(packets) < 3:
            return hints

        # Check for common bytes at the start
        header_size = 4
        common_bytes = []

        for i in range(header_size):
            byte_values = Counter()
            for packet in packets[:50]:
                if len(packet.raw_data) > i:
                    byte_values[packet.raw_data[i]] += 1

            if byte_values:
                most_common, count = byte_values.most_common(1)[0]
                if count > len(packets) * 0.7:
                    common_bytes.append((i, most_common, count / len(packets)))

        if common_bytes:
            hints.append({
                "type": "fixed_header",
                "bytes": [(i, hex(b), conf) for i, b, conf in common_bytes],
                "description": f"Fixed header bytes detected at positions {[i for i, _, _ in common_bytes]}",
            })

        return hints

    def _detect_delimiters(self, packets: List[Packet]) -> List[Dict]:
        """Detect common delimiters in packet data."""
        hints = []

        delimiters = [
            (b'\r\n\r\n', "HTTP header end"),
            (b'\r\n', "CRLF"),
            (b'\n', "LF"),
            (b'\x00', "Null byte"),
            (b'|', "Pipe"),
            (b',', "Comma"),
            (b':', "Colon"),
        ]

        for delim, name in delimiters:
            count = 0
            for packet in packets[:50]:
                if delim in packet.raw_data:
                    count += 1

            if count > len(packets) * 0.3:
                hints.append({
                    "type": "delimiter",
                    "delimiter": delim.hex(),
                    "name": name,
                    "occurrence_rate": count / len(packets),
                    "description": f"Common delimiter found: {name} ({count} packets)",
                })

        return hints

    def _analyze_timing(self, packets: List[Packet]) -> Dict:
        """Analyze packet timing patterns."""
        if len(packets) < 2:
            return {}

        timestamps = sorted([p.timestamp for p in packets])
        intervals = [timestamps[i + 1] - timestamps[i] for i in range(len(timestamps) - 1)]

        if not intervals:
            return {}

        return {
            "min_interval": min(intervals),
            "max_interval": max(intervals),
            "avg_interval": sum(intervals) / len(intervals),
            "burst_detected": min(intervals) < 0.001,  # Burst if packets arrive < 1ms apart
        }

    def generate_report(self, packets: List[Packet]) -> str:
        """Generate a human-readable analysis report."""
        results = self.analyze_packets(packets)

        lines = []
        lines.append("=" * 60)
        lines.append("PROTOCOL PATTERN ANALYSIS REPORT")
        lines.append("=" * 60)
        lines.append("")

        # Size analysis
        sizes = results.get("size_distribution", {})
        if sizes:
            lines.append("SIZE DISTRIBUTION")
            lines.append("-" * 40)
            lines.append(f"  Min: {sizes.get('min', 0)} bytes")
            lines.append(f"  Max: {sizes.get('max', 0)} bytes")
            lines.append(f"  Average: {sizes.get('average', 0):.1f} bytes")
            lines.append(f"  Distribution:")
            for k, v in sizes.get("distribution", {}).items():
                lines.append(f"    {k}: {v} packets")
            lines.append("")

        # Byte frequency
        freq = results.get("byte_frequency", {})
        if freq:
            lines.append("BYTE FREQUENCY ANALYSIS")
            lines.append("-" * 40)
            entropy = freq.get("entropy", 0)
            lines.append(f"  Entropy: {entropy:.2f} / 8.0 bits")
            lines.append(f"  Encrypted: {'Likely' if freq.get('is_encrypted') else 'Unlikely'}")
            lines.append("")

        # Structure hints
        hints = results.get("structure_hints", [])
        if hints:
            lines.append("DETECTED STRUCTURE HINTS")
            lines.append("-" * 40)
            for hint in hints:
                lines.append(f"  [{hint['type']}] {hint['description']}")
            lines.append("")

        # Common patterns
        patterns = results.get("common_patterns", [])
        if patterns:
            lines.append("COMMON PATTERNS")
            lines.append("-" * 40)
            for p in patterns[:10]:
                ascii_repr = p.get('ascii_repr', '')
                lines.append(f"  {p['pattern']} ({ascii_repr}) - {p['occurrences']} times")
            lines.append("")

        lines.append("=" * 60)

        return "\n".join(lines)