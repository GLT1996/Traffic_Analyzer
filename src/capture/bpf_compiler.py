"""BPF filter compilation and validation."""

from typing import List, Optional
import re


class BPFCompiler:
    """Compiles and validates BPF filter expressions."""

    # Common filter presets
    PRESETS = {
        "tcp": "tcp",
        "udp": "udp",
        "icmp": "icmp",
        "http": "tcp port 80 or tcp port 8080",
        "https": "tcp port 443",
        "dns": "udp port 53",
        "ssh": "tcp port 22",
        "ftp": "tcp port 21 or tcp port 20",
        "telnet": "tcp port 23",
        "smtp": "tcp port 25",
        "pop3": "tcp port 110",
        "imap": "tcp port 143",
    }

    @staticmethod
    def compile_filter(
        protocol: Optional[str] = None,
        src_ip: Optional[str] = None,
        dst_ip: Optional[str] = None,
        src_port: Optional[int] = None,
        dst_port: Optional[int] = None,
        port: Optional[int] = None,
        host: Optional[str] = None
    ) -> str:
        """Build a BPF filter from individual components."""
        parts = []

        if protocol:
            protocol = protocol.lower()
            if protocol in BPFCompiler.PRESETS:
                parts.append(BPFCompiler.PRESETS[protocol])
            else:
                parts.append(protocol)

        if host:
            parts.append(f"host {host}")

        if src_ip:
            parts.append(f"src host {src_ip}")

        if dst_ip:
            parts.append(f"dst host {dst_ip}")

        if port:
            parts.append(f"port {port}")

        if src_port:
            parts.append(f"src port {src_port}")

        if dst_port:
            parts.append(f"dst port {dst_port}")

        return " and ".join(parts) if parts else ""

    @staticmethod
    def validate_filter(filter_str: str) -> tuple[bool, str]:
        """Validate a BPF filter expression.

        Returns:
            (is_valid, error_message)
        """
        if not filter_str.strip():
            return True, ""

        # Basic syntax check
        filter_str = filter_str.strip()

        # Check for unbalanced parentheses
        if filter_str.count("(") != filter_str.count(")"):
            return False, "Unbalanced parentheses"

        # Check for valid characters
        valid_pattern = r'^[\w\s\.\:\-\(\)\'\"\/\[\]\&\|\!\=\<\>]+$'
        if not re.match(valid_pattern, filter_str):
            return False, "Invalid characters in filter"

        return True, ""

    @staticmethod
    def combine_filters(filters: List[str], operator: str = "and") -> str:
        """Combine multiple filters with a logical operator."""
        valid_filters = [f for f in filters if f.strip()]
        if not valid_filters:
            return ""
        if len(valid_filters) == 1:
            return valid_filters[0]

        op = f" {operator} "
        combined = op.join(f"({f})" for f in valid_filters)
        return combined

    @staticmethod
    def get_presets() -> dict:
        """Return available filter presets."""
        return BPFCompiler.PRESETS.copy()