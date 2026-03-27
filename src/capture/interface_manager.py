"""Network interface enumeration and management."""

import socket
from dataclasses import dataclass
from typing import List, Optional
import subprocess
import re


@dataclass
class NetworkInterface:
    """Represents a network interface."""
    name: str
    friendly_name: str
    ip_address: str
    mac_address: str
    is_up: bool

    @property
    def display_name(self) -> str:
        """Return a user-friendly display name."""
        if self.friendly_name and self.ip_address and self.ip_address != "N/A":
            return f"{self.friendly_name} ({self.ip_address})"
        elif self.friendly_name:
            return self.friendly_name
        elif self.ip_address and self.ip_address != "N/A":
            return f"Interface ({self.ip_address})"
        return self.name


class InterfaceManager:
    """Manages network interface enumeration and selection."""

    def __init__(self):
        self._interfaces: List[NetworkInterface] = []
        self._refresh()

    def _refresh(self) -> None:
        """Refresh the list of available interfaces."""
        self._interfaces.clear()

        # Get interface info from ipconfig /all
        iface_info = self._get_windows_interfaces()

        # Get scapy interface list
        try:
            from scapy.all import get_if_list, get_if_addr, get_if_hwaddr
            scapy_ifaces = get_if_list()
        except Exception:
            scapy_ifaces = []

        for name in scapy_ifaces:
            # Try to get IP
            try:
                ip = get_if_addr(name)
                if ip == "0.0.0.0":
                    ip = "N/A"
            except Exception:
                ip = "N/A"

            # Try to get MAC
            try:
                mac = get_if_hwaddr(name)
            except Exception:
                mac = "N/A"

            # Check if up
            is_up = ip != "N/A"

            # Try to find friendly name
            friendly_name = self._match_friendly_name(name, mac, iface_info)

            interface = NetworkInterface(
                name=name,
                friendly_name=friendly_name,
                ip_address=ip if ip else "N/A",
                mac_address=mac if mac else "N/A",
                is_up=is_up
            )
            self._interfaces.append(interface)

        # Sort: active interfaces first, then by name
        self._interfaces.sort(key=lambda x: (not x.is_up, x.display_name))

    def _get_windows_interfaces(self) -> dict:
        """Get interface information from Windows ipconfig."""
        info = {}
        try:
            result = subprocess.run(
                ["ipconfig", "/all"],
                capture_output=True,
                text=True,
                encoding='gbk',
                errors='ignore'
            )
            output = result.stdout

            # Parse ipconfig output
            current_iface = None
            for line in output.split('\n'):
                line = line.strip()

                # New interface section
                if line and not line.startswith(' ') and ':' in line and 'adapter' not in line.lower():
                    # Remove trailing colon and get name
                    current_iface = line.rstrip(':').strip()
                    info[current_iface] = {'ip': None, 'mac': None}

                # IP Address
                if 'IPv4' in line or 'IP Address' in line:
                    match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                    if match and current_iface:
                        info[current_iface]['ip'] = match.group(1)

                # MAC Address
                if 'Physical Address' in line or '物理地址' in line:
                    match = re.search(r'([0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2})', line)
                    if match and current_iface:
                        info[current_iface]['mac'] = match.group(1).upper().replace('-', ':')

        except Exception as e:
            print(f"Error getting Windows interfaces: {e}")

        return info

    def _match_friendly_name(self, scapy_name: str, mac: str, iface_info: dict) -> str:
        """Match scapy interface to Windows friendly name."""
        # Try to match by MAC address
        if mac and mac != "N/A":
            mac_clean = mac.upper().replace('-', ':')
            for name, data in iface_info.items():
                if data.get('mac') and data['mac'].upper() == mac_clean:
                    return name

        # Try to guess from scapy name
        name_lower = scapy_name.lower()

        if "\\eth" in name_lower or "\\et" in name_lower:
            return "Ethernet"
        elif "\\wi" in name_lower or "\\wl" in name_lower:
            return "Wi-Fi"
        elif "loopback" in name_lower:
            return "Loopback"

        # Return shortened NPF name
        if "NPF_" in scapy_name:
            return f"Interface ({scapy_name.split('_')[-1][:8]})"

        return "Unknown"

    def get_interfaces(self) -> List[NetworkInterface]:
        """Return list of all network interfaces."""
        return self._interfaces.copy()

    def get_active_interfaces(self) -> List[NetworkInterface]:
        """Return list of active (up) network interfaces."""
        return [iface for iface in self._interfaces if iface.is_up]

    def get_interface_by_name(self, name: str) -> Optional[NetworkInterface]:
        """Get interface by name."""
        for iface in self._interfaces:
            if iface.name == name:
                return iface
        return None

    @staticmethod
    def check_npcap_installed() -> bool:
        """Check if Npcap is installed."""
        try:
            from scapy.all import get_if_list
            interfaces = get_if_list()
            return len(interfaces) > 0
        except Exception:
            return False

    @staticmethod
    def check_admin_privileges() -> bool:
        """Check if running with administrator privileges."""
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False