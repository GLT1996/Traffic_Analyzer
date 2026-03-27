"""Process manager for mapping ports to processes."""

import psutil
from collections import defaultdict
from typing import Dict, List, Set, Optional
import time


class ProcessManager:
    """Maps network ports to running processes."""

    def __init__(self):
        self._port_to_process: Dict[int, str] = {}
        self._process_list: Dict[str, Set[int]] = defaultdict(set)  # process_name -> PIDs
        self._last_update = 0
        self._cache_duration = 2.0  # Cache for 2 seconds

    def refresh(self):
        """Refresh the port-to-process mapping."""
        now = time.time()
        if now - self._last_update < self._cache_duration:
            return

        self._port_to_process.clear()
        self._process_list.clear()

        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.pid:
                    try:
                        proc = psutil.Process(conn.pid)
                        name = proc.name().lower()

                        # Map local port to process
                        if conn.laddr:
                            self._port_to_process[conn.laddr.port] = name

                        # Track processes
                        self._process_list[name].add(conn.pid)

                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
        except Exception as e:
            print(f"Error refreshing processes: {e}")

        self._last_update = now

    def get_process_by_port(self, port: int) -> Optional[str]:
        """Get process name by local port."""
        self.refresh()
        return self._port_to_process.get(port)

    def get_all_processes(self) -> List[str]:
        """Get list of all processes with network connections."""
        self.refresh()
        return sorted(self._process_list.keys())

    def get_pids_for_process(self, name: str) -> Set[int]:
        """Get all PIDs for a process name."""
        self.refresh()
        return self._process_list.get(name.lower(), set())

    def get_ports_for_process(self, name: str) -> List[int]:
        """Get all local ports used by a process."""
        self.refresh()
        name_lower = name.lower()
        ports = []
        for port, proc_name in self._port_to_process.items():
            if proc_name == name_lower:
                ports.append(port)
        return ports


# Global instance
process_manager = ProcessManager()