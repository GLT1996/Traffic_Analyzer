"""Session tracking for TCP/UDP connections - Memory optimized."""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from enum import Enum
import time


class SessionState(Enum):
    """TCP session states."""
    CLOSED = "CLOSED"
    SYN_SENT = "SYN_SENT"
    ESTABLISHED = "ESTABLISHED"
    FIN_WAIT = "FIN_WAIT"
    TIME_WAIT = "TIME_WAIT"
    ACTIVE = "ACTIVE"  # UDP


@dataclass
class SessionKey:
    """5-tuple session identifier."""
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: str

    def __hash__(self):
        forward = (self.src_ip, self.src_port, self.dst_ip, self.dst_port, self.protocol)
        reverse = (self.dst_ip, self.dst_port, self.src_ip, self.src_port, self.protocol)
        return hash(min(forward, reverse))

    def __eq__(self, other):
        if not isinstance(other, SessionKey):
            return False
        return (self.src_ip, self.src_port, self.dst_ip, self.dst_port, self.protocol) == \
               (other.src_ip, other.src_port, other.dst_ip, other.dst_port, other.protocol) or \
               (self.src_ip, self.src_port, self.dst_ip, self.dst_port, self.protocol) == \
               (other.dst_ip, other.dst_port, other.src_ip, other.src_port, other.protocol)

    def to_display(self) -> str:
        return f"{self.src_ip}:{self.src_port} ↔ {self.dst_ip}:{self.dst_port}"


@dataclass
class SessionInfo:
    """Information about a network session - does NOT store packets."""
    key: SessionKey
    state: SessionState = SessionState.ACTIVE
    start_time: float = 0.0
    end_time: float = 0.0
    src_to_dst_bytes: int = 0
    dst_to_src_bytes: int = 0
    src_to_dst_packets: int = 0
    dst_to_src_packets: int = 0

    @property
    def total_bytes(self) -> int:
        return self.src_to_dst_bytes + self.dst_to_src_bytes

    @property
    def total_packets(self) -> int:
        return self.src_to_dst_packets + self.dst_to_src_packets

    @property
    def duration(self) -> float:
        if self.start_time and self.end_time:
            return self.end_time - self.start_time
        return 0.0


class SessionTracker:
    """Tracks network sessions - Memory optimized."""

    MAX_SESSIONS = 1000  # Maximum sessions to track

    def __init__(self, timeout: float = 300.0):
        self._sessions: Dict[SessionKey, SessionInfo] = {}
        self._timeout = timeout

    def process_packet(self, packet) -> Optional[SessionInfo]:
        """Process a packet and update/create session."""
        if not packet.src_ip or not packet.dst_ip:
            return None
        if not packet.src_port and not packet.dst_port:
            return None

        key = SessionKey(
            src_ip=packet.src_ip,
            src_port=packet.src_port,
            dst_ip=packet.dst_ip,
            dst_port=packet.dst_port,
            protocol=packet.protocol
        )

        # Find or create session
        if key in self._sessions:
            session = self._sessions[key]
        else:
            # Limit sessions
            if len(self._sessions) >= self.MAX_SESSIONS:
                self._cleanup_old_sessions()

            session = SessionInfo(
                key=key,
                state=SessionState.ACTIVE,
                start_time=packet.timestamp
            )
            self._sessions[key] = session

        # Update session (don't store packet!)
        session.end_time = packet.timestamp

        is_src = packet.src_ip == key.src_ip
        if is_src:
            session.src_to_dst_bytes += packet.length
            session.src_to_dst_packets += 1
        else:
            session.dst_to_src_bytes += packet.length
            session.dst_to_src_packets += 1

        # Update TCP state (simplified)
        if packet.protocol == "TCP":
            self._update_tcp_state(session, packet, is_src)

        return session

    def _update_tcp_state(self, session: SessionInfo, packet, is_src: bool):
        """Simplified TCP state tracking."""
        # Just track if connection seems established or closed
        # Don't store packet data
        pass

    def _cleanup_old_sessions(self):
        """Remove oldest/closed sessions."""
        current_time = time.time()

        # Remove timed out sessions
        expired = [
            k for k, s in self._sessions.items()
            if (current_time - s.end_time) > self._timeout or s.state == SessionState.CLOSED
        ]

        for k in expired[:self.MAX_SESSIONS // 2]:
            del self._sessions[k]

    def get_sessions(self) -> List[SessionInfo]:
        return list(self._sessions.values())

    def get_session_count(self) -> int:
        return len(self._sessions)

    def clear(self):
        self._sessions.clear()

    def get_statistics(self) -> Dict:
        tcp_count = sum(1 for s in self._sessions.values() if s.key.protocol == "TCP")
        udp_count = sum(1 for s in self._sessions.values() if s.key.protocol == "UDP")

        return {
            "total_sessions": len(self._sessions),
            "tcp_sessions": tcp_count,
            "udp_sessions": udp_count,
        }