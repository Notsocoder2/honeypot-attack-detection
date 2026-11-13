"""Thread-safe, in-memory detection rules for authentication events."""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
import threading
import time
from typing import Callable


@dataclass(frozen=True)
class Detection:
    category: str
    reason: str
    severity: str


class DetectionEngine:
    """Maintain bounded time-window counters and temporary source cooldowns."""

    def __init__(self, *, ip_threshold: int = 9, ip_window: float = 15.0,
                 username_threshold: int = 6, username_window: float = 20.0,
                 distributed_threshold: int = 12, distributed_window: float = 30.0,
                 global_threshold: int = 16, global_window: float = 10.0,
                 connection_threshold: int = 20, connection_window: float = 10.0,
                 cooldown: float = 60.0, alert_suppression: float = 60.0,
                 clock: Callable[[], float] = time.monotonic) -> None:
        self.ip_threshold = ip_threshold
        self.ip_window = ip_window
        self.username_threshold = username_threshold
        self.username_window = username_window
        self.distributed_threshold = distributed_threshold
        self.distributed_window = distributed_window
        self.global_threshold = global_threshold
        self.global_window = global_window
        self.connection_threshold = connection_threshold
        self.connection_window = connection_window
        self.cooldown = cooldown
        self.alert_suppression = alert_suppression
        self._clock = clock
        self._lock = threading.Lock()
        self._ip_events: dict[str, deque[float]] = defaultdict(deque)
        self._user_events: dict[str, deque[float]] = defaultdict(deque)
        self._global_events: deque[tuple[float, str]] = deque()
        self._global_rate_events: deque[float] = deque()
        self._connection_events: dict[str, deque[float]] = defaultdict(deque)
        self._blocked: dict[str, float] = {}
        self._last_alert: dict[tuple[str, str], float] = {}

    def is_blocked(self, ip: str) -> bool:
        now = self._clock()
        with self._lock:
            self._cleanup(now)
            until = self._blocked.get(ip)
            return until is not None and until > now

    def record_failure(self, ip: str, username: str) -> list[Detection]:
        now = self._clock()
        username_key = username.casefold()
        found: list[Detection] = []
        with self._lock:
            self._cleanup(now)
            ip_events = self._ip_events[ip]
            ip_events.append(now)
            self._trim(ip_events, now - self.ip_window)

            user_events = self._user_events[username_key]
            user_events.append(now)
            self._trim(user_events, now - self.username_window)

            self._global_events.append((now, ip))
            self._trim_global(now - self.distributed_window)
            self._global_rate_events.append(now)
            self._trim(self._global_rate_events, now - self.global_window)

            if len(ip_events) >= self.ip_threshold:
                self._blocked[ip] = now + self.cooldown
                self._alert(found, "brute_force_ip", ip,
                            f"{len(ip_events)} failures from one source within {self.ip_window:g}s", "high", now)
            if len(user_events) >= self.username_threshold:
                self._alert(found, "targeted_username", username_key,
                            f"{len(user_events)} failures for one username within {self.username_window:g}s", "medium", now)
            sources = {source for _, source in self._global_events}
            if len(self._global_events) >= self.distributed_threshold and len(sources) > 1:
                self._alert(found, "distributed_activity", "global",
                            f"{len(self._global_events)} failures from {len(sources)} sources within {self.distributed_window:g}s", "high", now)
            if len(self._global_rate_events) >= self.global_threshold:
                self._alert(found, "high_traffic_global", "global",
                            f"{len(self._global_rate_events)} failures across all sources within {self.global_window:g}s",
                            "medium", now)
        return found

    def record_connection(self, ip: str) -> list[Detection]:
        now = self._clock()
        found: list[Detection] = []
        with self._lock:
            self._cleanup(now)
            events = self._connection_events[ip]
            events.append(now)
            self._trim(events, now - self.connection_window)
            if len(events) >= self.connection_threshold:
                self._alert(found, "connection_burst", ip,
                            f"{len(events)} connections from one source within {self.connection_window:g}s",
                            "medium", now)
        return found

    def snapshot(self) -> dict[str, int]:
        now = self._clock()
        with self._lock:
            self._cleanup(now)
            return {
                "tracked_sources": max(len(self._ip_events), len(self._connection_events)),
                "tracked_usernames": len(self._user_events),
                "active_blocks": len(self._blocked),
                "recent_failures": len(self._global_events),
            }

    def _alert(self, output: list[Detection], category: str, key: str,
               reason: str, severity: str, now: float) -> None:
        alert_key = (category, key)
        previous = self._last_alert.get(alert_key)
        if previous is None or now - previous >= self.alert_suppression:
            output.append(Detection(category, reason, severity))
            self._last_alert[alert_key] = now

    @staticmethod
    def _trim(events: deque[float], cutoff: float) -> None:
        while events and events[0] <= cutoff:
            events.popleft()

    def _trim_global(self, cutoff: float) -> None:
        while self._global_events and self._global_events[0][0] <= cutoff:
            self._global_events.popleft()

    def _cleanup(self, now: float) -> None:
        self._blocked = {ip: until for ip, until in self._blocked.items() if until > now}
        self._trim_global(now - self.distributed_window)
        self._trim(self._global_rate_events, now - self.global_window)
        for mapping, window in ((self._ip_events, self.ip_window),
                                (self._user_events, self.username_window),
                                (self._connection_events, self.connection_window)):
            expired = []
            for key, events in mapping.items():
                self._trim(events, now - window)
                if not events:
                    expired.append(key)
            for key in expired:
                del mapping[key]
        self._last_alert = {key: at for key, at in self._last_alert.items()
                            if now - at < self.alert_suppression}
