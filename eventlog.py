"""Sanitized, rotating JSON Lines event writer."""

from __future__ import annotations

from datetime import datetime, timezone
import json
import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path
import re
import threading
from typing import Any


class EventLogger:
    def __init__(self, path: str, max_bytes: int, backup_count: int) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._handler = RotatingFileHandler(self.path, maxBytes=max_bytes,
                                            backupCount=backup_count, encoding="utf-8")
        self._lock = threading.Lock()

    def emit(self, *, source_ip: str, port: int, event_type: str,
             username: str | None = None, detection_category: str | None = None,
             reason: str | None = None, severity: str = "info",
             metadata: dict[str, Any] | None = None) -> None:
        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source_ip": source_ip,
            "service": "custom_tcp_login_demo",
            "port": port,
            "event_type": event_type,
            "detection_category": detection_category,
            "username": _sanitize(username) if username is not None else None,
            "reason": _sanitize(reason) if reason is not None else None,
            "severity": severity,
            "metadata": _sanitize_metadata(metadata or {}),
        }
        record = logging.LogRecord("honeypot", logging.INFO, "", 0,
                                   json.dumps(event, ensure_ascii=True), (), None)
        with self._lock:
            self._handler.emit(record)

    def close(self) -> None:
        with self._lock:
            self._handler.close()


def _sanitize(value: str) -> str:
    return "".join(ch if ch >= " " and ch != "\x7f" else " " for ch in value)[:256]


def _sanitize_metadata(value: Any) -> Any:
    """Escape metadata strings and omit fields that commonly contain credentials."""
    if isinstance(value, dict):
        safe: dict[str, Any] = {}
        for key, item in value.items():
            safe_key = _sanitize(str(key))
            if re.search(r"password|passwd|secret|token|credential|api[_-]?key|authorization|cookie",
                         safe_key, re.IGNORECASE):
                continue
            safe[safe_key] = _sanitize_metadata(item)
        return safe
    if isinstance(value, (list, tuple)):
        return [_sanitize_metadata(item) for item in value]
    if isinstance(value, str):
        return _sanitize(value)
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return _sanitize(str(value))
