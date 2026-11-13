"""Runtime configuration for the local TCP honeypot demo."""

from dataclasses import dataclass


@dataclass(frozen=True)
class Config:
    host: str = "127.0.0.1"
    port: int = 12348
    ip_threshold: int = 9
    ip_window_seconds: float = 15.0
    username_threshold: int = 6
    username_window_seconds: float = 20.0
    distributed_threshold: int = 12
    distributed_window_seconds: float = 30.0
    global_threshold: int = 16
    global_window_seconds: float = 10.0
    connection_threshold: int = 20
    connection_window_seconds: float = 10.0
    cooldown_seconds: float = 60.0
    alert_suppression_seconds: float = 60.0
    socket_timeout_seconds: float = 10.0
    max_field_bytes: int = 256
    max_workers: int = 32
    log_path: str = "logs/events.jsonl"
    log_max_bytes: int = 5_000_000
    log_backup_count: int = 3

    def __post_init__(self) -> None:
        positive = (self.ip_threshold, self.ip_window_seconds, self.username_threshold,
                    self.username_window_seconds, self.distributed_threshold,
                    self.distributed_window_seconds, self.global_threshold,
                    self.global_window_seconds, self.connection_threshold,
                    self.connection_window_seconds, self.cooldown_seconds,
                    self.alert_suppression_seconds, self.socket_timeout_seconds,
                    self.max_field_bytes, self.max_workers, self.log_max_bytes)
        if any(value <= 0 for value in positive) or self.log_backup_count < 0:
            raise ValueError("thresholds, limits, and time values must be positive; backups may be zero")
        if not 1 <= self.port <= 65535:
            raise ValueError("port must be between 1 and 65535")
