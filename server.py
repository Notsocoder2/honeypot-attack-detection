"""Run the localhost-first custom TCP login honeypot demonstration."""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import signal
import socket
import sys
import threading
import time

from config import Config
from detection import DetectionEngine
from eventlog import EventLogger


def read_field(client: socket.socket, max_bytes: int) -> str:
    """Read one newline-terminated UTF-8 field, bounded by max_bytes."""
    data = bytearray()
    original_timeout = client.gettimeout()
    deadline = time.monotonic() + original_timeout if original_timeout is not None else None
    try:
        while True:
            if deadline is not None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("field read deadline expired")
                client.settimeout(remaining)
            chunk = client.recv(1)
            if not chunk:
                raise ConnectionError("client disconnected before completing a field")
            if chunk == b"\n":
                break
            data.extend(chunk)
            # Permit a single CR before LF for CRLF, while bounding all other bytes.
            if len(data) > max_bytes + 1:
                raise ValueError("field exceeds configured byte limit")
        if data.endswith(b"\r"):
            data.pop()
        if len(data) > max_bytes:
            raise ValueError("field exceeds configured byte limit")
        value = data.decode("utf-8").strip()
    except UnicodeDecodeError as exc:
        raise ValueError("field is not valid UTF-8") from exc
    finally:
        if deadline is not None:
            client.settimeout(original_timeout)
    if not value or any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
        raise ValueError("field is empty or contains control characters")
    return value


class HoneypotServer:
    def __init__(self, config: Config) -> None:
        self.config = config
        self.detector = DetectionEngine(
            ip_threshold=config.ip_threshold, ip_window=config.ip_window_seconds,
            username_threshold=config.username_threshold, username_window=config.username_window_seconds,
            distributed_threshold=config.distributed_threshold,
            distributed_window=config.distributed_window_seconds,
            global_threshold=config.global_threshold,
            global_window=config.global_window_seconds,
            connection_threshold=config.connection_threshold,
            connection_window=config.connection_window_seconds,
            cooldown=config.cooldown_seconds,
            alert_suppression=config.alert_suppression_seconds,
        )
        self.events = EventLogger(config.log_path, config.log_max_bytes, config.log_backup_count)
        self._stop = threading.Event()
        self._workers = ThreadPoolExecutor(max_workers=config.max_workers, thread_name_prefix="honeypot")
        self._slots = threading.BoundedSemaphore(config.max_workers)
        self._listener: socket.socket | None = None

    def serve_forever(self) -> None:
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listener = listener
        try:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind((self.config.host, self.config.port))
            listener.listen(self.config.max_workers)
            listener.settimeout(0.5)
            print(f"Listening on {self.config.host}:{self.config.port}; Ctrl+C to stop")
            while not self._stop.is_set():
                try:
                    client, address = listener.accept()
                except socket.timeout:
                    continue
                except OSError:
                    if self._stop.is_set():
                        break
                    raise
                if not self._slots.acquire(blocking=False):
                    client.close()
                    continue
                future = self._workers.submit(self._handle_client, client, address)
                future.add_done_callback(self._report_worker_failure)
        finally:
            listener.close()
            self._listener = None
            self._workers.shutdown(wait=True, cancel_futures=True)
            self.events.close()

    def stop(self) -> None:
        self._stop.set()
        if self._listener is not None:
            self._listener.close()

    @staticmethod
    def _report_worker_failure(future) -> None:
        error = future.exception()
        if error is not None:
            print(f"[ERROR] client worker failed: {type(error).__name__}", file=sys.stderr)

    def _handle_client(self, client: socket.socket, address: tuple[str, int]) -> None:
        ip = address[0]
        try:
            client.settimeout(self.config.socket_timeout_seconds)
            for detection in self.detector.record_connection(ip):
                self.events.emit(source_ip=ip, port=self.config.port, event_type="detection",
                                 detection_category=detection.category, reason=detection.reason,
                                 severity=detection.severity)
                print(f"[{detection.severity.upper()}] {detection.category}: {detection.reason}")
            if self.detector.is_blocked(ip):
                self.events.emit(source_ip=ip, port=self.config.port, event_type="connection_rejected",
                                 detection_category="cooldown", severity="medium",
                                 reason="source is in temporary application-level cooldown")
                return
            client.sendall(b"Welcome to the login service\nUsername: ")
            username = read_field(client, self.config.max_field_bytes)
            client.sendall(b"Password: ")
            read_field(client, self.config.max_field_bytes)  # Deliberately discard the submitted secret.
            self.events.emit(source_ip=ip, port=self.config.port, event_type="authentication_failure",
                             username=username, reason="demo service rejects all credentials")
            for detection in self.detector.record_failure(ip, username):
                self.events.emit(source_ip=ip, port=self.config.port, event_type="detection",
                                 username=username, detection_category=detection.category,
                                 reason=detection.reason, severity=detection.severity)
                print(f"[{detection.severity.upper()}] {detection.category}: {detection.reason}")
            client.sendall(b"Login failed\n")
        except (OSError, ConnectionError, ValueError) as exc:
            self.events.emit(source_ip=ip, port=self.config.port, event_type="connection_error",
                             reason=type(exc).__name__, severity="low")
        finally:
            client.close()
            self._slots.release()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1", help="bind address (default: localhost)")
    parser.add_argument("--port", type=int, default=12348)
    parser.add_argument("--log", default="logs/events.jsonl")
    parser.add_argument("--max-workers", type=int, default=32)
    parser.add_argument("--cooldown", type=float, default=60.0)
    parser.add_argument("--ip-threshold", type=int, default=9)
    parser.add_argument("--ip-window", type=float, default=15.0)
    parser.add_argument("--username-threshold", type=int, default=6)
    parser.add_argument("--username-window", type=float, default=20.0)
    parser.add_argument("--distributed-threshold", type=int, default=12)
    parser.add_argument("--distributed-window", type=float, default=30.0)
    parser.add_argument("--global-threshold", type=int, default=16)
    parser.add_argument("--global-window", type=float, default=10.0)
    parser.add_argument("--connection-threshold", type=int, default=20)
    parser.add_argument("--connection-window", type=float, default=10.0)
    parser.add_argument("--alert-suppression", type=float, default=60.0)
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument("--max-field-bytes", type=int, default=256)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    try:
        config = replace(
            Config(), host=args.host, port=args.port, log_path=args.log,
            max_workers=args.max_workers, cooldown_seconds=args.cooldown,
            ip_threshold=args.ip_threshold, ip_window_seconds=args.ip_window,
            username_threshold=args.username_threshold,
            username_window_seconds=args.username_window,
            distributed_threshold=args.distributed_threshold,
            distributed_window_seconds=args.distributed_window,
            global_threshold=args.global_threshold,
            global_window_seconds=args.global_window,
            connection_threshold=args.connection_threshold,
            connection_window_seconds=args.connection_window,
            alert_suppression_seconds=args.alert_suppression,
            socket_timeout_seconds=args.timeout, max_field_bytes=args.max_field_bytes,
        )
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc
    app = HoneypotServer(config)
    signal.signal(signal.SIGINT, lambda _signum, _frame: app.stop())
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, lambda _signum, _frame: app.stop())
    app.serve_forever()


if __name__ == "__main__":
    main()
