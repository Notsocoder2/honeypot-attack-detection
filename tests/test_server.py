import json
import socket
import tempfile
import threading
import time
import unittest
from pathlib import Path

from config import Config
from server import HoneypotServer, read_field


class ServerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        self.port = port
        self.log = Path(self.temp.name) / "events.jsonl"
        self.app = HoneypotServer(Config(port=port, log_path=str(self.log), max_workers=4,
                                         socket_timeout_seconds=0.2,
                                         ip_threshold=2, username_threshold=20,
                                         cooldown_seconds=0.1))
        self.thread = threading.Thread(target=self.app.serve_forever, daemon=True)
        self.thread.start()
        for _ in range(50):
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                    break
            except OSError:
                time.sleep(0.02)
        else:
            self.fail("server did not start")

    def tearDown(self):
        self.app.stop()
        self.thread.join(timeout=3)
        self.temp.cleanup()
        self.assertFalse(self.thread.is_alive(), "server did not shut down")

    def test_records_attempt_without_password(self):
        with socket.create_connection(("127.0.0.1", self.port), timeout=1) as client:
            client.settimeout(1)
            greeting = client.recv(1024)
            self.assertIn(b"Username:", greeting)
            client.sendall(b"admin\n")
            self.assertIn(b"Password:", client.recv(1024))
            client.sendall(b"secret-must-not-be-logged\n")
            self.assertIn(b"Login failed", client.recv(1024))
        for _ in range(30):
            if self.log.exists() and self.log.stat().st_size:
                break
            time.sleep(0.01)
        content = self.log.read_text(encoding="utf-8")
        self.assertNotIn("secret-must-not-be-logged", content)
        event = next(json.loads(line) for line in content.splitlines()
                     if json.loads(line)["event_type"] == "authentication_failure")
        self.assertEqual(event["event_type"], "authentication_failure")
        self.assertEqual(event["username"], "admin")

    def _login(self, username="admin"):
        with socket.create_connection(("127.0.0.1", self.port), timeout=1) as client:
            client.settimeout(1)
            client.recv(1024)
            client.sendall((username + "\n").encode())
            client.recv(1024)
            client.sendall(b"throwaway\n")
            return client.recv(1024)

    def test_cooldown_rejects_following_connection(self):
        self.assertIn(b"Login failed", self._login())
        self.assertIn(b"Login failed", self._login())
        try:
            rejected = self._login()
        except OSError:  # TCP reset is also a valid result when the server closes immediately.
            rejected = b""
        self.assertEqual(rejected, b"")
        time.sleep(0.05)
        records = [json.loads(line) for line in self.log.read_text(encoding="utf-8").splitlines()]
        self.assertTrue(any(event["detection_category"] == "cooldown" for event in records))
        time.sleep(0.1)
        self.assertIn(b"Login failed", self._login())  # Expired cooldown allows the connection again.

    def test_multiple_simultaneous_clients(self):
        errors = []
        barrier = threading.Barrier(4)

        def connect(index):
            try:
                barrier.wait(timeout=2)
                self._login(f"user{index}")
            except Exception as exc:
                errors.append(exc)

        workers = [threading.Thread(target=connect, args=(index,)) for index in range(4)]
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join(timeout=3)
        self.assertFalse(errors, errors)
        self.assertTrue(all(not worker.is_alive() for worker in workers))

    def test_invalid_field_is_rejected_and_logged(self):
        with socket.create_connection(("127.0.0.1", self.port), timeout=1) as client:
            client.settimeout(1)
            client.recv(1024)
            client.sendall(b"bad\xff\n")
            time.sleep(0.05)
            self.assertEqual(client.recv(1024), b"")
        time.sleep(0.05)
        records = [json.loads(line) for line in self.log.read_text(encoding="utf-8").splitlines()]
        self.assertTrue(any(event["event_type"] == "connection_error" for event in records))

    def test_stalled_client_times_out(self):
        with socket.create_connection(("127.0.0.1", self.port), timeout=1) as client:
            client.settimeout(1)
            client.recv(1024)
            time.sleep(0.35)
            self.assertEqual(client.recv(1024), b"")
        time.sleep(0.05)
        records = [json.loads(line) for line in self.log.read_text(encoding="utf-8").splitlines()]
        self.assertTrue(any(event["event_type"] == "connection_error" for event in records))

    def test_read_field_rejects_oversized_input(self):
        left, right = socket.socketpair()
        try:
            right.sendall(b"abcdef\n")
            with self.assertRaises(ValueError):
                read_field(left, 4)
        finally:
            left.close()
            right.close()

    def test_read_field_counts_carriage_returns_toward_limit(self):
        left, right = socket.socketpair()
        try:
            right.sendall(b"\r" * 100 + b"admin\n")
            with self.assertRaisesRegex(ValueError, "byte limit"):
                read_field(left, 8)
        finally:
            left.close()
            right.close()

    def test_slow_drip_cannot_extend_field_deadline(self):
        left, right = socket.socketpair()
        left.settimeout(0.15)

        def drip_bytes():
            try:
                for byte in b"admin\n":
                    time.sleep(0.06)
                    right.sendall(bytes([byte]))
            except OSError:
                pass

        sender = threading.Thread(target=drip_bytes)
        sender.start()
        try:
            started = time.monotonic()
            with self.assertRaises(TimeoutError):
                read_field(left, 16)
            self.assertLess(time.monotonic() - started, 0.35)
        finally:
            left.close()
            right.close()
            sender.join(timeout=1)


if __name__ == "__main__":
    unittest.main()
