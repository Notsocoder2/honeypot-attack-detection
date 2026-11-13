import json
import tempfile
import unittest
from pathlib import Path

from eventlog import EventLogger


class EventLogTests(unittest.TestCase):
    def test_sanitizes_control_characters_and_emits_one_json_line(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.jsonl"
            log = EventLogger(str(path), 10_000, 2)
            try:
                log.emit(source_ip="127.0.0.1", port=12348, event_type="authentication_failure",
                         username="admin\r\nforged", reason="bad\x00input",
                         metadata={"nested": {"password": "must-not-appear", "safe": "line\nbreak"},
                                   "authorization": "Bearer must-not-appear"})
            finally:
                log.close()
            rows = path.read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(rows), 1)
            event = json.loads(rows[0])
            self.assertEqual(event["username"], "admin  forged")
            self.assertEqual(event["reason"], "bad input")
            self.assertNotIn("must-not-appear", rows[0])
            self.assertNotIn("password", rows[0].lower())
            self.assertNotIn("authorization", rows[0].lower())
            self.assertEqual(event["metadata"], {"nested": {"safe": "line break"}})

    def test_rotates_at_configured_size(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.jsonl"
            log = EventLogger(str(path), 500, 2)
            try:
                for index in range(8):
                    log.emit(source_ip="127.0.0.1", port=12348, event_type="test",
                             username=f"user{index}", reason="x" * 100)
            finally:
                log.close()
            self.assertTrue(Path(str(path) + ".1").exists())


if __name__ == "__main__":
    unittest.main()
