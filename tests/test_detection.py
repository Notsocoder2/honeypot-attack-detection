import threading
import unittest

from detection import DetectionEngine


class Clock:
    def __init__(self):
        self.now = 100.0

    def __call__(self):
        return self.now


class DetectionTests(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.engine = DetectionEngine(ip_threshold=3, ip_window=10,
                                      username_threshold=3, username_window=10,
                                      distributed_threshold=4, distributed_window=10,
                                      cooldown=5, alert_suppression=10,
                                      clock=self.clock)

    def test_ip_threshold_boundary_and_cooldown_expiry(self):
        self.assertEqual(self.engine.record_failure("127.0.0.1", "admin"), [])
        self.assertEqual(self.engine.record_failure("127.0.0.1", "admin"), [])
        detections = self.engine.record_failure("127.0.0.1", "admin")
        categories = {event.category for event in detections}
        self.assertEqual(categories, {"brute_force_ip", "targeted_username"})
        self.assertTrue(self.engine.is_blocked("127.0.0.1"))
        self.clock.now += 5
        self.assertFalse(self.engine.is_blocked("127.0.0.1"))

    def test_window_expiry_and_alert_suppression(self):
        for _ in range(3):
            detections = self.engine.record_failure("127.0.0.2", "root")
        self.assertTrue(detections)
        self.clock.now += 10
        self.assertEqual(self.engine.record_failure("127.0.0.2", "root"), [])

    def test_alert_is_suppressed_until_suppression_window_expires(self):
        engine = DetectionEngine(ip_threshold=3, ip_window=10, username_threshold=100,
                                 username_window=10, distributed_threshold=100,
                                 distributed_window=10, alert_suppression=2,
                                 clock=self.clock)
        for _ in range(3):
            first = engine.record_failure("127.0.0.5", "admin")
        self.assertTrue(first)
        self.assertEqual(engine.record_failure("127.0.0.5", "admin"), [])
        self.clock.now += 2
        detections = engine.record_failure("127.0.0.5", "admin")
        self.assertIn("brute_force_ip", {event.category for event in detections})

    def test_connection_frequency_has_separate_rule(self):
        engine = DetectionEngine(connection_threshold=3, connection_window=5,
                                  clock=self.clock)
        self.assertEqual(engine.record_connection("127.0.0.9"), [])
        self.assertEqual(engine.record_connection("127.0.0.9"), [])
        result = engine.record_connection("127.0.0.9")
        self.assertEqual(result[0].category, "connection_burst")

    def test_global_high_traffic_threshold_boundary(self):
        engine = DetectionEngine(ip_threshold=100, username_threshold=100,
                                 distributed_threshold=100, global_threshold=3,
                                 global_window=10, clock=self.clock)
        self.assertEqual(engine.record_failure("127.0.0.10", "admin"), [])
        self.assertEqual(engine.record_failure("127.0.0.10", "admin"), [])
        result = engine.record_failure("127.0.0.10", "admin")
        self.assertEqual({event.category for event in result}, {"high_traffic_global"})

    def test_distributed_rule_needs_multiple_sources(self):
        for _ in range(3):
            self.engine.record_failure("127.0.0.3", "same")
        result = self.engine.record_failure("127.0.0.3", "other")
        self.assertNotIn("distributed_activity", {event.category for event in result})
        result = self.engine.record_failure("127.0.0.4", "other")
        self.assertIn("distributed_activity", {event.category for event in result})

    def test_concurrent_updates_are_counted(self):
        engine = DetectionEngine(ip_threshold=25, ip_window=60, username_threshold=100,
                                 username_window=60, distributed_threshold=100,
                                 distributed_window=60, clock=self.clock)
        threads = [threading.Thread(target=engine.record_failure, args=("127.0.0.8", "x"))
                   for _ in range(100)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(engine.snapshot()["recent_failures"], 100)


if __name__ == "__main__":
    unittest.main()
