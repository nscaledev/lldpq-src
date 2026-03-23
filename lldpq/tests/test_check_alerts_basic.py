#!/usr/bin/env python3
import importlib.util
import json
import os
import sys
import tempfile
import types
import unittest
from pathlib import Path


class DummyResponse:
    def __init__(self, status_code=200):
        self.status_code = status_code


def _safe_load(stream):
    text = stream.read() if hasattr(stream, "read") else stream
    return json.loads(text)


if "yaml" not in sys.modules:
    sys.modules["yaml"] = types.SimpleNamespace(safe_load=_safe_load)
if "requests" not in sys.modules:
    sys.modules["requests"] = types.SimpleNamespace(post=lambda *args, **kwargs: DummyResponse(200))

MODULE_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "check_alerts.py")
SPEC = importlib.util.spec_from_file_location("check_alerts", MODULE_PATH)
CA = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(CA)


class CheckAlertsBasicTests(unittest.TestCase):
    def _write_config(self, base: Path, enabled: bool = True):
        cfg = {
            "notifications": {
                "enabled": enabled,
                "server_url": "http://localhost",
                "slack": {"enabled": False, "webhook": ""},
            },
            "frequency": {"min_interval_minutes": 0, "send_recovery": True},
            "alert_types": {"hardware_alerts": True},
            "thresholds": {"hardware": {"cpu_temp_warning": 75, "cpu_temp_critical": 85}},
        }
        (base / "notifications.yaml").write_text(json.dumps(cfg), encoding="utf-8")

    def test_load_config_disabled(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            self._write_config(base, enabled=False)
            alerts = CA.LLDPqAlerts(str(base))
            self.assertIsNone(alerts.config)

    def test_should_send_alert_state_changes(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            self._write_config(base, enabled=True)
            alerts = CA.LLDPqAlerts(str(base))
            self.assertIsNotNone(alerts.config)

            # First transition from UNKNOWN -> CRITICAL should alert.
            self.assertTrue(alerts.should_send_alert("swi1", "cpu_temp", "CRITICAL"))
            alerts.set_alert_state("swi1", "cpu_temp", "CRITICAL")

            # Same state should not alert.
            self.assertFalse(alerts.should_send_alert("swi1", "cpu_temp", "CRITICAL"))

            # New state should alert.
            self.assertTrue(alerts.should_send_alert("swi1", "cpu_temp", "WARNING"))


if __name__ == "__main__":
    unittest.main()
