#!/usr/bin/env python3
import importlib.util
import json
import os
import sys
import tempfile
import types
import unittest


if "yaml" not in sys.modules:
    yaml_stub = types.SimpleNamespace(
        safe_load=lambda stream: json.loads(stream.read() if hasattr(stream, "read") else stream)
    )
    sys.modules["yaml"] = yaml_stub

MODULE_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "lldp-validate.py")
SPEC = importlib.util.spec_from_file_location("lldp_validate", MODULE_PATH)
LV = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(LV)


class LldpValidateTests(unittest.TestCase):
    def _tmpfile(self, content: str) -> str:
        fd, path = tempfile.mkstemp(suffix=".ini")
        os.close(fd)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(content)
        return path

    def test_parse_lldp_output_with_port_status(self):
        content = """
-------------------------------------------------------------------------------
Interface: swp1,
SysName: swi2
SysDescr: Cumulus Linux
PortID: ifname swp49
-------------------------------------------------------------------------------
===PORT_STATUS_START===
swp1 UP
swp2 DOWN
===PORT_STATUS_END===
"""
        path = self._tmpfile(content)
        try:
            neighbors, port_status = LV.parse_lldp_output(path)
            self.assertEqual(len(neighbors), 1)
            self.assertEqual(neighbors[0]["interface"], "swp1")
            self.assertEqual(neighbors[0]["sys_name"], "swi2")
            self.assertEqual(neighbors[0]["port_id"], "swp49")
            self.assertEqual(port_status["swp2"], "DOWN")
        finally:
            os.unlink(path)

    def test_check_connections_pass_and_fail(self):
        topo = self._tmpfile('"swi1:swp1 -- swi2:swp49\nswi1:swp2 -- swi3:swp1\n')
        try:
            device_neighbors = {
                "swi1": [
                    {"interface": "swp1", "sys_name": "swi2", "port_id": "swp49"},
                    {"interface": "swp9", "sys_name": "swi2", "port_id": "swp9"},
                ],
                "swi2": [],
                "swi3": [],
            }
            port_status = {"swi1": {"swp1": "UP", "swp2": "DOWN"}, "swi2": {}, "swi3": {}}
            results = LV.check_connections(topo, device_neighbors, port_status)
            swi1_rows = results["swi1"]
            by_port = {row["Port"]: row for row in swi1_rows}
            self.assertEqual(by_port["swp1"]["Status"], "Pass")
            self.assertEqual(by_port["swp2"]["Status"], "Fail")  # DOWN port
            self.assertEqual(by_port["swp9"]["Status"], "Fail")  # unexpected neighbor
        finally:
            os.unlink(topo)


if __name__ == "__main__":
    unittest.main()
