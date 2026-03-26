#!/usr/bin/env python3
import importlib.util
import json
import os
import sys
import tempfile
import types
import unittest


def load_module(module_filename: str, module_name: str):
    # These scripts depend on PyYAML, which is not required for these unit tests.
    if "yaml" not in sys.modules:
        yaml_stub = types.SimpleNamespace(
            safe_load=lambda stream: json.loads(stream.read() if hasattr(stream, "read") else stream)
        )
        sys.modules["yaml"] = yaml_stub

    module_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), module_filename)
    spec = importlib.util.spec_from_file_location(module_name, module_path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


GT = load_module("generate_topology.py", "generate_topology")
GTF = load_module("generate_topology_full.py", "generate_topology_full")


class GenerateTopologyTests(unittest.TestCase):
    def _write_temp(self, content: str) -> str:
        fd, path = tempfile.mkstemp(suffix=".tmp")
        os.close(fd)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(content)
        return path

    def test_parse_topology_dot_file_minimal(self):
        path = self._write_temp(
            '\n'.join(
                [
                    'graph "ACME" {',
                    '"swi1":"swp1" -- "swi2":"swp1"',
                    '"swi1":"swp2" -- "rtr2":"1/1/c11"',
                    "# comment",
                    "}",
                ]
            )
        )
        try:
            links = GT.parse_topology_dot_file(path)
            self.assertIn(("swi1", "swp1", "swi2", "swp1"), links)
            self.assertIn(("swi1", "swp2", "rtr2", "1/1/c11"), links)
        finally:
            os.unlink(path)

    def test_parse_topology_dot_file_full(self):
        path = self._write_temp('"swi3":"swp3" -- "nfw1":"ethernet-1/1"\n')
        try:
            links = GTF.parse_topology_dot_file(path)
            self.assertEqual(links, {("swi3", "swp3", "nfw1", "ethernet-1/1")})
        finally:
            os.unlink(path)

    def test_format_speed(self):
        self.assertEqual(GT.format_speed(100), "100Mbps")
        self.assertEqual(GT.format_speed(1000), "1Gbps")
        self.assertEqual(GT.format_speed(25000), "25Gbps")
        self.assertEqual(GT.format_speed(None), "N/A")


if __name__ == "__main__":
    unittest.main()
