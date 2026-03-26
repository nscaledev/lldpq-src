#!/usr/bin/env python3
import os
import re
import unittest


ROOT = os.path.dirname(os.path.dirname(__file__))
FILES_TO_SCAN = [
    "netbox_topology_builder.py",
    os.path.join("tests", "test_netbox_topology_builder.py"),
]

FORBIDDEN_PATTERNS = [
    re.compile(r"netbox\.mgt\.boo\.nscale\.com", re.IGNORECASE),
    re.compile(r"\bnscale\b", re.IGNORECASE),
    re.compile(r"\b6640743ace66d15058c979f078c679ae8fa1e262\b", re.IGNORECASE),
    re.compile(r"--token\s+\"?[A-Za-z0-9]{20,}", re.IGNORECASE),
]


class PrivacyGuardrailTests(unittest.TestCase):
    def test_no_private_netbox_values_in_topology_builder_files(self):
        for rel_path in FILES_TO_SCAN:
            path = os.path.join(ROOT, rel_path)
            with open(path, "r", encoding="utf-8") as handle:
                content = handle.read()
            for pattern in FORBIDDEN_PATTERNS:
                self.assertIsNone(
                    pattern.search(content),
                    msg=f"Forbidden private pattern {pattern.pattern!r} found in {rel_path}",
                )


if __name__ == "__main__":
    unittest.main()
