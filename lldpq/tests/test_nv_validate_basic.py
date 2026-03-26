#!/usr/bin/env python3
import importlib.util
import json
import os
import sys
import tempfile
import types
import unittest
from pathlib import Path


class DummyYAMLError(Exception):
    pass


def _safe_load(stream):
    text = stream.read() if hasattr(stream, "read") else stream
    try:
        return json.loads(text)
    except Exception as exc:
        raise DummyYAMLError(str(exc))


sys.modules["yaml"] = types.SimpleNamespace(safe_load=_safe_load, YAMLError=DummyYAMLError)

MODULE_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "nv-validate.py")
SPEC = importlib.util.spec_from_file_location("nv_validate", MODULE_PATH)
NV = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(NV)


class NvValidateBasicTests(unittest.TestCase):
    def test_validate_file_parse_error(self):
        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as handle:
            handle.write("this is not json/yaml")
            path = Path(handle.name)
        try:
            result = NV.validate_file(path)
            self.assertFalse(result.is_valid)
            self.assertGreaterEqual(result.error_count, 1)
        finally:
            os.unlink(path)

    def test_validate_directory_empty(self):
        with tempfile.TemporaryDirectory() as td:
            results = NV.validate_directory(Path(td))
            self.assertEqual(results, [])

    def test_validate_directory_returns_results(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "device1.yaml"
            p.write_text("{}", encoding="utf-8")
            results = NV.validate_directory(Path(td))
            self.assertEqual(len(results), 1)
            self.assertEqual(Path(results[0].filename).name, "device1.yaml")


if __name__ == "__main__":
    unittest.main()
