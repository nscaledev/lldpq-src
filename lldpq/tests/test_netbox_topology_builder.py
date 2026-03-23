#!/usr/bin/env python3
import importlib.util
import argparse
import json
import os
import re
import tempfile
import unittest
from unittest.mock import patch


MODULE_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "netbox_topology_builder.py")
SPEC = importlib.util.spec_from_file_location("netbox_topology_builder", MODULE_PATH)
NTB = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(NTB)


class NetboxTopologyBuilderTests(unittest.TestCase):
    def test_parse_prefixes(self):
        prefixes = NTB.parse_prefixes("swi", "rtr,nfw, rtr")
        self.assertEqual(prefixes, ["swi", "rtr", "nfw"])

    def test_parse_extra_regexes_defaults_and_overrides(self):
        compiled = NTB.parse_extra_regexes(
            extra_prefixes=["rtr", "nfw", "edge"],
            raw_regexes="edge:^xe-",
            rtr_regex="^1/",
            nfw_regex="^ethernet-",
        )
        self.assertTrue(compiled["rtr"].search("1/1/c11"))
        self.assertTrue(compiled["nfw"].search("ethernet-1/41"))
        self.assertTrue(compiled["edge"].search("xe-0/0/0"))

    def test_parse_pcie_slot_map(self):
        mapping = NTB.parse_pcie_slot_map('{"host-storage-*":{"1":"5","2":"8"}}')
        self.assertEqual(mapping["host-storage-*"]["1"], "5")
        self.assertEqual(NTB.resolve_pcie_slot("host-storage-88", "1", mapping), "5")
        self.assertEqual(NTB.resolve_pcie_slot("host-storage-88", "7", mapping), "7")

    def test_parse_regex_list_and_exclusion(self):
        regexes = NTB.parse_regex_list("^eth0$,^mgmt")
        self.assertTrue(NTB.is_excluded_interface("eth0", regexes))
        self.assertTrue(NTB.is_excluded_interface("mgmt0", regexes))
        self.assertFalse(NTB.is_excluded_interface("swp1", regexes))

    def test_classification_and_link_rules(self):
        self.assertEqual(NTB.classify_device_kind("swi650", "swi", ["rtr", "nfw"], ["compute", "storage"]), "primary")
        self.assertEqual(NTB.classify_device_kind("rtr2", "swi", ["rtr", "nfw"], ["compute", "storage"]), "extra")
        self.assertEqual(
            NTB.classify_device_kind("host-compute-1001", "swi", ["rtr", "nfw"], ["compute", "storage"]), "extra"
        )
        self.assertEqual(
            NTB.classify_device_kind("host-storage-88", "swi", ["rtr", "nfw"], ["compute", "storage"]), "extra"
        )
        self.assertEqual(NTB.classify_device_kind("host1", "swi", ["rtr", "nfw"], ["compute", "storage"]), "other")
        self.assertTrue(NTB.is_supported_link("primary", "primary"))
        self.assertTrue(NTB.is_supported_link("primary", "extra"))
        self.assertFalse(NTB.is_supported_link("extra", "extra"))

    def test_allowed_port_for_device(self):
        regexes = {"rtr": re.compile("^1/"), "nfw": re.compile("^ethernet-")}
        primary_extra = [re.compile("^eth0$")]
        self.assertTrue(
            NTB.allowed_port_for_device(
                "swi650", "swp7", "swi", "swp", primary_extra, ["rtr", "nfw"], ["compute"], regexes
            )
        )
        self.assertTrue(
            NTB.allowed_port_for_device(
                "swi650", "eth0", "swi", "swp", primary_extra, ["rtr", "nfw"], ["compute"], regexes
            )
        )
        self.assertTrue(
            NTB.allowed_port_for_device(
                "rtr2", "1/1/c11", "swi", "swp", primary_extra, ["rtr", "nfw"], ["compute"], regexes
            )
        )
        self.assertTrue(
            NTB.allowed_port_for_device(
                "nfw11", "ethernet-1/41", "swi", "swp", primary_extra, ["rtr", "nfw"], ["compute"], regexes
            )
        )
        self.assertFalse(
            NTB.allowed_port_for_device(
                "nfw11", "ha1-a", "swi", "swp", primary_extra, ["rtr", "nfw"], ["compute"], regexes
            )
        )
        self.assertTrue(
            NTB.allowed_port_for_device(
                "host-compute-1001",
                "PCIe-9-200G-1",
                "swi",
                "swp",
                primary_extra,
                ["rtr", "nfw"],
                ["compute"],
                regexes,
            )
        )
        self.assertTrue(
            NTB.allowed_port_for_device(
                "host-storage-88",
                "PCIe-5-200G-1",
                "swi",
                "swp",
                primary_extra,
                ["rtr", "nfw"],
                ["compute", "storage"],
                regexes,
            )
        )

    def test_build_edges_includes_shared_external_peer(self):
        switches = {1: "swi650"}

        interfaces = [
            {
                "name": "swp7",
                "cable": {"id": 101},
                "connected_endpoints": [{"device": {"name": "rtr2", "id": 9999}, "name": "1/1/c11"}],
            }
        ]

        def fake_paginated_get(*args, **kwargs):
            endpoint = args[2]
            if endpoint == "/api/dcim/interfaces/":
                return interfaces
            return []

        with patch.object(NTB, "paginated_get", side_effect=fake_paginated_get):
            edges = NTB.build_edges(
                token="x",
                base_url="https://example.com",
                switches=switches,
                device_prefixes=["swi", "rtr", "nfw"],
                extra_prefixes=["rtr", "nfw"],
                extra_contains=["compute"],
                primary_device_prefix="swi",
                port_prefix="swp",
                primary_extra_port_regexes=[re.compile("^eth0$")],
                extra_port_regexes={"rtr": re.compile(".*"), "nfw": re.compile("^ethernet-")},
                timeout=10,
                verify_tls=True,
                proxy_url=None,
                focus_devices=None,
                shared_devices={"rtr2"},
                interface_overrides={},
            )

        self.assertEqual(edges, {("swi650", "swp7", "rtr2", "1/1/c11")})

    def test_apply_pattern_config(self):
        config_data = {
            "device_prefix": "leaf",
            "extra_device_prefixes": ["core", "fw"],
            "extra_device_contains": ["compute", "storage"],
            "port_prefix": "Ethernet",
            "primary_extra_port_regexes": "^eth0$",
            "interface_name_overrides": {"pcie-9-200g-1": "ens9f0np0"},
            "pcie_slot_map": {"host-storage-*": {"1": "5", "2": "8"}},
            "exclude_interface_regexes": "^eth0$,^mgmt",
            "shared_devices": ["core1", "core2"],
        }
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as tmp:
            json.dump(config_data, tmp)
            tmp_path = tmp.name

        try:
            args = argparse.Namespace(
                pattern_config=tmp_path,
                device_prefix="swi",
                extra_device_prefixes="rtr,nfw",
                extra_device_contains="compute,storage",
                port_prefix="swp",
                primary_extra_port_regexes="^eth0$",
                rtr_port_regex=".*",
                nfw_port_regex="^ethernet-",
                extra_port_regexes="",
                interface_name_overrides="{}",
                pcie_slot_map="{}",
                exclude_interface_regexes="",
                shared_devices="",
            )
            # Simulate no CLI override for these fields.
            with patch.object(NTB, "_cli_has_flag", return_value=False):
                merged = NTB.apply_pattern_config(args)
            self.assertEqual(merged.device_prefix, "leaf")
            self.assertEqual(merged.extra_device_prefixes, "core,fw")
            self.assertEqual(merged.extra_device_contains, "compute,storage")
            self.assertEqual(merged.port_prefix, "Ethernet")
            self.assertEqual(merged.primary_extra_port_regexes, "^eth0$")
            self.assertEqual(merged.interface_name_overrides, '{"pcie-9-200g-1": "ens9f0np0"}')
            self.assertEqual(merged.pcie_slot_map, '{"host-storage-*": {"1": "5", "2": "8"}}')
            self.assertEqual(merged.exclude_interface_regexes, "^eth0$,^mgmt")
            self.assertEqual(merged.shared_devices, "core1,core2")
        finally:
            os.unlink(tmp_path)

    def test_normalize_interface_for_output(self):
        # static override
        self.assertEqual(
            NTB.normalize_interface_for_output(
                "host-compute-1001", "PCIe-9-200G-1", {"pcie-9-200g-1": "ens9f0np0"}
            ),
            "ens9f0np0",
        )
        # fallback rewrite rules
        self.assertEqual(
            NTB.normalize_interface_for_output("host-compute-1001", "PCIe-12-200G-1", {}),
            "ens12f0np0",
        )
        self.assertEqual(
            NTB.normalize_interface_for_output("host-compute-1001", "PCIe-12-200G-2", {}),
            "ens12f1np1",
        )
        self.assertEqual(
            NTB.normalize_interface_for_output("host-storage-88", "PCIe-5-200G-1", {}, {}),
            "ens5f0np0",
        )
        self.assertEqual(
            NTB.normalize_interface_for_output("host-storage-88", "PCIe-8-200G-2", {}, {}),
            "ens8f1np1",
        )
        self.assertEqual(
            NTB.normalize_interface_for_output(
                "host-storage-88",
                "PCIe-1-200G-1",
                {},
                {"host-storage-*": {"1": "5", "2": "8"}},
            ),
            "ens5f0np0",
        )


if __name__ == "__main__":
    unittest.main()
