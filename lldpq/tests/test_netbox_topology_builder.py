#!/usr/bin/env python3
import importlib.util
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
    def _config(self, **overrides):
        data = {
            "netbox_url": "https://example.test",
            "netbox_token": "token123",
            "netbox_cluster": "sys2-sta1",
            "device_prefix": "swi",
            "device_name": None,
            "port_prefix": "swp",
            "primary_extra_port_regexes": [re.compile("^eth0$")],
            "include_peer_regex": re.compile(".*", re.IGNORECASE),
            "interface_name_overrides": {},
            "pcie_slot_map": {},
            "exclude_interface_regexes": [],
            "output": "topology.dot",
            "timeout": 10,
            "proxy_url": None,
            "verify_tls": True,
        }
        data.update(overrides)
        return NTB.NetboxTopologyConfig(**data)

    def test_parse_config_compiles_include_peer_regex(self):
        cfg = NTB.parse_config(
            [
                "--netbox-url",
                "https://example.test",
                "--netbox-token",
                "token123",
                "--netbox-cluster",
                "sys2-sta1",
                "--include-peer-regex",
                "^rtr",
            ]
        )
        self.assertTrue(cfg.include_peer_regex.search("rtr2"))
        self.assertFalse(cfg.include_peer_regex.search("nfw11"))

    def test_parse_config_applies_default_osh_pcie_slot_map(self):
        cfg = NTB.parse_config(
            [
                "--netbox-url",
                "https://example.test",
                "--netbox-token",
                "token123",
                "--netbox-cluster",
                "sys2-sta1",
            ]
        )
        self.assertEqual(cfg.pcie_slot_map.get("*-p-phy-osh*", {}).get("1"), "5")
        self.assertEqual(cfg.pcie_slot_map.get("*-p-phy-osh*", {}).get("2"), "8")
        self.assertEqual(cfg.pcie_slot_map.get("*-p-phy-cpo*", {}).get("1"), "5")
        self.assertEqual(cfg.pcie_slot_map.get("*-p-phy-cpo*", {}).get("2"), "8")
        self.assertEqual(cfg.pcie_slot_map.get("*-proxmox-mgt*", {}).get("1"), "5")
        self.assertEqual(cfg.pcie_slot_map.get("*-proxmox-mgt*", {}).get("2"), "8")

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

    def test_allowed_port_for_device_table_driven(self):
        primary_extra = [re.compile("^eth0$")]
        cases = [
            ("swi650", "swp7", True),
            ("swi650", "eth0", True),
            ("swi650", "lo", False),
            ("nfw11", "ethernet-1/41", False),
        ]
        for dev, iface, expected in cases:
            with self.subTest(device=dev, iface=iface):
                self.assertEqual(
                    NTB.allowed_port_for_device(dev, iface, "swi", "swp", primary_extra),
                    expected,
                )

    def test_in_cluster_uses_only_cluster_name(self):
        dev_ok = {"cluster": {"name": "sys2-sta1"}, "custom_fields": {"netbox_cluster": "wrong"}}
        dev_no_cluster_name = {"cluster": None, "custom_fields": {"netbox_cluster": "sys2-sta1"}}
        self.assertTrue(NTB.in_cluster(dev_ok, "sys2-sta1"))
        self.assertFalse(NTB.in_cluster(dev_no_cluster_name, "sys2-sta1"))

    def test_build_switch_map_filters_prefix_and_cluster_name(self):
        cfg = self._config(device_prefix="swi")
        devices = [
            {"id": 1, "name": "swi650", "cluster": {"name": "sys2-sta1"}},
            {"id": 2, "name": "nfw11", "cluster": {"name": "sys2-sta1"}},
            {"id": 3, "name": "swi651", "cluster": {"name": "other"}},
            {"id": 4, "name": "swi652", "cluster": None, "custom_fields": {"netbox_cluster": "sys2-sta1"}},
        ]

        with patch.object(NTB, "paginated_get", return_value=devices):
            switches = NTB.build_switch_map(cfg, cluster_id=123)

        self.assertEqual(switches, {1: "swi650"})

    def test_build_edges_table_driven_peer_shapes(self):
        cfg = self._config()
        switches = {1: "swi650"}

        cases = [
            (
                {
                    "name": "swp7",
                    "cable": {"id": 101},
                    "connected_endpoints": [{"device": {"name": "rtr2", "id": 9999}, "name": "1/1/c11"}],
                },
                {("swi650", "swp7", "rtr2", "1/1/c11")},
            ),
            (
                {
                    "name": "swp5",
                    "cable": {"id": 102},
                    "connected_endpoints": [{"device": {"name": "nfw11", "id": 9998}, "name": "ethernet-1/41"}],
                },
                {("swi650", "swp5", "nfw11", "ethernet-1/41")},
            ),
            (
                {
                    "name": "swp11",
                    "cable": {"id": 103},
                    "link_peers": [{"object": {"device": {"name": "edge-router-2", "id": 9203}, "name": "xe-0/0/1"}}],
                },
                {("swi650", "swp11", "edge-router-2", "xe-0/0/1")},
            ),
            (
                {
                    "name": "swp12",
                    "cable": {"id": 104},
                    "connected_endpoints": [{"device": "EDGE-ROUTER-3", "name": "ge-0/0/2"}],
                },
                {("swi650", "swp12", "EDGE-ROUTER-3", "ge-0/0/2")},
            ),
        ]

        def fake_paginated_get(*args, **kwargs):
            if args[1] == "/api/dcim/interfaces/":
                return [self.current_iface]
            return []

        with patch.object(NTB, "paginated_get", side_effect=fake_paginated_get):
            for iface, expected in cases:
                with self.subTest(iface=iface["name"]):
                    self.current_iface = iface
                    edges = NTB.build_edges(cfg, switches)
                    self.assertEqual(edges, expected)

    def test_build_edges_include_peer_regex_filters(self):
        cfg = self._config(include_peer_regex=re.compile("^rtr", re.IGNORECASE))
        switches = {1: "swi650"}
        interfaces = [
            {
                "name": "swp7",
                "cable": {"id": 201},
                "connected_endpoints": [{"device": {"name": "rtr2", "id": 9999}, "name": "1/1/c11"}],
            },
            {
                "name": "swp8",
                "cable": {"id": 202},
                "connected_endpoints": [{"device": {"name": "nfw11", "id": 9998}, "name": "ethernet-1/41"}],
            },
        ]

        with patch.object(NTB, "paginated_get", return_value=interfaces):
            edges = NTB.build_edges(cfg, switches)

        self.assertEqual(edges, {("swi650", "swp7", "rtr2", "1/1/c11")})

    def test_build_edges_excludes_peer_interfaces(self):
        cfg = self._config(exclude_interface_regexes=[re.compile("^XCC$", re.IGNORECASE)])
        switches = {1: "swi650"}
        interfaces = [
            {
                "name": "swp31",
                "cable": {"id": 251},
                "connected_endpoints": [{"device": {"name": "sta1-p-phy-osh88", "id": 501}, "name": "XCC"}],
            },
            {
                "name": "swp7",
                "cable": {"id": 252},
                "connected_endpoints": [{"device": {"name": "rtr2", "id": 9999}, "name": "1/1/c11"}],
            },
        ]

        with patch.object(NTB, "paginated_get", return_value=interfaces):
            edges = NTB.build_edges(cfg, switches)

        self.assertEqual(edges, {("swi650", "swp7", "rtr2", "1/1/c11")})

    def test_build_edges_dedupes_by_cable_id(self):
        cfg = self._config()
        switches = {1: "swi650"}
        interfaces = [
            {
                "name": "swp1",
                "cable": {"id": 301},
                "connected_endpoints": [{"device": {"name": "rtr2", "id": 9999}, "name": "1/1/c11"}],
            },
            {
                "name": "swp2",
                "cable": {"id": 301},
                "connected_endpoints": [{"device": {"name": "rtr2", "id": 9999}, "name": "1/1/c12"}],
            },
        ]

        with patch.object(NTB, "paginated_get", return_value=interfaces):
            edges = NTB.build_edges(cfg, switches)

        self.assertEqual(len(edges), 1)

    def test_parse_config_rejects_invalid_include_peer_regex(self):
        with self.assertRaises(re.error):
            NTB.parse_config(
                [
                    "--netbox-url",
                    "https://example.test",
                    "--netbox-token",
                    "token123",
                    "--netbox-cluster",
                    "sys2-sta1",
                    "--include-peer-regex",
                    "[",
                ]
            )

    def test_normalize_interface_for_output(self):
        self.assertEqual(
            NTB.normalize_interface_for_output("host-compute-1001", "PCIe-9-200G-1", {"pcie-9-200g-1": "ens9f0np0"}),
            "ens9f0np0",
        )
        self.assertEqual(NTB.normalize_interface_for_output("host-compute-1001", "PCIe-12-200G-1", {}), "ens12f0np0")
        self.assertEqual(NTB.normalize_interface_for_output("host-compute-1001", "PCIe-12-200G-2", {}), "ens12f1np1")
        self.assertEqual(
            NTB.normalize_interface_for_output(
                "sta1-p-phy-osh88",
                "PCIe-1-200G-1",
                {},
                {"*-p-phy-osh*": {"1": "5", "2": "8"}},
            ),
            "ens5f0np0",
        )
        self.assertEqual(
            NTB.normalize_interface_for_output(
                "sta1-p-phy-osh88",
                "PCIe-2-200G-2",
                {},
                {"*-p-phy-osh*": {"1": "5", "2": "8"}},
            ),
            "ens8f1np1",
        )
        self.assertEqual(
            NTB.normalize_interface_for_output(
                "sta1-p-phy-cpo15",
                "PCIe-1-200G-1",
                {},
                {"*-p-phy-cpo*": {"1": "5", "2": "8"}},
            ),
            "ens5f0np0",
        )
        self.assertEqual(
            NTB.normalize_interface_for_output(
                "sta1-p-phy-cpo15",
                "PCIe-2-200G-2",
                {},
                {"*-p-phy-cpo*": {"1": "5", "2": "8"}},
            ),
            "ens8f1np1",
        )
        self.assertEqual(
            NTB.normalize_interface_for_output(
                "sta1-p-proxmox-mgt11",
                "PCIe-1-200G-1",
                {},
                {"*-proxmox-mgt*": {"1": "5", "2": "8"}},
            ),
            "ens5f0np0",
        )
        self.assertEqual(
            NTB.normalize_interface_for_output(
                "sta1-p-proxmox-mgt11",
                "PCIe-2-200G-2",
                {},
                {"*-proxmox-mgt*": {"1": "5", "2": "8"}},
            ),
            "ens8f1np1",
        )

    def test_http_get_json_dispatches_by_proxy_scheme(self):
        with patch.object(NTB, "_http_get_json_via_socks", return_value={"s": 1}) as mock_socks, patch.object(
            NTB, "_http_get_json_via_urllib", return_value={"u": 1}
        ) as mock_url:
            socks = NTB.http_get_json("https://example.test/api", "tok", 10, True, "socks5://127.0.0.1:8888")
            direct = NTB.http_get_json("https://example.test/api", "tok", 10, True, None)

        self.assertEqual(socks, {"s": 1})
        self.assertEqual(direct, {"u": 1})
        self.assertTrue(mock_socks.called)
        self.assertTrue(mock_url.called)

    def test_http_get_json_via_urllib_https_uses_handler_not_open_context(self):
        class DummyContext:
            def __init__(self):
                self.minimum_version = None
                self.options = 0
                self.check_hostname = True
                self.verify_mode = NTB.ssl.CERT_REQUIRED

        class DummyResponse:
            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def read(self):
                return b'{"ok":1}'

        class DummyOpener:
            def __init__(self):
                self.kwargs = {}

            def open(self, *args, **kwargs):
                self.kwargs = kwargs
                return DummyResponse()

        opener = DummyOpener()
        fake_context = DummyContext()
        fake_handler = object()

        with patch.object(NTB.ssl, "create_default_context", return_value=fake_context), patch.object(
            NTB.urllib.request, "HTTPSHandler", return_value=fake_handler
        ) as mock_https_handler, patch.object(
            NTB.urllib.request, "build_opener", return_value=opener
        ) as mock_build_opener:
            result = NTB._http_get_json_via_urllib("https://example.test/api", "tok", 12, True, None)

        self.assertEqual(result, {"ok": 1})
        mock_https_handler.assert_called_once_with(context=fake_context)
        mock_build_opener.assert_called_once_with(fake_handler)
        self.assertEqual(opener.kwargs, {"timeout": 12})
        self.assertNotIn("context", opener.kwargs)

    def test_http_get_json_via_urllib_https_insecure_adjusts_context(self):
        class DummyContext:
            def __init__(self):
                self.check_hostname = True
                self.verify_mode = NTB.ssl.CERT_REQUIRED

        class DummyResponse:
            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def read(self):
                return b'{"ok":1}'

        class DummyOpener:
            def open(self, *args, **kwargs):
                return DummyResponse()

        ctx = DummyContext()

        with patch.object(NTB.ssl, "create_default_context", return_value=ctx), patch.object(
            NTB.urllib.request, "HTTPSHandler", return_value=object()
        ), patch.object(NTB.urllib.request, "build_opener", return_value=DummyOpener()):
            result = NTB._http_get_json_via_urllib("https://example.test/api", "tok", 12, False, None)

        self.assertEqual(result, {"ok": 1})
        self.assertFalse(ctx.check_hostname)
        self.assertEqual(ctx.verify_mode, NTB.ssl.CERT_NONE)

    def test_http_get_json_via_urllib_enforces_tls12_or_disables_legacy_tls(self):
        class DummyContext:
            def __init__(self):
                self.check_hostname = True
                self.verify_mode = NTB.ssl.CERT_REQUIRED
                self.minimum_version = None
                self.options = 0

        class DummyResponse:
            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def read(self):
                return b'{"ok":1}'

        class DummyOpener:
            def open(self, *args, **kwargs):
                return DummyResponse()

        ctx = DummyContext()
        with patch.object(NTB.ssl, "create_default_context", return_value=ctx), patch.object(
            NTB.urllib.request, "HTTPSHandler", return_value=object()
        ), patch.object(NTB.urllib.request, "build_opener", return_value=DummyOpener()):
            result = NTB._http_get_json_via_urllib("https://example.test/api", "tok", 12, True, None)

        self.assertEqual(result, {"ok": 1})
        if hasattr(NTB.ssl, "TLSVersion") and hasattr(NTB.ssl.TLSVersion, "TLSv1_2"):
            self.assertEqual(ctx.minimum_version, NTB.ssl.TLSVersion.TLSv1_2)
        else:
            expected_mask = 0
            if hasattr(NTB.ssl, "OP_NO_TLSv1"):
                expected_mask |= NTB.ssl.OP_NO_TLSv1
            if hasattr(NTB.ssl, "OP_NO_TLSv1_1"):
                expected_mask |= NTB.ssl.OP_NO_TLSv1_1
            self.assertEqual(ctx.options & expected_mask, expected_mask)


if __name__ == "__main__":
    unittest.main()
