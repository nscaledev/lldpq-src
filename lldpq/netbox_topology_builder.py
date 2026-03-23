#!/usr/bin/env python3
"""
Build topology.dot from NetBox cable data with strict switch filtering.

This builder only maps links when:
1) Both devices are in the requested `netbox_cluster`.
2) Device names match allowed patterns (prefixes + contains tokens).
3) Port names match per-device rules:
   - `swi*`: prefix match (default `swp`)
   - `rtr*` / `nfw*`: regex match (default allow-all)
4) The source interface has a cable assigned.
"""

import argparse
import fnmatch
import json
import os
import re
import subprocess
import sys
from typing import Dict, Iterable, List, Optional, Pattern, Set, Tuple
from urllib.parse import urlencode, urljoin


Edge = Tuple[str, str, str, str]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Generate a GraphViz DOT topology from NetBox cables, restricted "
            "to switch-prefix devices and port-prefix interfaces in a netbox_cluster."
        )
    )
    parser.add_argument("--netbox-url", default=os.getenv("NETBOX_URL"), help="NetBox base URL")
    parser.add_argument("--netbox-token", default=os.getenv("NETBOX_TOKEN"), help="NetBox API token")
    parser.add_argument(
        "--pattern-config",
        default=os.getenv("NETBOX_PATTERN_CONFIG", "lldpq/netbox_topology_patterns.json"),
        help="Pattern config JSON path (default: lldpq/netbox_topology_patterns.json)",
    )
    parser.add_argument(
        "--netbox-cluster",
        default=os.getenv("NETBOX_CLUSTER"),
        help="Cluster filter value (required)",
    )
    parser.add_argument(
        "--device-prefix",
        default="swi",
        help="Primary device name prefix filter (default: swi)",
    )
    parser.add_argument(
        "--extra-device-prefixes",
        default="rtr,nfw",
        help="Additional device prefixes (comma-separated, default: rtr,nfw)",
    )
    parser.add_argument(
        "--extra-device-contains",
        default="",
        help="Additional device substring matches (comma-separated, default: none)",
    )
    parser.add_argument(
        "--shared-devices",
        default=os.getenv("NETBOX_SHARED_DEVICES", ""),
        help=(
            "Static comma-separated device names to allow outside the cluster "
            "(example: edge-router-a,edge-router-b)"
        ),
    )
    parser.add_argument(
        "--device-name",
        default=None,
        help="Optional exact device name filter within the cluster",
    )
    parser.add_argument(
        "--port-prefix",
        default="swp",
        help="Primary interface prefix for primary device prefix (default: swp)",
    )
    parser.add_argument(
        "--primary-extra-port-regexes",
        default="^eth0$",
        help=(
            "Comma-separated regexes to allow extra primary interfaces "
            "(default: ^eth0$)"
        ),
    )
    parser.add_argument(
        "--rtr-port-regex",
        default=".*",
        help="Regex for rtr* interface names (default: .*)",
    )
    parser.add_argument(
        "--nfw-port-regex",
        default="^ethernet-",
        help="Regex for nfw* interface names (default: ^ethernet-)",
    )
    parser.add_argument(
        "--extra-port-regexes",
        default="",
        help=(
            "Extra prefix regexes (comma-separated prefix:regex, "
            "example: rtr:^et,nfw:^ethernet-,edge:^xe-)"
        ),
    )
    parser.add_argument(
        "--interface-name-overrides",
        default="{}",
        help=(
            "JSON dict for static interface rewrites. Keys can be 'iface' or "
            "'device:iface' (case-insensitive). Example: "
            '{"PCIe-9-200G-1":"ens9f0np0"}'
        ),
    )
    parser.add_argument(
        "--pcie-slot-map",
        default="{}",
        help=(
            "JSON dict of device-pattern -> slot map for PCIe names. "
            "Example: {\"host-*\": {\"1\": \"5\", \"2\": \"8\"}}"
        ),
    )
    parser.add_argument(
        "--exclude-interface-regexes",
        default="",
        help="Comma-separated regexes for interfaces to ignore (default: none)",
    )
    parser.add_argument(
        "--output",
        default="topology.dot",
        help="Output DOT path (default: topology.dot)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=30,
        help="HTTP timeout in seconds (default: 30)",
    )
    parser.add_argument(
        "--netbox-proxy",
        default=os.getenv("NETBOX_PROXY"),
        help="Optional proxy URL (for example socks5h://127.0.0.1:8888)",
    )
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="Disable TLS certificate verification",
    )
    args = parser.parse_args()

    missing = []
    if not args.netbox_url:
        missing.append("netbox-url/NETBOX_URL")
    if not args.netbox_token:
        missing.append("netbox-token/NETBOX_TOKEN")
    if not args.netbox_cluster:
        missing.append("netbox-cluster/NETBOX_CLUSTER")

    if missing:
        parser.error("Missing required settings: " + ", ".join(missing))

    return args


def parse_prefixes(primary_prefix: str, extra_prefixes: str) -> List[str]:
    prefixes = [primary_prefix.strip().lower()]
    for raw in (extra_prefixes or "").split(","):
        value = raw.strip().lower()
        if value and value not in prefixes:
            prefixes.append(value)
    return prefixes


def parse_extra_regexes(
    extra_prefixes: List[str],
    raw_regexes: str,
    rtr_regex: str,
    nfw_regex: str,
) -> Dict[str, Pattern[str]]:
    regex_by_prefix: Dict[str, str] = {}
    if "rtr" in extra_prefixes:
        regex_by_prefix["rtr"] = rtr_regex
    if "nfw" in extra_prefixes:
        regex_by_prefix["nfw"] = nfw_regex

    for part in (raw_regexes or "").split(","):
        chunk = part.strip()
        if not chunk or ":" not in chunk:
            continue
        prefix, regex = chunk.split(":", 1)
        prefix = prefix.strip().lower()
        regex = regex.strip()
        if prefix and regex:
            regex_by_prefix[prefix] = regex

    compiled: Dict[str, Pattern[str]] = {}
    for prefix in extra_prefixes:
        pattern_text = regex_by_prefix.get(prefix, ".*")
        compiled[prefix] = re.compile(pattern_text)
    return compiled


def parse_name_set(raw_value: str) -> Set[str]:
    return {item.strip().lower() for item in (raw_value or "").split(",") if item.strip()}


def parse_name_list(raw_value: str) -> List[str]:
    return [item.strip().lower() for item in (raw_value or "").split(",") if item.strip()]


def classify_device_kind(
    device_name: str,
    primary_prefix: str,
    extra_prefixes: List[str],
    extra_contains: List[str],
) -> str:
    lower = device_name.lower()
    if lower.startswith(primary_prefix.lower()):
        return "primary"
    if any(lower.startswith(prefix.lower()) for prefix in extra_prefixes):
        return "extra"
    if any(token in lower for token in extra_contains):
        return "extra"
    return "other"


def allowed_port_for_device(
    device_name: str,
    interface_name: str,
    primary_prefix: str,
    primary_port_prefix: str,
    primary_extra_port_regexes: List[Pattern[str]],
    extra_prefixes: List[str],
    extra_contains: List[str],
    extra_port_regexes: Dict[str, Pattern[str]],
) -> bool:
    dev = device_name.lower()
    if dev.startswith(primary_prefix.lower()):
        iface = interface_name.strip()
        return iface.lower().startswith(primary_port_prefix.lower()) or any(
            regex.search(iface) for regex in primary_extra_port_regexes
        )

    for prefix in extra_prefixes:
        if dev.startswith(prefix.lower()):
            regex = extra_port_regexes.get(prefix.lower())
            if regex is None:
                return True
            return bool(regex.search(interface_name))
    if any(token in dev for token in extra_contains):
        return True
    return False


def is_supported_link(local_kind: str, peer_kind: str) -> bool:
    return (local_kind == "primary" and peer_kind in {"primary", "extra"}) or (
        peer_kind == "primary" and local_kind in {"primary", "extra"}
    )


def _cli_has_flag(flag: str) -> bool:
    return any(arg == flag or arg.startswith(flag + "=") for arg in sys.argv[1:])


def apply_pattern_config(args: argparse.Namespace) -> argparse.Namespace:
    config_path = args.pattern_config
    if not config_path or not os.path.exists(config_path):
        return args

    with open(config_path, "r", encoding="utf-8") as handle:
        cfg = json.load(handle) or {}
    if not isinstance(cfg, dict):
        return args

    mapping = [
        ("device_prefix", "--device-prefix"),
        ("extra_device_prefixes", "--extra-device-prefixes"),
        ("extra_device_contains", "--extra-device-contains"),
        ("port_prefix", "--port-prefix"),
        ("primary_extra_port_regexes", "--primary-extra-port-regexes"),
        ("rtr_port_regex", "--rtr-port-regex"),
        ("nfw_port_regex", "--nfw-port-regex"),
        ("extra_port_regexes", "--extra-port-regexes"),
        ("interface_name_overrides", "--interface-name-overrides"),
        ("pcie_slot_map", "--pcie-slot-map"),
        ("exclude_interface_regexes", "--exclude-interface-regexes"),
        ("shared_devices", "--shared-devices"),
    ]

    for key, flag in mapping:
        if _cli_has_flag(flag):
            continue
        if key not in cfg:
            continue
        value = cfg[key]
        if isinstance(value, list):
            value = ",".join(str(item).strip() for item in value if str(item).strip())
        elif isinstance(value, dict):
            value = json.dumps(value)
        elif value is None:
            value = ""
        else:
            value = str(value)
        setattr(args, key, value)

    return args


def normalize_value(value: object) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, dict):
        for key in ("name", "slug", "label", "value", "display"):
            candidate = value.get(key)
            if candidate is not None:
                return str(candidate).strip().lower()
        return None
    text = str(value).strip()
    return text.lower() if text else None


def parse_interface_overrides(raw: str) -> Dict[str, str]:
    if not raw:
        return {}
    data = json.loads(raw)
    if not isinstance(data, dict):
        raise ValueError("interface-name-overrides must be a JSON object")
    return {str(k).strip().lower(): str(v).strip() for k, v in data.items() if str(k).strip()}


def parse_pcie_slot_map(raw: str) -> Dict[str, Dict[str, str]]:
    if not raw:
        return {}
    data = json.loads(raw)
    if not isinstance(data, dict):
        raise ValueError("pcie-slot-map must be a JSON object")
    parsed: Dict[str, Dict[str, str]] = {}
    for pattern, mapping in data.items():
        if not isinstance(mapping, dict):
            continue
        key = str(pattern).strip().lower()
        if not key:
            continue
        parsed[key] = {str(slot).strip(): str(mapped).strip() for slot, mapped in mapping.items()}
    return parsed


def parse_regex_list(raw: str) -> List[Pattern[str]]:
    compiled: List[Pattern[str]] = []
    for chunk in (raw or "").split(","):
        text = chunk.strip()
        if not text:
            continue
        compiled.append(re.compile(text, re.IGNORECASE))
    return compiled


def is_excluded_interface(interface_name: str, exclude_regexes: List[Pattern[str]]) -> bool:
    iface = (interface_name or "").strip()
    return any(regex.search(iface) for regex in exclude_regexes)


def resolve_pcie_slot(device_name: str, slot: str, pcie_slot_map: Dict[str, Dict[str, str]]) -> str:
    dev = (device_name or "").strip().lower()
    for pattern, mapping in pcie_slot_map.items():
        if fnmatch.fnmatch(dev, pattern):
            mapped = mapping.get(slot)
            if mapped:
                return mapped
    return slot


def normalize_interface_for_output(
    device_name: str,
    interface_name: str,
    overrides: Dict[str, str],
    pcie_slot_map: Optional[Dict[str, Dict[str, str]]] = None,
) -> str:
    dev = (device_name or "").strip()
    iface = (interface_name or "").strip()
    dev_key = dev.lower()
    iface_key = iface.lower()
    slot_map = pcie_slot_map or {}

    # Static overrides first (device-specific, then global interface mapping).
    if f"{dev_key}:{iface_key}" in overrides:
        return overrides[f"{dev_key}:{iface_key}"]
    if iface_key in overrides:
        return overrides[iface_key]

    # Generic PCIe convenience rewrite:
    # PCIe-<N>-200G-1 -> ens<N>f0np0
    # PCIe-<N>-200G-2 -> ens<N>f1np1
    match = re.match(r"^PCIe-(\d+)-200G-(\d+)$", iface, re.IGNORECASE)
    if match:
        slot, lane = match.groups()
        slot = resolve_pcie_slot(device_name, slot, slot_map)
        if lane == "1":
            return f"ens{slot}f0np0"
        if lane == "2":
            return f"ens{slot}f1np1"

    return iface


def device_netbox_cluster_name(device: Dict) -> Optional[str]:
    # Strict cluster source only:
    # 1) NetBox device.cluster.name (preferred)
    # 2) netbox_cluster field (if present)
    # No site/tenant/tag/other fallback matching.
    cluster_obj = device.get("cluster")
    norm = normalize_value(cluster_obj)
    if norm:
        return norm

    for container in (device, device.get("custom_fields") or {}, device.get("local_context_data") or {}):
        if isinstance(container, dict):
            raw = container.get("netbox_cluster")
            norm = normalize_value(raw)
            if norm:
                return norm
    return None


def in_cluster(device: Dict, cluster_value: str) -> bool:
    target = normalize_value(cluster_value)
    if not target:
        return False
    return device_netbox_cluster_name(device) == target


def paginated_get(
    token: str,
    base_url: str,
    endpoint: str,
    timeout: int,
    verify_tls: bool,
    proxy_url: Optional[str],
    params: Optional[Dict[str, object]] = None,
) -> Iterable[Dict]:
    url = urljoin(base_url.rstrip("/") + "/", endpoint.lstrip("/"))
    query = dict(params or {})
    if "limit" not in query:
        query["limit"] = 200

    while url:
        request_url = url
        if query:
            separator = "&" if "?" in request_url else "?"
            request_url = f"{request_url}{separator}{urlencode(query, doseq=True)}"
        payload = curl_get_json(
            request_url=request_url,
            token=token,
            timeout=timeout,
            verify_tls=verify_tls,
            proxy_url=proxy_url,
        )

        if isinstance(payload, dict) and "results" in payload:
            for item in payload["results"]:
                if isinstance(item, dict):
                    yield item
            next_url = payload.get("next")
            url = next_url if next_url else None
            query = None
            continue

        if isinstance(payload, list):
            for item in payload:
                if isinstance(item, dict):
                    yield item
            return

        return


def choose_peer_endpoint(interface_payload: Dict) -> Optional[Dict]:
    for key in ("connected_endpoints", "link_peers"):
        endpoints = interface_payload.get(key)
        if isinstance(endpoints, list) and endpoints:
            first = endpoints[0]
            if isinstance(first, dict):
                return first.get("object", first)
        if isinstance(endpoints, dict):
            return endpoints.get("object", endpoints)
    return None


def peer_details(interface_payload: Dict) -> Tuple[Optional[int], Optional[str], Optional[str]]:
    endpoint = choose_peer_endpoint(interface_payload)
    if not endpoint or not isinstance(endpoint, dict):
        return None, None, None

    peer_if = endpoint.get("name") or endpoint.get("display")
    device = endpoint.get("device")
    if isinstance(device, dict):
        peer_id = device.get("id")
        peer_device = device.get("name") or device.get("display")
        return peer_id, peer_device, peer_if

    if isinstance(device, str):
        return None, device, peer_if

    return None, None, peer_if


def curl_get_json(
    request_url: str,
    token: str,
    timeout: int,
    verify_tls: bool,
    proxy_url: Optional[str],
) -> object:
    cmd = [
        "curl",
        "-sS",
        "--max-time",
        str(timeout),
        "-H",
        f"Authorization: Token {token}",
        "-H",
        "Accept: application/json",
    ]
    if proxy_url:
        cmd.extend(["--proxy", proxy_url])
    if not verify_tls:
        cmd.append("--insecure")
    cmd.append(request_url)

    output = subprocess.check_output(cmd, stderr=subprocess.STDOUT)
    return json.loads(output.decode("utf-8"))


def build_switch_map(
    token: str,
    base_url: str,
    cluster: str,
    cluster_id: int,
    device_prefixes: List[str],
    extra_contains: List[str],
    timeout: int,
    verify_tls: bool,
    proxy_url: Optional[str],
) -> Dict[int, str]:
    switches: Dict[int, str] = {}

    for device in paginated_get(
        token,
        base_url,
        "/api/dcim/devices/",
        timeout=timeout,
        verify_tls=verify_tls,
        proxy_url=proxy_url,
        params={"cluster_id": cluster_id},
    ):
        name = str(device.get("name") or "").strip()
        device_id = device.get("id")
        if not name or not isinstance(device_id, int):
            continue
        lower_name = name.lower()
        if not any(lower_name.startswith(prefix) for prefix in device_prefixes) and not any(
            token in lower_name for token in extra_contains
        ):
            continue
        # Defensive check: enforce exact cluster-name match as requested.
        if not in_cluster(device, cluster):
            continue
        switches[device_id] = name

    return switches


def resolve_cluster_id(
    token: str,
    base_url: str,
    cluster_name: str,
    timeout: int,
    verify_tls: bool,
    proxy_url: Optional[str],
) -> int:
    target = normalize_value(cluster_name)
    if not target:
        raise ValueError("Invalid cluster name")

    # Try direct-name filter first.
    for cluster in paginated_get(
        token,
        base_url,
        "/api/virtualization/clusters/",
        timeout=timeout,
        verify_tls=verify_tls,
        proxy_url=proxy_url,
        params={"name": cluster_name},
    ):
        cid = cluster.get("id")
        cname = normalize_value(cluster.get("name"))
        if isinstance(cid, int) and cname == target:
            return cid

    # Fallback: scan all clusters if direct filter did not match exactly.
    for cluster in paginated_get(
        token,
        base_url,
        "/api/virtualization/clusters/",
        timeout=timeout,
        verify_tls=verify_tls,
        proxy_url=proxy_url,
    ):
        cid = cluster.get("id")
        cname = normalize_value(cluster.get("name"))
        if isinstance(cid, int) and cname == target:
            return cid

    raise ValueError(f"Cluster not found by name: {cluster_name}")


def build_edges(
    token: str,
    base_url: str,
    switches: Dict[int, str],
    device_prefixes: List[str],
    extra_prefixes: List[str],
    extra_contains: List[str],
    primary_device_prefix: str,
    port_prefix: str,
    primary_extra_port_regexes: List[Pattern[str]],
    extra_port_regexes: Dict[str, Pattern[str]],
    timeout: int,
    verify_tls: bool,
    proxy_url: Optional[str],
    focus_devices: Optional[Set[str]] = None,
    shared_devices: Optional[Set[str]] = None,
    interface_overrides: Optional[Dict[str, str]] = None,
    pcie_slot_map: Optional[Dict[str, Dict[str, str]]] = None,
    exclude_regexes: Optional[List[Pattern[str]]] = None,
) -> Set[Edge]:
    edges: Set[Edge] = set()
    seen_cables: Set[int] = set()
    valid_names = {name.lower() for name in switches.values()}
    shared_names = shared_devices or set()
    iface_overrides = interface_overrides or {}
    pcie_map = pcie_slot_map or {}
    excluded_ifaces = exclude_regexes or []
    primary_device_prefix_l = primary_device_prefix.lower()
    extra_prefixes_l = [prefix.lower() for prefix in extra_prefixes]
    extra_contains_l = [token.lower() for token in extra_contains]

    def allowed_device(name: str) -> bool:
        lower = name.lower()
        return any(lower.startswith(prefix) for prefix in device_prefixes) or any(
            token in lower for token in extra_contains_l
        )

    device_items = sorted(switches.items(), key=lambda pair: pair[1].lower())
    if focus_devices:
        device_items = [
            (device_id, device_name)
            for device_id, device_name in device_items
            if device_name.lower() in focus_devices
        ]
    else:
        # Only parse primary devices by default; supported links always include primary side.
        device_items = [
            (device_id, device_name)
            for device_id, device_name in device_items
            if classify_device_kind(device_name, primary_device_prefix_l, extra_prefixes_l, extra_contains_l)
            == "primary"
        ]

    for device_id, device_name in device_items:
        params = {"device_id": device_id}
        for iface in paginated_get(
            token,
            base_url,
            "/api/dcim/interfaces/",
            timeout=timeout,
            verify_tls=verify_tls,
            proxy_url=proxy_url,
            params=params,
        ):
            local_if = str(iface.get("name") or "").strip()
            if is_excluded_interface(local_if, excluded_ifaces):
                continue
            if not allowed_port_for_device(
                device_name=device_name,
                interface_name=local_if,
                primary_prefix=primary_device_prefix_l,
                primary_port_prefix=port_prefix,
                primary_extra_port_regexes=primary_extra_port_regexes,
                extra_prefixes=extra_prefixes_l,
                extra_contains=extra_contains_l,
                extra_port_regexes=extra_port_regexes,
            ):
                continue

            cable = iface.get("cable")
            if not cable:
                continue

            cable_id: Optional[int] = None
            if isinstance(cable, dict) and isinstance(cable.get("id"), int):
                cable_id = cable["id"]
            elif isinstance(cable, int):
                cable_id = cable

            if cable_id is not None and cable_id in seen_cables:
                continue

            peer_id, peer_device, peer_if = peer_details(iface)
            if not peer_device or not peer_if:
                continue
            if is_excluded_interface(str(peer_if), excluded_ifaces):
                continue
            if not allowed_device(peer_device):
                continue
            if not allowed_port_for_device(
                device_name=peer_device,
                interface_name=str(peer_if),
                primary_prefix=primary_device_prefix_l,
                primary_port_prefix=port_prefix,
                primary_extra_port_regexes=primary_extra_port_regexes,
                extra_prefixes=extra_prefixes_l,
                extra_contains=extra_contains_l,
                extra_port_regexes=extra_port_regexes,
            ):
                continue
            local_kind = classify_device_kind(
                device_name, primary_device_prefix_l, extra_prefixes_l, extra_contains_l
            )
            peer_kind = classify_device_kind(
                peer_device, primary_device_prefix_l, extra_prefixes_l, extra_contains_l
            )
            if not is_supported_link(local_kind, peer_kind):
                continue

            if peer_id is not None:
                if peer_id not in switches and peer_device.lower() not in shared_names:
                    continue
            elif peer_device.lower() not in valid_names and peer_device.lower() not in shared_names:
                continue

            normalized_local_if = normalize_interface_for_output(
                device_name, local_if, iface_overrides, pcie_map
            )
            normalized_peer_if = normalize_interface_for_output(
                peer_device, str(peer_if), iface_overrides, pcie_map
            )

            # Always render primary-side on the left so grouping is by switch.
            if local_kind == "primary":
                left = (device_name, normalized_local_if)
                right = (peer_device, normalized_peer_if)
            else:
                left = (peer_device, normalized_peer_if)
                right = (device_name, normalized_local_if)
            if left == right:
                continue
            if focus_devices and left[0].lower() not in focus_devices and right[0].lower() not in focus_devices:
                continue

            edges.add((left[0], left[1], right[0], right[1]))
            if cable_id is not None:
                seen_cables.add(cable_id)

    return edges


def render_dot(graph_name: str, edges: Set[Edge]) -> str:
    def natural_key(value: str) -> List[object]:
        return [int(part) if part.isdigit() else part.lower() for part in re.split(r"(\d+)", value)]

    def edge_sort_key(edge: Edge) -> Tuple[List[object], List[object], List[object], List[object]]:
        a_dev, a_if, b_dev, b_if = edge
        return (natural_key(a_dev), natural_key(a_if), natural_key(b_dev), natural_key(b_if))

    lines: List[str] = [f'graph "{graph_name}" {{', ""]
    last_device: Optional[str] = None
    for a_dev, a_if, b_dev, b_if in sorted(edges, key=edge_sort_key):
        if a_dev != last_device:
            if last_device is not None:
                lines.append("")
            lines.append(f"# {a_dev}")
            last_device = a_dev
        lines.append(f'"{a_dev}":"{a_if}" -- "{b_dev}":"{b_if}"')
    lines.extend(["", "}"])
    return "\n".join(lines) + "\n"


def main() -> int:
    args = apply_pattern_config(parse_args())
    verify_tls = not args.insecure
    proxy_url = args.netbox_proxy
    device_prefixes = parse_prefixes(args.device_prefix, args.extra_device_prefixes)
    primary_prefix = args.device_prefix.strip().lower()
    extra_prefixes = [prefix for prefix in device_prefixes if prefix != primary_prefix]
    extra_contains = parse_name_list(args.extra_device_contains)
    shared_devices = parse_name_set(args.shared_devices)
    try:
        extra_port_regexes = parse_extra_regexes(
            extra_prefixes=extra_prefixes,
            raw_regexes=args.extra_port_regexes,
            rtr_regex=args.rtr_port_regex,
            nfw_regex=args.nfw_port_regex,
        )
        primary_extra_port_regexes = parse_regex_list(args.primary_extra_port_regexes)
        interface_overrides = parse_interface_overrides(args.interface_name_overrides)
        pcie_slot_map = parse_pcie_slot_map(args.pcie_slot_map)
        exclude_regexes = parse_regex_list(args.exclude_interface_regexes)
    except re.error as exc:
        print(f"ERROR: Invalid port regex: {exc}", file=sys.stderr)
        return 1
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    try:
        cluster_id = resolve_cluster_id(
            token=args.netbox_token,
            base_url=args.netbox_url,
            cluster_name=args.netbox_cluster,
            timeout=args.timeout,
            verify_tls=verify_tls,
            proxy_url=proxy_url,
        )
        switches = build_switch_map(
            token=args.netbox_token,
            base_url=args.netbox_url,
            cluster=args.netbox_cluster,
            cluster_id=cluster_id,
            device_prefixes=device_prefixes,
            extra_contains=extra_contains,
            timeout=args.timeout,
            verify_tls=verify_tls,
            proxy_url=proxy_url,
        )
        focus_devices: Optional[Set[str]] = None
        if args.device_name:
            focus_devices = {args.device_name.strip().lower()}
            if args.device_name.strip().lower() not in {name.lower() for name in switches.values()}:
                raise ValueError(
                    f"Device '{args.device_name}' not found in cluster '{args.netbox_cluster}' "
                    f"with prefixes '{','.join(device_prefixes)}'."
                )

        edges = build_edges(
            token=args.netbox_token,
            base_url=args.netbox_url,
            switches=switches,
            device_prefixes=device_prefixes,
            extra_prefixes=extra_prefixes,
            extra_contains=extra_contains,
            primary_device_prefix=args.device_prefix,
            port_prefix=args.port_prefix,
            primary_extra_port_regexes=primary_extra_port_regexes,
            extra_port_regexes=extra_port_regexes,
            timeout=args.timeout,
            verify_tls=verify_tls,
            proxy_url=proxy_url,
            focus_devices=focus_devices,
            shared_devices=shared_devices,
            interface_overrides=interface_overrides,
            pcie_slot_map=pcie_slot_map,
            exclude_regexes=exclude_regexes,
        )
    except (subprocess.CalledProcessError, OSError, ValueError) as exc:
        print(f"ERROR: NetBox request failed: {exc}", file=sys.stderr)
        return 1

    dot = render_dot("NETBOX_TOPOLOGY", edges)
    with open(args.output, "w", encoding="utf-8") as handle:
        handle.write(dot)

    print(f"Generated {args.output}")
    print(f"Matched devices in cluster '{args.netbox_cluster}': {len(switches)}")
    print(
        "Cabled links "
        f"({','.join(device_prefixes)}* + contains[{','.join(extra_contains)}]; "
        f"{args.device_prefix} ports={args.port_prefix}*): {len(edges)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
