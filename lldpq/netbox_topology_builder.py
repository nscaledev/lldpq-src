#!/usr/bin/env python3
"""
Build topology.dot from NetBox cable data with strict switch filtering.

This builder maps links when:
1) Local device is in the requested `netbox_cluster`.
2) Local device name matches the requested prefix (default `swi`).
3) Local port matches prefix/extra rules (default `swp*` plus `eth0`).
4) The local interface has a cable assigned.
5) Peer device/interface are included without peer-side name/port filtering,
   with optional peer-name regex filtering.
"""

import argparse
import fnmatch
import http.client
import json
import os
import re
import socket
import ssl
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Pattern, Set, Tuple
from urllib.parse import urlencode, urljoin, urlparse


Edge = Tuple[str, str, str, str]
DEFAULT_PCIE_SLOT_MAP_JSON = (
    '{"*-p-phy-osh*":{"1":"5","2":"8"},'
    '"*-p-phy-cpo*":{"1":"5","2":"8"},'
    '"*-proxmox-mgt*":{"1":"5","2":"8"}}'
)


@dataclass
class NetboxTopologyConfig:
    netbox_url: str
    netbox_token: str
    netbox_cluster: str
    device_prefix: str
    device_name: Optional[str]
    port_prefix: str
    primary_extra_port_regexes: List[Pattern[str]]
    include_peer_regex: Pattern[str]
    interface_name_overrides: Dict[str, str]
    pcie_slot_map: Dict[str, Dict[str, str]]
    exclude_interface_regexes: List[Pattern[str]]
    output: str
    timeout: int
    proxy_url: Optional[str]
    verify_tls: bool


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Generate a GraphViz DOT topology from NetBox cables, restricted "
            "to switch-prefix devices and port-prefix interfaces in a netbox_cluster."
        )
    )
    parser.add_argument("--netbox-url", default=os.getenv("NETBOX_URL"), help="NetBox base URL")
    parser.add_argument("--netbox-token", default=os.getenv("NETBOX_TOKEN"), help="NetBox API token")
    parser.add_argument(
        "--netbox-cluster",
        default=os.getenv("NETBOX_CLUSTER"),
        help="Cluster name filter (required)",
    )
    parser.add_argument(
        "--device-prefix",
        default="swi",
        help="Local device name prefix filter (default: swi)",
    )
    parser.add_argument(
        "--device-name",
        default=None,
        help="Optional exact local device name filter within the cluster",
    )
    parser.add_argument(
        "--port-prefix",
        default="swp",
        help="Local interface prefix for local device prefix (default: swp)",
    )
    parser.add_argument(
        "--primary-extra-port-regexes",
        default="^eth0$",
        help=(
            "Comma-separated regexes to allow extra local interfaces "
            "(default: ^eth0$)"
        ),
    )
    parser.add_argument(
        "--include-peer-regex",
        default=".*",
        help="Regex for peer device name include filter (default: .*)",
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
        default=DEFAULT_PCIE_SLOT_MAP_JSON,
        help=(
            "JSON dict of device-pattern -> slot map for PCIe names. "
            'Example: {"host-*": {"1": "5", "2": "8"}} '
            '(default includes {"*-p-phy-osh*":{"1":"5","2":"8"},"*-p-phy-cpo*":{"1":"5","2":"8"},"*-proxmox-mgt*":{"1":"5","2":"8"}})'
        ),
    )
    parser.add_argument(
        "--exclude-interface-regexes",
        default="",
        help="Comma-separated regexes for interfaces to ignore on either cable end (default: none)",
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
        help="Optional proxy URL (for example socks5://127.0.0.1:8888)",
    )
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="Disable TLS certificate verification",
    )
    return parser.parse_args(argv)


def parse_config(argv: Optional[List[str]] = None) -> NetboxTopologyConfig:
    parser = argparse.ArgumentParser(add_help=False)
    args = parse_args(argv)

    missing = []
    if not args.netbox_url:
        missing.append("netbox-url/NETBOX_URL")
    if not args.netbox_token:
        missing.append("netbox-token/NETBOX_TOKEN")
    if not args.netbox_cluster:
        missing.append("netbox-cluster/NETBOX_CLUSTER")
    if missing:
        raise ValueError("Missing required settings: " + ", ".join(missing))

    primary_extra_port_regexes = parse_regex_list(args.primary_extra_port_regexes)
    exclude_regexes = parse_regex_list(args.exclude_interface_regexes)
    interface_overrides = parse_interface_overrides(args.interface_name_overrides)
    pcie_slot_map = parse_pcie_slot_map(args.pcie_slot_map)
    include_peer_regex = re.compile(args.include_peer_regex, re.IGNORECASE)

    return NetboxTopologyConfig(
        netbox_url=args.netbox_url,
        netbox_token=args.netbox_token,
        netbox_cluster=args.netbox_cluster,
        device_prefix=args.device_prefix,
        device_name=args.device_name.strip().lower() if args.device_name else None,
        port_prefix=args.port_prefix,
        primary_extra_port_regexes=primary_extra_port_regexes,
        include_peer_regex=include_peer_regex,
        interface_name_overrides=interface_overrides,
        pcie_slot_map=pcie_slot_map,
        exclude_interface_regexes=exclude_regexes,
        output=args.output,
        timeout=args.timeout,
        proxy_url=args.netbox_proxy,
        verify_tls=not args.insecure,
    )


def allowed_port_for_device(
    device_name: str,
    interface_name: str,
    primary_prefix: str,
    primary_port_prefix: str,
    primary_extra_port_regexes: List[Pattern[str]],
) -> bool:
    dev = device_name.lower()
    if dev.startswith(primary_prefix.lower()):
        iface = interface_name.strip()
        return iface.lower().startswith(primary_port_prefix.lower()) or any(
            regex.search(iface) for regex in primary_extra_port_regexes
        )
    return False


def normalize_value(value: object) -> Optional[str]:
    if value is None:
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

    if f"{dev_key}:{iface_key}" in overrides:
        return overrides[f"{dev_key}:{iface_key}"]
    if iface_key in overrides:
        return overrides[iface_key]

    match = re.match(r"^PCIe-(\d+)-200G-(\d+)$", iface, re.IGNORECASE)
    if match:
        slot, lane = match.groups()
        slot = resolve_pcie_slot(device_name, slot, slot_map)
        if lane == "1":
            return f"ens{slot}f0np0"
        if lane == "2":
            return f"ens{slot}f1np1"

    return iface


def device_cluster_name(device: Dict) -> Optional[str]:
    cluster_obj = device.get("cluster")
    if not isinstance(cluster_obj, dict):
        return None
    return normalize_value(cluster_obj.get("name"))


def in_cluster(device: Dict, cluster_value: str) -> bool:
    target = normalize_value(cluster_value)
    if not target:
        return False
    return device_cluster_name(device) == target


def _socks5_connect(proxy_host: str, proxy_port: int, target_host: str, target_port: int, timeout: int) -> socket.socket:
    sock = socket.create_connection((proxy_host, proxy_port), timeout=timeout)

    # no-auth SOCKS5
    sock.sendall(b"\x05\x01\x00")
    method_reply = sock.recv(2)
    if len(method_reply) != 2 or method_reply[0] != 0x05 or method_reply[1] == 0xFF:
        sock.close()
        raise OSError("SOCKS5 proxy does not accept no-auth")

    host_bytes = target_host.encode("idna")
    if len(host_bytes) > 255:
        sock.close()
        raise OSError("Target hostname is too long for SOCKS5")

    req = b"\x05\x01\x00\x03" + bytes([len(host_bytes)]) + host_bytes + target_port.to_bytes(2, "big")
    sock.sendall(req)

    head = sock.recv(4)
    if len(head) != 4 or head[0] != 0x05 or head[1] != 0x00:
        sock.close()
        raise OSError("SOCKS5 connect failed")

    atyp = head[3]
    if atyp == 0x01:
        to_read = 4 + 2
    elif atyp == 0x03:
        ln = sock.recv(1)
        if len(ln) != 1:
            sock.close()
            raise OSError("Invalid SOCKS5 reply")
        to_read = ln[0] + 2
    elif atyp == 0x04:
        to_read = 16 + 2
    else:
        sock.close()
        raise OSError("Unsupported SOCKS5 reply address type")

    remaining = to_read
    while remaining > 0:
        chunk = sock.recv(remaining)
        if not chunk:
            sock.close()
            raise OSError("Unexpected EOF from SOCKS5 proxy")
        remaining -= len(chunk)

    return sock


def _http_get_json_via_socks(
    request_url: str,
    token: str,
    timeout: int,
    verify_tls: bool,
    proxy_url: str,
) -> object:
    parsed = urlparse(request_url)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError(f"Unsupported URL scheme: {parsed.scheme}")

    proxy = urlparse(proxy_url)
    if proxy.scheme.lower() not in {"socks5", "socks5h"}:
        raise ValueError(f"Unsupported SOCKS proxy scheme: {proxy.scheme}")
    if not proxy.hostname or not proxy.port:
        raise ValueError("Invalid SOCKS proxy URL")

    target_host = parsed.hostname
    if not target_host:
        raise ValueError("Invalid request URL host")
    target_port = parsed.port or (443 if parsed.scheme == "https" else 80)

    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query

    sock = _socks5_connect(proxy.hostname, proxy.port, target_host, target_port, timeout)
    try:
        if parsed.scheme == "https":
            context = ssl.create_default_context()
            if not verify_tls:
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
            sock = context.wrap_socket(sock, server_hostname=target_host)

        request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {target_host}\r\n"
            f"Authorization: Token {token}\r\n"
            "Accept: application/json\r\n"
            "Accept-Encoding: identity\r\n"
            "Connection: close\r\n"
            "\r\n"
        )
        sock.sendall(request.encode("utf-8"))

        response = http.client.HTTPResponse(sock)
        response.begin()
        payload = response.read()
        if response.status >= 400:
            raise OSError(f"HTTP {response.status}: {response.reason}")

        return json.loads(payload.decode("utf-8"))
    finally:
        try:
            sock.close()
        except OSError:
            pass


def _http_get_json_via_urllib(
    request_url: str,
    token: str,
    timeout: int,
    verify_tls: bool,
    proxy_url: Optional[str],
) -> object:
    handlers: List[urllib.request.BaseHandler] = []
    if proxy_url:
        handlers.append(urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url}))

    opener = urllib.request.build_opener(*handlers)
    req = urllib.request.Request(
        request_url,
        headers={
            "Authorization": f"Token {token}",
            "Accept": "application/json",
            "Accept-Encoding": "identity",
        },
    )

    context: Optional[ssl.SSLContext] = None
    if request_url.lower().startswith("https://"):
        context = ssl.create_default_context()
        if not verify_tls:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

    open_kwargs = {"timeout": timeout}
    if context is not None:
        open_kwargs["context"] = context

    with opener.open(req, **open_kwargs) as response:
        payload = response.read()
        return json.loads(payload.decode("utf-8"))


def http_get_json(
    request_url: str,
    token: str,
    timeout: int,
    verify_tls: bool,
    proxy_url: Optional[str],
) -> object:
    if proxy_url and proxy_url.lower().startswith("socks5"):
        return _http_get_json_via_socks(request_url, token, timeout, verify_tls, proxy_url)
    return _http_get_json_via_urllib(request_url, token, timeout, verify_tls, proxy_url)


def paginated_get(
    config: NetboxTopologyConfig,
    endpoint: str,
    params: Optional[Dict[str, object]] = None,
) -> Iterable[Dict]:
    url = urljoin(config.netbox_url.rstrip("/") + "/", endpoint.lstrip("/"))
    query = dict(params or {})
    if "limit" not in query:
        query["limit"] = 200

    while url:
        request_url = url
        if query:
            separator = "&" if "?" in request_url else "?"
            request_url = f"{request_url}{separator}{urlencode(query, doseq=True)}"

        payload = http_get_json(
            request_url=request_url,
            token=config.netbox_token,
            timeout=config.timeout,
            verify_tls=config.verify_tls,
            proxy_url=config.proxy_url,
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


def build_switch_map(config: NetboxTopologyConfig, cluster_id: int) -> Dict[int, str]:
    switches: Dict[int, str] = {}

    for device in paginated_get(config, "/api/dcim/devices/", params={"cluster_id": cluster_id}):
        name = str(device.get("name") or "").strip()
        device_id = device.get("id")
        if not name or not isinstance(device_id, int):
            continue
        if not name.lower().startswith(config.device_prefix.lower()):
            continue
        if not in_cluster(device, config.netbox_cluster):
            continue
        switches[device_id] = name

    return switches


def resolve_cluster_id(config: NetboxTopologyConfig) -> int:
    target = normalize_value(config.netbox_cluster)
    if not target:
        raise ValueError("Invalid cluster name")

    for cluster in paginated_get(config, "/api/virtualization/clusters/", params={"name": config.netbox_cluster}):
        cid = cluster.get("id")
        cname = normalize_value(cluster.get("name"))
        if isinstance(cid, int) and cname == target:
            return cid

    for cluster in paginated_get(config, "/api/virtualization/clusters/"):
        cid = cluster.get("id")
        cname = normalize_value(cluster.get("name"))
        if isinstance(cid, int) and cname == target:
            return cid

    raise ValueError(f"Cluster not found by name: {config.netbox_cluster}")


def build_edges(
    config: NetboxTopologyConfig,
    switches: Dict[int, str],
    focus_devices: Optional[Set[str]] = None,
) -> Set[Edge]:
    edges: Set[Edge] = set()
    seen_cables: Set[int] = set()

    device_items = sorted(switches.items(), key=lambda pair: pair[1].lower())
    if focus_devices:
        device_items = [
            (device_id, device_name)
            for device_id, device_name in device_items
            if device_name.lower() in focus_devices
        ]

    for device_id, device_name in device_items:
        for iface in paginated_get(config, "/api/dcim/interfaces/", params={"device_id": device_id}):
            local_if = str(iface.get("name") or "").strip()
            if is_excluded_interface(local_if, config.exclude_interface_regexes):
                continue
            if not allowed_port_for_device(
                device_name=device_name,
                interface_name=local_if,
                primary_prefix=config.device_prefix,
                primary_port_prefix=config.port_prefix,
                primary_extra_port_regexes=config.primary_extra_port_regexes,
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

            _peer_id, peer_device, peer_if = peer_details(iface)
            if not peer_device or not peer_if:
                continue
            peer_if_text = str(peer_if).strip()
            if is_excluded_interface(peer_if_text, config.exclude_interface_regexes):
                continue
            if not config.include_peer_regex.search(peer_device):
                continue

            normalized_local_if = normalize_interface_for_output(
                device_name,
                local_if,
                config.interface_name_overrides,
                config.pcie_slot_map,
            )
            normalized_peer_if = normalize_interface_for_output(
                peer_device,
                peer_if_text,
                config.interface_name_overrides,
                config.pcie_slot_map,
            )

            left = (device_name, normalized_local_if)
            right = (peer_device, normalized_peer_if)
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
    try:
        config = parse_config()
    except (ValueError, re.error, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    try:
        cluster_id = resolve_cluster_id(config)
        switches = build_switch_map(config, cluster_id)
        focus_devices: Optional[Set[str]] = None
        if config.device_name:
            focus_devices = {config.device_name}
            if config.device_name not in {name.lower() for name in switches.values()}:
                raise ValueError(
                    f"Device '{config.device_name}' not found in cluster '{config.netbox_cluster}' "
                    f"with prefix '{config.device_prefix}'."
                )

        edges = build_edges(config, switches, focus_devices)
    except (
        OSError,
        ValueError,
        json.JSONDecodeError,
        urllib.error.URLError,
        urllib.error.HTTPError,
    ) as exc:
        print(f"ERROR: NetBox request failed: {exc}", file=sys.stderr)
        return 1

    dot = render_dot("NETBOX_TOPOLOGY", edges)
    with open(config.output, "w", encoding="utf-8") as handle:
        handle.write(dot)

    print(f"Generated {config.output}")
    print(f"Matched devices in cluster '{config.netbox_cluster}': {len(switches)}")
    print(
        "Cabled links "
        f"(cluster devices={config.device_prefix}*; "
        f"peer filter={config.include_peer_regex.pattern}; "
        f"{config.device_prefix} ports={config.port_prefix}*): {len(edges)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
