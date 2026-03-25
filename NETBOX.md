# NetBox Topology Builder

This repo includes `lldpq/netbox_topology_builder.py`, which builds a Graphviz DOT topology file from NetBox cable/interface data.

## Run

```bash
python3 lldpq/netbox_topology_builder.py \
  --netbox-url "$NETBOX_URL" \
  --netbox-token "$NETBOX_TOKEN" \
  --netbox-cluster "$NETBOX_CLUSTER"
```

Required inputs are:
- `--netbox-url` (or `NETBOX_URL`)
- `--netbox-token` (or `NETBOX_TOKEN`)
- `--netbox-cluster` (or `NETBOX_CLUSTER`)

## Option precedence

1. CLI flags
2. Environment variables (where supported)
3. Built-in script defaults

## Options

| Option | Purpose | Default / Source |
|---|---|---|
| `--netbox-url` | NetBox base URL | `NETBOX_URL` |
| `--netbox-token` | NetBox API token | `NETBOX_TOKEN` |
| `--netbox-cluster` | Cluster name filter | `NETBOX_CLUSTER` |
| `--device-prefix` | Primary device name prefix | `swi` |
| `--device-name` | Exact device filter (within matched cluster devices) | unset |
| `--port-prefix` | Primary interface prefix for primary devices | `swp` |
| `--primary-extra-port-regexes` | Extra allowed regexes for primary interfaces | `^eth0$` |
| `--include-peer-regex` | Regex include filter for peer device name | `.*` |
| `--interface-name-overrides` | JSON object for interface name rewrites (`iface` or `device:iface`) | `{}` |
| `--pcie-slot-map` | JSON object mapping device-pattern to PCIe slot rewrites | `{}` |
| `--exclude-interface-regexes` | Comma-separated regexes for interfaces to skip | empty |
| `--output` | Output DOT file path | `topology.dot` |
| `--timeout` | Request timeout in seconds | `30` |
| `--netbox-proxy` | Proxy URL (`socks5://...`, `http://...`, `https://...`) | `NETBOX_PROXY` |
| `--insecure` | Disable TLS certificate validation | off |
