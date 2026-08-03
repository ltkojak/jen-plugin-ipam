# IPAM Lite — Jen Plugin

Full IP address space management for Jen — covering both Kea-managed subnets and unmanaged (non-DHCP) networks. See every IP in each subnet at a glance — available, dynamic DHCP lease, Kea reservation, or statically noted. Add labels, owners, and notes to any address. Replaces Netbox for simple static IP tracking.

## Requirements

- [Jen](https://github.com/ltkojak/jen-kea) v3.6.0 or later

## Features

- **Overview page** — all subnets as cards with stacked utilisation bars (dynamic / reserved / static / available)
- **Unmanaged subnets** — track non-DHCP networks Kea doesn't manage (backend networks, management VLANs, etc.). Admins add them by name + CIDR; addresses support manual hostname and MAC since there's no DHCP to supply them
- **Subnet detail** — every IP in the pool with its current status and any annotations
- **Edit modal** — context-aware per IP status:
  - Dynamic / Reserved: notes only (Kea controls identity)
  - Available / Static: label, owner, notes, and status toggle
  - Unmanaged subnets additionally: manual hostname and MAC
- **Static designation** — mark IPs as statically assigned (router, NAS, printer, etc.) without touching Kea
- **Search + filter** — live client-side search across IP, hostname, label, MAC, owner, and notes; status filter tabs
- **CSV export** per subnet
- **Assignment history** logged with user and timestamp (UTC)
- Respects Jen subnet access control; unmanaged subnet add/delete is admin-only

## Installation

Open Jen → Settings → Plugins and click **Install** next to IPAM Lite.

Or manually:
```bash
cd /opt/jen/plugins
mkdir ipam && cd ipam
curl -LO https://github.com/ltkojak/jen-plugin-ipam/raw/main/plugin.zip
unzip plugin.zip
touch .enabled
sudo systemctl restart jen
```

## Version History

See [CHANGELOG.md](CHANGELOG.md).

## License

GPL v3 — Copyright 2026 Matthew Thibodeau
