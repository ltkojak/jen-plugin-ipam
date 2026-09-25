# IPAM Lite — Jen Plugin

Full IP address space management for Jen — covering both Kea-managed subnets and unmanaged (non-DHCP) networks. See every IP in each subnet at a glance — available, dynamic DHCP lease, Kea reservation, statically noted, or planned for future use. Add labels, owners, and notes to any address. Import from Netbox or other IPAM tools. Replaces Netbox for simple static IP tracking.

> **IPv4 only.** As of Jen v5.0's IPv6 rollout, IPAM Lite covers IPv4 subnets exclusively — full-address-space enumeration doesn't extend to IPv6's /64s (see Jen's `docs/ARCHITECTURE.md` for why). For IPv6 lease and reservation counts, use Jen's own Subnets/Leases/Reservations pages instead. This isn't a bug or a gap to report — it's a deliberate v5.0 scope decision.

## Requirements

- [Jen](https://github.com/ltkojak/jen-kea) v5.57.0 or later (v1.5.x runs on 5.34.0+)

## Features

- **Overview page** — all subnets as cards with stacked utilisation bars (dynamic / reserved / static / planned / infrastructure / conflict / available), counted without enumerating the address space
- **Unmanaged subnets** — track non-DHCP networks Kea doesn't manage (backend networks, management VLANs, etc.). Admins add them by name + CIDR; addresses support manual hostname and MAC since there's no DHCP to supply them
- **Subnet detail** — every IP with its current status and annotations, as a phone-friendly rowlist; the gateway, DNS servers, DHCP pools and the Kea/Jen hosts (from Jen's own subnet context) are shown and labelled as **infrastructure**, addresses inside a DHCP pool carry a `pool` badge, and runs of available addresses collapse into one row on every subnet (`?all=1` shows them all)
- **Next free** — the first available address outside every DHCP pool, one click
- **Devices** — a lease's row shows the device Jen knows for that MAC (name, vendor, icon); Owner prefills from it
- **Conflict** — a static/planned entry whose address a DHCP client now holds is flagged, not silently shown as a lease. A periodic check alerts once per new conflict (Settings → Alerts, type "IPAM Conflict") and emits an event for the Timeline
- **Search + JSON API** — entries show up in Jen's global search by label, owner, IP or hostname; `GET/POST /api/v1/plugins/ipam/entries` and `GET /api/v1/plugins/ipam/next-free/<subnet_id>` for scripting, authenticated with a Jen API key and scoped to whatever subnets it can see
- **"Open in IPAM"** row action on Jen's own Reservations page, linking straight to that address
- **Range…** — mark a from–to span planned/static (one label/owner) or clear it; leases and reservations are never overwritten
- **Edit modal** — context-aware per IP status:
  - Dynamic / Reserved: notes only (Kea controls identity)
  - Available / Static / Planned: label, owner, notes, and status toggle. Typing anything while an address is Available auto-switches it to Static — pick Planned yourself if that's what you mean instead
  - Manual hostname and MAC on any subnet (a static host has no lease to supply them; Network Discovery matches on the MAC)
- **Static designation** — mark IPs as statically assigned (router, NAS, printer, etc.) without touching Kea
- **Planned designation** — earmark an IP for something coming up without calling it a DHCP reservation
- **Import** — bring in addresses from a Jen export, Netbox's IP Addresses export, or a generic CSV (column names are matched automatically). Preview and confirm before anything is written
- **Search + filter** — live client-side search across IP, hostname, label, MAC, owner, and notes; status filter tabs
- **CSV export** per subnet — Jen's own format and a Netbox-shaped one; every cell passes a formula-injection guard
- **Assignment history** logged with user and timestamp (UTC), shown per address in the edit modal, in a Recent changes panel, and exportable
- Respects Jen subnet access control: a user restricted to specific Kea subnets sees only those, and none of the unmanaged subnets; unmanaged subnet add/delete is admin-only, and viewers are read-only: every change needs admin

## Installation

Open Jen → **Settings → Plugins** and click **Install** next to IPAM Lite. Jen downloads the release pinned in its plugin registry, verifies its checksum, and enables it; restart Jen when prompted.

To install by hand instead (a checkout without registry access), unzip `plugin.zip` from the release tag you want into `/var/lib/jen/plugins/ipam/`, then enable it from Settings → Plugins and restart Jen.

## Development

`python3 tools/verify.py --build` rebuilds `plugin.zip` deterministically from the tree and runs the same checks CI runs on every push and tag: the zip matches the tree byte-for-byte, no template carries an inline event handler, an inline `style=` attribute or an un-nonce'd `<script>` (Jen's CSP executes neither of the first and last), `manifest.json`'s version matches the top `CHANGELOG.md` entry, and `plugin.py` compiles and passes ruff. The committed `plugin.zip` is the artifact Jen installs, so rebuild it in the same commit as any change.

## Version History

See [CHANGELOG.md](CHANGELOG.md).

## License

GPL v3 — Copyright 2026 Matthew Thibodeau
