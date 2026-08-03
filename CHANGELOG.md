# IPAM Lite Plugin — Changelog

## [1.3.1] - 2026-08-03

### Fix: superadmin couldn't see or use unmanaged subnet controls

**Bug** — `_is_admin()` checked `role == "admin"` only. Jen's actual role system is three-tier (`superadmin` > `admin` > `viewer`, per `jen/services/access.py`), so a `superadmin` account — the top-level role most installs actually log in as — evaluated as *not* admin. This hid the **＋ Add Unmanaged Subnet** button entirely and would have blocked subnet delete as well, even though `admin` accounts worked fine.

**Fix** — `_is_admin()` now delegates to Jen's own `is_admin_or_above()` helper instead of re-deriving role logic in the plugin, so it can't drift out of sync with core again.

## [1.3.0] - 2026-08-03


### Unmanaged subnets + audit fixes

**Unmanaged subnet support** — IPAM Lite is no longer limited to Kea-managed subnets. Admins can add non-DHCP subnets (e.g. a backend network) from the overview page via **＋ Add Unmanaged Subnet** (name, CIDR, description). Unmanaged subnets:
- Appear on the overview alongside Kea subnets with an **unmanaged** badge
- Never query Kea — addresses are only Available or Static
- Support per-address **manual hostname and MAC** fields (since there's no DHCP to supply them), with MAC validation and normalisation
- Can be deleted (admin only) from the detail page, cascading their entries
- Reject CIDRs that overlap any Kea-managed or existing unmanaged subnet; hard cap at /16, warning above /22
- Are visible to all authenticated users; add/delete is admin-only

**Schema changes** (idempotent migrations):
- New `ipam_subnets` table
- `subnet_kind` discriminator on `ipam_static_entries` and `ipam_assignment_history`
- `hostname`, `mac`, `is_static` columns on `ipam_static_entries`
- The global `UNIQUE(ip)` is replaced with `UNIQUE(ip, subnet_kind, subnet_id)` — previously an entry saved in one subnet could silently overwrite the same IP string tracked in another subnet
- New index on `(subnet_kind, subnet_id)`

**Audit fixes:**
- Reservation identifiers are only rendered as MACs when `dhcp_identifier_type` is hw-address; other identifier types (client-id, DUID, circuit-id) display as labelled hex instead of garbage, and over-length identifiers are no longer silently truncated
- Reservations with NULL/zero `ipv4_address` (hostname-only / option-only) are excluded from the address-space query
- DB connections are now released in `finally` blocks — previously an exception mid-query stranded a pooled connection
- "Available with annotation" is now a real state: `is_static` is stored explicitly, so saving an annotated IP with status Available no longer forcibly displays it as Static (existing entries migrate as Static, preserving current behaviour)
- Saved IPs are validated as belonging to the subnet's CIDR
- All plugin-written timestamps now use `UTC_TIMESTAMP()` per Jen's UTC-throughout convention
- CSV export filename is sanitised (subnet names with spaces/quotes no longer malform the `Content-Disposition` header)
- The `filter` query parameter is whitelisted server-side
- Edit modal data is passed via `data-entry` JSON attributes instead of hand-escaped inline JS arguments
- The ✕ clear-search button described in the 1.2.0 changelog now actually exists
- Per-subnet summary errors on the overview are logged instead of silently swallowed
- Redundant class-swap logic in the filter-tab JS replaced with `classList.toggle`

## [1.2.1 – 1.2.3]

Changelog entries were not recorded at release time.

## [1.2.0] - 2026-06-09

### Search, MAC display, quick links

**Live search** — A search box above the address table filters as you type across IP address, hostname, label, MAC, owner, and notes simultaneously. No page reload — purely client-side filtering so it works instantly across all 500+ addresses in a /23. Combines with the status filter tabs: you can filter to "Reserved" and search within those results. A result count shows how many addresses match. An ✕ button clears the search.

**MAC address column** — MAC addresses for dynamic and reserved IPs are now always visible in the table rather than only appearing in the edit modal. Useful for cross-referencing with physical hardware.

**Quick action links** — second button per row based on IP status:
- Available / Static → 📌 "Create Reservation" — opens the Add Reservation form with the IP pre-filled
- Dynamic → 🔗 "View Lease" — links to Leases page filtered to that IP
- Reserved → 🔗 "View Reservation" — links to Reservations page filtered to that IP

**Filter tabs are now client-side** — the status filter tabs no longer reload the page; they use the same JS filtering as search. Switching between All/Available/Dynamic/Reserved/Static is instant.

## [1.1.0] - 2026-06-09

### Edit modal UX overhaul

- **Single ✏️ button** per row replaces the scattered "+ Note" / "Edit" / "✕" buttons
- **Context-aware modal** — fields shown depend on the IP's current status:
  - Dynamic / Reserved: Notes field only (label/owner/status are read-only from Kea). Kea hostname and MAC shown as read-only info.
  - Available / Static: Status selector (Available ↔ Static), Label, Owner, Notes all editable
- **Status selector** for available/static IPs — mark an address as Static to designate it as intentionally assigned outside the DHCP pool (router, NAS, printer, etc.)
- **"Clear all notes"** button in the modal removes the IPAM entry entirely
- Setting status back to Available with no other fields also clears the entry cleanly

## [1.0.0] - 2026-06-08

### First full release

- **Overview page** — all accessible subnets shown as cards with stacked utilisation bars (dynamic/reserved/static/available) and percentage used
- **Subnet detail page** — full address space table showing every IP in the pool with its current status
- **Status types:** Available (no lease/reservation/note), Dynamic (active DHCP lease), Reserved (Kea reservation), Static (manually noted)
- **Notes/annotations** — click "＋ Note" on any IP to add a label (e.g. "NAS"), owner (e.g. "Matthew"), and free-text notes. Edit or remove at any time.
- **Filter tabs** — filter the address table by status (All / Available / Dynamic / Reserved / Static)
- **CSV export** — download the full address space as CSV for any subnet
- **Assignment history** — every add/edit/remove is logged to `ipam_assignment_history` with user and timestamp
- **Subnet access control** — respects Jen's role-based subnet restrictions

## [0.1.0] - 2026-06-05

- Stub plugin for framework testing
