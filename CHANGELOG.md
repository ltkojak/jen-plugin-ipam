# IPAM Lite Plugin — Changelog

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

## [1.1.0] - 2026-06-09

### Edit modal UX overhaul

- **Single ✏️ button** per row replaces the scattered "+ Note" / "Edit" / "✕" buttons
- **Context-aware modal** — fields shown depend on the IP's current status:
  - Dynamic / Reserved: Notes field only (label/owner/status are read-only from Kea). Kea hostname and MAC shown as read-only info.
  - Available / Static: Status selector (Available ↔ Static), Label, Owner, Notes all editable
- **Status selector** for available/static IPs — mark an address as Static to designate it as intentionally assigned outside the DHCP pool (router, NAS, printer, etc.)
- **"Clear all notes"** button in the modal removes the IPAM entry entirely
- Setting status back to Available with no other fields also clears the entry cleanly
