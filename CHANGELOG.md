# IPAM Lite Plugin — Changelog

## [1.4.4] - 2026-09-13

### Fix: migrations were MariaDB-only — installs on MySQL 8 could never migrate

Every schema change since v1.3.0 used MariaDB's `ALTER TABLE … ADD
COLUMN IF NOT EXISTS` / `DROP INDEX IF EXISTS` / `ADD … KEY IF NOT
EXISTS` forms. MySQL 8 has no `IF [NOT] EXISTS` for those, so on a
Jen running against MySQL the first ALTER (migration 4) was a syntax
error, the migration run stopped there, and — since Jen v5.28.1 gates
activation on migrations — the plugin never enabled. Jen supports both
databases; this plugin only ever worked on one.

The migrations are now plain, portable DDL, and the manifest uses
Jen's explicit `{version, description, sql}` format instead of the
flat positional list, so each migration's number is pinned in the file
rather than implied by its position. Versions 1–13 map one-to-one onto
the old positions, so an existing install (which has all thirteen
recorded) runs nothing new; a fresh install runs all thirteen on
either database.

Idempotency moved from the SQL to Jen: **this release requires Jen
v5.28.2**, whose migration runner treats "duplicate column", "duplicate
key name" and "can't DROP — doesn't exist" as *already in the desired
state* and records the migration as applied rather than failing. That
is what lets migration 8 (`DROP INDEX ip`, which undoes v1.1.0's
`UNIQUE` on `ip`) run cleanly on a fresh database that never had that
index, without MariaDB's `IF EXISTS`. On an older Jen the manifest is
refused at install time with the usual "requires Jen …" message.

## [1.4.3] - 2026-09-13

### Housekeeping: dead `.enabled` marker, stale install docs

Dropped the in-tree `.enabled` file — Jen has kept its enable marker
outside the plugin directory (`/var/lib/jen/plugins-enabled/`) since
v5.13.0, so the one shipped in the zip did nothing. The README's manual
install steps still told you to `touch .enabled` in `/opt/jen/plugins`,
a path Jen no longer installs to; they now describe the Settings →
Plugins install (the registry-pinned, checksum-verified path) and the
actual manual location. Added a Development section covering
`tools/verify.py --build` and what CI enforces. No code changes.

## [1.4.2] - 2026-09-13

### Fix: unmanaged subnets ignored Jen's subnet restrictions

Every route gates a Kea-managed subnet through Jen's own subnet-access
check, so a user restricted to specific subnets only ever sees those.
Unmanaged subnets had no equivalent check at all — only "logged in" —
so a subnet-restricted viewer could open, export, annotate, and clear
entries on *any* unmanaged subnet, and the overview page listed them
all regardless. Unmanaged subnets aren't part of Jen's subnet map, so
there's no per-subnet grant to consult; the fix treats them like any
other out-of-scope subnet: a user whose access is restricted to
specific Kea subnets gets none of them, on the overview and on every
detail/edit/import/export route. Unrestricted users and superadmins
see no change.

Separately, the entry save/clear routes answered an access-denied
POST with a raw JSON `403` — but the forms that post to them are plain
HTML forms, so the browser just showed `{"error": "Access denied"}` as
a page. They now flash and redirect like every other error path.

### Fix: Content-Security-Policy compatibility (no inline scripts)

Jen v5.22.0 dropped `'unsafe-inline'` from its script-src CSP — every
`<script>` tag now needs a per-request nonce, and inline event-handler
attributes (`onclick=`, `oninput=`, `onmouseover=`, etc.) are simply
never executed under that policy. This plugin's two templates
(`index.html`, `subnet.html`) still had ~19 inline handlers and two
un-nonce'd `<script>` blocks from before that change, so every button,
filter tab, and the per-row edit action silently stopped working the
moment CSP enforcement was turned on — nothing errored, the browser
just refused to run the attribute.

Every inline handler is now bound via `addEventListener` (delegated on
the containers that already existed — `#filter-tabs`, `#ipam-table` —
for the per-row edit button and the filter tabs, so a new row or a new
tab doesn't need a new listener), both `<script>` blocks carry
`nonce="{{ csp_nonce }}"`, and the two `onmouseover`/`onmouseout`
handlers on the subnet-card hover effect became a plain CSS `:hover`
rule instead of JS entirely. No functional or visual change — every
button does exactly what it did before, just via a CSP-compliant
binding.

Also corrected `manifest.json`'s `changelog_url`, which pointed at the
copy of this file bundled inside the main `jen-kea` repo instead of
this repo's own — stale since this plugin was split out on its own.

## [1.4.1] - 2026-08-23

### Fix: version-bump-only release — v1.4.0 never actually shipped

v1.4.0's source was correct, but the repo's `plugin.zip` — the actual
artifact Jen's Update button downloads from `raw/main/plugin.zip` —
wasn't rebuilt alongside it, so the update silently kept installing the
old v1.3.3 code. No functional changes from what v1.4.0 was meant to
be; this release exists only to get a correctly-built `plugin.zip` onto
`main` under a version number that was never live. See v1.4.0 below for
the actual feature changes (import, Planned status, auto-detect
Static).

## [1.4.0] - 2026-08-23

### Feature: import from Netbox, Jen's own export, or other CSV sources

New "⬆ Import" button on each subnet's detail page. Upload a CSV and
pick a source:

- **Jen IPAM export** — round-trips Jen's own `Export CSV` output.
  Rows with `status=dynamic`/`reserved` are skipped on import (that's
  Kea-derived state, not a manual IPAM annotation); `static` and
  `planned` rows import as-is.
- **Netbox** — reads a Netbox "IP Addresses" export. Matches `address`
  (tolerates the `10.0.0.5/24` CIDR form Netbox uses), `status`,
  `dns_name`, `description`/`comments`, and `tenant`. Netbox's
  `reserved` status maps to Jen's new `planned` status (see below) —
  both mean "set aside, not actively assigned yet." `dhcp`/`slaac`
  rows are skipped since Kea already owns that state for managed
  subnets.
- **Generic CSV** — column-name sniffing for anything else (`ip`/
  `address`, `label`/`name`, `owner`/`tenant`, `notes`/`description`,
  `hostname`, `mac`, `status`), so exports from other tools can be
  imported without a Jen- or Netbox-specific format.

Nothing is saved on upload. Import is a two-step preview → confirm
flow: rows outside the target subnet's CIDR are filtered out and
counted, the parsed rows are shown in a table, and only "Confirm
Import" writes to `ipam_static_entries` (upserted the same way a
manual edit is — importing the same IP twice just updates it). Each
import writes a summary line to the audit log and one `import` row
per address to `ipam_assignment_history`. Capped at 2000 importable
rows per file.

### Feature: third "Planned" status, and auto-detecting Static on edit

The edit-address modal previously offered only Available and Static.
Two related changes:

- Typing into Label/Owner/Notes (or Hostname/MAC on unmanaged subnets)
  while an address is still set to Available now switches the Status
  dropdown to Static automatically, rather than silently leaving it as
  a plain annotation. Clearing those fields back to empty switches it
  back to Available. Manually picking a status yourself (including
  picking Available back again, or picking Planned) is respected for
  the rest of that modal session — the auto-switch only ever acts on
  an untouched Available dropdown.
- Added a third status, **Planned** — "earmarked for future use,"
  distinct from a Kea reservation (`reserved` status is Kea's own DHCP
  reservation and is unrelated). Shown throughout with a violet ◔/●
  marker: subnet summary card, filter tabs, table rows, edit modal,
  index-page subnet cards and legend, CSV export, and import preview.

DB: new `entry_status` column on `ipam_static_entries`
(`static`/`planned`/`available`), backfilled once from the existing
`is_static` flag. `is_static` is kept in sync going forward for
backward compatibility rather than dropped.

### Fix: reservation quick-link now shows for Planned addresses

The 📌 "Create Reservation" quick-link in the table's action column
previously only appeared for Available and Static rows; it now also
appears for Planned, since a planned address is exactly the kind of
row someone is likely to turn into a real reservation next.

## [1.3.3] - 2026-08-15

### Feature: multi-select status filtering on the subnet detail page

Requested directly: previously the status filter tabs (All / Available
/ Dynamic / Reserved / Static) were single-select — clicking one
deselected any other. Now Available/Dynamic/Reserved/Static toggle
independently and can be combined (e.g. show Reserved + Static
together, excluding Available/Dynamic), while "All" remains a distinct
action that clears back to showing everything rather than being one
more option to combine with the others. Deselecting the last active
filter falls back to "All" automatically rather than leaving a
confusing empty table with no obvious way back.

Pure client-side change — `_currentFilter` is now a `Set` instead of a
single string, with `toggleFilter(f)` replacing the old `setFilter(f)`
for the four specific status buttons and a new `setFilterAll()` for
the "All" button specifically. No backend or database changes.

**Verification:** the actual filter logic (not a reimplementation of
it) was extracted and run directly under Node.js against 13 scenarios
covering the exact requested behavior — toggling multiple filters on
together, toggling one back off while others remain active, the
empty-selection fallback to "All", and a three-way combination — all
passed. No headless browser was available to click-test the UI itself,
so this covers the actual selection/matching logic precisely rather
than the full rendered page.

## [1.3.2] - 2026-08-15

### Fixed: every POST form was missing its CSRF token — guaranteed 403 on save/delete/add-subnet

**Bug** — none of this plugin's four POST forms (`edit-form` /
save_entry, `clear-form` / delete_entry, `subnet-delete-form` /
delete_subnet, and the add-unmanaged-subnet form) included a
`csrf_token` hidden input. `csrf_token()` is registered as an
app-wide Jinja global by Jen's core `context_processor` and is
genuinely available inside plugin templates — it was just never
called in any of these four forms. Every submission through any of
them hit Jen's CSRF middleware and got rejected with a 403
"session security token is missing or expired," regardless of how
valid the actual session was.

**Fix** — `<input type="hidden" name="csrf_token" value="{{ csrf_token() }}">`
added to all four forms in `templates/ipam/subnet.html` and
`templates/ipam/index.html`.

**Verification** — reproduced against this plugin's own real code
running inside a real Jen instance: real login, real session, real
CSRF middleware enabled (the test suite it was found from normally
runs with CSRF checks off, which is exactly why this had no test
coverage). Confirmed all four forms genuinely 403 before the fix and
genuinely succeed after it, using a token actually extracted from the
real rendered page rather than a synthetic one — including this
plugin's own DB migrations and full `kind`-parameterized route set
(`/entry/<kind>/<subnet_id>`, `/subnets/add`, `/subnets/<id>/delete`),
not just the simpler bundled copy of this plugin that ships inside
jen-kea itself (which had the same bug, fixed separately there).

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
