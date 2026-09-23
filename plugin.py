"""
IPAM Lite plugin for Jen.
Full IP address space management for Kea-managed and unmanaged subnets.
Version lives in manifest.json — not duplicated here.

v1.5.0 — the "Jen already knows this" release. Everything Jen holds
about a subnet is used before an address is called available or a
count is made: the gateway, DNS servers, pools, the Kea servers' and
Jen host's own addresses (Jen's `subnet_context`, v5.30.0), the
`devices` table (a device's name/owner/vendor beside its lease), and
the plugin's own entries — so an address inside a DHCP pool is marked
as such, infrastructure addresses are labelled instead of "available",
a static entry whose IP now carries a dynamic lease is a *conflict*,
and "next free outside the pools" is one click. Overview counts no
longer enumerate every host address of every subnet, and the detail
page collapses long runs of available addresses into one row.
"""

import csv
import io
import ipaddress
import json
import logging
import os as _os
import re

from flask import Blueprint, flash, jsonify, make_response, redirect, render_template, request, url_for
from flask_login import current_user, login_required

logger = logging.getLogger(__name__)

bp = Blueprint(
    "ipam",
    __name__,
    template_folder="templates",
    root_path=_os.path.dirname(_os.path.abspath(__file__)),
    url_prefix="/network/ipam",
)

# URL kind → DB kind. 'kea' = Kea-managed subnet, 'u' = unmanaged (IPAM-only).
_KIND_DB = {"kea": "kea", "u": "ipam"}

_MAC_RE = re.compile(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$")
_FILENAME_SAFE_RE = re.compile(r"[^A-Za-z0-9._-]+")

# Hard cap on unmanaged subnet size: nothing larger than a /16.
_MAX_PREFIX = 16
# Above this size the detail page collapses runs of available addresses
# by default (a /22 is 1,022 rows; a /16 is 65,534).
_COLLAPSE_PREFIX = 22
# A run of at least this many consecutive available addresses becomes one
# row on the detail page.
_MIN_RUN = 4
# Range operations (mark/clear a from–to span) are capped per action.
_RANGE_MAX = 1024

# Statuses. 'infrastructure' and 'conflict' are derived (never stored).
_DESIGNATED = ("static", "planned")
_ALL_STATUSES = ("available", "dynamic", "reserved", "static", "planned", "infrastructure", "conflict")

# ── Import ────────────────────────────────────────────────────────────────────

_IMPORT_FORMATS = {"jen", "netbox", "generic"}
_IMPORT_MAX_ROWS = 2000
# v1.5.2 — _read_csv_rows() used to read the whole upload into memory before
# _IMPORT_MAX_ROWS ever applied, and Jen sets no MAX_CONTENT_LENGTH. 2 MB is
# about 40x the row cap at Netbox-export row widths, so a legitimate import
# never gets near it.
_IMPORT_MAX_BYTES = 2 * 1024 * 1024

# Netbox IPAM status values → Jen entry status. 'reserved' in Netbox means
# "set aside, not actively assigned yet" — the same idea as Jen's own
# 'planned' status, so that's a natural mapping rather than a guess.
# 'dhcp'/'slaac' rows are Netbox's record of a dynamically-assigned address;
# Kea already owns that state for managed subnets, so those rows are skipped.
_NETBOX_STATUS_MAP = {
    "active": "static",
    "reserved": "planned",
    "deprecated": "static",
    "dhcp": None,
    "slaac": None,
}
# The inverse, for the Netbox-shaped export.
_NETBOX_EXPORT_STATUS = {
    "static": "active",
    "planned": "reserved",
    "reserved": "active",
    "dynamic": "dhcp",
    "infrastructure": "active",
    "conflict": "active",
}

# Column-name aliases used to sniff a generic/unknown CSV export.
_GENERIC_HEADER_ALIASES = {
    "ip": ["ip", "ip address", "ipaddress", "address", "ipaddr"],
    "label": ["label", "name", "device", "device name"],
    "hostname": ["hostname", "dns_name", "dns name", "fqdn"],
    "mac": ["mac", "mac address", "hwaddr", "hardware address"],
    "owner": ["owner", "tenant", "assigned to", "contact"],
    "notes": ["notes", "description", "comments", "comment"],
    "status": ["status", "state"],
}


# ── DB helpers ────────────────────────────────────────────────────────────────


def _jen_db():
    from jen.plugin_api import get_jen_db

    return get_jen_db()


def _kea_db():
    from jen.plugin_api import get_kea_db

    return get_kea_db()


def _accessible_subnets():
    from jen.plugin_api import get_accessible_subnet_map

    return get_accessible_subnet_map()


def _assert_kea_access(subnet_id):
    from jen.plugin_api import assert_subnet_access

    return assert_subnet_access(subnet_id)


def _is_admin():
    try:
        from jen.plugin_api import is_admin_or_above

        return is_admin_or_above()
    except Exception:
        # Fall back to a direct role check if the import shape ever changes.
        role = getattr(current_user, "role", None)
        if role is not None:
            return role in ("superadmin", "admin")
        return bool(getattr(current_user, "is_admin", False))


def _require_write():
    """v1.5.2 — Jen's viewer tier is read-only everywhere else; IPAM's five
    write routes (save_entry, delete_entry, range_action, import_preview,
    import_commit) used to check only subnet access via _check_access, never
    the role — the templates hid the buttons from viewers, but the routes
    themselves were open to anyone with subnet access. Every write route
    calls this FIRST, before _check_access and before touching
    request.form/request.files."""
    if _is_admin():
        return True
    flash("Viewers can look at IPAM but not change it.", "error")
    return False


def _audit(action, target, detail):
    try:
        from jen.plugin_api import audit

        audit(action, target, detail)
    except Exception as e:
        logger.error(f"IPAM: audit failed: {e}")


def _safe_row(values):
    """Jen's CSV formula-injection guard (v5.30.0); a local copy of the
    same rule when running against an older Jen."""
    try:
        from jen.plugin_api import safe_row

        return safe_row(values)
    except Exception:
        out = []
        for v in values:
            s = "" if v is None else str(v)
            out.append(f"'{s}" if s and s[0] in ("=", "+", "-", "@", "\t", "\r") else s)
        return out


def _normalize_mac(raw):
    """Normalize a user-entered MAC to lowercase colon format, or '' / None on failure."""
    if not raw:
        return ""
    cleaned = re.sub(r"[^0-9a-fA-F]", "", raw).lower()
    if len(cleaned) != 12:
        return None
    mac = ":".join(cleaned[i : i + 2] for i in range(0, 12, 2))
    return mac if _MAC_RE.match(mac) else None


def _format_identifier(hex_str, ident_type):
    """Format a Kea host identifier for display. Only type 0 (hw-address) is a MAC."""
    if not hex_str:
        return ""
    if ident_type == 0 and len(hex_str) == 12:
        return ":".join(hex_str[i : i + 2] for i in range(0, 12, 2)).lower()
    # Non-MAC identifier (client-id, DUID, circuit-id) — show raw hex, labelled.
    return f"id:{hex_str.lower()}"


# ── Unmanaged subnet store ────────────────────────────────────────────────────


def _get_ipam_subnets():
    """Return {id: {name, cidr, description, gateway}} for all unmanaged subnets."""
    subnets = {}
    db = _jen_db()
    try:
        with db.cursor() as cur:
            cur.execute("SELECT id, name, cidr, description, gateway FROM ipam_subnets ORDER BY cidr")
            for row in cur.fetchall():
                subnets[row["id"]] = {
                    "name": row["name"],
                    "cidr": row["cidr"],
                    "description": row["description"] or "",
                    "gateway": row.get("gateway") or "",
                }
    finally:
        db.close()
    return subnets


def _get_subnet(kind, subnet_id):
    """Return the subnet info dict for a kind+id, or None."""
    if kind == "kea":
        return _accessible_subnets().get(subnet_id)
    return _get_ipam_subnets().get(subnet_id)


# ── What Jen already knows about a subnet ─────────────────────────────────────


def _bare_ctx(cidr, gateway=""):
    """The context for a subnet Jen holds no Kea config for (an unmanaged
    subnet, or a Jen older than 5.30.0): network/broadcast, an optional
    operator-recorded gateway, no pools."""
    infra = {}
    try:
        network = ipaddress.IPv4Network(cidr, strict=False)
    except ValueError:
        return {"gateways": [], "dns": [], "pools": [], "infrastructure": {}, "notes": ""}
    if network.prefixlen < 31:
        infra[str(network.network_address)] = "network"
        infra[str(network.broadcast_address)] = "broadcast"
    gateways = []
    if gateway:
        try:
            if ipaddress.IPv4Address(gateway) in network:
                gateways = [gateway]
                infra.setdefault(gateway, "gateway")
        except ValueError:
            pass
    return {"gateways": gateways, "dns": [], "pools": [], "infrastructure": infra, "notes": ""}


def _subnet_ctx(kind, subnet_id, subnet):
    """Jen's subnet_context() for a Kea subnet (gateway, DNS, pools, the
    Kea servers' and Jen host's addresses, notes), else the bare one."""
    if kind == "kea":
        try:
            from jen.plugin_api import subnet_context

            ctx = subnet_context(subnet_id)
            if ctx:
                return ctx
        except Exception as e:
            logger.warning(f"IPAM: subnet_context unavailable for {subnet_id}: {e}")
        return _bare_ctx(subnet["cidr"])
    return _bare_ctx(subnet["cidr"], subnet.get("gateway", ""))


def _in_pool(ctx, ip):
    try:
        n = int(ipaddress.IPv4Address(ip))
    except ValueError:
        return False
    return any(first <= n <= last for first, last, _t in ctx.get("pools", []))


_INFRA_LABELS = {
    "gateway": "Gateway",
    "dns": "DNS server",
    "kea-server": "Kea server",
    "jen-host": "Jen host",
    "network": "Network",
    "broadcast": "Broadcast",
}


def _devices_by_mac(macs):
    """{mac: {name, owner, manufacturer, device_type, icon}} from Jen's
    devices table for the given MACs. Best effort — {} on any failure."""
    macs = [m for m in macs if m and not m.startswith("id:")]
    if not macs:
        return {}
    out = {}
    db = None
    try:
        db = _jen_db()
        with db.cursor() as cur:
            # One fixed statement per MAC (never a runtime-built IN list —
            # Jen's bandit gate scans the bundled copy).
            for mac in macs:
                cur.execute(
                    "SELECT mac, device_name, owner, manufacturer, manufacturer_override, device_type, "
                    "device_type_override, device_icon, device_icon_override FROM devices WHERE mac=%s",
                    (mac,),
                )
                row = cur.fetchone()
                if row:
                    out[mac] = {
                        "name": row.get("device_name") or "",
                        "owner": row.get("owner") or "",
                        "manufacturer": row.get("manufacturer_override") or row.get("manufacturer") or "",
                        "device_type": row.get("device_type_override") or row.get("device_type") or "",
                        "icon": row.get("device_icon_override") or row.get("device_icon") or "",
                    }
    except Exception as e:
        logger.warning(f"IPAM: devices lookup failed: {e}")
    finally:
        if db:
            db.close()
    return out


# ── Address space ─────────────────────────────────────────────────────────────


def _load_kea_sets(subnet_id):
    """(active_leases {ip: {hostname, mac}}, reservations {ip: {hostname, mac, host_id}})."""
    active_leases = {}
    reservations = {}
    db = None
    try:
        db = _kea_db()
        with db.cursor() as cur:
            cur.execute(
                """
                SELECT inet_ntoa(l.address) AS ip,
                       l.hostname,
                       HEX(l.hwaddr) AS mac_hex
                FROM lease4 l
                WHERE l.state=0 AND l.subnet_id=%s
            """,
                (subnet_id,),
            )
            for row in cur.fetchall():
                if not row["ip"]:
                    continue
                active_leases[row["ip"]] = {
                    "hostname": row["hostname"] or "",
                    "mac": _format_identifier(row["mac_hex"], 0),
                }
            cur.execute(
                """
                SELECT inet_ntoa(h.ipv4_address) AS ip,
                       h.hostname,
                       HEX(h.dhcp_identifier) AS ident_hex,
                       h.dhcp_identifier_type AS ident_type,
                       h.host_id
                FROM hosts h
                WHERE h.dhcp4_subnet_id=%s
                  AND h.ipv4_address IS NOT NULL
                  AND h.ipv4_address > 0
            """,
                (subnet_id,),
            )
            for row in cur.fetchall():
                reservations[row["ip"]] = {
                    "hostname": row["hostname"] or "",
                    "mac": _format_identifier(row["ident_hex"], row["ident_type"]),
                    "host_id": row["host_id"],
                }
    except Exception as e:
        logger.error(f"IPAM: Kea DB error for subnet {subnet_id}: {e}")
    finally:
        if db:
            db.close()
    return active_leases, reservations


def _load_entries(db_kind, subnet_id):
    ipam_entries = {}
    db = None
    try:
        db = _jen_db()
        with db.cursor() as cur:
            cur.execute(
                """
                SELECT ip, label, owner, notes, hostname, mac, is_static, entry_status
                FROM ipam_static_entries
                WHERE subnet_kind=%s AND subnet_id=%s
            """,
                (db_kind, subnet_id),
            )
            for row in cur.fetchall():
                ipam_entries[row["ip"]] = row
    except Exception as e:
        logger.error(f"IPAM: entries error for {db_kind}/{subnet_id}: {e}")
    finally:
        if db:
            db.close()
    return ipam_entries


def _designated_status(entry_row):
    s = entry_row.get("entry_status") or ("static" if entry_row.get("is_static") else "available")
    return s if s in _DESIGNATED else "available"


def _compose_space(all_ips, active_leases, reservations, ipam_entries, ctx, devices=None):
    """Pure: the per-address entries. Precedence: reservation > lease
    (a designated entry under a lease is a *conflict*, not silently
    'dynamic') > infrastructure > static/planned > available."""
    devices = devices or {}
    infra = ctx.get("infrastructure", {})
    space = []
    for ip in all_ips:
        entry = {
            "ip": ip,
            "hostname": "",
            "mac": "",
            "label": "",
            "owner": "",
            "notes": "",
            "host_id": None,
            "status": "available",
            "designated": "",
            "infra": "",
            "in_pool": _in_pool(ctx, ip),
            "device": None,
        }
        s = ipam_entries.get(ip)
        if s:
            entry["label"] = s.get("label") or ""
            entry["owner"] = s.get("owner") or ""
            entry["notes"] = s.get("notes") or ""
            entry["hostname"] = s.get("hostname") or ""
            entry["mac"] = s.get("mac") or ""
            entry["designated"] = _designated_status(s)

        if ip in reservations:
            r = reservations[ip]
            entry["status"] = "reserved"
            entry["host_id"] = r["host_id"]
            entry["hostname"] = r["hostname"] or entry["hostname"]
            entry["mac"] = r["mac"] or entry["mac"]
            if ip in active_leases:
                entry["hostname"] = entry["hostname"] or active_leases[ip]["hostname"]
                entry["mac"] = entry["mac"] or active_leases[ip]["mac"]
        elif ip in active_leases:
            lease = active_leases[ip]
            # v1.5.0 — a designated static/planned address that a DHCP client
            # is now using is a conflict, not a lease that "wins".
            entry["status"] = "conflict" if entry["designated"] in _DESIGNATED else "dynamic"
            entry["hostname"] = lease["hostname"] or entry["hostname"]
            entry["mac"] = lease["mac"] or entry["mac"]
        elif ip in infra:
            entry["status"] = "infrastructure"
            entry["infra"] = infra[ip]
            if not entry["label"]:
                entry["label"] = _INFRA_LABELS.get(infra[ip], infra[ip])
        elif entry["designated"] in _DESIGNATED:
            entry["status"] = entry["designated"]

        if entry["mac"] and entry["mac"] in devices:
            entry["device"] = devices[entry["mac"]]
        space.append(entry)
    return space


def _build_address_space(kind, subnet_id, cidr, ctx=None, subnet=None):
    """Every host address of the subnet, with status, annotations, pool
    membership, infrastructure label and (Kea subnets) the device Jen
    knows for the MAC."""
    try:
        network = ipaddress.IPv4Network(cidr, strict=False)
    except ValueError:
        return []
    all_ips = [str(h) for h in network.hosts()]
    db_kind = _KIND_DB[kind]
    if ctx is None:
        ctx = _subnet_ctx(kind, subnet_id, subnet or {"cidr": cidr})
    active_leases, reservations = _load_kea_sets(subnet_id) if kind == "kea" else ({}, {})
    ipam_entries = _load_entries(db_kind, subnet_id)
    devices = {}
    if kind == "kea":
        macs = {v["mac"] for v in active_leases.values()} | {v["mac"] for v in reservations.values()}
        devices = _devices_by_mac(sorted(m for m in macs if m))
    return _compose_space(all_ips, active_leases, reservations, ipam_entries, ctx, devices)


def _count_sets(total_hosts, host_ips_in, active_leases, reservations, ipam_entries, ctx):
    """Pure set arithmetic — the overview never enumerates the address
    space (v1.5.0; the old count built every host of every subnet)."""
    res = set(reservations)
    leases = set(active_leases)
    designated = {ip for ip, r in ipam_entries.items() if _designated_status(r) in _DESIGNATED}
    infra = {ip for ip in ctx.get("infrastructure", {}) if host_ips_in(ip)}
    dynamic = leases - res
    conflict = dynamic & designated
    dynamic -= conflict
    infra -= res | leases
    static = {ip for ip in designated - res - leases - infra if _designated_status(ipam_entries[ip]) == "static"}
    planned = {ip for ip in designated - res - leases - infra if _designated_status(ipam_entries[ip]) == "planned"}
    counts = {
        "total": total_hosts,
        "reserved": len(res),
        "dynamic": len(dynamic),
        "conflict": len(conflict),
        "infrastructure": len(infra),
        "static": len(static),
        "planned": len(planned),
    }
    counts["used"] = sum(counts[k] for k in ("reserved", "dynamic", "conflict", "infrastructure", "static", "planned"))
    counts["available"] = max(total_hosts - counts["used"], 0)
    counts["pct"] = round(counts["used"] / total_hosts * 100) if total_hosts else 0
    return counts


def _count_space(space):
    """Counts from an already-built space (the detail page)."""
    counts = dict.fromkeys(_ALL_STATUSES, 0)
    counts["total"] = len(space)
    for e in space:
        counts[e["status"]] = counts.get(e["status"], 0) + 1
    counts["used"] = counts["total"] - counts["available"]
    counts["pct"] = round(counts["used"] / counts["total"] * 100) if counts["total"] else 0
    return counts


def _summary(kind, subnet_id, subnet):
    """Overview card numbers without building the space."""
    network = ipaddress.IPv4Network(subnet["cidr"], strict=False)
    total = max(network.num_addresses - (2 if network.prefixlen < 31 else 0), 0)
    ctx = _subnet_ctx(kind, subnet_id, subnet)
    leases, res = _load_kea_sets(subnet_id) if kind == "kea" else ({}, {})
    entries = _load_entries(_KIND_DB[kind], subnet_id)

    def host_in(ip):
        try:
            a = ipaddress.IPv4Address(ip)
        except ValueError:
            return False
        return a in network and a not in (network.network_address, network.broadcast_address)

    return _count_sets(total, host_in, leases, res, entries, ctx)


def _collapse_runs(space, collapse, expand=None, min_run=_MIN_RUN):
    """Pure: table rows for the detail page. With `collapse`, a run of
    ≥ min_run consecutive available addresses becomes one row
    {"run": True, "first", "last", "count", "in_pool"}; `expand` is a
    "first-last" text naming one run to show in full."""
    if not collapse:
        return list(space)
    rows = []
    i, n = 0, len(space)
    while i < n:
        e = space[i]
        if e["status"] != "available":
            rows.append(e)
            i += 1
            continue
        j = i
        while j < n and space[j]["status"] == "available" and space[j]["in_pool"] == e["in_pool"]:
            j += 1
        run = space[i:j]
        key = f"{run[0]['ip']}-{run[-1]['ip']}"
        if len(run) >= min_run and expand != key:
            rows.append(
                {
                    "run": True,
                    "first": run[0]["ip"],
                    "last": run[-1]["ip"],
                    "count": len(run),
                    "in_pool": e["in_pool"],
                    "key": key,
                }
            )
        else:
            rows.extend(run)
        i = j
    return rows


def _next_free(space):
    """The first available address outside every pool — what Netbox was
    being used for. None when there isn't one."""
    for e in space:
        if e["status"] == "available" and not e["in_pool"]:
            return e["ip"]
    return None


def _can_see_unmanaged():
    """Unmanaged subnets aren't part of Jen's SUBNET_MAP, so the per-subnet
    restriction check can't apply to them — a user whose access is limited
    to specific Kea subnets gets none of them, the same way an out-of-scope
    Kea subnet is off-limits."""
    return bool(getattr(current_user, "all_subnets", False))


def _check_access(kind, subnet_id):
    """Access + existence check. Returns subnet info dict, or None if denied/missing."""
    if kind not in _KIND_DB:
        return None
    if kind == "kea" and not _assert_kea_access(subnet_id):
        return None
    if kind == "u" and not _can_see_unmanaged():
        flash("You do not have access to unmanaged subnets.", "error")
        return None
    return _get_subnet(kind, subnet_id)


# ── History ───────────────────────────────────────────────────────────────────


def _record_history(cur, ip, db_kind, subnet_id, action, label="", owner="", actor=None):
    """`actor` overrides current_user.username — the JSON API (v1.6.0) has
    no Flask-Login session, just an API key, so it passes its own actor
    string instead."""
    cur.execute(
        """
        INSERT INTO ipam_assignment_history
            (ip, subnet_kind, subnet_id, label, owner, action, acted_at, acted_by)
        VALUES (%s, %s, %s, %s, %s, %s, UTC_TIMESTAMP(), %s)
    """,
        (ip, db_kind, subnet_id, label, owner, action, actor or current_user.username),
    )


def _history_rows(db_kind, subnet_id, ip=None, limit=25):
    db = None
    rows = []
    try:
        db = _jen_db()
        with db.cursor() as cur:
            if ip:
                cur.execute(
                    "SELECT ip, label, owner, action, acted_at, acted_by FROM ipam_assignment_history "
                    "WHERE subnet_kind=%s AND subnet_id=%s AND ip=%s ORDER BY acted_at DESC, id DESC LIMIT %s",
                    (db_kind, subnet_id, ip, int(limit)),
                )
            else:
                cur.execute(
                    "SELECT ip, label, owner, action, acted_at, acted_by FROM ipam_assignment_history "
                    "WHERE subnet_kind=%s AND subnet_id=%s ORDER BY acted_at DESC, id DESC LIMIT %s",
                    (db_kind, subnet_id, int(limit)),
                )
            for r in cur.fetchall():
                rows.append(
                    {
                        "ip": r["ip"],
                        "label": r.get("label") or "",
                        "owner": r.get("owner") or "",
                        "action": r.get("action") or "",
                        "acted_at": r["acted_at"].strftime("%Y-%m-%d %H:%M") if r.get("acted_at") else "",
                        "acted_by": r.get("acted_by") or "",
                    }
                )
    except Exception as e:
        logger.error(f"IPAM: history error for {db_kind}/{subnet_id}: {e}")
    finally:
        if db:
            db.close()
    return rows


# ── Import ────────────────────────────────────────────────────────────────────


def _norm_header(h):
    return (h or "").strip().lower()


def _find_header(fieldnames, aliases):
    """Case-insensitive lookup of the first matching header name."""
    norm_map = {_norm_header(f): f for f in fieldnames}
    for alias in aliases:
        if alias in norm_map:
            return norm_map[alias]
    return None


def _extract_ip(raw):
    """Pull a bare IPv4 out of a cell — tolerates Netbox-style '10.0.0.5/24'."""
    raw = (raw or "").strip()
    if not raw:
        return None
    raw = raw.split("/")[0].strip()
    try:
        ipaddress.IPv4Address(raw)
        return raw
    except ValueError:
        return None


class _ImportTooLarge(Exception):
    """Raised by _read_csv_rows() when the upload exceeds _IMPORT_MAX_BYTES."""


def _read_csv_rows(file_storage):
    # v1.5.2 — read at most _IMPORT_MAX_BYTES + 1 bytes rather than the
    # whole upload: enough to tell "too large" apart from "exactly at the
    # cap" without ever buffering more than one byte past the limit.
    raw = file_storage.read(_IMPORT_MAX_BYTES + 1)
    if len(raw) > _IMPORT_MAX_BYTES:
        raise _ImportTooLarge("That CSV is larger than 2 MB — split it.")
    text = raw.decode("utf-8-sig", errors="replace")
    reader = csv.DictReader(io.StringIO(text))
    rows = list(reader)
    return rows, (reader.fieldnames or [])


def _has_content(row):
    return any(row.get(k) for k in ("label", "owner", "notes", "hostname", "mac"))


def _parse_import_rows(rows, fieldnames, fmt):
    """Map a raw CSV (rows + header list) to a common entry shape:
    {ip, status, label, owner, notes, hostname, mac}
    status is one of 'available' | 'static' | 'planned'.
    Returns (parsed_rows, errors) — errors are fatal (no rows returned).
    """
    parsed = []

    if fmt == "jen":
        ip_col = _find_header(fieldnames, _GENERIC_HEADER_ALIASES["ip"])
        if not ip_col:
            return [], ['No "ip" column found — is this really a Jen IPAM export?']
        status_col = _find_header(fieldnames, ["status"])
        label_col = _find_header(fieldnames, ["label"])
        owner_col = _find_header(fieldnames, ["owner"])
        notes_col = _find_header(fieldnames, ["notes"])
        hostname_col = _find_header(fieldnames, ["hostname"])
        mac_col = _find_header(fieldnames, ["mac"])
        for r in rows:
            ip = _extract_ip(r.get(ip_col))
            if not ip:
                continue
            status = _norm_header(r.get(status_col) if status_col else "")
            if status in ("dynamic", "reserved", "infrastructure", "conflict"):
                # Kea-derived or derived state, not a manual IPAM entry —
                # importing it back would just create a redundant row.
                continue
            if status not in _DESIGNATED:
                status = "available"
            parsed.append(
                {
                    "ip": ip,
                    "status": status,
                    "label": (r.get(label_col) or "").strip() if label_col else "",
                    "owner": (r.get(owner_col) or "").strip() if owner_col else "",
                    "notes": (r.get(notes_col) or "").strip() if notes_col else "",
                    "hostname": (r.get(hostname_col) or "").strip() if hostname_col else "",
                    "mac": (r.get(mac_col) or "").strip() if mac_col else "",
                }
            )

    elif fmt == "netbox":
        ip_col = _find_header(fieldnames, ["address", "ip", "ip address"])
        if not ip_col:
            return [], ['No "address" column found — expected a Netbox IP Addresses export.']
        status_col = _find_header(fieldnames, ["status"])
        dns_col = _find_header(fieldnames, ["dns_name", "dns name"])
        desc_col = _find_header(fieldnames, ["description"])
        comments_col = _find_header(fieldnames, ["comments"])
        tenant_col = _find_header(fieldnames, ["tenant"])
        for r in rows:
            ip = _extract_ip(r.get(ip_col))
            if not ip:
                continue
            nb_status = _norm_header(r.get(status_col) if status_col else "")
            status = _NETBOX_STATUS_MAP.get(nb_status, "static")
            if status is None:
                continue
            notes_parts = [
                p
                for p in [
                    (r.get(desc_col) or "").strip() if desc_col else "",
                    (r.get(comments_col) or "").strip() if comments_col else "",
                ]
                if p
            ]
            dns_name = (r.get(dns_col) or "").strip() if dns_col else ""
            parsed.append(
                {
                    "ip": ip,
                    "status": status,
                    "label": dns_name,
                    "owner": (r.get(tenant_col) or "").strip() if tenant_col else "",
                    "notes": " — ".join(notes_parts),
                    "hostname": dns_name,
                    "mac": "",
                }
            )

    elif fmt == "generic":
        ip_col = _find_header(fieldnames, _GENERIC_HEADER_ALIASES["ip"])
        if not ip_col:
            return [], ["Couldn't find an IP address column. Columns seen: " + ", ".join(fieldnames)]
        label_col = _find_header(fieldnames, _GENERIC_HEADER_ALIASES["label"])
        owner_col = _find_header(fieldnames, _GENERIC_HEADER_ALIASES["owner"])
        notes_col = _find_header(fieldnames, _GENERIC_HEADER_ALIASES["notes"])
        hostname_col = _find_header(fieldnames, _GENERIC_HEADER_ALIASES["hostname"])
        mac_col = _find_header(fieldnames, _GENERIC_HEADER_ALIASES["mac"])
        status_col = _find_header(fieldnames, _GENERIC_HEADER_ALIASES["status"])
        for r in rows:
            ip = _extract_ip(r.get(ip_col))
            if not ip:
                continue
            raw_status = _norm_header(r.get(status_col) if status_col else "")
            status = raw_status if raw_status in ("static", "planned", "available") else "static"
            parsed.append(
                {
                    "ip": ip,
                    "status": status,
                    "label": (r.get(label_col) or "").strip() if label_col else "",
                    "owner": (r.get(owner_col) or "").strip() if owner_col else "",
                    "notes": (r.get(notes_col) or "").strip() if notes_col else "",
                    "hostname": (r.get(hostname_col) or "").strip() if hostname_col else "",
                    "mac": (r.get(mac_col) or "").strip() if mac_col else "",
                }
            )
    else:
        return [], ["Unknown import format."]

    # A blank 'available' row designates nothing and just clutters the
    # preview — drop it, matching how a blank save from the edit modal
    # already clears an entry rather than storing an empty one.
    parsed = [r for r in parsed if r["status"] != "available" or _has_content(r)]
    return parsed, []


# ── Routes: overview ──────────────────────────────────────────────────────────


@bp.route("/")
@login_required
def index():
    subnet_map = _accessible_subnets()
    ipam_subnets = _get_ipam_subnets() if _can_see_unmanaged() else {}

    summaries = {}
    for sid, info in subnet_map.items():
        try:
            summaries[("kea", sid)] = _summary("kea", sid, info)
        except Exception as e:
            logger.error(f"IPAM: summary failed for kea subnet {sid}: {e}")
            summaries[("kea", sid)] = {}
    for sid, info in ipam_subnets.items():
        try:
            summaries[("u", sid)] = _summary("u", sid, info)
        except Exception as e:
            logger.error(f"IPAM: summary failed for unmanaged subnet {sid}: {e}")
            summaries[("u", sid)] = {}

    return render_template(
        "ipam/index.html", subnet_map=subnet_map, ipam_subnets=ipam_subnets, summaries=summaries, is_admin=_is_admin()
    )


# ── Routes: subnet detail / export ────────────────────────────────────────────


def _parse_expand(raw, network):
    """`?expand=first-last` → the same text, only if both ends are inside
    the subnet (anything else is ignored, never echoed)."""
    raw = (raw or "").strip()
    if not raw or "-" not in raw:
        return None
    a, _, b = raw.partition("-")
    try:
        fa, fb = ipaddress.IPv4Address(a.strip()), ipaddress.IPv4Address(b.strip())
    except ValueError:
        return None
    if fa in network and fb in network and fa <= fb:
        return f"{fa}-{fb}"
    return None


@bp.route("/subnet/<kind>/<int:subnet_id>")
@login_required
def subnet_detail(kind, subnet_id):
    subnet = _check_access(kind, subnet_id)
    if subnet is None:
        flash("Subnet not found or access denied.", "error")
        return redirect(url_for("ipam.index"))

    network = ipaddress.IPv4Network(subnet["cidr"], strict=False)
    ctx = _subnet_ctx(kind, subnet_id, subnet)
    space = _build_address_space(kind, subnet_id, subnet["cidr"], ctx=ctx, subnet=subnet)
    counts = _count_space(space)
    status_filter = request.args.get("filter", "all")
    if status_filter not in ("all", *_ALL_STATUSES):
        status_filter = "all"

    # v1.5.0 — an address to open the edit modal on (Discovery's "Add IPAM
    # entry" link, or "Next free"): if it sits inside a collapsed run,
    # that run is expanded so the row exists.
    open_ip = _extract_ip(request.args.get("ip", ""))
    if open_ip and ipaddress.IPv4Address(open_ip) not in network:
        open_ip = None
    collapse = request.args.get("all") != "1" and network.prefixlen <= _COLLAPSE_PREFIX
    expand = _parse_expand(request.args.get("expand", ""), network)
    rows = _collapse_runs(space, collapse, expand)
    if open_ip and not any(not r.get("run") and r["ip"] == open_ip for r in rows):
        for r in rows:
            if r.get("run") and int(ipaddress.IPv4Address(r["first"])) <= int(ipaddress.IPv4Address(open_ip)) <= int(
                ipaddress.IPv4Address(r["last"])
            ):
                rows = _collapse_runs(space, collapse, r["key"])
                break

    return render_template(
        "ipam/subnet.html",
        kind=kind,
        subnet_id=subnet_id,
        subnet=subnet,
        space=space,
        rows=rows,
        collapsed=collapse,
        counts=counts,
        ctx=ctx,
        pool_texts=[t for _f, _l, t in ctx.get("pools", [])],
        next_free=_next_free(space),
        recent_history=_history_rows(_KIND_DB[kind], subnet_id, limit=15),
        status_filter=status_filter,
        open_ip=open_ip,
        is_admin=_is_admin(),
    )


# Legacy URL from v1.x — redirect to the kea-kind route.
@bp.route("/subnet/<int:subnet_id>")
@login_required
def subnet_detail_legacy(subnet_id):
    return redirect(url_for("ipam.subnet_detail", kind="kea", subnet_id=subnet_id))


@bp.route("/subnet/<kind>/<int:subnet_id>/export")
@login_required
def export_csv(kind, subnet_id):
    subnet = _check_access(kind, subnet_id)
    if subnet is None:
        flash("Subnet not found or access denied.", "error")
        return redirect(url_for("ipam.index"))

    fmt = request.args.get("format", "jen")
    space = _build_address_space(kind, subnet_id, subnet["cidr"], subnet=subnet)
    prefixlen = ipaddress.IPv4Network(subnet["cidr"], strict=False).prefixlen

    output = io.StringIO()
    if fmt == "netbox":
        # Netbox's IP Addresses import columns — for anyone keeping both.
        writer = csv.writer(output)
        writer.writerow(["address", "status", "dns_name", "description", "tenant"])
        for entry in space:
            if entry["status"] == "available":
                continue
            desc = entry["label"] if entry["label"] != entry["hostname"] else ""
            if entry["notes"]:
                desc = f"{desc} — {entry['notes']}" if desc else entry["notes"]
            writer.writerow(
                _safe_row(
                    [
                        f"{entry['ip']}/{prefixlen}",
                        _NETBOX_EXPORT_STATUS.get(entry["status"], "active"),
                        entry["hostname"],
                        desc,
                        entry["owner"],
                    ]
                )
            )
        suffix = "netbox"
    else:
        fields = ["ip", "status", "hostname", "mac", "label", "owner", "notes", "in_pool", "device", "vendor"]
        writer = csv.writer(output)
        writer.writerow(fields)
        for entry in space:
            dev = entry.get("device") or {}
            writer.writerow(
                _safe_row(
                    [
                        entry["ip"],
                        entry["status"],
                        entry["hostname"],
                        entry["mac"],
                        entry["label"],
                        entry["owner"],
                        entry["notes"],
                        "yes" if entry["in_pool"] else "no",
                        dev.get("name", ""),
                        dev.get("manufacturer", ""),
                    ]
                )
            )
        suffix = "jen"

    safe_name = _FILENAME_SAFE_RE.sub("_", subnet["name"]).strip("_") or "subnet"
    response = make_response(output.getvalue())
    response.headers["Content-Type"] = "text/csv"
    response.headers["Content-Disposition"] = f"attachment; filename=ipam-{safe_name}-{kind}-{subnet_id}-{suffix}.csv"
    return response


@bp.route("/subnet/<kind>/<int:subnet_id>/history")
@login_required
def history(kind, subnet_id):
    """JSON (the edit modal's History section) or CSV (`?format=csv`)."""
    subnet = _check_access(kind, subnet_id)
    if subnet is None:
        return jsonify({"error": "not found"}), 404
    db_kind = _KIND_DB[kind]
    if request.args.get("format") == "csv":
        rows = _history_rows(db_kind, subnet_id, limit=5000)
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["when_utc", "ip", "action", "label", "owner", "by"])
        for r in rows:
            writer.writerow(_safe_row([r["acted_at"], r["ip"], r["action"], r["label"], r["owner"], r["acted_by"]]))
        safe_name = _FILENAME_SAFE_RE.sub("_", subnet["name"]).strip("_") or "subnet"
        response = make_response(output.getvalue())
        response.headers["Content-Type"] = "text/csv"
        response.headers["Content-Disposition"] = (
            f"attachment; filename=ipam-history-{safe_name}-{kind}-{subnet_id}.csv"
        )
        return response
    ip = _extract_ip(request.args.get("ip", ""))
    return jsonify({"rows": _history_rows(db_kind, subnet_id, ip=ip, limit=10 if ip else 50)})


@bp.route("/subnet/<kind>/<int:subnet_id>/import/preview", methods=["POST"])
@login_required
def import_preview(kind, subnet_id):
    if not _require_write():
        return redirect(url_for("ipam.subnet_detail", kind=kind, subnet_id=subnet_id))
    subnet = _check_access(kind, subnet_id)
    if subnet is None:
        flash("Subnet not found or access denied.", "error")
        return redirect(url_for("ipam.index"))

    detail_url = url_for("ipam.subnet_detail", kind=kind, subnet_id=subnet_id)

    # v1.5.2 — cheap, early refusal off the browser-declared size, before
    # touching request.form/request.files at all; _read_csv_rows() below
    # enforces the same cap against the actual bytes read, in case
    # Content-Length is absent or wrong.
    if request.content_length and request.content_length > _IMPORT_MAX_BYTES:
        flash("That CSV is larger than 2 MB — split it.", "error")
        return redirect(detail_url)

    fmt = request.form.get("import_format", "").strip().lower()
    if fmt not in _IMPORT_FORMATS:
        flash("Unknown import source.", "error")
        return redirect(detail_url)

    upload = request.files.get("import_file")
    if not upload or not upload.filename:
        flash("Choose a CSV file to import.", "error")
        return redirect(detail_url)
    if not upload.filename.lower().endswith(".csv"):
        flash("Only CSV files are supported.", "error")
        return redirect(detail_url)

    try:
        raw_rows, fieldnames = _read_csv_rows(upload)
    except _ImportTooLarge as e:
        flash(str(e), "error")
        return redirect(detail_url)
    except Exception as e:
        flash(f"Could not read CSV: {e}", "error")
        return redirect(detail_url)

    if not raw_rows:
        flash("The CSV file has no data rows.", "error")
        return redirect(detail_url)

    parsed, errors = _parse_import_rows(raw_rows, fieldnames, fmt)
    if errors:
        for e in errors:
            flash(e, "error")
        return redirect(detail_url)

    if not parsed:
        flash("Nothing in that file looked like an address to import.", "error")
        return redirect(detail_url)

    if len(parsed) > _IMPORT_MAX_ROWS:
        flash(
            f"That file has {len(parsed)} importable rows — imports are capped at {_IMPORT_MAX_ROWS} rows per file.",
            "error",
        )
        return redirect(detail_url)

    try:
        network = ipaddress.IPv4Network(subnet["cidr"], strict=False)
    except ValueError:
        flash("Subnet CIDR is invalid.", "error")
        return redirect(detail_url)

    preview_rows = []
    for row in parsed:
        try:
            in_subnet = ipaddress.IPv4Address(row["ip"]) in network
        except ValueError:
            in_subnet = False
        mac = _normalize_mac(row.get("mac", "")) or ""
        preview_rows.append(
            {
                "ip": row["ip"],
                "status": row["status"],
                "label": row.get("label", "")[:100],
                "owner": row.get("owner", "")[:100],
                "notes": row.get("notes", ""),
                "hostname": row.get("hostname", "")[:255],
                "mac": mac,
                "in_subnet": in_subnet,
            }
        )

    importable = [r for r in preview_rows if r["in_subnet"]]
    skipped = len(preview_rows) - len(importable)

    if not importable:
        flash(f"None of the {len(preview_rows)} rows in that file fall inside {subnet['cidr']}.", "error")
        return redirect(detail_url)

    return render_template(
        "ipam/import_preview.html",
        kind=kind,
        subnet_id=subnet_id,
        subnet=subnet,
        import_format=fmt,
        rows=importable,
        skipped=skipped,
        payload=json.dumps(importable),
    )


def _upsert_entry(cur, ip, db_kind, subnet_id, label, owner, notes, hostname, mac, status):
    is_static = 1 if status == "static" else 0
    cur.execute(
        """
        INSERT INTO ipam_static_entries
            (ip, subnet_kind, subnet_id, label, owner, notes,
             hostname, mac, is_static, entry_status,
             created_at, updated_at)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                UTC_TIMESTAMP(), UTC_TIMESTAMP())
        ON DUPLICATE KEY UPDATE
            label=VALUES(label), owner=VALUES(owner),
            notes=VALUES(notes), hostname=VALUES(hostname),
            mac=VALUES(mac), is_static=VALUES(is_static),
            entry_status=VALUES(entry_status),
            updated_at=UTC_TIMESTAMP()
    """,
        (ip, db_kind, subnet_id, label, owner, notes, hostname, mac, is_static, status),
    )


@bp.route("/subnet/<kind>/<int:subnet_id>/import/commit", methods=["POST"])
@login_required
def import_commit(kind, subnet_id):
    if not _require_write():
        return redirect(url_for("ipam.subnet_detail", kind=kind, subnet_id=subnet_id))
    subnet = _check_access(kind, subnet_id)
    if subnet is None:
        flash("Subnet not found or access denied.", "error")
        return redirect(url_for("ipam.index"))

    db_kind = _KIND_DB[kind]
    detail_url = url_for("ipam.subnet_detail", kind=kind, subnet_id=subnet_id)

    try:
        rows = json.loads(request.form.get("payload", "[]"))
        if not isinstance(rows, list):
            raise ValueError
    except (ValueError, TypeError):
        flash("Import payload was corrupted — please re-upload the file.", "error")
        return redirect(detail_url)

    try:
        network = ipaddress.IPv4Network(subnet["cidr"], strict=False)
    except ValueError:
        flash("Subnet CIDR is invalid.", "error")
        return redirect(detail_url)

    saved = 0
    rejected = 0
    db = None
    try:
        db = _jen_db()
        with db.cursor() as cur:
            for row in rows[:_IMPORT_MAX_ROWS]:
                if not isinstance(row, dict):
                    rejected += 1
                    continue
                ip = str(row.get("ip", "")).strip()
                try:
                    addr = ipaddress.IPv4Address(ip)
                except ValueError:
                    rejected += 1
                    continue
                if addr not in network:
                    rejected += 1
                    continue

                status = row.get("status")
                if status not in _DESIGNATED:
                    status = "available"
                label = str(row.get("label", "") or "")[:100]
                owner = str(row.get("owner", "") or "")[:100]
                notes = str(row.get("notes", "") or "")
                hostname = str(row.get("hostname", "") or "")[:255]
                mac = _normalize_mac(row.get("mac", "")) or ""
                _upsert_entry(cur, ip, db_kind, subnet_id, label, owner, notes, hostname, mac, status)
                _record_history(cur, ip, db_kind, subnet_id, "import", label, owner)
                saved += 1
        db.commit()
        if saved:
            flash(
                f"Imported {saved} address{'es' if saved != 1 else ''}"
                + (f" ({rejected} skipped)" if rejected else "")
                + ".",
                "success",
            )
            _audit(
                "IPAM_IMPORT", subnet["cidr"], f"kind={db_kind} subnet={subnet_id} saved={saved} rejected={rejected}"
            )
        else:
            flash("Nothing was imported — all rows were rejected.", "error")
    except Exception as e:
        flash(f"Import failed: {e}", "error")
    finally:
        if db:
            db.close()

    return redirect(detail_url)


# ── Routes: entries ───────────────────────────────────────────────────────────


@bp.route("/entry/<kind>/<int:subnet_id>", methods=["POST"])
@login_required
def save_entry(kind, subnet_id):
    """Create or update an IPAM entry."""
    if not _require_write():
        return redirect(url_for("ipam.subnet_detail", kind=kind, subnet_id=subnet_id))
    subnet = _check_access(kind, subnet_id)
    if subnet is None:
        flash("Subnet not found or access denied.", "error")
        return redirect(url_for("ipam.index"))

    db_kind = _KIND_DB[kind]
    detail_url = url_for("ipam.subnet_detail", kind=kind, subnet_id=subnet_id)

    ip = request.form.get("ip", "").strip()
    label = request.form.get("label", "").strip()[:100]
    owner = request.form.get("owner", "").strip()[:100]
    notes = request.form.get("notes", "").strip()
    hostname = request.form.get("hostname", "").strip()[:255]
    mac_raw = request.form.get("mac", "").strip()
    # ipam_status: 'static' = designated static, 'planned' = earmarked for
    # future use, 'available' = plain annotation (or nothing at all).
    ipam_status = request.form.get("ipam_status", "").strip()
    if ipam_status not in _DESIGNATED:
        ipam_status = "available"

    try:
        addr = ipaddress.IPv4Address(ip)
    except ValueError:
        flash("Invalid IP address.", "error")
        return redirect(detail_url)

    # The IP must belong to this subnet.
    try:
        network = ipaddress.IPv4Network(subnet["cidr"], strict=False)
    except ValueError:
        flash("Subnet CIDR is invalid.", "error")
        return redirect(detail_url)
    if addr not in network:
        flash(f"{ip} is not inside {subnet['cidr']}.", "error")
        return redirect(detail_url)

    # v1.5.0 — a manual hostname/MAC is allowed on Kea subnets too: a
    # genuinely static host (no DHCP) has a MAC the operator knows, and
    # Network Discovery matches on it.
    mac = _normalize_mac(mac_raw)
    if mac is None:
        flash("Invalid MAC address format.", "error")
        return redirect(detail_url)

    # Status set back to available with nothing else filled in — clear the entry.
    if ipam_status == "available" and not label and not owner and not notes and not hostname and not mac:
        db = None
        try:
            db = _jen_db()
            with db.cursor() as cur:
                cur.execute(
                    """
                    DELETE FROM ipam_static_entries
                    WHERE ip=%s AND subnet_kind=%s AND subnet_id=%s
                """,
                    (ip, db_kind, subnet_id),
                )
                _record_history(cur, ip, db_kind, subnet_id, "cleared")
            db.commit()
            flash(f"Entry for {ip} cleared.", "success")
        except Exception as e:
            flash(f"Error clearing entry: {e}", "error")
        finally:
            if db:
                db.close()
        return redirect(detail_url)

    db = None
    try:
        db = _jen_db()
        with db.cursor() as cur:
            _upsert_entry(cur, ip, db_kind, subnet_id, label, owner, notes, hostname, mac, ipam_status)
            _record_history(
                cur, ip, db_kind, subnet_id, ipam_status if ipam_status != "available" else "note", label, owner
            )
        db.commit()
        flash(f"Entry saved for {ip}.", "success")
        _audit("IPAM_ENTRY", ip, f"kind={db_kind} subnet={subnet_id} label={label} owner={owner} status={ipam_status}")
    except Exception as e:
        flash(f"Error saving entry: {e}", "error")
    finally:
        if db:
            db.close()

    return redirect(detail_url)


@bp.route("/entry/<kind>/<int:subnet_id>/delete", methods=["POST"])
@login_required
def delete_entry(kind, subnet_id):
    if not _require_write():
        return redirect(url_for("ipam.subnet_detail", kind=kind, subnet_id=subnet_id))
    subnet = _check_access(kind, subnet_id)
    if subnet is None:
        flash("Subnet not found or access denied.", "error")
        return redirect(url_for("ipam.index"))

    db_kind = _KIND_DB[kind]
    detail_url = url_for("ipam.subnet_detail", kind=kind, subnet_id=subnet_id)

    ip = request.form.get("ip", "").strip()
    try:
        ipaddress.IPv4Address(ip)
    except ValueError:
        flash("Invalid IP address.", "error")
        return redirect(detail_url)

    db = None
    try:
        db = _jen_db()
        with db.cursor() as cur:
            cur.execute(
                """
                DELETE FROM ipam_static_entries
                WHERE ip=%s AND subnet_kind=%s AND subnet_id=%s
            """,
                (ip, db_kind, subnet_id),
            )
            _record_history(cur, ip, db_kind, subnet_id, "removed")
        db.commit()
        flash(f"Entry for {ip} removed.", "success")
        _audit("IPAM_DELETE", ip, f"kind={db_kind} subnet={subnet_id} entry removed")
    except Exception as e:
        flash(f"Error removing entry: {e}", "error")
    finally:
        if db:
            db.close()

    return redirect(detail_url)


def _range_addresses(network, first_raw, last_raw):
    """Pure: the host addresses from first to last inclusive, both inside
    the subnet, capped at _RANGE_MAX. Returns (ips, error)."""
    try:
        first = ipaddress.IPv4Address((first_raw or "").strip())
        last = ipaddress.IPv4Address((last_raw or "").strip())
    except ValueError:
        return [], "Both ends of the range must be IPv4 addresses."
    if first not in network or last not in network:
        return [], f"The range must lie inside {network}."
    if last < first:
        return [], "The range end is before its start."
    if int(last) - int(first) + 1 > _RANGE_MAX:
        return [], f"A range action covers at most {_RANGE_MAX} addresses at a time."
    hosts = {network.network_address, network.broadcast_address} if network.prefixlen < 31 else set()
    return [
        str(ipaddress.IPv4Address(n)) for n in range(int(first), int(last) + 1) if ipaddress.IPv4Address(n) not in hosts
    ], ""


@bp.route("/range/<kind>/<int:subnet_id>", methods=["POST"])
@login_required
def range_action(kind, subnet_id):
    """v1.5.0 — mark a from–to span planned/static (one label/owner) or
    clear it; one history row per address."""
    if not _require_write():
        return redirect(url_for("ipam.subnet_detail", kind=kind, subnet_id=subnet_id))
    subnet = _check_access(kind, subnet_id)
    if subnet is None:
        flash("Subnet not found or access denied.", "error")
        return redirect(url_for("ipam.index"))
    db_kind = _KIND_DB[kind]
    detail_url = url_for("ipam.subnet_detail", kind=kind, subnet_id=subnet_id)

    action = request.form.get("action", "").strip()
    if action not in ("static", "planned", "clear"):
        flash("Unknown range action.", "error")
        return redirect(detail_url)
    network = ipaddress.IPv4Network(subnet["cidr"], strict=False)
    ips, err = _range_addresses(network, request.form.get("first", ""), request.form.get("last", ""))
    if err:
        flash(err, "error")
        return redirect(detail_url)
    label = request.form.get("label", "").strip()[:100]
    owner = request.form.get("owner", "").strip()[:100]

    # Never overwrite a reservation's or a live lease's address silently.
    skipped = set()
    if kind == "kea" and action != "clear":
        leases, res = _load_kea_sets(subnet_id)
        skipped = (set(leases) | set(res)) & set(ips)
        ips = [ip for ip in ips if ip not in skipped]

    db = None
    done = 0
    try:
        db = _jen_db()
        with db.cursor() as cur:
            for ip in ips:
                if action == "clear":
                    cur.execute(
                        "DELETE FROM ipam_static_entries WHERE ip=%s AND subnet_kind=%s AND subnet_id=%s",
                        (ip, db_kind, subnet_id),
                    )
                    _record_history(cur, ip, db_kind, subnet_id, "cleared")
                else:
                    _upsert_entry(cur, ip, db_kind, subnet_id, label, owner, "", "", "", action)
                    _record_history(cur, ip, db_kind, subnet_id, action, label, owner)
                done += 1
        db.commit()
        verb = "cleared" if action == "clear" else f"marked {action}"
        msg = f"{done} address{'es' if done != 1 else ''} {verb}."
        if skipped:
            msg += f" {len(skipped)} skipped (a Kea lease or reservation is there)."
        flash(msg, "success")
        _audit("IPAM_RANGE", subnet["cidr"], f"kind={db_kind} subnet={subnet_id} action={action} count={done}")
    except Exception as e:
        flash(f"Range action failed: {e}", "error")
    finally:
        if db:
            db.close()
    return redirect(detail_url)


# ── Routes: unmanaged subnet management (admin only) ─────────────────────────


@bp.route("/subnets/add", methods=["POST"])
@login_required
def add_subnet():
    if not _is_admin():
        flash("Only administrators can add unmanaged subnets.", "error")
        return redirect(url_for("ipam.index"))

    name = request.form.get("name", "").strip()[:100]
    cidr_raw = request.form.get("cidr", "").strip()
    description = request.form.get("description", "").strip()
    gateway = request.form.get("gateway", "").strip()

    if not name:
        flash("Subnet name is required.", "error")
        return redirect(url_for("ipam.index"))

    try:
        network = ipaddress.IPv4Network(cidr_raw, strict=False)
    except ValueError:
        flash(f"Invalid CIDR: {cidr_raw}", "error")
        return redirect(url_for("ipam.index"))

    if network.prefixlen < _MAX_PREFIX:
        flash(f"Subnets larger than a /{_MAX_PREFIX} are not supported.", "error")
        return redirect(url_for("ipam.index"))

    if gateway:
        try:
            if ipaddress.IPv4Address(gateway) not in network:
                raise ValueError
        except ValueError:
            flash(f"The gateway must be an address inside {network}.", "error")
            return redirect(url_for("ipam.index"))

    cidr = str(network)

    # Reject overlap with Kea-managed subnets and existing unmanaged subnets.
    for _sid, info in _accessible_subnets().items():
        try:
            if network.overlaps(ipaddress.IPv4Network(info["cidr"], strict=False)):
                flash(f"{cidr} overlaps Kea-managed subnet {info['name']} ({info['cidr']}).", "error")
                return redirect(url_for("ipam.index"))
        except ValueError:
            continue
    for _sid, info in _get_ipam_subnets().items():
        try:
            if network.overlaps(ipaddress.IPv4Network(info["cidr"], strict=False)):
                flash(f"{cidr} overlaps unmanaged subnet {info['name']} ({info['cidr']}).", "error")
                return redirect(url_for("ipam.index"))
        except ValueError:
            continue

    db = None
    try:
        db = _jen_db()
        with db.cursor() as cur:
            cur.execute(
                """
                INSERT INTO ipam_subnets
                    (name, cidr, description, gateway, created_at, updated_at)
                VALUES (%s, %s, %s, %s, UTC_TIMESTAMP(), UTC_TIMESTAMP())
            """,
                (name, cidr, description, gateway or None),
            )
        db.commit()
        flash(f"Unmanaged subnet {name} ({cidr}) added.", "success")
        _audit("IPAM_SUBNET_ADD", cidr, f"name={name} gateway={gateway}")
    except Exception as e:
        flash(f"Error adding subnet: {e}", "error")
    finally:
        if db:
            db.close()

    return redirect(url_for("ipam.index"))


@bp.route("/subnets/<int:subnet_id>/delete", methods=["POST"])
@login_required
def delete_subnet(subnet_id):
    if not _is_admin():
        flash("Only administrators can delete unmanaged subnets.", "error")
        return redirect(url_for("ipam.index"))

    subnet = _get_ipam_subnets().get(subnet_id)
    if subnet is None:
        flash("Subnet not found.", "error")
        return redirect(url_for("ipam.index"))

    db = None
    try:
        db = _jen_db()
        with db.cursor() as cur:
            cur.execute(
                """
                DELETE FROM ipam_static_entries
                WHERE subnet_kind='ipam' AND subnet_id=%s
            """,
                (subnet_id,),
            )
            cur.execute("DELETE FROM ipam_subnets WHERE id=%s", (subnet_id,))
        db.commit()
        flash(f"Unmanaged subnet {subnet['name']} ({subnet['cidr']}) and its entries deleted.", "success")
        _audit("IPAM_SUBNET_DELETE", subnet["cidr"], f"name={subnet['name']}")
    except Exception as e:
        flash(f"Error deleting subnet: {e}", "error")
    finally:
        if db:
            db.close()

    return redirect(url_for("ipam.index"))


# ── Conflict alerts (v1.6.0, plugin API v3) ───────────────────────────────────

_CONFLICT_ALERT_TYPE = "ipam_conflict"
_CONFLICT_TEMPLATE = (
    "⚠️ <b>IPAM Conflict</b>\n{ip} is designated {designated} in {subnet}, "
    "but a DHCP client currently holds it.\nHostname: {hostname}\nMAC: {mac}"
)


def _kea_conflicts():
    """(subnet_id, subnet_info, entry) for every conflict across every Kea
    subnet Jen knows — unrestricted, for the periodic job (no current_user
    in a background thread). Unmanaged subnets never produce a conflict:
    _build_address_space only loads Kea leases for kind='kea'."""
    from jen.plugin_api import subnet_map

    out = []
    for sid, info in subnet_map().items():
        try:
            space = _build_address_space("kea", sid, info["cidr"], subnet=info)
        except Exception as e:
            logger.error(f"IPAM: conflict scan failed for subnet {sid}: {e}")
            continue
        for entry in space:
            if entry["status"] == "conflict":
                out.append((sid, info, entry))
    return out


def _check_conflicts():
    """Periodic job (every 15 min): alert once per NEW conflict and drop
    tracking rows for conflicts that have resolved, so a recurrence alerts
    again — the same 'alert only once per new occurrence' rule Network
    Discovery uses for rogue devices."""
    from jen.plugin_api import emit, send_alert

    conflicts = _kea_conflicts()
    seen_keys = set()
    db = None
    try:
        db = _jen_db()
        with db.cursor() as cur:
            for sid, info, entry in conflicts:
                key = (entry["ip"], "kea", sid)
                seen_keys.add(key)
                cur.execute("SELECT id FROM ipam_conflict_state WHERE ip=%s AND subnet_kind=%s AND subnet_id=%s", key)
                row = cur.fetchone()
                if row:
                    cur.execute("UPDATE ipam_conflict_state SET last_seen=UTC_TIMESTAMP() WHERE id=%s", (row["id"],))
                    continue
                cur.execute("INSERT INTO ipam_conflict_state (ip, subnet_kind, subnet_id) VALUES (%s, %s, %s)", key)
                send_alert(
                    _CONFLICT_ALERT_TYPE,
                    subnet_id=sid,
                    ip=entry["ip"],
                    subnet=info["name"],
                    designated=entry["designated"] or "static",
                    hostname=entry["hostname"],
                    mac=entry["mac"],
                )
                emit(
                    "plugin.ipam.conflict",
                    mac=entry["mac"] or None,
                    ip=entry["ip"],
                    subnet_id=sid,
                    detail=f"{entry['ip']} designated {entry['designated']} in {info['name']}, but a DHCP client holds it",
                )
            cur.execute("SELECT id, ip, subnet_kind, subnet_id FROM ipam_conflict_state")
            stale = [r["id"] for r in cur.fetchall() if (r["ip"], r["subnet_kind"], r["subnet_id"]) not in seen_keys]
            for row_id in stale:
                cur.execute("DELETE FROM ipam_conflict_state WHERE id=%s", (row_id,))
        db.commit()
    except Exception as e:
        logger.error(f"IPAM: conflict check failed: {e}")
    finally:
        if db:
            db.close()


# ── Search provider (v1.6.0, plugin API v3) ───────────────────────────────────


def _ipam_search(query, accessible_subnet_ids, all_subnets):
    """register_search_provider callback. Only kea-kind entries are
    returned: an unmanaged subnet's id is a separate numbering space from
    Jen's SUBNET_MAP, so it can't be safely compared against
    accessible_subnet_ids — Jen re-filters kea-kind rows by subnet_id
    itself afterward (the Q55 rule), this just supplies candidates."""
    q = (query or "").strip()
    if not q:
        return []
    like = f"%{q}%"
    out = []
    db = None
    try:
        db = _jen_db()
        with db.cursor() as cur:
            cur.execute(
                """
                SELECT ip, subnet_kind, subnet_id, label, owner, hostname, mac FROM ipam_static_entries
                WHERE (label LIKE %s OR owner LIKE %s OR ip LIKE %s OR hostname LIKE %s)
                ORDER BY updated_at DESC LIMIT 20
            """,
                (like, like, like, like),
            )
            for row in cur.fetchall():
                if row["subnet_kind"] != "kea":
                    continue
                out.append(
                    {
                        "title": row["label"] or row["hostname"] or row["ip"],
                        "subtitle": f"{row['ip']} · {row['owner'] or 'no owner'}",
                        "href": f"/network/ipam/subnet/kea/{row['subnet_id']}?ip={row['ip']}",
                        "subnet_id": row["subnet_id"],
                    }
                )
    except Exception as e:
        logger.error(f"IPAM: search provider failed: {e}")
    finally:
        if db:
            db.close()
    return out


# ── JSON API (v1.6.0, plugin API v3) ──────────────────────────────────────────
# Undecorated on purpose: api_key_required() is applied in register(app),
# not here, so plugin.py's top level never imports jen.plugin_api — the
# standalone harness (tools/test_plugin.py) stubs flask/flask_login only
# and loads plugin.py with neither Jen nor a database on the path.

api_bp = Blueprint("ipam_api", __name__, url_prefix="/api/v1/plugins/ipam")


def _api_subnet_ok(subnet_id):
    from flask import g

    from jen.plugin_api import filter_subnet_ids

    return subnet_id in filter_subnet_ids(g.api_key, [subnet_id])


def _api_list_entries():
    try:
        subnet_id = int(request.args.get("subnet_id", ""))
    except (TypeError, ValueError):
        return jsonify({"error": "subnet_id is required"}), 400
    if not _api_subnet_ok(subnet_id):
        return jsonify({"error": "subnet not accessible to this key"}), 403
    subnet = _accessible_subnets().get(subnet_id)
    if subnet is None:
        return jsonify({"error": "not found"}), 404
    entries = _load_entries("kea", subnet_id)
    return jsonify(
        {
            "subnet_id": subnet_id,
            "entries": [
                {
                    "ip": ip,
                    "label": e.get("label") or "",
                    "owner": e.get("owner") or "",
                    "notes": e.get("notes") or "",
                    "hostname": e.get("hostname") or "",
                    "mac": e.get("mac") or "",
                    "status": _designated_status(e),
                }
                for ip, e in entries.items()
            ],
        }
    )


def _api_save_entry():
    from flask import g

    body = request.get_json(silent=True) or {}
    try:
        subnet_id = int(body.get("subnet_id"))
    except (TypeError, ValueError):
        return jsonify({"error": "subnet_id is required"}), 400
    if not _api_subnet_ok(subnet_id):
        return jsonify({"error": "subnet not accessible to this key"}), 403
    subnet = _accessible_subnets().get(subnet_id)
    if subnet is None:
        return jsonify({"error": "not found"}), 404

    ip = str(body.get("ip", "")).strip()
    try:
        addr = ipaddress.IPv4Address(ip)
        network = ipaddress.IPv4Network(subnet["cidr"], strict=False)
    except ValueError:
        return jsonify({"error": "invalid ip"}), 400
    if addr not in network:
        return jsonify({"error": f"{ip} is not inside {subnet['cidr']}"}), 400

    status = body.get("status", "static")
    if status not in _DESIGNATED:
        status = "static"
    label = str(body.get("label", "") or "")[:100]
    owner = str(body.get("owner", "") or "")[:100]
    notes = str(body.get("notes", "") or "")
    hostname = str(body.get("hostname", "") or "")[:255]
    mac = _normalize_mac(body.get("mac", "")) or ""
    actor = f"api:{g.api_key['name']}"

    db = None
    try:
        db = _jen_db()
        with db.cursor() as cur:
            _upsert_entry(cur, ip, "kea", subnet_id, label, owner, notes, hostname, mac, status)
            _record_history(cur, ip, "kea", subnet_id, status, label, owner, actor=actor)
        db.commit()
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        if db:
            db.close()
    return jsonify({"ok": True, "ip": ip, "status": status})


def _api_next_free(subnet_id):
    if not _api_subnet_ok(subnet_id):
        return jsonify({"error": "subnet not accessible to this key"}), 403
    subnet = _accessible_subnets().get(subnet_id)
    if subnet is None:
        return jsonify({"error": "not found"}), 404
    space = _build_address_space("kea", subnet_id, subnet["cidr"], subnet=subnet)
    return jsonify({"ip": _next_free(space)})


def register(app):
    app.register_blueprint(bp)

    from jen.plugin_api import (
        api_key_required,
        register_alert_type,
        register_periodic,
        register_row_action,
        register_search_provider,
    )

    api_bp.add_url_rule(
        "/entries", "api_list_entries", api_key_required(write=False)(_api_list_entries), methods=["GET"]
    )
    api_bp.add_url_rule("/entries", "api_save_entry", api_key_required(write=True)(_api_save_entry), methods=["POST"])
    api_bp.add_url_rule(
        "/next-free/<int:subnet_id>", "api_next_free", api_key_required(write=False)(_api_next_free), methods=["GET"]
    )
    app.register_blueprint(api_bp)

    register_alert_type(
        "ipam", _CONFLICT_ALERT_TYPE, label="IPAM Conflict", icon="triangle-alert", default_template=_CONFLICT_TEMPLATE
    )
    register_periodic("ipam", "conflict_check", _check_conflicts, every_minutes=15)
    register_row_action(
        "ipam",
        "reservation",
        label="Open in IPAM",
        icon="clipboard-list",
        href="/network/ipam/subnet/kea/{subnet_id}?ip={ip}",
    )
    register_search_provider("ipam", title="IPAM", fn=_ipam_search)

    logger.info("IPAM Lite plugin registered")
