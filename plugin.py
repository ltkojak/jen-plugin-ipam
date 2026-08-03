"""
IPAM Lite plugin for Jen.
Full IP address space management for Kea-managed and unmanaged subnets.
Version lives in manifest.json — not duplicated here.
"""
import csv
import io
import ipaddress
import logging
import re

from flask import (Blueprint, flash, jsonify, make_response,
                   redirect, render_template, request, url_for)
from flask_login import current_user, login_required

logger = logging.getLogger(__name__)

import os as _os
bp = Blueprint("ipam", __name__,
               template_folder="templates",
               root_path=_os.path.dirname(_os.path.abspath(__file__)),
               url_prefix="/network/ipam")

# URL kind → DB kind. 'kea' = Kea-managed subnet, 'u' = unmanaged (IPAM-only).
_KIND_DB = {"kea": "kea", "u": "ipam"}

_MAC_RE = re.compile(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$")
_FILENAME_SAFE_RE = re.compile(r"[^A-Za-z0-9._-]+")

# Hard cap on unmanaged subnet size: nothing larger than a /16.
_MAX_PREFIX = 16
# Soft warning threshold: larger than a /22 renders thousands of table rows.
_WARN_PREFIX = 22


# ── DB helpers ────────────────────────────────────────────────────────────────

def _jen_db():
    from jen.models.db import get_jen_db
    return get_jen_db()


def _kea_db():
    from jen.models.db import get_kea_db
    return get_kea_db()


def _accessible_subnets():
    from jen.services.access import get_accessible_subnet_map
    return get_accessible_subnet_map()


def _assert_kea_access(subnet_id):
    from jen.services.access import assert_subnet_access
    return assert_subnet_access(subnet_id)


def _is_admin():
    try:
        from jen.services.access import is_admin_or_above
        return is_admin_or_above()
    except Exception:
        # Fall back to a direct role check if the import shape ever changes.
        role = getattr(current_user, "role", None)
        if role is not None:
            return role in ("superadmin", "admin")
        return bool(getattr(current_user, "is_admin", False))


def _audit(action, target, detail):
    try:
        from jen.models import user as _user
        _user.audit(action, target, detail)
    except Exception as e:
        logger.error(f"IPAM: audit failed: {e}")


def _normalize_mac(raw):
    """Normalize a user-entered MAC to lowercase colon format, or '' / None on failure."""
    if not raw:
        return ""
    cleaned = re.sub(r"[^0-9a-fA-F]", "", raw).lower()
    if len(cleaned) != 12:
        return None
    mac = ":".join(cleaned[i:i + 2] for i in range(0, 12, 2))
    return mac if _MAC_RE.match(mac) else None


def _format_identifier(hex_str, ident_type):
    """Format a Kea host identifier for display. Only type 0 (hw-address) is a MAC."""
    if not hex_str:
        return ""
    if ident_type == 0 and len(hex_str) == 12:
        return ":".join(hex_str[i:i + 2] for i in range(0, 12, 2)).lower()
    # Non-MAC identifier (client-id, DUID, circuit-id) — show raw hex, labelled.
    return f"id:{hex_str.lower()}"


# ── Unmanaged subnet store ────────────────────────────────────────────────────

def _get_ipam_subnets():
    """Return {id: {name, cidr, description}} for all unmanaged subnets."""
    subnets = {}
    db = _jen_db()
    try:
        with db.cursor() as cur:
            cur.execute(
                "SELECT id, name, cidr, description FROM ipam_subnets ORDER BY cidr"
            )
            for row in cur.fetchall():
                subnets[row["id"]] = {
                    "name": row["name"],
                    "cidr": row["cidr"],
                    "description": row["description"] or "",
                }
    finally:
        db.close()
    return subnets


def _get_subnet(kind, subnet_id):
    """Return the subnet info dict for a kind+id, or None."""
    if kind == "kea":
        return _accessible_subnets().get(subnet_id)
    return _get_ipam_subnets().get(subnet_id)


# ── Address space ─────────────────────────────────────────────────────────────

def _build_address_space(kind, subnet_id, cidr):
    """
    Build the full address space for a subnet.
    Each entry: {ip, status, hostname, mac, label, owner, notes, host_id}
    Status: 'available' | 'dynamic' | 'reserved' | 'static'
    For unmanaged (kind='u') subnets Kea is never queried; only
    'available' and 'static' occur, and hostname/mac come from the entry.
    """
    try:
        network = ipaddress.IPv4Network(cidr, strict=False)
    except ValueError:
        return []

    all_ips = [str(h) for h in network.hosts()]
    db_kind = _KIND_DB[kind]

    active_leases = {}
    reservations = {}

    if kind == "kea":
        db = None
        try:
            db = _kea_db()
            with db.cursor() as cur:
                cur.execute("""
                    SELECT inet_ntoa(l.address) AS ip,
                           l.hostname,
                           HEX(l.hwaddr) AS mac_hex
                    FROM lease4 l
                    WHERE l.state=0 AND l.subnet_id=%s
                """, (subnet_id,))
                for row in cur.fetchall():
                    if not row["ip"]:
                        continue
                    active_leases[row["ip"]] = {
                        "hostname": row["hostname"] or "",
                        "mac": _format_identifier(row["mac_hex"], 0),
                    }
                cur.execute("""
                    SELECT inet_ntoa(h.ipv4_address) AS ip,
                           h.hostname,
                           HEX(h.dhcp_identifier) AS ident_hex,
                           h.dhcp_identifier_type AS ident_type,
                           h.host_id
                    FROM hosts h
                    WHERE h.dhcp4_subnet_id=%s
                      AND h.ipv4_address IS NOT NULL
                      AND h.ipv4_address > 0
                """, (subnet_id,))
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

    # IPAM entries
    ipam_entries = {}
    db = None
    try:
        db = _jen_db()
        with db.cursor() as cur:
            cur.execute("""
                SELECT ip, label, owner, notes, hostname, mac, is_static
                FROM ipam_static_entries
                WHERE subnet_kind=%s AND subnet_id=%s
            """, (db_kind, subnet_id))
            for row in cur.fetchall():
                ipam_entries[row["ip"]] = row
    except Exception as e:
        logger.error(f"IPAM: entries error for {db_kind}/{subnet_id}: {e}")
    finally:
        if db:
            db.close()

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
        }

        if ip in reservations:
            entry.update(reservations[ip])
            entry["status"] = "reserved"
            if ip in active_leases:
                entry["hostname"] = entry["hostname"] or active_leases[ip]["hostname"]
                entry["mac"] = entry["mac"] or active_leases[ip]["mac"]
        elif ip in active_leases:
            entry.update(active_leases[ip])
            entry["status"] = "dynamic"

        if ip in ipam_entries:
            s = ipam_entries[ip]
            entry["label"] = s.get("label") or ""
            entry["owner"] = s.get("owner") or ""
            entry["notes"] = s.get("notes") or ""
            if kind == "u":
                entry["hostname"] = s.get("hostname") or ""
                entry["mac"] = s.get("mac") or ""
            # Only an explicit static designation flips the status.
            if entry["status"] == "available" and s.get("is_static"):
                entry["status"] = "static"

        space.append(entry)

    return space


def _count_space(space):
    counts = {"available": 0, "dynamic": 0, "reserved": 0, "static": 0,
              "total": len(space)}
    for e in space:
        counts[e["status"]] = counts.get(e["status"], 0) + 1
    counts["used"] = counts["dynamic"] + counts["reserved"] + counts["static"]
    counts["pct"] = round(counts["used"] / counts["total"] * 100) if counts["total"] else 0
    return counts


def _check_access(kind, subnet_id):
    """Access + existence check. Returns subnet info dict, or None if denied/missing."""
    if kind not in _KIND_DB:
        return None
    if kind == "kea" and not _assert_kea_access(subnet_id):
        return None
    return _get_subnet(kind, subnet_id)


# ── Routes: overview ──────────────────────────────────────────────────────────

@bp.route("/")
@login_required
def index():
    subnet_map = _accessible_subnets()
    ipam_subnets = _get_ipam_subnets()

    summaries = {}
    for sid, info in subnet_map.items():
        try:
            summaries[("kea", sid)] = _count_space(
                _build_address_space("kea", sid, info["cidr"]))
        except Exception as e:
            logger.error(f"IPAM: summary failed for kea subnet {sid}: {e}")
            summaries[("kea", sid)] = {}
    for sid, info in ipam_subnets.items():
        try:
            summaries[("u", sid)] = _count_space(
                _build_address_space("u", sid, info["cidr"]))
        except Exception as e:
            logger.error(f"IPAM: summary failed for unmanaged subnet {sid}: {e}")
            summaries[("u", sid)] = {}

    return render_template("ipam/index.html",
                           subnet_map=subnet_map,
                           ipam_subnets=ipam_subnets,
                           summaries=summaries,
                           is_admin=_is_admin())


# ── Routes: subnet detail / export ────────────────────────────────────────────

@bp.route("/subnet/<kind>/<int:subnet_id>")
@login_required
def subnet_detail(kind, subnet_id):
    subnet = _check_access(kind, subnet_id)
    if subnet is None:
        flash("Subnet not found or access denied.", "error")
        return redirect(url_for("ipam.index"))

    space = _build_address_space(kind, subnet_id, subnet["cidr"])
    counts = _count_space(space)
    status_filter = request.args.get("filter", "all")
    if status_filter not in ("all", "available", "dynamic", "reserved", "static"):
        status_filter = "all"

    return render_template("ipam/subnet.html",
                           kind=kind,
                           subnet_id=subnet_id,
                           subnet=subnet,
                           space=space,
                           counts=counts,
                           status_filter=status_filter,
                           is_admin=_is_admin())


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

    space = _build_address_space(kind, subnet_id, subnet["cidr"])

    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=[
        "ip", "status", "hostname", "mac", "label", "owner", "notes"
    ])
    writer.writeheader()
    for entry in space:
        writer.writerow({k: entry.get(k, "") for k in writer.fieldnames})

    safe_name = _FILENAME_SAFE_RE.sub("_", subnet["name"]).strip("_") or "subnet"
    response = make_response(output.getvalue())
    response.headers["Content-Type"] = "text/csv"
    response.headers["Content-Disposition"] = (
        f"attachment; filename=ipam-{safe_name}-{kind}-{subnet_id}.csv"
    )
    return response


# ── Routes: entries ───────────────────────────────────────────────────────────

@bp.route("/entry/<kind>/<int:subnet_id>", methods=["POST"])
@login_required
def save_entry(kind, subnet_id):
    """Create or update an IPAM entry."""
    subnet = _check_access(kind, subnet_id)
    if subnet is None:
        return jsonify({"error": "Access denied"}), 403

    db_kind = _KIND_DB[kind]
    detail_url = url_for("ipam.subnet_detail", kind=kind, subnet_id=subnet_id)

    ip = request.form.get("ip", "").strip()
    label = request.form.get("label", "").strip()[:100]
    owner = request.form.get("owner", "").strip()[:100]
    notes = request.form.get("notes", "").strip()
    hostname = request.form.get("hostname", "").strip()[:255]
    mac_raw = request.form.get("mac", "").strip()
    # ipam_status: 'static' = designated static, 'available' = plain annotation
    ipam_status = request.form.get("ipam_status", "").strip()

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

    # Manual hostname/MAC only apply to unmanaged subnets.
    if kind != "u":
        hostname, mac = "", ""
    else:
        mac = _normalize_mac(mac_raw)
        if mac is None:
            flash("Invalid MAC address format.", "error")
            return redirect(detail_url)

    is_static = 1 if ipam_status == "static" else 0

    # Status set back to available with nothing else filled in — clear the entry.
    if (ipam_status == "available" and not label and not owner
            and not notes and not hostname and not mac):
        db = None
        try:
            db = _jen_db()
            with db.cursor() as cur:
                cur.execute("""
                    DELETE FROM ipam_static_entries
                    WHERE ip=%s AND subnet_kind=%s AND subnet_id=%s
                """, (ip, db_kind, subnet_id))
                cur.execute("""
                    INSERT INTO ipam_assignment_history
                        (ip, subnet_kind, subnet_id, action, acted_at, acted_by)
                    VALUES (%s, %s, %s, 'cleared', UTC_TIMESTAMP(), %s)
                """, (ip, db_kind, subnet_id, current_user.username))
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
            cur.execute("""
                INSERT INTO ipam_static_entries
                    (ip, subnet_kind, subnet_id, label, owner, notes,
                     hostname, mac, is_static, created_at, updated_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s,
                        UTC_TIMESTAMP(), UTC_TIMESTAMP())
                ON DUPLICATE KEY UPDATE
                    label=VALUES(label), owner=VALUES(owner),
                    notes=VALUES(notes), hostname=VALUES(hostname),
                    mac=VALUES(mac), is_static=VALUES(is_static),
                    updated_at=UTC_TIMESTAMP()
            """, (ip, db_kind, subnet_id, label, owner, notes,
                  hostname, mac, is_static))
            cur.execute("""
                INSERT INTO ipam_assignment_history
                    (ip, subnet_kind, subnet_id, label, owner, action,
                     acted_at, acted_by)
                VALUES (%s, %s, %s, %s, %s, %s, UTC_TIMESTAMP(), %s)
            """, (ip, db_kind, subnet_id, label, owner,
                  "static" if is_static else "note",
                  current_user.username))
        db.commit()
        flash(f"Entry saved for {ip}.", "success")
        _audit("IPAM_ENTRY", ip,
               f"kind={db_kind} subnet={subnet_id} label={label} "
               f"owner={owner} status={ipam_status}")
    except Exception as e:
        flash(f"Error saving entry: {e}", "error")
    finally:
        if db:
            db.close()

    return redirect(detail_url)


@bp.route("/entry/<kind>/<int:subnet_id>/delete", methods=["POST"])
@login_required
def delete_entry(kind, subnet_id):
    subnet = _check_access(kind, subnet_id)
    if subnet is None:
        return jsonify({"error": "Access denied"}), 403

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
            cur.execute("""
                DELETE FROM ipam_static_entries
                WHERE ip=%s AND subnet_kind=%s AND subnet_id=%s
            """, (ip, db_kind, subnet_id))
            cur.execute("""
                INSERT INTO ipam_assignment_history
                    (ip, subnet_kind, subnet_id, action, acted_at, acted_by)
                VALUES (%s, %s, %s, 'removed', UTC_TIMESTAMP(), %s)
            """, (ip, db_kind, subnet_id, current_user.username))
        db.commit()
        flash(f"Entry for {ip} removed.", "success")
        _audit("IPAM_DELETE", ip, f"kind={db_kind} subnet={subnet_id} entry removed")
    except Exception as e:
        flash(f"Error removing entry: {e}", "error")
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

    cidr = str(network)

    # Reject overlap with Kea-managed subnets and existing unmanaged subnets.
    for sid, info in _accessible_subnets().items():
        try:
            if network.overlaps(ipaddress.IPv4Network(info["cidr"], strict=False)):
                flash(f"{cidr} overlaps Kea-managed subnet "
                      f"{info['name']} ({info['cidr']}).", "error")
                return redirect(url_for("ipam.index"))
        except ValueError:
            continue
    for sid, info in _get_ipam_subnets().items():
        try:
            if network.overlaps(ipaddress.IPv4Network(info["cidr"], strict=False)):
                flash(f"{cidr} overlaps unmanaged subnet "
                      f"{info['name']} ({info['cidr']}).", "error")
                return redirect(url_for("ipam.index"))
        except ValueError:
            continue

    db = None
    try:
        db = _jen_db()
        with db.cursor() as cur:
            cur.execute("""
                INSERT INTO ipam_subnets
                    (name, cidr, description, created_at, updated_at)
                VALUES (%s, %s, %s, UTC_TIMESTAMP(), UTC_TIMESTAMP())
            """, (name, cidr, description))
        db.commit()
        flash(f"Unmanaged subnet {name} ({cidr}) added.", "success")
        _audit("IPAM_SUBNET_ADD", cidr, f"name={name}")
        if network.prefixlen < _WARN_PREFIX:
            flash(f"Note: {cidr} contains {network.num_addresses - 2} host "
                  "addresses — the detail page will render a large table.",
                  "warning")
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
            cur.execute("""
                DELETE FROM ipam_static_entries
                WHERE subnet_kind='ipam' AND subnet_id=%s
            """, (subnet_id,))
            cur.execute("DELETE FROM ipam_subnets WHERE id=%s", (subnet_id,))
        db.commit()
        flash(f"Unmanaged subnet {subnet['name']} ({subnet['cidr']}) "
              "and its entries deleted.", "success")
        _audit("IPAM_SUBNET_DELETE", subnet["cidr"], f"name={subnet['name']}")
    except Exception as e:
        flash(f"Error deleting subnet: {e}", "error")
    finally:
        if db:
            db.close()

    return redirect(url_for("ipam.index"))


def register(app):
    app.register_blueprint(bp)
    logger.info("IPAM Lite plugin registered")
