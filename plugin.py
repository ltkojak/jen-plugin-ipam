"""
IPAM Lite plugin for Jen — v1.0.0
Full IP address space management.
Shows every IP in each subnet: available, dynamic lease, reserved, or static.
"""
import ipaddress
import csv
import io
import logging

from flask import (Blueprint, flash, jsonify, make_response,
                   redirect, render_template, request, url_for)
from flask_login import current_user, login_required

logger = logging.getLogger(__name__)

bp = Blueprint("ipam", __name__,
               template_folder="templates",
               url_prefix="/network/ipam")


# ── Helpers ───────────────────────────────────────────────────────────────────

def _get_jen_db():
    from jen.models.db import get_jen_db
    return get_jen_db()

def _get_kea_db():
    from jen.models.db import get_kea_db
    return get_kea_db()

def _accessible_subnets():
    from jen.services.access import get_accessible_subnet_map
    return get_accessible_subnet_map()

def _subnet_map():
    from jen import extensions
    return extensions.SUBNET_MAP


def _build_address_space(subnet_id: int, cidr: str) -> list:
    """
    Build the full address space for a subnet.
    Each entry: {ip, status, hostname, mac, label, owner, notes, host_id}
    Status: 'available' | 'dynamic' | 'reserved' | 'static'
    """
    try:
        network = ipaddress.IPv4Network(cidr, strict=False)
    except ValueError:
        return []

    # All IPs in the pool (skip network and broadcast)
    all_ips = [str(h) for h in network.hosts()]

    # Build lookup dicts from Kea
    active_leases = {}   # ip -> {hostname, mac}
    reservations = {}    # ip -> {hostname, mac, host_id}

    try:
        kdb = _get_kea_db()
        with kdb.cursor() as cur:
            # Active leases
            cur.execute("""
                SELECT inet_ntoa(address) as ip,
                       l.hostname,
                       HEX(l.hwaddr) as mac_hex
                FROM lease4 l
                WHERE l.state=0 AND l.subnet_id=%s
            """, (subnet_id,))
            for row in cur.fetchall():
                mac = ":".join(row["mac_hex"][i:i+2] for i in range(0,12,2)) if row["mac_hex"] else ""
                active_leases[row["ip"]] = {
                    "hostname": row["hostname"] or "",
                    "mac": mac
                }
            # Reservations
            cur.execute("""
                SELECT inet_ntoa(h.ipv4_address) as ip,
                       h.hostname,
                       HEX(h.dhcp_identifier) as mac_hex,
                       h.host_id
                FROM hosts h
                WHERE h.dhcp4_subnet_id=%s
            """, (subnet_id,))
            for row in cur.fetchall():
                mac = ":".join(row["mac_hex"][i:i+2] for i in range(0,12,2)) if row["mac_hex"] else ""
                reservations[row["ip"]] = {
                    "hostname": row["hostname"] or "",
                    "mac": mac,
                    "host_id": row["host_id"]
                }
        kdb.close()
    except Exception as e:
        logger.error(f"IPAM: Kea DB error: {e}")

    # Static entries from IPAM DB
    static_entries = {}
    try:
        jdb = _get_jen_db()
        with jdb.cursor() as cur:
            cur.execute(
                "SELECT ip, label, owner, notes FROM ipam_static_entries WHERE subnet_id=%s",
                (subnet_id,)
            )
            for row in cur.fetchall():
                static_entries[row["ip"]] = row
        jdb.close()
    except Exception as e:
        logger.error(f"IPAM: static entries error: {e}")

    # Build the address space
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
            # If also has active lease, still "reserved"
            if ip in active_leases:
                entry["hostname"] = entry["hostname"] or active_leases[ip]["hostname"]
                entry["mac"] = entry["mac"] or active_leases[ip]["mac"]
        elif ip in active_leases:
            entry.update(active_leases[ip])
            entry["status"] = "dynamic"

        # Overlay static entry (label/owner/notes) regardless of Kea status
        if ip in static_entries:
            s = static_entries[ip]
            entry["label"] = s.get("label", "")
            entry["owner"] = s.get("owner", "")
            entry["notes"] = s.get("notes", "")
            # If not already leased/reserved, mark as static
            if entry["status"] == "available":
                entry["status"] = "static"

        space.append(entry)

    return space


# ── Routes ────────────────────────────────────────────────────────────────────

@bp.route("/")
@login_required
def index():
    subnet_map = _accessible_subnets()
    # Summary stats per subnet
    summaries = {}
    for sid, info in subnet_map.items():
        try:
            space = _build_address_space(sid, info["cidr"])
            counts = {"available": 0, "dynamic": 0, "reserved": 0, "static": 0, "total": len(space)}
            for entry in space:
                counts[entry["status"]] = counts.get(entry["status"], 0) + 1
            counts["used"] = counts["dynamic"] + counts["reserved"] + counts["static"]
            counts["pct"] = round(counts["used"] / counts["total"] * 100) if counts["total"] else 0
            summaries[sid] = counts
        except Exception as e:
            summaries[sid] = {}
    return render_template("ipam/index.html", subnet_map=subnet_map, summaries=summaries)


@bp.route("/subnet/<int:subnet_id>")
@login_required
def subnet_detail(subnet_id):
    from jen.services.access import assert_subnet_access
    if not assert_subnet_access(subnet_id):
        return redirect(url_for("ipam.index"))

    subnet_map = _subnet_map()
    if subnet_id not in subnet_map:
        flash("Subnet not found.", "error")
        return redirect(url_for("ipam.index"))

    subnet = subnet_map[subnet_id]
    space = _build_address_space(subnet_id, subnet["cidr"])

    # Count by status
    counts = {"available": 0, "dynamic": 0, "reserved": 0, "static": 0}
    for e in space:
        counts[e["status"]] = counts.get(e["status"], 0) + 1

    status_filter = request.args.get("filter", "all")

    return render_template(
        "ipam/subnet.html",
        subnet_id=subnet_id,
        subnet=subnet,
        space=space,
        counts=counts,
        status_filter=status_filter,
    )


@bp.route("/subnet/<int:subnet_id>/export")
@login_required
def export_csv(subnet_id):
    from jen.services.access import assert_subnet_access
    if not assert_subnet_access(subnet_id):
        return redirect(url_for("ipam.index"))

    subnet_map = _subnet_map()
    if subnet_id not in subnet_map:
        flash("Subnet not found.", "error")
        return redirect(url_for("ipam.index"))

    subnet = subnet_map[subnet_id]
    space = _build_address_space(subnet_id, subnet["cidr"])

    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=[
        "ip", "status", "hostname", "mac", "label", "owner", "notes"
    ])
    writer.writeheader()
    for entry in space:
        writer.writerow({k: entry.get(k, "") for k in writer.fieldnames})

    response = make_response(output.getvalue())
    response.headers["Content-Type"] = "text/csv"
    response.headers["Content-Disposition"] = (
        f"attachment; filename=ipam-{subnet['name']}-{subnet_id}.csv"
    )
    return response


@bp.route("/entry/<int:subnet_id>", methods=["POST"])
@login_required
def save_entry(subnet_id):
    """Create or update a static IPAM entry."""
    from jen.services.access import assert_subnet_access
    from jen.models import user as __user
    if not assert_subnet_access(subnet_id):
        return jsonify({"error": "Access denied"}), 403

    ip      = request.form.get("ip", "").strip()
    label   = request.form.get("label", "").strip()[:100]
    owner   = request.form.get("owner", "").strip()[:100]
    notes   = request.form.get("notes", "").strip()
    # ipam_status: 'static' = designated static entry, 'available' = clear to available
    ipam_status = request.form.get("ipam_status", "").strip()

    # Validate IP
    try:
        ipaddress.IPv4Address(ip)
    except ValueError:
        flash("Invalid IP address.", "error")
        return redirect(url_for("ipam.subnet_detail", subnet_id=subnet_id))

    # If status set to available and no other fields — just delete the entry
    if ipam_status == "available" and not label and not owner and not notes:
        try:
            db = _get_jen_db()
            with db.cursor() as cur:
                cur.execute(
                    "DELETE FROM ipam_static_entries WHERE ip=%s AND subnet_id=%s",
                    (ip, subnet_id)
                )
                cur.execute("""
                    INSERT INTO ipam_assignment_history
                        (ip, subnet_id, action, acted_by)
                    VALUES (%s, %s, 'cleared', %s)
                """, (ip, subnet_id, current_user.username))
            db.commit()
            db.close()
            flash(f"Entry for {ip} cleared.", "success")
        except Exception as e:
            flash(f"Error clearing entry: {e}", "error")
        return redirect(url_for("ipam.subnet_detail", subnet_id=subnet_id))

    try:
        db = _get_jen_db()
        with db.cursor() as cur:
            cur.execute("""
                INSERT INTO ipam_static_entries (ip, subnet_id, label, owner, notes)
                VALUES (%s, %s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE
                    label=VALUES(label), owner=VALUES(owner),
                    notes=VALUES(notes), updated_at=NOW()
            """, (ip, subnet_id, label, owner, notes))
            cur.execute("""
                INSERT INTO ipam_assignment_history
                    (ip, subnet_id, label, owner, action, acted_by)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (ip, subnet_id, label, owner,
                  'static' if ipam_status == 'static' else 'note',
                  current_user.username))
        db.commit()
        db.close()
        flash(f"Entry saved for {ip}.", "success")
        __user.audit("IPAM_ENTRY", ip, f"label={label} owner={owner} status={ipam_status}")
    except Exception as e:
        flash(f"Error saving entry: {e}", "error")

    return redirect(url_for("ipam.subnet_detail", subnet_id=subnet_id))


@bp.route("/entry/<int:subnet_id>/delete", methods=["POST"])
@login_required
def delete_entry(subnet_id):
    from jen.services.access import assert_subnet_access
    from jen.models import user as __user
    if not assert_subnet_access(subnet_id):
        return jsonify({"error": "Access denied"}), 403

    ip = request.form.get("ip", "").strip()
    try:
        db = _get_jen_db()
        with db.cursor() as cur:
            cur.execute(
                "DELETE FROM ipam_static_entries WHERE ip=%s AND subnet_id=%s",
                (ip, subnet_id)
            )
            cur.execute("""
                INSERT INTO ipam_assignment_history
                    (ip, subnet_id, action, acted_by)
                VALUES (%s, %s, 'removed', %s)
            """, (ip, subnet_id, current_user.username))
        db.commit()
        db.close()
        flash(f"Entry for {ip} removed.", "success")
        __user.audit("IPAM_DELETE", ip, "Static entry removed")
    except Exception as e:
        flash(f"Error removing entry: {e}", "error")

    return redirect(url_for("ipam.subnet_detail", subnet_id=subnet_id))


def register(app):
    app.register_blueprint(bp)
    logger.info("IPAM Lite plugin registered")
