#!/usr/bin/env python3
"""
tools/test_plugin.py — the plugin's own unit checks, run by CI after
tools/verify.py. Loads plugin.py with importlib against a stub `jen`
package and fake Flask/flask_login modules so nothing here needs Jen, a
database, or a browser; every check exercises a PURE function of the
plugin (space composition, counting, run collapsing, import parsing,
range parsing, next-free) with hand-built inputs.

Run: `python3 tools/test_plugin.py` (exit 1 on the first failing check).
"""

import functools
import importlib.util
import ipaddress
import os
import pathlib
import re
import sys
import types

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _stub_modules():
    """Enough of flask / flask_login for plugin.py to import."""
    flask = types.ModuleType("flask")

    class Blueprint:
        def __init__(self, *a, **k):
            pass

        def route(self, *a, **k):
            def deco(fn):
                return fn

            return deco

        def add_url_rule(self, *a, **k):
            pass

    flask.Blueprint = Blueprint
    for name in ("flash", "jsonify", "make_response", "redirect", "render_template", "url_for"):
        setattr(flask, name, lambda *a, **k: None)

    def _fake_response(body=None, **k):
        # a streamed CSV passes an iterable of chunks; join it so a test can inspect the result
        data = "".join(body) if body is not None and not isinstance(body, (str, bytes)) else (body or "")
        return types.SimpleNamespace(headers={}, get_data=lambda: data)

    flask.Response = _fake_response
    flask.stream_with_context = lambda gen: gen
    flask.request = None
    sys.modules["flask"] = flask
    fl = types.ModuleType("flask_login")
    fl.current_user = types.SimpleNamespace(username="tester", all_subnets=True, role="admin")
    fl.login_required = lambda fn: fn
    sys.modules["flask_login"] = fl


class _FakeApp:
    def register_blueprint(self, bp):
        pass


# The role gate the real jen.plugin_api provides (`is_admin_or_above`, `is_superadmin`, `require_write`), reading the
# stub current_user's role LIVE so a check can flip it. plugin.py imports them at the top, so they must exist before it
# is loaded. A refusal is recorded (message, endpoint) and the route is not run, which is what the real decorator does
# for a page request: flash, redirect, never touch the request.
GATE_REFUSALS = []


def _gate_is_admin_or_above():
    return getattr(sys.modules["flask_login"].current_user, "role", None) in ("superadmin", "admin")


def _gate_is_superadmin():
    return getattr(sys.modules["flask_login"].current_user, "role", None) == "superadmin"


def _gate_require_write(message="Viewers can look at this but not change it.", redirect_endpoint="dashboard.dashboard"):
    def deco(fn):
        @functools.wraps(fn)
        def wrapped(*a, **k):
            if _gate_is_admin_or_above():
                return fn(*a, **k)
            GATE_REFUSALS.append((message, redirect_endpoint))
            return "refused"

        return wrapped

    return deco


def _gate_safe_row(values):
    """jen.services.csv_safe.safe_row, as the real jen.plugin_api re-exports it."""
    return [
        "" if v is None else (f"'{v}" if str(v) and str(v)[0] in ("=", "+", "-", "@", "\t", "\r") else str(v))
        for v in values
    ]


def _install_gate_api(plugin_api=None):
    """Put the gate functions on the stub jen.plugin_api (creating the stub package when none exists yet)."""
    if plugin_api is None:
        plugin_api = sys.modules.get("jen.plugin_api")
        if plugin_api is None:
            jen_pkg = types.ModuleType("jen")
            plugin_api = types.ModuleType("jen.plugin_api")
            jen_pkg.plugin_api = plugin_api
            sys.modules["jen"] = jen_pkg
            sys.modules["jen.plugin_api"] = plugin_api
    plugin_api.is_admin_or_above = _gate_is_admin_or_above
    plugin_api.is_superadmin = _gate_is_superadmin
    plugin_api.require_write = _gate_require_write
    plugin_api.safe_row = _gate_safe_row


def _stub_jen_plugin_api():
    """A stub `jen.plugin_api` sufficient for register(app) to run end to end, enforcing the SAME
    two rules Jen's real one does: an alert type id must start with '<plugin_id>_', and a periodic job
    may not run more often than PERIODIC_MIN_MINUTES (5). A plugin that breaks either raises at
    register() in Jen, is swallowed by its per-plugin error handling, and simply never loads — the
    exact way watchdog 1.0.0 and dns-sync 1.0.0 shipped dead (Q89). Returns the registered calls."""
    calls = {"alert_types": [], "periodic": [], "row_actions": [], "search": [], "investigation": []}
    subnets = {5: {"name": "n", "cidr": "10.5.0.0/24"}}

    def api_key_can_access_subnet(key, subnet_id, *, allow_unattributed=False):
        """Jen's own rule: a missing key is False; no scope is unrestricted; a scoped key its subnets."""
        if not key:
            return False
        scope = key.get("subnet_access")
        if scope is None:
            return True
        if subnet_id is None:
            return allow_unattributed
        return subnet_id in scope

    def register_alert_type(plugin_id, type_id, **kwargs):
        prefix = f"{plugin_id}_"
        if not type_id.startswith(prefix):
            raise ValueError(f"type_id {type_id!r} must start with {prefix!r}")
        calls["alert_types"].append(type_id)

    def register_periodic(plugin_id, name, fn, every_minutes):
        if every_minutes < 5:
            raise ValueError("every_minutes must be at least 5")
        calls["periodic"].append((plugin_id, name, every_minutes))

    jen_pkg = types.ModuleType("jen")
    plugin_api = types.ModuleType("jen.plugin_api")
    plugin_api.register_alert_type = register_alert_type
    plugin_api.ACTIVE_LEASE4 = "state = 0 AND expire > NOW()"
    plugin_api.register_periodic = register_periodic
    plugin_api.register_row_action = lambda *a, **k: calls["row_actions"].append(a)
    plugin_api.register_search_provider = lambda *a, **k: calls["search"].append(a)
    plugin_api.register_investigation_provider = lambda *a, **k: calls["investigation"].append((a, k))
    plugin_api.api_key_required = lambda write=False: lambda fn: fn
    plugin_api.subnet_map = lambda: subnets
    plugin_api.api_key_can_access_subnet = api_key_can_access_subnet
    _install_gate_api(plugin_api)

    def normalize_mac(raw):
        import re as _re

        if not isinstance(raw, str) or not raw.strip():
            return None
        cleaned = _re.sub(r"[^0-9a-fA-F]", "", raw).lower()
        if len(cleaned) != 12:
            return None
        mac = ":".join(cleaned[i : i + 2] for i in range(0, 12, 2))
        return mac if _re.match(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$", mac) else None

    def like_pattern(text):
        return "%" + str(text).replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"

    def in_placeholders(values):
        n = len(list(values))
        return ",".join(["%s"] * n) if n else "NULL"

    def search_scope(accessible_ids, all_subnets, column):
        if all_subnets:
            return "1=1", []
        ids = sorted({int(i) for i in (accessible_ids or [])})
        if not ids:
            return None
        return f"{column} IN ({in_placeholders(ids)})", ids

    def json_object_body():
        # fetched fresh from sys.modules["flask"].request each call, so a per-test
        # `sys.modules["flask"].request = types.SimpleNamespace(get_json=...)` is seen
        import sys as _sys

        req = getattr(_sys.modules.get("flask"), "request", None)
        try:
            body = req.get_json(silent=True) if req is not None else None
        except Exception:
            body = None
        if isinstance(body, dict):
            return body, None
        return None, ({"error": "expected a JSON object"}, 400)

    def str_field(body, name, max_len=None):
        value = body.get(name) if isinstance(body, dict) else None
        if not isinstance(value, str):
            return ""
        value = value.strip()
        return value[:max_len] if max_len is not None else value

    def assert_subnet_access(subnet_id, *, notify=True):
        return True

    plugin_api.normalize_mac = normalize_mac
    plugin_api.like_pattern = like_pattern
    plugin_api.in_placeholders = in_placeholders
    plugin_api.search_scope = search_scope
    plugin_api.json_object_body = json_object_body
    plugin_api.str_field = str_field
    plugin_api.assert_subnet_access = assert_subnet_access
    calls["subnets"] = subnets
    jen_pkg.plugin_api = plugin_api
    sys.modules["jen"] = jen_pkg
    sys.modules["jen.plugin_api"] = plugin_api
    return calls


def load_plugin():
    _stub_modules()
    _install_gate_api()
    spec = importlib.util.spec_from_file_location("ipam_plugin", os.path.join(ROOT, "plugin.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


failures = []


def check(cond, msg):
    if cond:
        print(f"ok    {msg}")
    else:
        failures.append(msg)
        print(f"FAIL  {msg}")


def main():
    p = load_plugin()
    net = ipaddress.IPv4Network("10.0.0.0/28")  # .1 – .14
    ips = [str(h) for h in net.hosts()]
    ctx = {
        "gateways": ["10.0.0.1"],
        "dns": [],
        "pools": [
            (int(ipaddress.IPv4Address("10.0.0.10")), int(ipaddress.IPv4Address("10.0.0.14")), "10.0.0.10 - 10.0.0.14")
        ],
        "infrastructure": {
            "10.0.0.0": "network",
            "10.0.0.15": "broadcast",
            "10.0.0.1": "gateway",
            "10.0.0.2": "jen-host",
        },
        "notes": "",
    }
    leases = {
        "10.0.0.11": {"hostname": "laptop", "mac": "aa:aa:aa:aa:aa:01"},
        "10.0.0.5": {"hostname": "rogue", "mac": "aa:aa:aa:aa:aa:05"},
    }
    res = {"10.0.0.12": {"hostname": "printer", "mac": "aa:aa:aa:aa:aa:02", "host_id": 7}}
    entries = {
        "10.0.0.5": {
            "label": "NAS",
            "owner": "",
            "notes": "",
            "hostname": "",
            "mac": "",
            "is_static": 1,
            "entry_status": "static",
        },
        "10.0.0.6": {
            "label": "Cam",
            "owner": "",
            "notes": "",
            "hostname": "cam1",
            "mac": "aa:aa:aa:aa:aa:06",
            "is_static": 0,
            "entry_status": "planned",
        },
        "10.0.0.1": {
            "label": "",
            "owner": "",
            "notes": "core router",
            "hostname": "",
            "mac": "",
            "is_static": 0,
            "entry_status": "available",
        },
    }
    devices = {
        "aa:aa:aa:aa:aa:01": {
            "name": "Matt's laptop",
            "owner": "Matthew",
            "manufacturer": "Apple",
            "device_type": "apple",
            "icon": "💻",
        }
    }

    # ── composition ──────────────────────────────────────────────────────────
    space = p._compose_space(ips, leases, res, entries, ctx, devices)
    by = {e["ip"]: e for e in space}
    check(
        by["10.0.0.1"]["status"] == "infrastructure" and by["10.0.0.1"]["label"] == "Gateway",
        "gateway is infrastructure, labelled",
    )
    check(by["10.0.0.1"]["notes"] == "core router", "an annotation on an infrastructure address is kept")
    check(
        by["10.0.0.2"]["status"] == "infrastructure" and by["10.0.0.2"]["label"] == "Jen host",
        "the Jen host is infrastructure",
    )
    check(
        by["10.0.0.5"]["status"] == "conflict" and by["10.0.0.5"]["designated"] == "static",
        "static entry under a lease is a conflict",
    )
    check(
        by["10.0.0.5"]["hostname"] == "rogue" and by["10.0.0.5"]["label"] == "NAS",
        "conflict keeps both the lease's hostname and the entry's label",
    )
    check(
        by["10.0.0.11"]["status"] == "dynamic" and by["10.0.0.11"]["device"]["name"] == "Matt's laptop",
        "lease joined to the devices table by MAC",
    )
    check(by["10.0.0.12"]["status"] == "reserved" and by["10.0.0.12"]["host_id"] == 7, "reservation wins")
    check(
        by["10.0.0.6"]["status"] == "planned" and by["10.0.0.6"]["mac"] == "aa:aa:aa:aa:aa:06",
        "planned entry carries its manual MAC on a Kea subnet",
    )
    check(by["10.0.0.3"]["status"] == "available" and not by["10.0.0.3"]["in_pool"], "plain address outside the pool")
    check(
        by["10.0.0.13"]["status"] == "available" and by["10.0.0.13"]["in_pool"],
        "available inside the pool is marked in_pool",
    )

    # ── counts (fast path vs full path agree) ────────────────────────────────
    full = p._count_space(space)

    def host_in(ip):
        a = ipaddress.IPv4Address(ip)
        return a in net and a not in (net.network_address, net.broadcast_address)

    fast = p._count_sets(len(ips), host_in, leases, res, entries, ctx)
    for k in (
        "available",
        "dynamic",
        "reserved",
        "static",
        "planned",
        "infrastructure",
        "conflict",
        "used",
        "pct",
        "total",
    ):
        check(full[k] == fast[k], f"fast count matches full count for {k} ({fast[k]})")

    # ── next free outside the pools ──────────────────────────────────────────
    check(p._next_free(space) == "10.0.0.3", "next free skips infrastructure/entries and the pool")

    # ── run collapsing ───────────────────────────────────────────────────────
    big = ipaddress.IPv4Network("10.1.0.0/24")
    big_ips = [str(h) for h in big.hosts()]
    big_ctx = {
        "gateways": [],
        "dns": [],
        "pools": [(int(ipaddress.IPv4Address("10.1.0.100")), int(ipaddress.IPv4Address("10.1.0.199")), "p")],
        "infrastructure": {},
        "notes": "",
    }
    big_space = p._compose_space(big_ips, {"10.1.0.50": {"hostname": "x", "mac": ""}}, {}, {}, big_ctx)
    rows = p._collapse_runs(big_space, True)
    runs = [r for r in rows if r.get("run")]
    # .1–.49 | lease .50 | .51–.99 | pool .100–.199 | .200–.254 → 4 runs + 1 lease
    check(
        len(rows) == 5 and len(runs) == 4,
        f"254 addresses collapse to 5 rows: 4 runs + 1 lease ({len(rows)} rows, {len(runs)} runs)",
    )
    check(
        runs[0]["first"] == "10.1.0.1" and runs[0]["last"] == "10.1.0.49" and runs[0]["count"] == 49, "first run bounds"
    )
    check(
        runs[1]["first"] == "10.1.0.51" and runs[1]["last"] == "10.1.0.99" and not runs[1]["in_pool"],
        "second run stops at the pool boundary",
    )
    check(
        runs[2]["first"] == "10.1.0.100" and runs[2]["last"] == "10.1.0.199" and runs[2]["in_pool"],
        "the pool is its own run",
    )
    check(
        runs[3]["first"] == "10.1.0.200" and runs[3]["last"] == "10.1.0.254" and not runs[3]["in_pool"],
        "addresses after the pool are a separate run",
    )
    expanded = p._collapse_runs(big_space, True, expand=runs[0]["key"])
    check(sum(1 for r in expanded if not r.get("run")) == 50, "expanding one run shows its 49 addresses plus the lease")
    check(len(p._collapse_runs(big_space, False)) == 254, "collapse=False keeps every address")
    small = p._compose_space(["10.2.0.1", "10.2.0.2", "10.2.0.3"], {}, {}, {}, {"pools": [], "infrastructure": {}})
    check(
        all(not r.get("run") for r in p._collapse_runs(small, True)), "a run shorter than the minimum is not collapsed"
    )

    # ── 1.6.1: a run of available addresses collapses at EVERY prefix length ──
    for prefix in (16, 20, 22, 24, 25, 26, 28, 29, 30):
        check(p._should_collapse(prefix, None) is True, f"_should_collapse: a /{prefix} collapses by default")
    check(p._should_collapse(24, "1") is False, "_should_collapse: ?all=1 shows every address of a /24")
    check(p._should_collapse(24, "0") is True, "_should_collapse: only the literal 1 asks for everything")
    # a busy /24 — a few leases, a couple of statics — is a handful of rows, not 254
    busy_leases = {
        f"10.1.0.{n}": {"hostname": f"h{n}", "mac": f"aa:aa:aa:aa:aa:{n:02x}"} for n in (5, 6, 7, 40, 41, 120)
    }
    busy_entries = {
        "10.1.0.10": {
            "label": "printer",
            "owner": "",
            "notes": "",
            "hostname": "",
            "mac": "",
            "is_static": 1,
            "entry_status": "static",
        }
    }
    busy = p._compose_space(big_ips, busy_leases, {}, busy_entries, big_ctx)
    busy_rows = p._collapse_runs(busy, p._should_collapse(24, None))
    check(
        len(busy) == 254 and len(busy_rows) <= 20,
        f"a /24 with 7 occupied addresses renders at most 20 rows (got {len(busy_rows)})",
    )
    check(
        sum(r["count"] for r in busy_rows if r.get("run")) + sum(1 for r in busy_rows if not r.get("run")) == 254,
        "collapsing loses no address: every one is in a run or a row of its own",
    )
    # the 4-address floor: a run of 3 stays as three rows, a run of 4 becomes one
    floor = (
        [{"ip": f"10.9.0.{n}", "status": "available", "in_pool": False} for n in (1, 2, 3)]
        + [{"ip": "10.9.0.4", "status": "static", "in_pool": False}]
        + [{"ip": f"10.9.0.{n}", "status": "available", "in_pool": False} for n in (5, 6, 7, 8)]
    )
    floor_rows = p._collapse_runs(floor, True)
    check(
        [bool(r.get("run")) for r in floor_rows] == [False, False, False, False, True],
        f"the 4-address floor: 3 available stay rows, 4 become one run (got {[bool(r.get('run')) for r in floor_rows]})",
    )
    tiny = p._compose_space(
        ["10.8.0.1", "10.8.0.2", "10.8.0.3", "10.8.0.4", "10.8.0.5", "10.8.0.6"],
        {},
        {},
        {},
        {"pools": [], "infrastructure": {}},
    )
    check(len(p._collapse_runs(tiny, p._should_collapse(29, None))) == 1, "an empty /29 is one run row, not six")

    # ── range parsing ────────────────────────────────────────────────────────
    ips24, err = p._range_addresses(big, "10.1.0.10", "10.1.0.12")
    check(ips24 == ["10.1.0.10", "10.1.0.11", "10.1.0.12"] and not err, "range: inclusive span")
    check(p._range_addresses(big, "10.1.0.12", "10.1.0.10")[1] != "", "range: reversed refused")
    check(p._range_addresses(big, "10.9.0.1", "10.9.0.2")[1] != "", "range: outside the subnet refused")
    check(p._range_addresses(big, "x", "y")[1] != "", "range: garbage refused")
    check(
        p._range_addresses(ipaddress.IPv4Network("10.0.0.0/16"), "10.0.0.1", "10.0.8.0")[1] != "",
        "range: over the cap refused",
    )
    check(
        p._range_addresses(big, "10.1.0.0", "10.1.0.2")[0] == ["10.1.0.1", "10.1.0.2"],
        "range: network address excluded",
    )

    # ── expand param ─────────────────────────────────────────────────────────
    check(p._parse_expand("10.1.0.1-10.1.0.49", big) == "10.1.0.1-10.1.0.49", "expand param accepted")
    check(
        p._parse_expand("10.9.0.1-10.9.0.2", big) is None and p._parse_expand("<script>", big) is None,
        "expand param outside/garbage ignored",
    )

    # ── bare context (unmanaged) ─────────────────────────────────────────────
    bare = p._bare_ctx("172.16.10.0/24", "172.16.10.1")
    check(
        bare["infrastructure"]["172.16.10.1"] == "gateway" and bare["gateways"] == ["172.16.10.1"],
        "unmanaged gateway is infrastructure",
    )
    check(p._bare_ctx("172.16.10.0/24", "10.0.0.1")["gateways"] == [], "a gateway outside the subnet is ignored")

    # ── import parsing (unchanged behaviour, guarded) ───────────────────────
    parsed, errs = p._parse_import_rows(
        [
            {"address": "10.0.0.5/24", "status": "Active", "dns_name": "nas", "description": "d", "tenant": "T"},
            {"address": "10.0.0.6/24", "status": "DHCP", "dns_name": "", "description": "", "tenant": ""},
        ],
        ["address", "status", "dns_name", "description", "tenant"],
        "netbox",
    )
    check(
        not errs and len(parsed) == 1 and parsed[0]["status"] == "static" and parsed[0]["hostname"] == "nas",
        "netbox import: active → static, dhcp skipped",
    )
    jen_rows, _ = p._parse_import_rows(
        [
            {"ip": "10.0.0.1", "status": "infrastructure", "label": "Gateway"},
            {"ip": "10.0.0.5", "status": "conflict", "label": "NAS"},
        ],
        ["ip", "status", "label"],
        "jen",
    )
    check(jen_rows == [], "jen import: derived statuses (infrastructure/conflict) are never re-imported")

    # ── csv guard fallback ───────────────────────────────────────────────────
    src = pathlib.Path(ROOT, "plugin.py").read_text(encoding="utf-8")
    check(
        "def _safe_row" not in src and src.count("writer.writerow(safe_row(") == 3,
        "CSV formula guard: the three CSV writers use jen.plugin_api's safe_row, with no local copy of it",
    )

    # ── write gate (v1.5.2) — viewers can look at IPAM but not change it ────
    p.current_user.role = "viewer"
    check(p.is_admin_or_above() is False, "a viewer is not admin")
    check(p._require_write() is False, "a viewer cannot write")
    # request is None in this harness; a route that reaches request.form/
    # request.files raises AttributeError, so returning None without
    # raising proves _require_write() stopped it first.
    for fn, args in (
        (p.save_entry, ("kea", 1)),
        (p.delete_entry, ("kea", 1)),
        (p.range_action, ("kea", 1)),
        (p.import_preview, ("kea", 1)),
        (p.import_commit, ("kea", 1)),
    ):
        try:
            fn(*args)
            gated = True
        except Exception:
            gated = False
        check(gated, f"{fn.__name__} refuses a viewer before touching the request")
    p.current_user.role = "admin"
    check(p.is_admin_or_above() is True, "admin role restored for the rest of the run")
    check(
        "def _is_admin" not in src,
        "plugin.py no longer carries its own copy of the admin check (the write gate stays: its redirect needs the route's own kind and subnet_id)",
    )

    # ── import byte cap (v1.5.2) ─────────────────────────────────────────────
    class _FakeUpload:
        def __init__(self, data):
            self._data = data

        def read(self, n=-1):
            if n < 0 or n > len(self._data):
                n = len(self._data)
            out, self._data = self._data[:n], self._data[n:]
            return out

    try:
        p._read_csv_rows(_FakeUpload(b"a" * (p._IMPORT_MAX_BYTES + 1)))
        check(False, "an upload one byte over the cap is refused")
    except p._ImportTooLarge:
        check(True, "an upload one byte over the cap is refused")

    # A single _IMPORT_MAX_BYTES-long field trips csv's own unrelated field
    # size limit — pad with real newlines so this only exercises the byte cap.
    line = b"ip\n"
    padded = line * (p._IMPORT_MAX_BYTES // len(line))
    padded += b"a" * (p._IMPORT_MAX_BYTES - len(padded))
    check(len(padded) == p._IMPORT_MAX_BYTES, "test fixture is exactly at the cap")
    try:
        p._read_csv_rows(_FakeUpload(padded))
        check(True, "an upload exactly at the cap is accepted")
    except p._ImportTooLarge:
        check(False, "an upload exactly at the cap is accepted")

    # ── 1.6.2: unmanaged subnets are a global object ─────────────────────────
    class FakeDB:
        def __init__(self):
            self.statements = []
            self.sql = []

        def cursor(self):
            return self

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def execute(self, sql, params=()):
            self.statements.append((sql.split()[0].upper(), params))
            self.sql.append(" ".join(sql.split()))

        def commit(self):
            pass

        def close(self):
            pass

    flashed = []
    p.flash = lambda msg, cat="message": flashed.append(msg)
    p.redirect = lambda where: "redirect"
    p.url_for = lambda *a, **k: "/x"
    p._audit = lambda *a, **k: None
    for role, all_subnets, expect in (
        ("admin", False, False),
        ("admin", True, True),
        ("viewer", True, False),
        ("superadmin", True, True),
    ):
        p.current_user.role = role
        p.current_user.all_subnets = all_subnets
        check(
            p._can_manage_unmanaged() is expect,
            f"_can_manage_unmanaged: a {role} with all_subnets={all_subnets} -> {expect}",
        )

    hidden_kea = {9: {"name": "HIDDEN-KEA", "cidr": "10.9.0.0/24"}}
    p._accessible_subnets = dict  # the caller can see no Kea subnet at all
    p._all_kea_subnets = lambda: hidden_kea
    p._get_ipam_subnets = lambda: {4: {"name": "HIDDEN-U", "cidr": "10.4.0.0/24"}}
    p.current_user.role = "admin"
    p.current_user.all_subnets = False  # a subnet-scoped admin
    p.request = types.SimpleNamespace(form={"name": "x", "cidr": "10.20.0.0/24"}, args={})
    fdb = FakeDB()
    p._jen_db = lambda: fdb
    p.add_subnet()
    check(fdb.statements == [], "add_subnet: a subnet-scoped admin is refused, nothing stored")
    p.request = types.SimpleNamespace(form={}, args={})
    p.delete_subnet(4)
    check(fdb.statements == [], "delete_subnet: a subnet-scoped admin cannot delete an unmanaged subnet by id")
    check(
        all("HIDDEN" not in m and "10.4.0.0" not in m for m in flashed),
        "the refusals name no hidden subnet or CIDR",
    )
    p.current_user.all_subnets = True  # an unrestricted admin
    flashed.clear()
    p.request = types.SimpleNamespace(form={"name": "x", "cidr": "10.9.0.128/25"}, args={})
    fdb = FakeDB()
    p._jen_db = lambda: fdb
    p.add_subnet()
    check(
        fdb.statements == [] and any("HIDDEN-KEA" in m for m in flashed),
        "add_subnet: the overlap check runs over EVERY Kea subnet, not the caller's own (an unrestricted admin sees the hit)",
    )
    flashed.clear()
    p.request = types.SimpleNamespace(form={"name": "x", "cidr": "10.20.0.0/24"}, args={})
    fdb = FakeDB()
    p._jen_db = lambda: fdb
    p.add_subnet()
    check(
        any(s[0] == "INSERT" for s in fdb.statements),
        "add_subnet: an unrestricted admin can add a non-overlapping unmanaged subnet",
    )
    fdb = FakeDB()
    p._jen_db = lambda: fdb
    p.delete_subnet(4)
    check(any(s[0] == "DELETE" for s in fdb.statements), "delete_subnet: an unrestricted admin can delete one")
    check(
        any("DELETE FROM ipam_assignment_history" in s and "'ipam'" in s for s in fdb.sql),
        "delete_subnet: the subnet's assignment history goes with it (1.6.3)",
    )

    # ── 1.6.3: the JSON API, positive path, with NO session ──────────────────
    # The 1.6.2 check patched `_api_subnet_ok` away, so it never noticed that every ALLOWED call
    # raised: the API asked the logged-in user for the subnet map, and a Bearer request has none.
    # Here `_accessible_subnets` raises exactly as Jen's does for an anonymous user, the stub
    # plugin_api supplies the two unfiltered helpers the API must use, and the calls must SUCCEED.
    _stub_jen_plugin_api()
    _real_load_kea_sets = p._load_kea_sets

    def _no_session():
        raise AttributeError("'AnonymousUserMixin' object has no attribute 'filter_subnet_map'")

    p.jsonify = lambda payload: payload
    p._accessible_subnets = _no_session
    p._load_kea_sets = lambda sid, cidr=None, strict=False: ({}, {})
    p._load_entries = lambda kind, sid, strict=False: {
        "10.5.0.20": {"label": "NAS", "entry_status": "static", "is_static": 1}
    }
    unrestricted = {"name": "k", "subnet_access": None}
    sys.modules["flask"].g = types.SimpleNamespace(api_key=unrestricted)
    p.request = types.SimpleNamespace(args={"subnet_id": "5"})
    result = p._api_list_entries()
    check(
        isinstance(result, dict)
        and result.get("subnet_id") == 5
        and [e["ip"] for e in result["entries"]] == ["10.5.0.20"],
        f"API list entries: an allowed key gets its answer with no session (got {result})",
    )
    result = p._api_next_free(5)
    check(result == {"ip": "10.5.0.1"}, f"API next-free: an allowed key gets an address with no session (got {result})")
    p._load_kea_sets = lambda sid, cidr=None, strict=False: (
        {},
        {"10.5.0.1": {"hostname": "", "mac": "", "host_id": 1}},
    )
    check(
        p._api_next_free(5) == {"ip": "10.5.0.2"},
        "API next-free: a reservation (a global one included) is never handed out",
    )
    p._load_kea_sets = lambda sid, cidr=None, strict=False: ({}, {})
    fdb = FakeDB()
    p._jen_db = lambda: fdb
    sys.modules["flask"].request = types.SimpleNamespace(
        get_json=lambda silent=True: {"subnet_id": 5, "ip": "10.5.0.7", "label": "x"}
    )
    result = p._api_save_entry()
    check(
        isinstance(result, dict) and result.get("ok") is True and any(s[0] == "INSERT" for s in fdb.statements),
        f"API save: an allowed key saves an entry with no session (got {result})",
    )
    p._load_kea_sets = lambda sid, cidr=None, strict=False: (
        {"10.5.0.7": {"hostname": "h", "mac": "aa:aa:aa:aa:aa:07"}},
        {},
    )
    fdb = FakeDB()
    p._jen_db = lambda: fdb
    result = p._api_save_entry()
    check(
        isinstance(result, tuple) and result[1] == 409 and fdb.statements == [],
        f"API save: an address a lease holds cannot be newly designated (got {result})",
    )
    p._load_kea_sets = lambda sid, cidr=None, strict=False: ({}, {})
    sys.modules["flask"].g = types.SimpleNamespace(api_key={"name": "k", "subnet_access": [1]})
    result = p._api_next_free(5)
    check(isinstance(result, tuple) and result[1] == 403, "API: a key scoped to another subnet is refused (403)")
    result = p._api_next_free(77)
    check(
        isinstance(result, tuple) and result[1] == 403,
        "API: a scoped key gets the same 403 for a subnet that does not exist",
    )
    sys.modules["flask"].g = types.SimpleNamespace(api_key=unrestricted)
    result = p._api_next_free(77)
    check(
        isinstance(result, tuple) and result[1] == 404,
        "API: an unrestricted key gets 404 for a subnet that does not exist",
    )
    sys.modules["flask"].g = types.SimpleNamespace(api_key=None)
    result = p._api_next_free(5)
    check(isinstance(result, tuple) and result[1] == 403, "API: a missing key fails closed")
    sys.modules["flask"].g = types.SimpleNamespace(api_key=unrestricted)

    # ── 1.6.2: the API does not return a raw database error ──────────────────
    sys.modules["flask"].request = types.SimpleNamespace(
        get_json=lambda silent=True: {"subnet_id": 5, "ip": "10.5.0.7", "label": "x"}
    )
    p._jen_db = lambda: (_ for _ in ()).throw(RuntimeError("Access denied marker-xyz"))
    result = p._api_save_entry()
    check(
        isinstance(result, tuple) and result[1] == 500 and "marker-xyz" not in str(result[0]),
        f"_api_save_entry: a database failure returns a generic 500, not the exception text (got {result})",
    )
    p.current_user.role = "admin"

    # ── 1.6.3: global reservations, unexpired leases, conflicts as set arithmetic ─
    class KeaDB:
        def __init__(self, leases, hosts):
            self.leases, self.hosts, self.sql, self.last = leases, hosts, [], ""

        def cursor(self):
            return self

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def execute(self, sql, params=()):
            self.last = " ".join(sql.split())
            self.sql.append(self.last)

        def fetchall(self):
            return self.leases if "FROM lease4" in self.last else self.hosts

        def close(self):
            pass

    kdb = KeaDB(
        [{"ip": "10.5.0.30", "hostname": "lap", "mac_hex": "AABBCCDDEE01"}],
        [
            {
                "ip": "10.5.0.9",
                "hostname": "own",
                "ident_hex": "AABBCCDDEE02",
                "ident_type": 0,
                "host_id": 1,
                "host_subnet_id": 5,
            },
            {
                "ip": "10.5.0.10",
                "hostname": "glob-in",
                "ident_hex": "AABBCCDDEE03",
                "ident_type": 0,
                "host_id": 2,
                "host_subnet_id": None,
            },
            {
                "ip": "10.5.0.11",
                "hostname": "glob-zero",
                "ident_hex": "AABBCCDDEE04",
                "ident_type": 0,
                "host_id": 3,
                "host_subnet_id": 0,
            },
            {
                "ip": "10.99.0.1",
                "hostname": "glob-out",
                "ident_hex": "AABBCCDDEE05",
                "ident_type": 0,
                "host_id": 4,
                "host_subnet_id": None,
            },
        ],
    )
    p._kea_db = lambda: kdb
    real_load = _real_load_kea_sets
    leases_out, res_out = real_load(5, "10.5.0.0/24")
    check(
        sorted(res_out) == ["10.5.0.10", "10.5.0.11", "10.5.0.9"],
        f"_load_kea_sets: global reservations inside the subnet count, one outside it does not (got {sorted(res_out)})",
    )
    check(
        any("state = 0 AND expire > NOW()" in s for s in kdb.sql)
        and any("dhcp4_subnet_id IS NULL" in s for s in kdb.sql),
        "_load_kea_sets: a lease must be unexpired, and the reservation query includes subnet-less hosts",
    )
    check(list(leases_out) == ["10.5.0.30"], "_load_kea_sets: the subnet's own lease is returned")
    check(
        sorted(real_load(5)[1]) == ["10.5.0.9"],
        "_load_kea_sets: with no CIDR a global reservation cannot be placed, so none is included",
    )
    check(
        real_load(5, "not-a-cidr")[1].keys() == {"10.5.0.9"},
        "_load_kea_sets: an unparseable CIDR is treated as none",
    )
    net5 = ipaddress.IPv4Network("10.5.0.0/24")
    counts = p._count_sets(254, lambda ip: p._host_in_network(net5, ip), {}, res_out | {"10.99.0.1": {}}, {}, {})
    check(
        counts["reserved"] == 3,
        f"_count_sets: a global reservation elsewhere is not this subnet's (got {counts['reserved']})",
    )

    lz = {
        "10.5.0.20": {"hostname": "", "mac": "aa:aa:aa:aa:aa:20"},
        "10.5.0.21": {"hostname": "res", "mac": "aa:aa:aa:aa:aa:21"},
        "10.5.0.22": {"hostname": "plain", "mac": "aa:aa:aa:aa:aa:22"},
        "10.6.0.5": {"hostname": "off", "mac": "aa:aa:aa:aa:aa:23"},
    }
    rz = {"10.5.0.21": {"hostname": "res", "mac": "", "host_id": 9}}
    ez = {
        "10.5.0.20": {"entry_status": "static", "is_static": 1, "hostname": "nas", "mac": ""},
        "10.5.0.21": {"entry_status": "static", "is_static": 1},
        "10.5.0.22": {"entry_status": "available", "is_static": 0},
        "10.6.0.5": {"entry_status": "planned", "is_static": 0},
    }
    found = p._conflicts_in(lz, rz, ez, lambda ip: p._host_in_network(net5, ip))
    check(
        [c["ip"] for c in found] == ["10.5.0.20"]
        and found[0]["designated"] == "static"
        and found[0]["hostname"] == "nas",
        f"_conflicts_in: (leases - reservations) & designated, in the subnet only (got {found})",
    )
    # the same answer the per-address composition gives
    space_z = p._compose_space([str(h) for h in net5.hosts()], lz, rz, ez, {"infrastructure": {}})
    check(
        [e["ip"] for e in space_z if e["status"] == "conflict"] == [c["ip"] for c in found],
        "_conflicts_in agrees with _compose_space's conflict status",
    )
    devices_asked = []
    p._devices_by_mac = lambda macs: devices_asked.append(macs) or {}
    p._load_kea_sets = lambda sid, cidr=None, strict=False: (lz, rz)
    p._load_entries = lambda kind, sid, strict=False: ez
    p._build_address_space = lambda *a, **k: (_ for _ in ()).throw(AssertionError("the whole space was built"))
    sys.modules["jen.plugin_api"].subnet_map = lambda: {5: {"name": "n", "cidr": "10.5.0.0/24"}}
    got, unread = p._kea_conflicts()
    check(
        [(sid, e["ip"]) for sid, _info, e in got] == [(5, "10.5.0.20")] and devices_asked == [] and unread == set(),
        "_kea_conflicts: no address space is built and no device is looked up (1.6.3)",
    )

    # ── 1.6.3: designating an address a lease or reservation holds ───────────
    blk = p._designation_blocker
    check(blk("10.5.0.21", "static", lz, rz, None) != "", "designation: a Kea reservation blocks a new static entry")
    check(blk("10.5.0.22", "planned", lz, rz, None) != "", "designation: a live lease blocks a new planned entry")
    check(blk("10.5.0.22", "available", lz, rz, None) == "", "designation: a plain annotation is never blocked")
    check(blk("10.5.0.99", "static", lz, rz, None) == "", "designation: a free address is fine")
    check(
        blk("10.5.0.20", "static", lz, rz, ez["10.5.0.20"]) == "",
        "designation: an address ALREADY designated stays editable (a conflict can be worked on)",
    )

    # ── 1.6.3: JSON routes do not flash; the search takes % and _ literally ──
    flashed.clear()
    p.current_user.all_subnets = False
    check(
        p._check_access("u", 4, notify=False) is None and flashed == [],
        "_check_access(notify=False): denied without a flash",
    )
    check(p._check_access("u", 4) is None and len(flashed) == 1, "_check_access: a page route still flashes")
    p.current_user.all_subnets = True
    from jen.plugin_api import like_pattern as _like_pattern

    check(_like_pattern("10.0_1") == "%10.0\\_1%", "search: an underscore is literal")
    check(_like_pattern("50%") == "%50\\%%", "search: a percent sign is literal")
    check(_like_pattern("a\\b") == "%a\\\\b%", "search: a backslash is literal")

    # ── 1.6.4: the search provider scopes in SQL, before its own LIMIT ────────
    class _QueryDB:
        def __init__(self):
            self.log = []

        def cursor(self):
            return self

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def execute(self, sql, params=()):
            self.log.append((" ".join(sql.split()), params))

        def fetchall(self):
            return []

        def close(self):
            pass

    _stub_jen_plugin_api()
    fdb = _QueryDB()
    p._jen_db = lambda: fdb
    p._ipam_search("printer", {1}, False)
    sql, params = fdb.log[0]
    check(
        "IN (%s)" in sql and params[0] == 1,
        f"search: the caller's own subnet scope is in the SQL, not applied afterward (got {sql!r}, {params})",
    )
    fdb = _QueryDB()
    p._jen_db = lambda: fdb
    p._ipam_search("printer", set(), False)
    check(fdb.log == [], "search: a caller who may see nothing runs no query at all")

    # ── 1.6.4: the collapsed detail view, built without materialising the subnet ──
    net_big = ipaddress.IPv4Network("10.9.0.0/24")
    ctx_big = {
        "gateways": ["10.9.0.1"],
        "dns": [],
        "pools": [(int(ipaddress.IPv4Address("10.9.0.100")), int(ipaddress.IPv4Address("10.9.0.150")), "x")],
        "infrastructure": {"10.9.0.0": "network", "10.9.0.1": "gateway", "10.9.0.255": "broadcast"},
        "notes": "",
    }
    leases_big = {"10.9.0.50": {"hostname": "a", "mac": "aa:aa:aa:aa:aa:50"}}
    res_big = {"10.9.0.60": {"hostname": "b", "mac": "aa:aa:aa:aa:aa:60", "host_id": 1}}
    entries_big = {"10.9.0.70": {"label": "x", "entry_status": "static", "is_static": 1}}
    old_ips = [str(h) for h in net_big.hosts()]
    old_space = p._compose_space(old_ips, leases_big, res_big, entries_big, ctx_big)
    old_rows = p._collapse_runs(old_space, True)
    lazy_rows = p._build_rows_lazy(net_big, leases_big, res_big, entries_big, ctx_big, {})
    check(lazy_rows == old_rows, "_build_rows_lazy: identical output to the old full-materialisation path")
    old_expanded = p._collapse_runs(old_space, True, expand=old_rows[0]["key"]) if old_rows[0].get("run") else None
    if old_expanded is not None:
        lazy_expanded = p._build_rows_lazy(
            net_big, leases_big, res_big, entries_big, ctx_big, {}, expand=old_rows[0]["key"]
        )
        check(lazy_expanded == old_expanded, "_build_rows_lazy: expand gives the same rows as the old path")
    check(
        p._next_free_lazy(net_big, leases_big, res_big, entries_big, ctx_big) == p._next_free(old_space),
        "_next_free_lazy: the same answer as the old full-materialisation next_free",
    )

    # ── 1.6.4: the collapsed /16 detail page — the actual scale finding — never materialises the
    # 65,536-address space (the old `_build_address_space` cost ~60 MB and ~1 s of that alone) ──
    import time

    net_16 = ipaddress.IPv4Network("10.200.0.0/16")
    ctx_16 = {
        "gateways": ["10.200.0.1"],
        "dns": [],
        "pools": [(int(ipaddress.IPv4Address("10.200.10.0")), int(ipaddress.IPv4Address("10.200.10.255")), "x")],
        "infrastructure": {"10.200.0.0": "network", "10.200.0.1": "gateway", "10.200.255.255": "broadcast"},
        "notes": "",
    }
    # 500 addresses spread across the /16 — a realistic populated subnet, nowhere near "everything".
    leases_16 = {
        str(ipaddress.IPv4Address(int(net_16.network_address) + i * 100 + 1)): {
            "hostname": f"host-{i}",
            "mac": f"aa:aa:aa:aa:{i // 256:02x}:{i % 256:02x}",
        }
        for i in range(500)
    }
    start = time.perf_counter()
    rows_16 = p._build_rows_lazy(net_16, leases_16, {}, {}, ctx_16, {})
    elapsed_ms = (time.perf_counter() - start) * 1000
    check(
        elapsed_ms < 200,
        f"_build_rows_lazy: a /16 (65,536 addresses, 500 occupied) collapses in under 200ms (got {elapsed_ms:.1f}ms)",
    )
    check(
        len(rows_16) < 2000,
        f"_build_rows_lazy: a /16's collapsed rows are proportional to what's occupied, not to 65,536 (got {len(rows_16)} rows)",
    )
    start = time.perf_counter()
    free_16 = p._next_free_lazy(net_16, leases_16, {}, {}, ctx_16)
    elapsed_ms = (time.perf_counter() - start) * 1000
    check(
        free_16 is not None and elapsed_ms < 200,
        f"_next_free_lazy: a /16 with sparse occupancy answers in under 200ms (got {elapsed_ms:.1f}ms, free={free_16})",
    )

    # ── 1.6.4: ?all=1 refused above a /22; a Kea subnet larger than /16 refused on detail/export ──
    check(p._MAX_ALL_PREFIX == 22, "the ?all=1 cap is a /22")
    flashed.clear()
    p.request = types.SimpleNamespace(args={"all": "1"}, form={})
    p._check_access = lambda kind, sid, notify=True: {"name": "n", "cidr": "10.9.0.0/16"}
    p._subnet_ctx = lambda kind, sid, subnet: ctx_big
    p._load_kea_sets = lambda sid, cidr=None, strict=False: ({}, {})
    p._load_entries = lambda kind, sid, strict=False: {}
    p._history_rows = lambda *a, **k: []
    p.render_template = lambda name, **kw: kw
    page = p.subnet_detail("kea", 9)
    check(
        page["collapsed"] is True and any("22" in m for m in flashed),
        f"subnet_detail: ?all=1 on a /16 is refused and falls back to collapsed (got {page.get('collapsed')}, {flashed})",
    )
    oversized_net = ipaddress.IPv4Network("10.0.0.0/12")
    check(p._oversized_kea_subnet("kea", oversized_net) is True, "_oversized_kea_subnet: a Kea /12 is oversized")
    check(p._oversized_kea_subnet("kea", net_big) is False, "_oversized_kea_subnet: a Kea /24 is fine")
    check(
        p._oversized_kea_subnet("u", oversized_net) is False,
        "_oversized_kea_subnet: only the kea kind is checked here (unmanaged already capped at add_subnet)",
    )
    flashed.clear()
    p._check_access = lambda kind, sid, notify=True: {"name": "n", "cidr": "10.0.0.0/12"}
    page = p.subnet_detail("kea", 9)
    check(
        page == "redirect" and any("larger than" in m and "/16" in m for m in flashed),
        f"subnet_detail: an oversized Kea subnet is refused before anything is built (got {page}, {flashed})",
    )
    flashed.clear()
    r = p.export_csv("kea", 9)
    check(
        r == "redirect" and any("does not export" in m for m in flashed),
        f"export_csv: an oversized Kea subnet is refused before anything is streamed (got {r}, {flashed})",
    )

    # ── 1.6.4: the CSV export streams instead of building the whole subnet in memory ──
    p._check_access = lambda kind, sid, notify=True: {"name": "sub", "cidr": "10.9.0.0/24"}
    p._subnet_ctx = lambda kind, sid, subnet: ctx_big
    p._load_kea_sets = lambda sid, cidr=None, strict=False: (leases_big, res_big)
    p._load_entries = lambda kind, sid, strict=False: entries_big
    p._devices_by_mac = lambda macs: {}
    resp = p.export_csv("kea", 9)
    body = resp.get_data()
    check(
        "10.9.0.50" in body and "10.9.0.60" in body and "10.9.0.70" in body,
        "export_csv: the streamed rows include the occupied addresses",
    )
    check("ip,status,hostname" in body, "export_csv: the header is the first streamed chunk")
    p._load_kea_sets = lambda sid, cidr=None, strict=False: (
        {"10.9.0.50": {"hostname": "=1+1", "mac": "aa:aa:aa:aa:aa:50"}},
        {},
    )
    body = p.export_csv("kea", 9).get_data()
    check(
        "'=1+1" in body and ",=1+1" not in body,
        "export_csv: a hostname that starts with = leaves the file as text, not a formula",
    )

    # ── 1.6.6: the Create Reservation link carries subnet_id=, not subnet= ──
    # Jen's own add_reservation() route only ever reads subnet_id (subnet= is
    # accepted as an alias, but the canonical name is what every link should
    # send). render_template is stubbed above to return its own kwargs rather
    # than real HTML, so this reads the template SOURCE directly instead.
    with open(os.path.join(ROOT, "templates", "ipam", "subnet.html"), encoding="utf-8") as f:
        subnet_html = f.read()
    reservation_line = next(
        (line for line in subnet_html.splitlines() if "/reservations/add?" in line),
        "",
    )
    check(
        "subnet_id={{ subnet_id" in reservation_line,
        f"subnet.html: the Create Reservation link must carry subnet_id= (got: {reservation_line!r})",
    )
    check(
        "&subnet={{" not in reservation_line,
        f"subnet.html: the Create Reservation link must not still carry the wrong subnet= alias (got: {reservation_line!r})",
    )
    check(
        "entry.ip|urlencode" in reservation_line and "subnet_id|urlencode" in reservation_line,
        f"subnet.html: the Create Reservation link's values must be urlencoded (got: {reservation_line!r})",
    )

    # ── register(): runs end to end against a stub that enforces Jen's rules ──
    calls = _stub_jen_plugin_api()
    try:
        p.register(_FakeApp())
        registered = True
    except Exception as e:
        registered = False
        print(f"      register() raised: {e}")
    check(registered, "register(): runs end to end without raising against a real-rule stub")
    check(
        calls["alert_types"] == [p._CONFLICT_ALERT_TYPE],
        "register(): the conflict alert type is registered under the plugin's own prefix",
    )
    check(
        calls["periodic"] == [("ipam", "conflict_check", 15)],
        f"register(): the conflict check runs every 15 minutes (got {calls['periodic']})",
    )
    check(
        len(calls["row_actions"]) == 1 and len(calls["search"]) == 1,
        "register(): one row action and one search provider",
    )
    check(
        len(calls["investigation"]) == 1
        and calls["investigation"][0][0] == ("ipam",)
        and calls["investigation"][0][1]["fn"] is p._investigate,
        "register(): exactly one investigation provider, the plugin's own",
    )

    # ── 1.7.0: the investigation provider ────────────────────────────────────
    ns = types.SimpleNamespace
    subject = ns(
        mac="AA:BB:CC:DD:EE:01", ip="10.5.0.9", hostname="Desk.lan",
        leases4=[{"ip": "10.5.0.5", "hostname": "desk"}], reservations=[{"ip": "10.5.0.6"}, {"ip": "10.5.0.5"}],
    )  # fmt: skip
    check(
        p._held_addresses(subject) == {"10.5.0.5": "reservation", "10.5.0.6": "reservation", "10.5.0.9": "address"},
        f"_held_addresses: a reservation wins over a lease, a typed-only address is 'address' (got {p._held_addresses(subject)})",
    )
    check(
        p._held_addresses(ns(ip="", leases4=None, reservations=None)) == {}, "_held_addresses: nothing known is empty"
    )
    mine = {"ip": "10.5.0.5", "subnet_id": 5, "label": "printer", "owner": "ops", "hostname": None, "mac": None,
            "is_static": 1, "entry_status": "static"}  # fmt: skip
    check(
        p._who_for(dict(mine, mac="AA:BB:CC:DD:EE:01"), "aa:bb:cc:dd:ee:01", set()) == "yes",
        "_who_for: a matching MAC is this client",
    )
    check(
        p._who_for(dict(mine, mac="aa:bb:cc:dd:ee:99"), "aa:bb:cc:dd:ee:01", {"desk"}) == "no",
        "_who_for: a different MAC is not, whatever the hostname",
    )
    check(
        p._who_for(dict(mine, hostname="Desk.example.com"), "aa:bb:cc:dd:ee:01", {"desk"}) == "yes",
        "_who_for: a matching hostname label is this client",
    )
    check(
        p._who_for(dict(mine, hostname="other"), "aa:bb:cc:dd:ee:01", {"desk"}) == "no",
        "_who_for: a different hostname is not",
    )
    check(
        p._who_for(mine, "aa:bb:cc:dd:ee:01", {"desk"}) == "",
        "_who_for: an entry naming neither says nothing about who",
    )
    check(p.investigation_card([], {}) is None, "investigation_card: no entry adds no card")
    check(
        p.investigation_card([dict(mine, label="", owner="", entry_status="available", is_static=0)], {}) is None,
        "investigation_card: an available address with no annotation says nothing",
    )
    conflict = p.investigation_card([mine], {"10.5.0.5": "lease"})
    check(
        conflict["status"] == "warn"
        and "10.5.0.5 is static (printer)" in conflict["summary"]
        and "conflict" in conflict["summary"],
        f"investigation_card: a designated address held by a lease is the conflict IPAM flags (got {conflict['summary']!r})",
    )
    check(
        {
            "label": "10.5.0.5",
            "value": "static - printer - owner ops (held by a DHCP lease - IPAM flags that as a conflict)",
        }
        in conflict["rows"],
        f"investigation_card: the row names the entry and why (got {conflict['rows']})",
    )
    calm = p.investigation_card([dict(mine, entry_status="planned", is_static=0)], {"10.5.0.5": "address"})
    check(
        calm["status"] == "ok" and calm["summary"] == "10.5.0.5 is planned (printer)",
        f"investigation_card: a planned address nobody holds is an ok card (got {calm['summary']!r})",
    )
    other = p.investigation_card(
        [dict(mine, mac="aa:bb:cc:dd:ee:99")], {"10.5.0.5": "address"}, "aa:bb:cc:dd:ee:01", set()
    )
    check(
        other["status"] == "warn" and "designated for a different client" in other["summary"],
        "investigation_card: an address designated for a different MAC is a warn card",
    )
    own = p.investigation_card(
        [dict(mine, mac="aa:bb:cc:dd:ee:01")], {"10.5.0.5": "address"}, "aa:bb:cc:dd:ee:01", set()
    )
    check(
        own["status"] == "ok" and "designated for this client" in own["summary"],
        "investigation_card: an address designated for this client is an ok card",
    )
    note_only = p.investigation_card([dict(mine, entry_status="available", is_static=0)], {"10.5.0.5": "lease"})
    check(
        note_only["status"] == "ok" and "annotated" in note_only["summary"],
        "investigation_card: an annotated available address held by a lease is no conflict",
    )

    # the impure provider, end to end through the plugin's own query
    class RowsDB:
        def __init__(self, rows):
            self.rows, self.sql, self.params = rows, "", ()

        def cursor(self):
            return self

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def execute(self, sql, params=()):
            self.sql, self.params = " ".join(sql.split()), params

        def fetchall(self):
            return list(self.rows)

        def close(self):
            pass

    db = RowsDB([dict(mine)])
    p._jen_db = lambda: db
    got = p._investigate(subject, {5}, False)
    check(
        got is not None and got["href"] == "/network/ipam/subnet/kea/5?ip=10.5.0.5" and got["status"] == "ok",
        f"_investigate: the card for a seeded client, linking to its entry (got {got})",
    )
    check(
        "subnet_kind='kea'" in db.sql
        and "subnet_id IN (%s)" in db.sql
        and "ip IN (%s,%s,%s)" in db.sql
        and db.params == (5, "10.5.0.5", "10.5.0.6", "10.5.0.9"),
        f"_investigate: the caller's scope and every address are bound parameters of the one query (got {db.sql!r}, {db.params})",
    )
    db = RowsDB([])
    p._jen_db = lambda: db
    check(
        p._investigate(subject, None, True) is None and "1=1" in db.sql,
        "_investigate: an unknown client gets None; unrestricted scope is 1=1",
    )
    db = RowsDB([dict(mine)])
    p._jen_db = lambda: db
    check(
        p._investigate(subject, set(), False) is None and db.sql == "",
        "_investigate: a caller who may see no subnet runs no query at all",
    )
    check(
        p._investigate(ns(mac="", ip="", hostname="", leases4=[], reservations=[]), None, True) is None
        and db.sql == "",
        "_investigate: a subject with no address runs no query",
    )

    # ── 1.7.1: the address space treats only a CURRENT lease as in use (Jen's ACTIVE_LEASE4, never a bare state = 0) ──
    q = load_plugin()
    _stub_jen_plugin_api()
    src = pathlib.Path(ROOT, "plugin.py").read_text(encoding="utf-8")
    check("state=0" not in src and "state = 0" not in src, "the plugin never spells the current-lease predicate itself")

    class _KeaDB:
        def __init__(self):
            self.sql = []

        def cursor(self):
            return self

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def execute(self, sql, params=()):
            self.sql.append(" ".join(sql.split()))

        def fetchall(self):
            return []

        def close(self):
            pass

    kea_db = _KeaDB()
    q._kea_db = lambda: kea_db
    q._load_kea_sets(1, "10.0.0.0/24")
    check(
        any("FROM lease4" in s and "state = 0 AND expire > NOW()" in s for s in kea_db.sql),
        f"_load_kea_sets: the lease query asks for a current lease (got {kea_db.sql[:1]})",
    )

    # ── 1.7.2: every row that names a client carries Jen's Investigate macro; the bar widths are defined once ──
    tdir = pathlib.Path(ROOT, "templates", "ipam")
    sub_html = (tdir / "subnet.html").read_text(encoding="utf-8")
    prev_html = (tdir / "import_preview.html").read_text(encoding="utf-8")
    index_html = (tdir / "index.html").read_text(encoding="utf-8")
    shared_css = (tdir / "_bar_widths.html").read_text(encoding="utf-8")
    macro_import = "{% from '_investigate.html' import investigate_link %}"
    check(
        macro_import in sub_html and 'investigate_link(who, "icon")' in sub_html,
        "subnet.html: each address row that names a client carries Jen's Investigate macro (its MAC, else its address)",
    )
    check(
        macro_import in prev_html and 'investigate_link(entry.mac, "icon")' in prev_html,
        "import_preview.html: the MAC column carries Jen's Investigate macro",
    )
    check(
        "{% for i in range(101) %}.ip-w{{ i }}" in shared_css
        and shared_css.count(".ip-seg-") == 6
        and "ip-w{{ i }}" not in sub_html
        and "ip-w{{ i }}" not in index_html
        and "{% include 'ipam/_bar_widths.html' %}" in sub_html
        and "{% include 'ipam/_bar_widths.html' %}" in index_html,
        "the .ip-w0 .. .ip-w100 and .ip-seg-* rules are defined once, in _bar_widths.html, and included by both pages",
    )

    # ── 1.7.3: a viewer is not shown a write control; the page is handed the truth the routes use ──
    # The routes refuse a viewer (_require_write / _can_manage_unmanaged); the template used to print Range, Import,
    # the per-row edit pencil and Create Reservation anyway, each leading only to "you cannot do that".
    p._check_access = lambda kind, sid, notify=True: {"name": "n", "cidr": "10.9.0.0/24"}
    p._subnet_ctx = lambda kind, sid, subnet: ctx_big
    p._load_kea_sets = lambda sid, cidr=None, strict=False: ({}, {})
    p._load_entries = lambda kind, sid, strict=False: {}
    p._history_rows = lambda *a, **k: []
    p.render_template = lambda name, **kw: kw
    p.request = types.SimpleNamespace(args={}, form={})
    p._accessible_subnets = dict
    p._get_ipam_subnets = dict
    # register(): above rebuilt the stub flask_login, so the role gate reads the NEWEST current_user while p keeps the
    # one it imported; a faithful session sets both.
    gate_user = sys.modules["flask_login"].current_user
    saved_role, saved_all = gate_user.role, p.current_user.all_subnets
    seen = {}
    for who, role, all_subnets in (
        ("viewer", "viewer", True),
        ("scoped admin", "admin", False),
        ("admin", "admin", True),
        ("superadmin", "superadmin", True),
    ):
        gate_user.role, p.current_user.all_subnets = role, all_subnets
        seen[who] = (p.subnet_detail("kea", 9), p.index())
    gate_user.role, p.current_user.all_subnets = saved_role, saved_all
    check(
        seen["viewer"][0]["can_write"] is False and seen["viewer"][0]["can_manage_unmanaged"] is False,
        "subnet_detail: a viewer is handed can_write=False and can_manage_unmanaged=False",
    )
    check(
        seen["admin"][0]["can_write"] is True and seen["superadmin"][0]["can_write"] is True,
        "subnet_detail: an admin and a superadmin are handed can_write=True",
    )
    check(
        seen["admin"][0]["can_manage_unmanaged"] is True and seen["scoped admin"][0]["can_manage_unmanaged"] is False,
        "subnet_detail: can_manage_unmanaged is the route's own rule (an admin who sees every subnet), not the role alone",
    )
    check(
        seen["scoped admin"][0]["can_write"] is True,
        "subnet_detail: a subnet-scoped admin still writes Kea-subnet entries (_require_write is role-only)",
    )
    check(
        seen["viewer"][1]["can_manage_unmanaged"] is False and seen["admin"][1]["can_manage_unmanaged"] is True,
        "index: Add Unmanaged Subnet is gated by the route's own rule",
    )

    try:
        import jinja2
    except ImportError:  # the harness is stdlib-only; verify.py (which needs jinja2) parses the templates anyway
        jinja2 = None
    if jinja2 is not None:
        macro = (
            '{% macro investigate_link(who, kind="menu") -%}{%- if who -%}'
            '<a href="/client?q={{ who|urlencode }}" class="btn btn-sm btn-secondary">{{ icon("search") }}</a>'
            "{%- endif -%}{%- endmacro %}"
        )
        tpl_dir = pathlib.Path(ROOT, "templates", "ipam")
        env = jinja2.Environment(
            loader=jinja2.DictLoader(
                {
                    "base.html": "{% block title %}{% endblock %}{% block content %}{% endblock %}",
                    "_investigate.html": macro,
                    "ipam/_bar_widths.html": (tpl_dir / "_bar_widths.html").read_text(encoding="utf-8"),
                    "ipam/subnet.html": (tpl_dir / "subnet.html").read_text(encoding="utf-8"),
                    "ipam/index.html": (tpl_dir / "index.html").read_text(encoding="utf-8"),
                    "ipam/import_preview.html": (tpl_dir / "import_preview.html").read_text(encoding="utf-8"),
                }
            ),
            autoescape=True,
        )
        env.globals.update(
            icon=lambda *a, **k: "[icon]", csrf_token=lambda: "t", url_for=lambda *a, **k: "/x", csp_nonce="n"
        )
        counts = {
            "total": 2,
            "available": 1,
            "dynamic": 0,
            "reserved": 0,
            "static": 1,
            "planned": 0,
            "infrastructure": 0,
            "conflict": 0,
            "pct": 50,
        }
        entries = [
            {
                "ip": "10.9.0.5",
                "status": "static",
                "hostname": "",
                "label": "nas",
                "mac": "aa:bb:cc:dd:ee:05",
                "owner": "",
                "notes": "",
                "device": None,
                "in_pool": False,
                "designated": "static",
            },
            {
                "ip": "10.9.0.6",
                "status": "available",
                "hostname": "",
                "label": "",
                "mac": "",
                "owner": "",
                "notes": "",
                "device": None,
                "in_pool": False,
                "designated": "",
            },
        ]

        def render_subnet(kind, can_write, can_manage):
            return env.get_template("ipam/subnet.html").render(
                kind=kind,
                subnet_id=9,
                subnet={"name": "lan", "cidr": "10.9.0.0/24", "description": ""},
                rows=entries,
                collapsed=False,
                counts=counts,
                ctx={"gateways": [], "dns": [], "notes": ""},
                pool_texts=[],
                next_free="10.9.0.6",
                recent_history=[],
                status_filter="all",
                open_ip="",
                at_ip="",
                address_map=None,
                map_blocks=None,
                is_admin=can_write,
                can_write=can_write,
                can_manage_unmanaged=can_manage,
            )

        write_controls = (
            ('id="ipam-range-btn"', "the Range button"),
            ('id="ipam-import-btn"', "the Import button"),
            ("ipam-edit-btn", "the per-row edit pencil"),
            ("/reservations/add?", "the Create Reservation link"),
            ('id="edit-modal"', "the edit modal"),
            ('id="range-modal"', "the range modal"),
            ('id="import-modal"', "the import modal"),
            ('id="clear-form"', "the clear form"),
            ("openEditModal", "the edit script"),
        )
        viewer_page = render_subnet("kea", False, False)
        admin_page = render_subnet("kea", True, False)
        for marker, what in write_controls:
            check(marker not in viewer_page, f"subnet.html as a viewer: {what} is absent")
            check(marker in admin_page, f"subnet.html as an admin: {what} is present")
        check(
            "ipam-delete-subnet-btn" not in viewer_page and "ipam-delete-subnet-btn" not in admin_page,
            "subnet.html: a Kea subnet never shows Delete Subnet",
        )
        check(
            'id="ipam-search"' in viewer_page
            and 'data-filter="static"' in viewer_page
            and "/client?q=aa%3Abb%3Acc%3Add%3Aee%3A05" in viewer_page
            and "Next Free: 10.9.0.6" in viewer_page,
            "subnet.html as a viewer: the search, the filters, Investigate and Next free are all still there",
        )
        check(
            "getElementById('edit-" not in viewer_page
            and "getElementById('range-" not in viewer_page
            and "getElementById('import-" not in viewer_page
            and "getElementById('clear-" not in viewer_page,
            "subnet.html as a viewer: no script reaches for a control that is not on the page",
        )
        check(
            "[icon] Export CSV</a>" in viewer_page and "[icon] Export Netbox CSV</a>" in viewer_page,
            "subnet.html as a viewer: the CSV export links are reads and stay",
        )
        # unmanaged: Delete Subnet follows _can_manage_unmanaged, not the role alone
        check(
            "ipam-delete-subnet-btn" in render_subnet("u", True, True)
            and "subnet-delete-form" in render_subnet("u", True, True),
            "subnet.html as an unrestricted admin on an unmanaged subnet: Delete Subnet and its form are present",
        )
        check(
            "ipam-delete-subnet-btn" not in render_subnet("u", False, False)
            and "subnet-delete-form" not in render_subnet("u", False, False),
            "subnet.html as a viewer on an unmanaged subnet: Delete Subnet and its form are absent",
        )
        check(
            "ipam-delete-subnet-btn" not in render_subnet("u", True, False),
            "subnet.html as a scoped admin on an unmanaged subnet: Delete Subnet is absent (the route would refuse it)",
        )

        def render_index(can_manage):
            return env.get_template("ipam/index.html").render(
                subnet_map={},
                ipam_subnets={},
                summaries={},
                is_admin=can_manage,
                can_manage_unmanaged=can_manage,
                ipv6_enabled=False,
            )

        check(
            "ipam-add-subnet-btn" not in render_index(False) and "add-subnet-modal" not in render_index(False),
            "index.html as a viewer: Add Unmanaged Subnet and its modal are absent",
        )
        check(
            "ipam-add-subnet-btn" in render_index(True) and "add-subnet-modal" in render_index(True),
            "index.html as an unrestricted admin: Add Unmanaged Subnet and its modal are present",
        )

        # 1.8.5: the Getting started card of the overview
        def render_overview(first_run, subnets, can_manage, is_admin=True):
            return env.get_template("ipam/index.html").render(
                subnet_map=subnets,
                ipam_subnets={},
                summaries={("kea", sid): {"total": 254, "pct": 0, "available": 254} for sid in subnets},
                first_run=first_run,
                is_admin=is_admin,
                can_manage_unmanaged=can_manage,
                ipv6_enabled=False,
            )

        one_subnet = {5: {"name": "lan", "cidr": "10.5.0.0/24"}}
        fresh = render_overview(True, one_subnet, True)
        check(
            '<div class="card first-run">' in fresh
            and "<h3>Getting started</h3>" in fresh
            and fresh.count("<li>") == 3
            and fresh.index('<div class="card first-run">') < fresh.index('class="ip-cd5a1e"'),
            "index.html on a fresh install: the Getting started card, three steps, above the subnet cards",
        )
        check(
            fresh.count("ipam-add-subnet-open") == 3 and '<a href="/settings/alerts">Settings - Alerts</a>' in fresh,
            "index.html: step 1 carries the page's own Add Unmanaged Subnet button and step 3 links Settings - Alerts",
        )
        used = render_overview(False, one_subnet, True)
        check(
            "first-run" not in used and "Getting started" not in used and "lan" in used,
            "index.html once IPAM holds something: no Getting started card and no rule for one, the subnet cards as before",
        )
        viewer_fresh = render_overview(True, one_subnet, False, is_admin=False)
        check(
            "ipam-add-subnet-open" not in viewer_fresh
            and 'href="/settings/alerts"' not in viewer_fresh
            and "Settings - Alerts" in viewer_fresh
            and "Open a subnet below." in viewer_fresh,
            "index.html as a viewer on a fresh install: the steps without the button and without a link a viewer is refused",
        )
        nothing = render_overview(True, {}, True)
        check(
            '<div class="card first-run">' in nothing
            and "No subnets available." not in nothing
            and 'class="ip-cd5a1e"' not in nothing
            and "Add an unmanaged subnet: a network Kea does not serve, tracked in IPAM only." in nothing,
            "index.html with no subnet at all: the card stands in place of the empty grid, and step 1 is the unmanaged subnet",
        )
        check(
            "No subnets available." in render_overview(False, {}, False, is_admin=False),
            "index.html with no subnet and no first step to offer: the plain sentence, as before",
        )

        check(
            "import_commit" in (tpl_dir / "import_preview.html").read_text(encoding="utf-8"),
            "import_preview.html: only ever rendered by import_preview, a route that refuses a viewer first (no gate needed)",
        )

    # ── 1.8.0: the address map ───────────────────────────────────────────────
    m = load_plugin()  # a fresh copy: the checks above replaced functions on `p`
    map_net = ipaddress.IPv4Network("10.7.0.0/24")
    map_ctx = {
        "gateways": ["10.7.0.1"],
        "dns": [],
        "pools": [(int(ipaddress.IPv4Address("10.7.0.100")), int(ipaddress.IPv4Address("10.7.0.199")), "p")],
        "infrastructure": {"10.7.0.1": "gateway"},
        "notes": "",
    }
    map_leases = {"10.7.0.100": {"hostname": "a", "mac": ""}, "10.7.0.20": {"hostname": "b", "mac": ""}}
    map_res = {"10.7.0.10": {"hostname": "r", "mac": "", "host_id": 3}}
    map_entries = {
        "10.7.0.20": {"entry_status": "static", "is_static": 1, "label": "nas"},
        "10.7.0.30": {"entry_status": "static", "is_static": 1, "label": "printer"},
        "10.7.0.31": {"entry_status": "planned", "is_static": 0, "label": "later"},
    }
    cells = m._address_map(map_net, map_leases, map_res, map_entries, map_ctx)
    by_ip = {c["ip"]: c for c in cells}
    check(
        len(cells) == 254 and cells[0]["ip"] == "10.7.0.1" and cells[-1]["ip"] == "10.7.0.254",
        "map: a /24 is 254 cells, in address order",
    )
    want = {
        "10.7.0.1": ("infrastructure", "ip-cell ip-seg-inf"),
        "10.7.0.10": ("reserved", "ip-cell ip-seg-res"),
        "10.7.0.20": ("conflict", "ip-cell ip-seg-con"),
        "10.7.0.30": ("static", "ip-cell ip-seg-sta"),
        "10.7.0.31": ("planned", "ip-cell ip-seg-pla"),
        "10.7.0.100": ("dynamic", "ip-cell ip-seg-dyn ip-cell-pool"),
        "10.7.0.150": ("available", "ip-cell ip-cell-pool"),
        "10.7.0.200": ("available", "ip-cell"),
    }
    for ip, (status, cls) in want.items():
        check(
            (by_ip[ip]["status"], by_ip[ip]["cls"]) == (status, cls),
            f"map: {ip} is {status} with class {cls!r} (got {by_ip[ip]['status']}, {by_ip[ip]['cls']!r})",
        )
    map_space = m._compose_space([str(h) for h in map_net.hosts()], map_leases, map_res, map_entries, map_ctx)
    check(
        [c["status"] for c in cells] == [e["status"] for e in map_space],
        "map: every cell's status is the status the table gives that address",
    )
    check(m._map_cells(map_space) == cells, "map: ?all=1's already-built space gives the same cells")
    check(
        set(m._MAP_CLASS) == set(m._ALL_STATUSES) - {"available"}, "map: every status but available has a color class"
    )
    check(
        len(m._address_map(ipaddress.IPv4Network("10.8.0.0/22"), {}, {}, {}, map_ctx)) == 1022,
        "map: a /22 is drawn (1,022 cells)",
    )
    check(
        m._address_map(ipaddress.IPv4Network("10.8.0.0/21"), {}, {}, {}, map_ctx) is None,
        "map: a /21 is not drawn - the same ceiling as ?all=1",
    )
    check(
        len(m._address_map(ipaddress.IPv4Network("10.8.0.4/30"), {}, {}, {}, map_ctx)) == 2, "map: a /30 is two cells"
    )

    # the route: ?at= expands the run that holds the address and opens no modal; a foreign address is dropped
    m._check_access = lambda kind, sid, notify=True: {"name": "n", "cidr": "10.7.0.0/24"}
    m._subnet_ctx = lambda kind, sid, subnet: map_ctx
    m._load_kea_sets = lambda sid, cidr=None, strict=False: (map_leases, map_res)
    m._load_entries = lambda kind, sid, strict=False: map_entries
    m._devices_by_mac = lambda macs: {}
    m._history_rows = lambda *a, **k: []
    m.render_template = lambda name, **kw: kw
    m.request = types.SimpleNamespace(args={}, form={})
    page = m.subnet_detail("kea", 9)
    check(
        page["address_map"] == cells and page["map_blocks"] == m._map_blocks(map_net, cells) and page["at_ip"] is None,
        "subnet_detail: the collapsed page is handed the map and its blocks, and no address to find",
    )
    check(
        not any(not r.get("run") and r["ip"] == "10.7.0.150" for r in page["rows"]),
        "subnet_detail: 10.7.0.150 sits inside a collapsed run by default",
    )
    m.request = types.SimpleNamespace(args={"at": "10.7.0.150"}, form={})
    page = m.subnet_detail("kea", 9)
    check(
        page["at_ip"] == "10.7.0.150"
        and page["open_ip"] is None
        and any(not r.get("run") and r["ip"] == "10.7.0.150" for r in page["rows"]),
        "subnet_detail: ?at= expands the run that holds the address, and it is not the edit modal's ?ip=",
    )
    for foreign in ("10.99.0.5", "10.7.0.0", "10.7.0.255", "x", ""):
        m.request = types.SimpleNamespace(args={"at": foreign}, form={})
        check(
            m.subnet_detail("kea", 9)["at_ip"] is None,
            f"subnet_detail: ?at={foreign!r} is not a host of this subnet and is dropped",
        )
    m.request = types.SimpleNamespace(args={"all": "1"}, form={})
    check(m.subnet_detail("kea", 9)["address_map"] == cells, "subnet_detail: ?all=1 is handed the same map")
    m._check_access = lambda kind, sid, notify=True: {"name": "n", "cidr": "10.7.0.0/21"}
    m.request = types.SimpleNamespace(args={}, form={})
    check(m.subnet_detail("kea", 9)["address_map"] is None, "subnet_detail: a /21 is handed no map")

    # 1.8.2: the cells grouped for drawing - a block per /24, a gap where an address is not a host
    blocks = m._map_blocks(map_net, cells)
    check(
        len(blocks) == 1
        and blocks[0]["label"] == "10.7.0.0"
        and len(blocks[0]["cells"]) == 256
        and blocks[0]["cells"][0] is None
        and blocks[0]["cells"][255] is None
        and [c for c in blocks[0]["cells"] if c] == cells,
        "blocks: a /24 is one block of 256 places, the network and the broadcast address empty, every cell in order",
    )
    check(
        all(c["octet"] == c["ip"].rsplit(".", 1)[1] for c in cells) and cells[99]["octet"] == "100",
        "cells: each carries its last octet",
    )
    wide_net = ipaddress.IPv4Network("10.10.10.0/23")
    wide_cells = m._address_map(wide_net, {}, {}, {}, map_ctx)
    wide = m._map_blocks(wide_net, wide_cells)
    check(
        [b["label"] for b in wide] == ["10.10.10.0", "10.10.11.0"]
        and [len(b["cells"]) for b in wide] == [256, 256]
        and wide[0]["cells"][0] is None
        and wide[0]["cells"][255]["ip"] == "10.10.10.255"
        and wide[1]["cells"][0]["ip"] == "10.10.11.0"
        and wide[1]["cells"][255] is None,
        "blocks: a /23 is two blocks; .255 of the first and .0 of the second are hosts and are drawn",
    )
    small_net = ipaddress.IPv4Network("10.8.0.64/26")
    small = m._map_blocks(small_net, m._address_map(small_net, {}, {}, {}, map_ctx))
    check(
        len(small) == 1
        and small[0]["label"] == "10.8.0.64"
        and len(small[0]["cells"]) == 64
        and small[0]["cells"][1]["octet"] == "65",
        "blocks: a /26 is one block that starts at its own first address",
    )
    big_net = ipaddress.IPv4Network("10.8.0.0/22")
    check(
        [b["label"] for b in m._map_blocks(big_net, m._address_map(big_net, {}, {}, {}, map_ctx))]
        == ["10.8.0.0", "10.8.1.0", "10.8.2.0", "10.8.3.0"],
        "blocks: a /22 is four blocks",
    )
    check(m._map_blocks(map_net, None) is None, "blocks: no cells (above a /22), no blocks")

    map_html = pathlib.Path(ROOT, "templates", "ipam", "subnet.html").read_text(encoding="utf-8")
    check(
        "aspect-ratio" not in map_html
        and ".ip-map{display:grid;grid-template-columns:repeat(32,minmax(0,1fr))" in map_html
        and "@container (max-width:859px){.ip-map{grid-template-columns:repeat(16,minmax(0,1fr))}}" in map_html
        and ".ip-map-block{margin-bottom:14px;container-type:inline-size}" in map_html
        and "height:20px" in map_html,
        "subnet.html (1.8.2): a cell is 20 px tall whatever the card's width, 32 to a row, 16 in a narrow card",
    )
    check(
        ".ip-cell-pool{border:2px" not in map_html
        and "color-mix(in srgb,var(--primary) 18%,var(--surface2))" in map_html,
        "subnet.html (1.8.2): a pool is a tint on its free cells, never an outline",
    )
    check(
        map_html.index(".ip-cell{") < map_html.index("{% include 'ipam/_bar_widths.html' %}"),
        "subnet.html: the map's rules come before the bar classes, so a status color beats the cell's own background",
    )
    check(
        "@media screen and (max-width:479px){.ip-map-block{display:none}}" in map_html,
        "subnet.html: the map is hidden below 480 px",
    )
    check(
        "jenFetch(HISTORY_URL" in map_html and re.search(r"(?<![A-Za-z.])fetch\(", map_html) is None,
        "subnet.html: the history request goes through Jen's jenFetch, never a bare fetch",
    )
    check("utilised" not in map_html and "% utilized" in map_html, "subnet.html: American spelling")
    if jinja2 is not None:

        def render_map(kind, address_map, at_ip="", pool_texts=("10.7.0.100 - 10.7.0.199",), conflict=1):
            return env.get_template("ipam/subnet.html").render(
                kind=kind,
                subnet_id=9,
                subnet={"name": "lan", "cidr": "10.7.0.0/24", "description": ""},
                rows=entries,
                collapsed=True,
                counts={**counts, "conflict": conflict},
                ctx={"gateways": [], "dns": [], "notes": ""},
                pool_texts=list(pool_texts),
                next_free="",
                recent_history=[],
                status_filter="all",
                open_ip="",
                at_ip=at_ip,
                address_map=address_map,
                map_blocks=m._map_blocks(map_net, address_map),
                is_admin=False,
                can_write=False,
                can_manage_unmanaged=False,
            )

        drawn = render_map("kea", cells, at_ip="10.7.0.150")
        check(drawn.count('<a class="ip-cell') == 254, "subnet.html: one cell per address")
        check(
            '<a class="ip-cell ip-seg-dyn ip-cell-pool" href="?at=10.7.0.100" data-ip="10.7.0.100" aria-label="10.7.0.100 dynamic">100</a>'
            in drawn,
            "subnet.html: a cell is a link to ?at=<its address>, named for a screen reader, colored by class, with its last octet in it",
        )
        map_part = drawn.split('id="ipam-map"')[1].split('class="ip-map-legend"')[0]
        check(
            map_part.count('<div class="ip-map-head">') == 1
            and '<div class="ip-map-head">10.7.0.0</div>' in map_part
            and map_part.count('<div class="ip-map">') == 1,
            "subnet.html (1.8.2): a /24 is one block under one heading, its first address",
        )
        check(
            map_part.count("<span></span>") == 2
            and '<div class="ip-map"><span></span><a class="ip-cell ip-seg-inf" href="?at=10.7.0.1"' in map_part
            and '">254</a><span></span></div>' in map_part,
            "subnet.html (1.8.2): the network and the broadcast address are gaps, so a row starts on a multiple of 32",
        )
        two = env.get_template("ipam/subnet.html").render(
            kind="kea",
            subnet_id=9,
            subnet={"name": "lan", "cidr": "10.10.10.0/23", "description": ""},
            rows=entries,
            collapsed=True,
            counts=counts,
            ctx={"gateways": [], "dns": [], "notes": ""},
            pool_texts=[],
            next_free="",
            recent_history=[],
            status_filter="all",
            open_ip="",
            at_ip="",
            address_map=wide_cells,
            map_blocks=m._map_blocks(wide_net, wide_cells),
            is_admin=False,
            can_write=False,
            can_manage_unmanaged=False,
        )
        check(
            two.count('<div class="ip-map-head">') == 2
            and two.index('<div class="ip-map-head">10.10.10.0</div>')
            < two.index('data-ip="10.10.10.255"')
            < two.index('<div class="ip-map-head">10.10.11.0</div>')
            < two.index('data-ip="10.10.11.0"')
            and two.count('<a class="ip-cell') == 510,
            "subnet.html (1.8.2): a /23 is two blocks, each under the heading of its /24",
        )
        check(
            re.search(r"<a class=\"ip-cell[^>]*\sstyle=", drawn) is None
            and " title=" not in drawn.split('id="ipam-map"')[1].split("</div>")[0],
            "subnet.html: a cell carries no inline style and no hover readout",
        )
        check(
            drawn.index('id="ipam-map"') < drawn.index('id="ipam-search"')
            and drawn.index("Available</div>") < drawn.index('id="ipam-map"'),
            "subnet.html: the map sits between the counts and the search box",
        )
        check(
            'var AT_IP = "10.7.0.150";' in drawn and "if (AT_IP) showAddress(AT_IP);" in drawn,
            "subnet.html: ?at= reaches the script",
        )
        check(
            "Dynamic</span>" in drawn and "Conflict</span>" in drawn and "Available, in a DHCP pool</span>" in drawn,
            "subnet.html: the legend names every color on a Kea subnet, the conflict color and the pool tint",
        )
        plain = render_map("u", cells, pool_texts=(), conflict=0)
        check(
            "Dynamic</span>" not in plain
            and "Reserved</span>" not in plain
            and "Conflict</span>" not in plain
            and "in a DHCP pool</span>" not in plain,
            "subnet.html: an unmanaged subnet's legend has no Dynamic, Reserved or pool key, and no Conflict key without a conflict",
        )
        none = render_map("kea", None)
        check(
            'id="ipam-map"' not in none
            and 'class="ip-map-legend"' not in none
            and "getElementById('ipam-map')" in none,
            "subnet.html: no map above a /22, and the script copes with its absence",
        )

    # ── 1.8.1: a width query names the screen (Jen's tests/test_print.py, held here too) ──
    width_offenders, width_scanned = [], 0
    for path in sorted(pathlib.Path(ROOT).rglob("*")):
        rel = path.relative_to(ROOT).as_posix()
        if (
            not path.is_file()
            or rel.startswith((".git/", "tools/"))
            or path.suffix not in (".html", ".css", ".js", ".py")
        ):
            continue
        width_scanned += 1
        for found in re.finditer(r"@media([^{]*)\{", path.read_text(encoding="utf-8")):
            if re.search(r"(?:max|min)-width", found.group(1)) and not re.search(r"\bscreen\b", found.group(1)):
                width_offenders.append(f"{rel}: {found.group(0).strip()}")
    check(
        width_scanned >= 5 and not width_offenders,
        f"every @media with a width names the screen, so print is not taken for a phone ({width_scanned} files; {width_offenders})",
    )

    # ── 1.8.3 (IPAM-1, IPAM-5): "the lookup failed" is not "nothing there" ────────────────────────────────────────────
    s = load_plugin()
    _stub_jen_plugin_api()

    def _kea_away():
        raise RuntimeError(2013, "Lost connection to MySQL server during query")

    s._kea_db = _kea_away
    check(
        s._load_kea_sets(5, "10.5.0.0/24") == ({}, {}),
        "_load_kea_sets: a page still gets two empty dicts from a read that failed",
    )
    try:
        s._load_kea_sets(5, "10.5.0.0/24", strict=True)
        raised = None
    except s._LookupFailed as e:
        raised = str(e)
    check(
        raised == "Kea's leases and reservations",
        f"_load_kea_sets: a caller that decides gets _LookupFailed (got {raised!r})",
    )
    s._jen_db = _kea_away
    check(s._load_entries("kea", 5) == {}, "_load_entries: a page still gets an empty dict from a read that failed")
    try:
        s._load_entries("kea", 5, strict=True)
        raised = None
    except s._LookupFailed as e:
        raised = str(e)
    check(raised == "IPAM's own entries", f"_load_entries: a caller that decides gets _LookupFailed (got {raised!r})")

    class _Store:
        """Jen's database for the conflict job: keeps ipam_conflict_state, logs every statement and what happened around it."""

        def __init__(self, fail_on=None, fail_commit=False):
            self.rows, self.next_id, self.log, self.events = {}, 1, [], []
            self.pending, self.fail_on, self.fail_commit, self._answer = None, fail_on, fail_commit, None

        def cursor(self):
            if self.pending is None:
                self.pending = dict(self.rows)
            return self

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def execute(self, sql, params=()):
            sql = " ".join(sql.split())
            self.log.append(sql)
            if self.fail_on and self.fail_on in sql:
                raise RuntimeError("statement failed")
            if sql.startswith("SELECT id FROM ipam_conflict_state WHERE"):
                hit = [i for i, k in self.pending.items() if k == tuple(params)]
                self._answer = {"id": hit[0]} if hit else None
            elif sql.startswith("INSERT INTO ipam_conflict_state"):
                self.pending[self.next_id] = tuple(params)
                self.next_id += 1
            elif sql.startswith("SELECT id, ip, subnet_kind, subnet_id FROM ipam_conflict_state"):
                self._answer = [
                    {"id": i, "ip": k[0], "subnet_kind": k[1], "subnet_id": k[2]} for i, k in self.pending.items()
                ]
            elif sql.startswith("DELETE FROM ipam_conflict_state"):
                self.pending.pop(params[0], None)

        def fetchone(self):
            return self._answer

        def fetchall(self):
            return self._answer or []

        def commit(self):
            if self.fail_commit:
                raise RuntimeError("commit failed")
            self.rows, self.pending = dict(self.pending), None
            self.events.append("commit")

        def rollback(self):
            self.pending = None
            self.events.append("rollback")

        def close(self):
            self.pending = None
            self.events.append("close")

    api = sys.modules["jen.plugin_api"]
    api.subnet_map = lambda: {5: {"name": "lan", "cidr": "10.5.0.0/24"}, 6: {"name": "lab", "cidr": "10.6.0.0/24"}}
    kea_up = {"up": True}
    standing = {
        5: ({"10.5.0.20": {"hostname": "nas", "mac": "aa:aa:aa:aa:aa:20"}}, {}),
        6: ({"10.6.0.9": {"hostname": "cam", "mac": "aa:aa:aa:aa:aa:09"}}, {}),
    }

    def _sets(sid, cidr=None, strict=False):
        if not kea_up["up"]:
            if strict:
                raise s._LookupFailed("Kea's leases and reservations", "kea")
            return {}, {}
        return standing[sid]

    static = {"label": "x", "entry_status": "static", "is_static": 1}
    s._load_kea_sets = _sets
    s._load_entries = lambda kind, sid, strict=False: {"10.5.0.20": static} if sid == 5 else {"10.6.0.9": static}
    store = _Store()
    s._jen_db = lambda: store
    announced = []
    s._announce_conflict = lambda sid, info, entry: announced.append((entry["ip"], list(store.events)))
    s._check_conflicts()
    check(
        sorted(ip for ip, _e in announced) == ["10.5.0.20", "10.6.0.9"] and len(store.rows) == 2,
        f"_check_conflicts: two new conflicts are tracked and announced once each (got {announced})",
    )
    check(
        all(events[-2:] == ["commit", "close"] for _ip, events in announced),
        f"_check_conflicts: each is announced after the commit and after the connection is closed (IPAM-2) (got {announced})",
    )
    announced.clear()
    s._check_conflicts()
    check(announced == [], "_check_conflicts: a standing conflict is not announced again")
    kea_up["up"] = False
    s._check_conflicts()
    check(
        len(store.rows) == 2 and announced == [],
        f"_check_conflicts: a run with the Kea database away keeps every tracking row (IPAM-1) (got {store.rows})",
    )
    kea_up["up"] = True
    s._check_conflicts()
    check(announced == [], f"_check_conflicts: the next good run announces nothing a second time (got {announced})")
    standing[6] = ({}, {})
    s._check_conflicts()
    check(
        sorted(k[0] for k in store.rows.values()) == ["10.5.0.20"],
        f"_check_conflicts: a conflict that really ended in a subnet that was read is forgotten (got {store.rows})",
    )
    api.subnet_map = dict
    s._check_conflicts()
    check(len(store.rows) == 1, "_check_conflicts: an empty subnet list forgets nothing")
    api.subnet_map = lambda: {5: {"name": "lan", "cidr": "10.5.0.0/24"}, 6: {"name": "lab", "cidr": "10.6.0.0/24"}}

    # IPAM-2: a statement or a commit that fails after the INSERT sends nothing, and the next run sends it once
    for label, broken in (
        ("the stale sweep fails", _Store(fail_on="SELECT id, ip, subnet_kind, subnet_id")),
        ("the commit fails", _Store(fail_commit=True)),
    ):
        announced.clear()
        s._jen_db = lambda broken=broken: broken
        s._check_conflicts()
        check(
            announced == [] and broken.rows == {},
            f"_check_conflicts: when {label}, no alert is sent for a row that was not stored (got {announced})",
        )
        broken.fail_on, broken.fail_commit = None, False
        s._check_conflicts()
        check(
            [ip for ip, _e in announced] == ["10.5.0.20"],
            f"_check_conflicts: after {label}, the next run announces the conflict exactly once (got {announced})",
        )

    # IPAM-5: every caller that DECIDES from the lookup refuses, and writes nothing
    r = load_plugin()
    _stub_jen_plugin_api()
    said = []
    writes = FakeDB()
    r.flash = lambda msg, cat="message": said.append(msg)
    r.redirect = lambda *a, **k: "back"
    r.url_for = lambda *a, **k: "/x"
    r.jsonify = lambda payload: payload
    r.current_user.role = "admin"
    r._check_access = lambda kind, sid, notify=True: {"name": "lan", "cidr": "10.5.0.0/24"}
    r._subnet_ctx = lambda kind, sid, subnet: {"pools": [], "infrastructure": {}, "gateways": [], "dns": []}
    r._kea_db = _kea_away
    r._jen_db = lambda: writes
    r.request = types.SimpleNamespace(form={"ip": "10.5.0.30", "label": "x", "ipam_status": "static"}, args={})
    r.save_entry("kea", 5)
    check(
        said == [r.LOOKUP_REFUSAL] and not any(st[0] in ("INSERT", "UPDATE", "DELETE") for st in writes.statements),
        f"save_entry: with Kea's database away the save is refused in one sentence and nothing is written (got {said})",
    )
    said.clear()
    r.request = types.SimpleNamespace(form={"action": "static", "first": "10.5.0.30", "last": "10.5.0.40"}, args={})
    r.range_action("kea", 5)
    check(
        said == [r.LOOKUP_REFUSAL] and not any(st[0] in ("INSERT", "UPDATE", "DELETE") for st in writes.statements),
        f"range_action: the same refusal, nothing written (got {said})",
    )
    said.clear()
    r.request = types.SimpleNamespace(form={"payload": '[{"ip": "10.5.0.31", "status": "static"}]'}, args={})
    r.import_commit("kea", 5)
    check(
        said == [r.LOOKUP_REFUSAL] and not any(st[0] in ("INSERT", "UPDATE", "DELETE") for st in writes.statements),
        f"import_commit: the same refusal, and nothing is written (got {said})",
    )
    unrestricted_key = {"name": "k", "subnet_access": None}
    sys.modules["flask"].g = types.SimpleNamespace(api_key=unrestricted_key)
    got = r._api_next_free(5)
    check(
        isinstance(got, tuple) and got[1] == 503 and "ip" not in got[0],
        f"API next-free: with Kea's database away the answer is 503 and no address (got {got})",
    )
    sys.modules["flask"].request = types.SimpleNamespace(
        get_json=lambda silent=True: {"subnet_id": 5, "ip": "10.5.0.32"}
    )
    got = r._api_save_entry()
    check(
        isinstance(got, tuple) and got[1] == 503 and not any(st[0] == "INSERT" for st in writes.statements),
        f"API save: 503 and nothing written (got {got})",
    )
    r._jen_db = _kea_away
    r.request = types.SimpleNamespace(args={"subnet_id": "5"})
    got = r._api_list_entries()
    check(
        isinstance(got, tuple) and got[1] == 503,
        f"API list entries: entries that could not be read are 503, not an empty list (got {got})",
    )
    r._jen_db = lambda: writes
    r._load_entries = lambda kind, sid, strict=False: {}
    r._history_rows = lambda *a, **k: []
    r._devices_by_mac = lambda macs: {}
    r.render_template = lambda name, **kw: kw
    r.request = types.SimpleNamespace(args={}, form={})
    page = r.subnet_detail("kea", 5)
    check(
        page["kea_unavailable"] is True and page["next_free"] is None,
        "subnet_detail: with Kea's database away the page opens, says so, and offers no next free address",
    )
    r._load_kea_sets = lambda sid, cidr=None, strict=False: ({}, {})
    page = r.subnet_detail("kea", 5)
    check(
        page["kea_unavailable"] is False and page["next_free"] == "10.5.0.1",
        "subnet_detail: with Kea answering, as before",
    )

    # ── 1.8.3 (IPAM-4): no URL opens more than _MAX_EXPAND addresses of a run ──────────────────────────────────────────
    v = load_plugin()
    net16 = ipaddress.IPv4Network("10.20.0.0/16")
    bare = {"pools": [], "infrastructure": {}}
    whole = v._build_rows_lazy(net16, {}, {}, {}, bare, {})
    check(len(whole) == 1 and whole[0]["count"] == 65534, "a sparse /16 is one run by default")
    opened = v._build_rows_lazy(net16, {}, {}, {}, bare, {}, expand=whole[0]["key"])
    shown = [row for row in opened if not row.get("run")]
    check(
        len(shown) == v._MAX_EXPAND and shown[0]["ip"] == "10.20.0.1" and len(opened) == v._MAX_EXPAND + 1,
        f"?expand= of the whole /16 run opens its first {v._MAX_EXPAND} addresses and leaves one run (got {len(shown)} rows, {len(opened)} in all)",
    )
    rest = opened[-1]
    check(
        rest["run"] and rest["first"] == "10.20.1.1" and rest["count"] == 65534 - v._MAX_EXPAND,
        f"the rest stays a run that starts where the open part ended (got {rest})",
    )
    again = v._build_rows_lazy(net16, {}, {}, {}, bare, {}, expand=rest["key"])
    shown = [row for row in again if not row.get("run")]
    check(
        len(shown) == v._MAX_EXPAND and shown[0]["ip"] == "10.20.1.1" and again[0]["run"] and again[-1]["run"],
        "opening that run shows the next 256, with a run before and a run after",
    )
    focused = v._build_rows_lazy(net16, {}, {}, {}, bare, {}, focus="10.20.100.7")
    shown = [row["ip"] for row in focused if not row.get("run")]
    check(
        len(shown) == v._MAX_EXPAND and "10.20.100.7" in shown and len(focused) == v._MAX_EXPAND + 2,
        f"?ip= / ?at= opens {v._MAX_EXPAND} addresses around the one asked for (got {len(shown)})",
    )
    first_free = v._build_rows_lazy(net16, {}, {}, {}, bare, {}, focus="10.20.0.1")
    check(
        sum(1 for row in first_free if not row.get("run")) == v._MAX_EXPAND and first_free[0]["ip"] == "10.20.0.1",
        "the Next free button on a sparse /16 (the first address) draws 256 rows, not 65,534",
    )
    last_one = v._build_rows_lazy(net16, {}, {}, {}, bare, {}, focus="10.20.255.254")
    check(
        [row["ip"] for row in last_one if not row.get("run")][-1] == "10.20.255.254"
        and sum(1 for row in last_one if not row.get("run")) == v._MAX_EXPAND,
        "a focus at the end of the run opens the last 256",
    )
    check(
        v._expand_window(10, 20, (10, 19), None) == (10, 20), "_expand_window: a run shorter than the cap opens whole"
    )
    check(
        v._expand_window(10, 20, (5, 19), None) is None,
        "_expand_window: a range that is not inside this run opens nothing",
    )
    check(v._expand_window(10, 20, None, 25) is None, "_expand_window: a focus outside this run opens nothing")

    # ── 1.8.3 (IPAM-6): a reservation on a designated address is not the conflict IPAM flags ──────────────────────────
    entry = {
        "ip": "10.5.0.20",
        "label": "nas",
        "owner": "",
        "entry_status": "static",
        "is_static": 1,
        "mac": "",
        "hostname": "",
    }
    reserved_card = v.investigation_card([entry], {"10.5.0.20": "reservation"})
    check(
        reserved_card["status"] == "ok"
        and "also a Kea reservation" in reserved_card["summary"]
        and "conflict" not in reserved_card["summary"],
        f"investigation_card: static in IPAM and reserved in Kea is an ok card (got {reserved_card})",
    )
    check(
        v.investigation_card([entry], {"10.5.0.20": "lease"})["status"] == "warn",
        "investigation_card: static in IPAM and held by a lease is still the warning",
    )
    check(
        v._conflicts_in(
            {}, {"10.5.0.20": {"hostname": "", "mac": "", "host_id": 1}}, {"10.5.0.20": entry}, lambda ip: True
        )
        == [],
        "and that is the same answer the periodic job gives for it",
    )
    detail_page = pathlib.Path(ROOT, "templates", "ipam", "subnet.html").read_text(encoding="utf-8")
    check(
        "{% if kea_unavailable %}" in detail_page and 'data-ipam-note="kea-unavailable"' in detail_page,
        "subnet.html: the page says when Kea's leases and reservations could not be read",
    )

    # ── 1.8.4 (BG1): what a device or an operator typed is escaped before it goes into the alert ───────────────────────
    b = load_plugin()
    _stub_jen_plugin_api()
    api = sys.modules["jen.plugin_api"]
    sent, events = [], []
    api.send_alert = lambda alert_type, **kw: sent.append(kw)
    api.emit = lambda name, **kw: events.append(kw)
    odd = {"ip": "10.5.0.20", "designated": "static", "hostname": "AT&T <hotspot>", "mac": "aa:aa:aa:aa:aa:20"}
    check(not hasattr(api, "safe_text"), "the stub jen.plugin_api starts without safe_text, as a Jen before 7.2.0 is")
    b._announce_conflict(5, {"name": "Lab & <one>", "cidr": "10.5.0.0/24"}, odd)
    text = b._CONFLICT_TEMPLATE.format(**{k: v for k, v in sent[-1].items() if k != "subnet_id"}) if sent else ""
    check(
        "Hostname: AT&amp;T &lt;hotspot&gt;" in text and "in Lab &amp; &lt;one&gt;," in text,
        f"_announce_conflict: on a Jen without safe_text the hostname and the subnet name are escaped (got {text!r})",
    )
    check(
        text.count("<") == 2
        and text.count(">") == 2
        and "&" not in text.replace("&amp;", "").replace("&lt;", "").replace("&gt;", ""),
        f"the rendered alert holds no markup but the template's own <b> pair (got {text!r})",
    )
    check(
        sent[-1]["ip"] == "10.5.0.20" and sent[-1]["mac"] == "aa:aa:aa:aa:aa:20" and sent[-1]["subnet_id"] == 5,
        "the address, the MAC and the subnet id are passed as they are",
    )
    check(
        len(events) == 1 and "Lab & <one>" in events[0]["detail"],
        f"the Timeline event is not HTML and keeps the name as typed (got {events})",
    )
    through = []

    def _stub_safe_text(value):
        through.append(value)
        return str(value).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    api.safe_text = _stub_safe_text
    b._announce_conflict(5, {"name": "Lab & <one>", "cidr": "10.5.0.0/24"}, odd)
    text = b._CONFLICT_TEMPLATE.format(**{k: v for k, v in sent[-1].items() if k != "subnet_id"})
    check(
        "Hostname: AT&amp;T &lt;hotspot&gt;" in text and "in Lab &amp; &lt;one&gt;," in text,
        f"_announce_conflict: on a Jen with safe_text the same text is sent (got {text!r})",
    )
    check(
        through == ["Lab & <one>", "static", "AT&T <hotspot>"],
        f"and Jen's own safe_text is what escaped the subnet, the designation and the hostname (got {through})",
    )
    del api.safe_text
    check(
        b._alert_text("a & b") == "a &amp; b" and b._alert_text('say "hi"') == 'say "hi"' and b._alert_text(7) == "7",
        "_alert_text: the fallback escapes &, < and >, leaves quotes, and takes a value that is not a string",
    )
    plugin_source = pathlib.Path(ROOT, "plugin.py").read_text(encoding="utf-8")
    check(
        plugin_source.count("send_alert(") == 1,
        "plugin.py sends an alert in one place, so one place has to escape",
    )

    # ── 1.8.4 (BG6): the refusal names the read that failed ────────────────────────────────────────────────────────────
    class _EntriesAway(FakeDB):
        """Jen's database with ipam_static_entries unreadable: a read of it fails, anything else is recorded."""

        def execute(self, sql, params=()):
            if sql.split()[0].upper() == "SELECT" and "ipam_static_entries" in sql:
                raise RuntimeError(1146, "Table 'jen.ipam_static_entries' doesn't exist")
            super().execute(sql, params)

    def _wrote(db):
        return [st for st in db.statements if st[0] in ("INSERT", "UPDATE", "DELETE")]

    b._kea_db = _kea_away
    for loader, args, want in (
        (b._load_kea_sets, (5, "10.5.0.0/24"), ("kea", "Kea's leases and reservations")),
        (b._load_entries, ("kea", 5), ("entries", "IPAM's own entries")),
    ):
        b._jen_db = _EntriesAway
        try:
            loader(*args, strict=True)
            got = None
        except b._LookupFailed as e:
            got = (getattr(e, "source", None), str(e))
        check(got == want, f"{loader.__name__}: _LookupFailed says which read failed (got {got})")
    check(
        b.ENTRIES_REFUSAL == "Could not read IPAM's own entries - nothing was changed. Try again in a moment."
        and b.LOOKUP_REFUSAL
        == "Could not check Kea's leases and reservations - nothing was changed. Try again in a moment.",
        "the two refusal sentences are the two the notes give",
    )

    said = []
    b.flash = lambda msg, cat="message": said.append(msg)
    b.redirect = lambda *a, **k: "back"
    b.url_for = lambda *a, **k: "/x"
    b.jsonify = lambda payload: payload
    b._audit = lambda *a, **k: None
    b.current_user.role = "admin"
    b._check_access = lambda kind, sid, notify=True: {"name": "lan", "cidr": "10.5.0.0/24"}
    b._subnet_ctx = lambda kind, sid, subnet: {"pools": [], "infrastructure": {}, "gateways": [], "dns": []}
    real_kea_sets = b._load_kea_sets
    kea_answers = lambda sid, cidr=None, strict=False: ({}, {})  # noqa: E731
    sys.modules["flask"].g = types.SimpleNamespace(api_key={"name": "k", "subnet_access": None})
    forms = {
        "save_entry": {"ip": "10.5.0.30", "label": "x", "ipam_status": "static"},
        "import_commit": {"payload": '[{"ip": "10.5.0.31", "status": "static"}]'},
    }
    for state, kea_sets, sentence, api_save, api_next in (
        (
            "IPAM's own table unreadable",
            kea_answers,
            b.ENTRIES_REFUSAL,
            "IPAM's entries could not be read",
            "IPAM's entries could not be read",
        ),
        (
            "Kea's database away",
            real_kea_sets,
            b.LOOKUP_REFUSAL,
            "Kea's leases and reservations could not be checked; nothing was changed",
            "Kea's leases and reservations could not be read; no address is offered",
        ),
    ):
        store = _EntriesAway()
        b._jen_db = lambda store=store: store
        b._load_kea_sets = kea_sets
        for route in ("save_entry", "import_commit"):
            said.clear()
            b.request = types.SimpleNamespace(form=forms[route], args={})
            getattr(b, route)("kea", 5)
            check(
                said == [sentence] and not _wrote(store),
                f"{route}: with {state} the refusal names that read and nothing is written (got {said})",
            )
        sys.modules["flask"].request = types.SimpleNamespace(
            get_json=lambda silent=True: {"subnet_id": 5, "ip": "10.5.0.32"}
        )
        got = b._api_save_entry()
        check(
            got == ({"error": api_save}, 503) and not _wrote(store),
            f"API save: with {state} the answer is 503 with the matching sentence and nothing is written (got {got})",
        )
        got = b._api_next_free(5)
        check(
            got == ({"error": api_next}, 503),
            f"API next-free: with {state} the answer is 503 with the matching sentence and no address (got {got})",
        )
    said.clear()
    b.request = types.SimpleNamespace(form={"action": "static", "first": "10.5.0.30", "last": "10.5.0.40"}, args={})
    b.range_action("kea", 5)
    check(
        said == [b.LOOKUP_REFUSAL] and not _wrote(store),
        f"range_action: it reads Kea only, and with Kea's database away it still says so (got {said})",
    )
    b.request = types.SimpleNamespace(args={"subnet_id": "5"})
    got = b._api_list_entries()
    check(
        got == ({"error": "IPAM's entries could not be read"}, 503),
        f"API list entries: the sentence it always used, the one the two other routes now share (got {got})",
    )
    logged = []
    b.logger = types.SimpleNamespace(
        error=logged.append, warning=logged.append, info=logged.append, debug=logged.append
    )
    api.subnet_map = lambda: {5: {"name": "lan", "cidr": "10.5.0.0/24"}}
    b._load_kea_sets = kea_answers
    found, unread = b._kea_conflicts()
    check(
        found == []
        and unread == {5}
        and any("could not read IPAM's own entries for subnet 5" in line for line in logged),
        f"the conflict job: with IPAM's own table unreadable the subnet is unread and the log names that read (got {logged})",
    )
    logged.clear()
    b._load_kea_sets = real_kea_sets
    found, unread = b._kea_conflicts()
    check(
        unread == {5} and any("could not read Kea's leases and reservations for subnet 5" in line for line in logged),
        f"the conflict job: with Kea's database away the log names Kea's read (got {logged})",
    )

    # ── 1.8.4 (BG7): the subnet page says when IPAM's own table could not be read, and offers no Next free ─────────────
    b._load_kea_sets = kea_answers
    b._history_rows = lambda *a, **k: []
    b._devices_by_mac = lambda macs: {}
    b.render_template = lambda name, **kw: kw
    b.request = types.SimpleNamespace(args={}, form={})
    page = b.subnet_detail("kea", 5)
    check(
        page.get("entries_unavailable") is True and page["next_free"] is None and page["kea_unavailable"] is False,
        f"subnet_detail: with IPAM's own table unreadable the page opens, says so, and offers no next free address (got {page.get('entries_unavailable')}, {page['next_free']})",
    )
    check(
        page["counts"]["total"] == 254 and not any(row.get("ipam") for row in page["rows"] if not row.get("run")),
        "and it is drawn from Kea's answer alone",
    )
    b._load_kea_sets = real_kea_sets
    page = b.subnet_detail("kea", 5)
    check(
        page.get("entries_unavailable") is True and page["kea_unavailable"] is True and page["next_free"] is None,
        "subnet_detail: with both reads failing both notices are set and no next free address is offered",
    )
    b._load_kea_sets = kea_answers
    b._load_entries = lambda kind, sid, strict=False: {}
    page = b.subnet_detail("kea", 5)
    check(
        page.get("entries_unavailable") is False
        and page["kea_unavailable"] is False
        and page["next_free"] == "10.5.0.1",
        "subnet_detail: with both reads answering, as before",
    )
    detail_page = pathlib.Path(ROOT, "templates", "ipam", "subnet.html").read_text(encoding="utf-8")
    notice = re.search(r"\{% if entries_unavailable %\}\n(.*?)\n\{% endif %\}", detail_page, re.S)
    kea_notice = re.search(r"\{% if kea_unavailable %\}\n(.*?)\n\{% endif %\}", detail_page, re.S)
    check(
        notice is not None
        and notice.group(1).startswith('<div class="alert alert-danger" data-ipam-note="entries-unavailable">')
        and "IPAM's own entries could not be read, so this page shows Kea's leases and reservations only and Next free is "
        "switched off. Try again in a moment.{% endif %}</div>"
        in notice.group(1),
        "subnet.html: the page says when IPAM's own entries could not be read",
    )
    check(
        notice is not None
        and "{% if unmanaged %}IPAM's own entries could not be read, so this page shows no entries and Next free is "
        "switched off. Try again in a moment.{% else %}IPAM's own entries"
        in notice.group(1),
        "subnet.html: on an unmanaged subnet, which has no Kea leases, the notice does not name them",
    )
    check(
        kea_notice is not None
        and notice is not None
        and re.match(r"<div class=\"[^\"]+\"", kea_notice.group(1)).group(0)
        == re.match(r"<div class=\"[^\"]+\"", notice.group(1)).group(0),
        "subnet.html: the new notice is built like the one for Kea",
    )

    # ── 1.8.5 (BH9): a save on an unmanaged subnet reads IPAM's entries before it writes ──────────────────────────────
    class _EntriesGone(FakeDB):
        """Jen's database with ipam_static_entries gone, which is what an unreadable table is: every statement that names
        it fails, a read and a write alike. Anything else is recorded."""

        def execute(self, sql, params=()):
            if "ipam_static_entries" in sql:
                raise RuntimeError(1146, "Table 'jen.ipam_static_entries' doesn't exist")
            super().execute(sql, params)

    class _WriteFails(FakeDB):
        """The read of ipam_static_entries answers (no rows) and a write to it fails."""

        def execute(self, sql, params=()):
            if "ipam_static_entries" in sql and sql.split()[0].upper() != "SELECT":
                raise RuntimeError(1205, "Lock wait timeout exceeded")
            super().execute(sql, params)

        def fetchall(self):
            return []

    class _Answers(FakeDB):
        def fetchall(self):
            return []

    h = load_plugin()
    _stub_jen_plugin_api()
    h_said = []
    h.flash = lambda msg, cat="message": h_said.append(msg)
    h.redirect = lambda *a, **k: "back"
    h.url_for = lambda *a, **k: "/x"
    h._audit = lambda *a, **k: None
    h.current_user.role = "admin"
    h._check_access = lambda kind, sid, notify=True: {"name": "backend", "cidr": "10.5.0.0/24", "gateway": ""}
    kea_asked = []

    def _kea_sets_recorded(sid, cidr=None, strict=False):
        kea_asked.append(sid)
        return {}, {}

    h._load_kea_sets = _kea_sets_recorded
    static_form = {"ip": "10.5.0.30", "label": "x", "ipam_status": "static"}
    write_sentence = "Could not save the entry; the details are in Jen's log."

    gone = _EntriesGone()
    h._jen_db = lambda: gone
    h.request = types.SimpleNamespace(form=static_form, args={})
    h.save_entry("u", 7)
    check(
        h_said == [h.ENTRIES_REFUSAL] and not _wrote(gone),
        f"save_entry on an unmanaged subnet: with IPAM's own table unreadable the refusal names that read and nothing is written (BH9) (got {h_said})",
    )
    check(
        kea_asked == [], f"and Kea, which has nothing to say about an unmanaged subnet, is not asked (got {kea_asked})"
    )
    h_said.clear()
    h.save_entry("kea", 5)
    check(
        h_said == [h.ENTRIES_REFUSAL] and not _wrote(gone) and kea_asked == [5],
        f"save_entry on a Kea subnet in the same state: the same sentence, as in 1.8.4 (got {h_said})",
    )
    stuck = _WriteFails()
    h._jen_db = lambda: stuck
    h_said.clear()
    h.save_entry("u", 7)
    check(
        h_said == [write_sentence] and [st[0] for st in stuck.statements] == ["SELECT"],
        f"save_entry on an unmanaged subnet: a WRITE that fails after the read answered keeps the write's sentence (got {h_said})",
    )
    fine = _Answers()
    h._jen_db = lambda: fine
    h_said.clear()
    h.save_entry("u", 7)
    check(
        h_said == ["Entry saved for 10.5.0.30."]
        and [st[0] for st in fine.statements] == ["SELECT", "INSERT", "INSERT"],
        f"save_entry on an unmanaged subnet with everything answering: read, then the entry and its history row (got {h_said}, {[st[0] for st in fine.statements]})",
    )
    gone = _EntriesGone()
    h._jen_db = lambda: gone
    h_said.clear()
    h.request = types.SimpleNamespace(form={"ip": "10.5.0.30", "label": "x", "ipam_status": "available"}, args={})
    h.save_entry("u", 7)
    check(
        h_said == [write_sentence] and not _wrote(gone),
        f"save_entry: a note that designates nothing decides nothing from the entries and reads none, as before (got {h_said})",
    )

    # ── 1.8.5: the overview's Getting started card ──────────────────────────────────────────────────────────────────────
    class _Entries(FakeDB):
        """Jen's database for the overview: ipam_static_entries answers with `rows`, or fails when `rows` is None."""

        def __init__(self, rows):
            super().__init__()
            self.rows = rows

        def execute(self, sql, params=()):
            if self.rows is None and "ipam_static_entries" in sql:
                raise RuntimeError(1146, "Table 'jen.ipam_static_entries' doesn't exist")
            super().execute(sql, params)

        def fetchall(self):
            return list(self.rows)

    note = {"ip": "10.5.0.9", "label": "spare", "owner": "", "notes": "", "hostname": "", "mac": "", "is_static": 0}
    note["entry_status"] = "available"
    lan = {5: {"name": "lan", "cidr": "10.5.0.0/24"}}
    h._load_kea_sets = lambda sid, cidr=None, strict=False: ({}, {})
    h._subnet_ctx = lambda kind, sid, subnet: {"pools": [], "infrastructure": {}, "gateways": [], "dns": []}
    h.render_template = lambda name, **kw: kw
    gate_user_h = sys.modules["flask_login"].current_user

    def overview(rows, subnets=lan, unmanaged=None, role="admin", all_subnets=True):
        store = _Entries(rows)
        h._jen_db = lambda: store
        h._accessible_subnets = lambda: dict(subnets)
        h._get_ipam_subnets = lambda: dict(unmanaged or {})
        gate_user_h.role, h.current_user.role, h.current_user.all_subnets = role, role, all_subnets
        return h.index()

    page = overview([])
    check(
        page.get("first_run") is True and page["summaries"][("kea", 5)]["entries"] == 0,
        f"index: with no entry and no unmanaged subnet the overview is a first run (got {page.get('first_run')})",
    )
    page = overview([note])
    check(
        page.get("first_run") is False and page["summaries"][("kea", 5)]["entries"] == 1,
        "index: one entry, even a note that designates nothing, and it is not a first run",
    )
    page = overview(None)
    check(
        page.get("first_run") is False
        and page["summaries"][("kea", 5)]["entries"] is None
        and page["summaries"][("kea", 5)]["total"] == 254,
        f"index: entries that could not be read are not 'no entries': no first-run card, and the card's counts still come (got {page.get('first_run')})",
    )
    page = overview([], unmanaged={3: {"name": "backend", "cidr": "172.16.0.0/24", "description": "", "gateway": ""}})
    check(page.get("first_run") is False, "index: an unmanaged subnet exists, so it is not a first run")
    check(
        overview([], subnets={}).get("first_run") is True,
        "index: no subnet at all and the caller may add an unmanaged one: the first run's step is that",
    )
    check(
        overview([], subnets={}, role="viewer").get("first_run") is False
        and overview([], subnets={}, role="admin", all_subnets=False).get("first_run") is False,
        "index: no subnet at all and nothing this caller may add: no first-run card",
    )
    check(
        overview([], role="viewer").get("first_run") is True,
        "index: a viewer with a subnet to open and nothing stored still gets the steps",
    )
    real_summary = h._summary

    def _summary_breaks(kind, sid, info):
        raise RuntimeError("summary failed")

    h._summary = _summary_breaks
    check(
        overview([]).get("first_run") is False, "index: a subnet whose summary failed is not read, so no first-run card"
    )
    h._summary = real_summary
    gate_user_h.role, h.current_user.role, h.current_user.all_subnets = "admin", "admin", True

    # ── 1.8.5: the pages (the look-over's rows on plugin pages) ─────────────────────────────────────────────────────────
    overview_page = pathlib.Path(ROOT, "templates", "ipam", "index.html").read_text(encoding="utf-8")
    subnet_page = pathlib.Path(ROOT, "templates", "ipam", "subnet.html").read_text(encoding="utf-8")
    check(
        "{% if first_run %}" in overview_page
        and '<div class="card first-run">\n    <h3>Getting started</h3>\n    <ol>' in overview_page
        and overview_page.count("<li>") == 3,
        "index.html: one first-run card, headed Getting started, with three steps",
    )
    check(
        "IPAM then lists every address of the subnet: on a Kea subnet the leases and reservations it reads from Kea "
        "beside the entries you add, on an unmanaged subnet your entries alone."
        in overview_page
        and "Every 15 minutes IPAM checks whether a DHCP client holds an address you marked Static or Planned, and "
        "announces a new conflict once."
        in overview_page
        and '<a href="/settings/alerts">Settings - Alerts</a>' in overview_page,
        "index.html: step 2 says what IPAM shows by itself and step 3 where the conflict alert is set",
    )
    plugin_text = pathlib.Path(ROOT, "plugin.py").read_text(encoding="utf-8")
    check(
        'register_periodic("ipam", "conflict_check", _check_conflicts, every_minutes=15)' in plugin_text
        and 'label="IPAM Conflict"' in plugin_text,
        "and the 15 minutes and the alert's name in step 3 are the ones register() gives",
    )
    check(
        ".ip-cd5a1e .card{margin-bottom:0}" in overview_page
        and ".ip-cd5a1e{display:grid;grid-template-columns:repeat(auto-fill,minmax(340px,1fr));gap:16px;margin-bottom:16px}"
        in overview_page,
        "index.html: the subnet cards are 16px apart both ways (a card's own bottom margin no longer doubles the row gap)",
    )
    check(
        "document.querySelectorAll('.ipam-add-subnet-open')" in overview_page
        and overview_page.count("ipam-add-subnet-open") == 3,
        "index.html: the header's button and the first-run card's button open the one form",
    )
    content_start = subnet_page.index("{% block content %}")
    first_element = subnet_page[content_start:].split("\n")[2]
    check(
        first_element == """<a class="back-link" href="{{ url_for('ipam.index') }}">&larr; IPAM Lite</a>"""
        and subnet_page.count("url_for('ipam.index')") == 1
        and "All Subnets" not in subnet_page,
        f"subnet.html: one way back, the first element of the page, named after the overview (got {first_element!r})",
    )
    check(
        ".back-link { display: inline-block; margin-bottom: 8px; font-size: 13px; }" in subnet_page,
        "subnet.html: the back link's style is the one every plugin's detail page uses",
    )
    check(
        "{% block content_class %}content--wide{% endblock %}" in subnet_page and "content_class" not in overview_page,
        "subnet.html: the address table may use a wide page; the overview keeps the usual width",
    )
    labels = re.findall(r"<button\b[^>]*>(.*?)</button>", subnet_page, re.S) + re.findall(
        r'<a\b[^>]*class="btn[^>]*>(.*?)</a>', subnet_page, re.S
    )
    labels = [re.sub(r"\{\{.*?\}\}|\{%.*?%\}", "", label).strip() for label in labels]
    words = [w for label in labels for w in re.findall(r"[A-Za-z]+", label)]
    check(
        all(w[0].isupper() or w in ("to", "a", "the", "of") for w in words) and len(labels) >= 20,
        f"subnet.html: every button's label is Title Case (got {[w for w in words if not w[0].isupper()]})",
    )
    for label in ("Next Free:", "⇔ Mark Range", "Import Addresses", "Export CSV", "Export Netbox CSV", "Save Entry"):
        check(label in labels, f"subnet.html: a button reads {label!r}")
    check(
        "Clear All Notes" in subnet_page and "Apply to Range" in subnet_page and "Use next free" not in subnet_page,
        "subnet.html: the two dialog buttons name what they act on, and nothing new is offered beside Next Free",
    )

    if failures:
        print(f"\n{len(failures)} check(s) failed")
        return 1
    print("\nall plugin checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
