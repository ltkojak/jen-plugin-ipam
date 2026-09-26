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

import importlib.util
import ipaddress
import os
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
    flask.request = None
    sys.modules["flask"] = flask
    fl = types.ModuleType("flask_login")
    fl.current_user = types.SimpleNamespace(username="tester", all_subnets=True, role="admin")
    fl.login_required = lambda fn: fn
    sys.modules["flask_login"] = fl


class _FakeApp:
    def register_blueprint(self, bp):
        pass


def _stub_jen_plugin_api():
    """A stub `jen.plugin_api` sufficient for register(app) to run end to end, enforcing the SAME
    two rules Jen's real one does: an alert type id must start with '<plugin_id>_', and a periodic job
    may not run more often than PERIODIC_MIN_MINUTES (5). A plugin that breaks either raises at
    register() in Jen, is swallowed by its per-plugin error handling, and simply never loads — the
    exact way watchdog 1.0.0 and dns-sync 1.0.0 shipped dead (Q89). Returns the registered calls."""
    calls = {"alert_types": [], "periodic": [], "row_actions": [], "search": []}

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
    plugin_api.register_periodic = register_periodic
    plugin_api.register_row_action = lambda *a, **k: calls["row_actions"].append(a)
    plugin_api.register_search_provider = lambda *a, **k: calls["search"].append(a)
    plugin_api.api_key_required = lambda write=False: lambda fn: fn
    jen_pkg.plugin_api = plugin_api
    sys.modules["jen"] = jen_pkg
    sys.modules["jen.plugin_api"] = plugin_api
    return calls


def load_plugin():
    _stub_modules()
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
    check(p._safe_row(["=1+1", "ok", None]) == ["'=1+1", "ok", ""], "CSV formula guard (local fallback)")

    # ── write gate (v1.5.2) — viewers can look at IPAM but not change it ────
    p.current_user.role = "viewer"
    check(p._is_admin() is False, "a viewer is not admin")
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
    check(p._is_admin() is True, "admin role restored for the rest of the run")

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

        def cursor(self):
            return self

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def execute(self, sql, params=()):
            self.statements.append((sql.split()[0].upper(), params))

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

    # ── 1.6.2: the API does not return a raw database error ──────────────────
    p.jsonify = lambda payload: payload
    sys.modules["flask"].g = types.SimpleNamespace(api_key={"name": "k"})
    p.request = types.SimpleNamespace(get_json=lambda silent=True: {"subnet_id": 5, "ip": "10.5.0.7", "label": "x"})
    p._api_subnet_ok = lambda sid: True
    p._accessible_subnets = lambda: {5: {"name": "n", "cidr": "10.5.0.0/24"}}
    p._jen_db = lambda: (_ for _ in ()).throw(RuntimeError("Access denied marker-xyz"))
    result = p._api_save_entry()
    check(
        isinstance(result, tuple) and result[1] == 500 and "marker-xyz" not in str(result[0]),
        f"_api_save_entry: a database failure returns a generic 500, not the exception text (got {result})",
    )
    p.current_user.role = "admin"

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

    if failures:
        print(f"\n{len(failures)} check(s) failed")
        return 1
    print("\nall plugin checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
