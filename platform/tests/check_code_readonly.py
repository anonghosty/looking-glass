#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""The service can read its code but never change it (code integrity, layer 1).

The installed service runs sandboxed: the whole folder is read-only for it (ProtectSystem=strict, ReadOnlyPaths=),
data/ is the one folder it may write (ReadWritePaths=), and nothing in data/ may be run (NoExecPaths=). That only
works while every place the service writes is inside data/. This check, without root and without a database:

  1. the service template carries those protections, and data/ is the only writable folder;
  2. deploy/service_unit.py writes the service file from it (deploy/install.sh) and finds an out-of-date installed copy
     after an update (deploy/update_libraries.sh), against a temporary folder, never /etc;
  3. every write in the code the service runs (app.py, gunicorn.conf.py, every platform module they import, and the
     script the service starts) is in the list below, each with where it writes. A new write fails here until someone
     has made sure it goes to data/ (or a temporary file) and added it to the list;
  4. nothing the service runs writes beside its own code (a path built from the code folder that does not go into
     data/), and nothing loads code from a file it could write (pickle, marshal, shelve, exec, eval).

Run: .venv/bin/python tests/check_code_readonly.py          (--list: print every write found, for the list below)
"""
import ast
import os
import re
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "deploy"))
import service_unit  # noqa: E402

checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info and not cond else ""), flush=True)


# the folders the service may write, as the template names them (anything more needs a reason, and this list)
WRITABLE = ["@PROJECT@/data"]
ENTRIES = ["app.py", "gunicorn.conf.py"]
# scripts the running service starts itself (they run inside its sandbox): name_sources.py starts this one
STARTED = ["manage/fetch_offline_names.py"]

# Every write in the code the service runs: "file::function" -> (how many, where it writes). Where:
#   data     inside data/ (the folder the service gets from app.py, DATA_DIR, or base_dir + "data")
#   tmp      a temporary file of its own (the service has a private /tmp, PrivateTmp=true)
#   copy     AUDIT_CHECKPOINT_COPY_DIR, a folder the administrator adds to the sandbox (docs/OPERATIONS.md)
#   runs     a program it starts: what that program writes is said after the colon
#   memory   a ZIP built in memory (io.BytesIO), sent as a download; no file
#   cli      only reached from that module's own command line (an administrator's tool), never in the service
#   none     not a file at all (a method with the same name)
#   refused  a change to a code file that the sandbox refuses on purpose; the page then says how to do it by hand
# Each one was read and its path followed back to where it is made (2026-11-21, r91). The service writes data/ only.
INVENTORY = {
    "acodes.py::install.save_ids": (3, "data: data/acode_ids/<code>.json"),
    "address_blocks.py::remember": (2, "data: constituency_blocks.json beside data/settings.json"),
    "advisory.py::Store.drop_file": (1, "data: data/advisories/files/"),
    "advisory.py::Store.keep_file": (2, "data: data/advisories/files/"),
    "advisory.py::Store.save": (3, "data: data/advisories/"),
    "advisory.py::install._build": (1, "memory: the ZIP mailed to the organisation"),
    "app.py::<module>": (1, "data: the shipped geocache.json copied to data/geocache.json once"),
    # moved out of app.py unchanged (2026-11-24): the same writes, in their new modules
    "lookup_jobs.py::_autocheck": (1, "data: data/.malpedia_check.lock"),
    "infection_kb.py::_cve_loop": (1, "data: data/.cve_check.lock"),
    "report_downloads.py::_report_response": (1, "memory: the report download"),
    "lookup_jobs.py::_write_names": (2, "data: data/malpedia_names.json"),
    "name_definitions.py::api_kb_entry": (2, "data: data/definitions.json"),
    "app.py::api_networks_entry": (2, "data: data/asns.json"),
    "asn_lookup.py::save": (2, "data: data/asns.json"),
    "at_rest.py::_run": (1, "runs: findmnt/lsblk/cryptsetup status, read only"),
    "attack_map.py::AttackMap._locked": (1, "data: data/.attack_mappings.lock"),
    "attack_map.py::AttackMap._write": (3, "data: data/attack_mappings.json"),
    "caddy_watch.py::_run": (1, "runs: dpkg-query/apt-cache policy/dpkg --compare-versions/apt-config dump, read only"),
    "audit_chain.py::Chain._adopt_old_copy": (1, "data: data/audit_archive/"),
    "audit_chain.py::Chain._gzip": (2, "data: data/audit_archive/"),
    "audit_chain.py::Chain._set_recorded_count": (3, "data: data/audit_archive/removed.recorded"),
    "audit_chain.py::Chain._write": (1, "data: data/audit.log"),
    "audit_chain.py::Chain._write_head": (2, "data: data/audit.head"),
    "audit_chain.py::Chain.append": (1, "data: data/audit.log.lock"),
    "audit_chain.py::Chain.prune": (2, "data: data/audit_archive/"),
    "audit_chain.py::Chain.record_retention_setting": (1, "data: data/audit.log.lock"),
    "audit_chain.py::Chain.rotate": (1, "data: data/audit_archive/"),
    "audit_chain.py::Chain.seal": (2, "data: data/audit.log.lock and the seal beside it"),
    "audit_chain.py::Chain.verify": (1, "data: data/audit.log.lock"),
    "audit_checkpoint.py::Signer.ensure_key": (5, "data: data/audit_signing/ (ssh-keygen writes the key there)"),
    "audit_checkpoint.py::Signer.make": (4, "data: data/audit_checkpoints/"),
    "audit_checkpoint.py::Signer.sign": (3, "data: the .sig beside the checkpoint in data/audit_checkpoints/"),
    "audit_checkpoint.py::copy_out": (1, "copy: AUDIT_CHECKPOINT_COPY_DIR"),
    "audit_checkpoint.py::verify_file": (3, "tmp: the allowed-signers file; ssh-keygen -Y verify only reads"),
    "audit_portal.py::install.ntp_synchronised": (1, "runs: timedatectl show, read only"),
    "audit_proof.py::build": (3, "tmp: a private temporary folder, then the ZIP in memory"),
    "audit_proof.py::install.api_audit_continuity": (1, "data: data/audit.log.lock"),
    "audit_proof.py::snapshot": (6, "tmp: into the temporary folder build() made"),
    "audit_verifier.py::signature": (3, "tmp: the allowed-signers file; ssh-keygen -Y verify only reads"),
    "auth.py::Audit._clear_gap": (1, "data: data/audit_write_failed.json"),
    "auth.py::Audit._write_gap": (2, "data: data/audit_write_failed.json"),
    "auth.py::Roles.__init__": (1, "data: data/.roles_networks_added"),
    "auth.py::Throttle._save": (2, "data: data/login_counters.json"),
    "auth.py::_secure_write": (3, "data: data/roles.json and the other account files"),
    "auth.py::install": (1, "data: data/automation.key"),
    "beacon_keep.py::SummaryStore.flush": (3, "data: data/beacon_summaries.json"),
    "beacon_unknown.py::Unknown.set_state": (3, "data: data/beacon_unknown.json"),
    "combo_review.py::install.keep_search": (3, "data: data/review_searches/"),
    "combos.py::CodeBook._save": (2, "data: data/combo_codes.json"),
    "combos.py::install._sweep": (1, "data: data/combo_exports/"),
    "combos.py::install.package": (3, "data: data/combo_exports/ (and a ZIP in memory)"),
    "config_page.py::_save": (2, "data: data/configuration.json"),
    "code_integrity.py::_write_json": (3, "data: data/code_integrity.json, data/code_approved.json"),
    "cves.py::CveIntel._save": (2, "data: data/cve_cache.json"),
    "findings.py::Findings._save": (2, "data: data/findings.json"),
    "first_run.py::SetupCode.discard": (1, "data: data/setup_code"),
    "first_run.py::SetupCode.sync": (1, "data: data/setup_code"),
    "geo.py::Geocoder.flush": (2, "data: data/geocache.json"),
    "greetings.py::Welcomed.first_time": (3, "data: data/greetings.json"),
    "insider.py::Sealer.prune": (2, "data: data/copy_seals.jsonl"),
    "insider.py::Sealer.write": (2, "data: data/copy_seals.jsonl"),
    "insider.py::install.note_small_trace": (2, "data: data/trace_watch.json"),
    "insider.py::load_key": (2, "data: data/copy_seal.key"),
    "invites.py::Invites._save": (3, "data: data/invites.json"),
    "library_supply.py::audit_new": (3, "data: data/suspected_packages_audited.json"),
    "malpedia.py::Malpedia._get": (2, "data: data/malpedia_cache.json"),
    "manage/fetch_offline_names.py::download": (2, "data: LG_OFFLINE_NAMES_DIR, which name_sources.py sets to data/"),
    "manage/fetch_offline_names.py::fetch_attack": (3, "data: LG_OFFLINE_NAMES_DIR (data/)"),
    "manage/fetch_offline_names.py::fetch_kev": (3, "data: LG_OFFLINE_NAMES_DIR (data/)"),
    "manage/fetch_offline_names.py::log": (2, "data: LG_OFFLINE_NAMES_DIR (data/)"),
    "manage/fetch_offline_names.py::main": (1, "data: LG_OFFLINE_NAMES_DIR (data/)"),
    "manage/fetch_offline_names.py::save": (3, "data: LG_OFFLINE_NAMES_DIR (data/)"),
    "manage/fetch_offline_names.py::schedule": (2, "cli: crontab, only with --schedule, which the service never passes"),
    "manage/fetch_offline_names.py::write_status": (3, "data: LG_OFFLINE_NAMES_DIR (data/)"),
    "management.py::register._base_save": (2, "data: data/mgmt_baseline.json"),
    "management.py::register.mgmt_report": (1, "memory: the Executive download"),
    "name_levels_catchup.py::catch_up": (2, "data: data/name_levels.done"),
    "name_sources.py::install.api_name_sources_refresh": (1, "runs: manage/fetch_offline_names.py, into data/ (scanned here too)"),
    "net_drift.py::cert_addresses": (1, "runs: openssl x509, read only"),
    "net_drift.py::own_addresses": (1, "runs: hostname -I, read only"),
    "netypes.py::add": (2, "data: data/network_types.json"),
    "notes.py::Notes._save": (2, "data: data/notes.json"),
    "notifications.py::Seen.clear": (3, "data: data/notifications.json"),
    "organisation.py::Organisation.save": (3, "data: data/organisation.json"),
    "password_policy.py::Policy._save": (2, "data: data/password_policy.json"),
    "pdf_refs.py::remember": (3, "data: data/pdf_refs_seen.json"),
    "pdf_refs.py::remember_kinds": (3, "data: data/pdf_refs_kinds.json"),
    "peace.py::Peace.set": (3, "data: data/peace_of_mind.json"),
    "pipeline_settings.py::install.log_results": (3, "data: data/pipeline_requests.logged.json"),
    "pipeline_settings.py::install.save_api_state": (2, "data: data/pipeline_api.json"),
    "quarterly.py::_write": (1, "data: data/quarterly/<quarter>/"),
    "quarterly.py::_write_json": (2, "data: data/quarterly/"),
    "quarterly.py::build": (9, "data: data/quarterly/ (a temporary folder made inside it, then renamed)"),
    "quarterly.py::install.api_quarterly_purge": (2, "data: data/quarterly/.lock"),
    "quarterly.py::install.make_now": (2, "data: data/quarterly/.lock"),
    "quarterly.py::install.state": (1, "data: data/quarterly/"),
    "quarterly.py::publish": (2, "data: the temporary folder build() made in data/quarterly/"),
    "quarterly.py::set_purge": (1, "data: data/quarterly/"),
    "quarterly.py::sync_permits": (2, "data: data/quarterly/<quarter>/purge_permit.json"),
    "quarterly_pdf.py::write_advisor": (1, "data: the folder publish() writes in data/quarterly/"),
    "quarterly_pdf.py::write_management": (1, "data: the folder publish() writes in data/quarterly/"),
    "region_matches.py::Matches.set": (2, "data: data/region_matches.json"),
    "report_map.py::FeedBuilder.schema": (2, "cli: the private feed builder (report_map.py --build-feed), never the service"),
    "report_map.py::ReportMap.loop": (1, "data: data/.report_map.lock"),
    "report_map.py::_write": (3, "data: data/report_map*.json (the feed builder's own folder when run by hand)"),
    "response_cache.py::save_ttl": (2, "data: data/performance.json"),
    "schedule.py::ReplaySchedule._save": (2, "data: data/schedule.json"),
    "security.py::_own_names": (1, "runs: hostname -I, read only"),
    "seen_index.py::SeenIndex._save": (2, "data: data/seen_names.json"),
    "seen_index.py::SeenIndex.backfill": (2, "data: the lock beside data/seen_names.json"),
    "seen_index.py::SeenIndex.backfill.run": (2, "data: the done-marker and lock beside data/seen_names.json"),
    "settings.py::Settings.save": (2, "data: data/settings.json"),
    "severity_map.py::Ratings.set": (3, "data: data/name_ratings.json"),
    "slow_log.py::record": (2, "data: data/slow_requests.jsonl"),
    "svc_patterns.py::Patterns.add_rule": (2, "data: data/ (the local rules file)"),
    "svc_patterns.py::Patterns.reset": (2, "data: data/pattern_fields_local.json"),
    "svc_patterns.py::Patterns.save": (2, "data: data/pattern_fields_local.json"),
    "system_alerts.py::Alerts.clear": (2, "data: data/system_alerts_seen.json"),
    "system_alerts.py::note_start": (2, "data: data/restarts.jsonl"),
    "task_monitor.py::_cron": (1, "runs: crontab -l, read only"),
    "task_monitor.py::_mongod": (1, "runs: ps, read only"),
    "task_monitor.py::snapshot": (1, "none: Sampler.touch(), the performance sampler, not a file"),
    "tour_prefs.py::TourPrefs.mark": (3, "data: data/tour_seen.json"),
}


# ---------------------------------------------------------------------------------------------------------------- scan
OS_WRITES = {"replace", "rename", "renames", "makedirs", "mkdir", "remove", "unlink", "rmdir", "removedirs", "symlink",
             "link", "chmod", "chown", "truncate", "utime", "mkfifo", "mknod"}
SHUTIL_WRITES = {"copy", "copy2", "copyfile", "copytree", "move", "rmtree", "make_archive", "copymode", "copystat",
                 "chown"}
PATH_WRITES = {"write_text", "write_bytes", "touch", "symlink_to", "hardlink_to"}
TEMP = {"mkstemp", "mkdtemp", "NamedTemporaryFile", "TemporaryFile", "SpooledTemporaryFile", "TemporaryDirectory"}
RUNS = {("subprocess", n) for n in ("run", "Popen", "call", "check_call", "check_output")} | \
       {("os", n) for n in ("system", "popen", "execv", "execve", "execvp", "execl", "spawnv", "spawnl")}
CODE_LOADERS = {"pickle", "marshal", "shelve", "dill", "joblib"}
CODE_ROOT_WORDS = re.compile(r"\b(BASE_DIR|HERE|ROOT|_HERE|_BASE|_d|base_dir|__file__)\b|\[\s*['\"]base_dir['\"]\s*\]")


def _src(node, text):
    return " ".join((ast.get_source_segment(text, node) or "?").split())


def _dotted(f):
    if isinstance(f, ast.Name):
        return (None, f.id)
    if isinstance(f, ast.Attribute):
        base = f.value.id if isinstance(f.value, ast.Name) else None
        return (base, f.attr)
    return (None, None)


def _mode(call, pos):
    m = call.args[pos] if len(call.args) > pos else next((k.value for k in call.keywords if k.arg == "mode"), None)
    if m is None:
        return "r"
    return m.value if isinstance(m, ast.Constant) and isinstance(m.value, str) else "?"


MOVED_FROM_APP = {"analytics_api.py", "report_downloads.py", "infection_kb.py", "lookup_jobs.py", "card_notes.py",
                  "name_definitions.py", "intel_match_api.py"}


def writes_in(rel, text=None):
    """[(qualname, line, kind, path source)] of every write in one file (or in TEXT)."""
    text = open(os.path.join(ROOT, rel), encoding="utf-8").read() if text is None else text
    # the parts moved out of app.py (2026-11-24) reach app.py's names as _A.name (_A.os.replace, _A.open...): read as
    # written in app.py, so every write in them is found (the prefix is the same length on each line it is taken from)
    if os.path.basename(rel) in MOVED_FROM_APP:
        text = text.replace("_A.", "")
    tree = ast.parse(text)
    out = []
    # a path from a small helper of the same file (done_path(base_dir)): what it returns is shown with it
    returns = {}
    for fn in ast.walk(tree):
        if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            rs = [_src(r.value, text) for r in ast.walk(fn) if isinstance(r, ast.Return) and r.value is not None]
            returns.setdefault(fn.name, " ; ".join(rs))

    def shown(p):
        s = _src(p, text)
        if isinstance(p, ast.Call) and isinstance(p.func, ast.Name) and returns.get(p.func.id):
            s += f" -> {returns[p.func.id]}"
        return s

    class V(ast.NodeVisitor):
        def __init__(self):
            self.stack = []

        def _scope(self, node):
            self.stack.append(node.name)
            self.generic_visit(node)
            self.stack.pop()
        visit_FunctionDef = visit_AsyncFunctionDef = visit_ClassDef = _scope

        def add(self, node, kind, paths):
            out.append((".".join(self.stack) or "<module>", node.lineno, kind, " | ".join(shown(p) for p in paths)))

        def visit_Call(self, node):
            base, name = _dotted(node.func)
            a = node.args
            if name == "open" and base in (None, "io", "codecs", "gzip", "bz2", "lzma") and a:
                mode = _mode(node, 1)
                if mode == "?" or set(mode) & set("wax+"):
                    self.add(node, f"open {mode}", a[:1])
            elif base == "os" and name == "open" and len(a) > 1 and re.search(r"O_(WRONLY|RDWR|CREAT|APPEND|TRUNC)", _src(a[1], text)):
                self.add(node, "os.open", a[:1])
            elif base == "os" and name in OS_WRITES and a:
                self.add(node, f"os.{name}", a[:2] if name in ("replace", "rename", "renames", "symlink", "link") else a[:1])
            elif base == "shutil" and name in SHUTIL_WRITES and a:
                self.add(node, f"shutil.{name}", a[:2] if name == "move" else (a[1:2] if len(a) > 1 and name != "rmtree" else a[:1]))
            elif base == "tempfile" and name in TEMP:
                d = next((k.value for k in node.keywords if k.arg == "dir"), None)
                self.add(node, f"tempfile.{name}" + ("" if d is not None else " (private /tmp)"), [d] if d is not None else [])
            elif name in PATH_WRITES and isinstance(node.func, ast.Attribute) and base not in ("os", "shutil"):
                self.add(node, f".{name}", [node.func.value])
            elif base == "sqlite3" and name == "connect" and a and "mode=ro" not in _src(a[0], text):
                self.add(node, "sqlite3.connect", a[:1])
            elif name and name.endswith("FileHandler"):
                self.add(node, name, a[:1])
            elif name == "ZipFile" and _mode(node, 1) != "r":
                self.add(node, f"ZipFile {_mode(node, 1)}", a[:1])
            elif (base, name) in RUNS:
                self.add(node, f"{base}.{name}", a[:1])
            self.generic_visit(node)
    V().visit(tree)
    return out, tree


def runtime_files():
    """The files the service runs: the entries, every platform module they import (at any depth, also inside
    functions), and the scripts it starts with what those import."""
    local = {f[:-3] for f in os.listdir(ROOT) if f.endswith(".py")}
    seen, todo = set(), list(ENTRIES) + list(STARTED)
    while todo:
        rel = todo.pop()
        if rel in seen or not os.path.exists(os.path.join(ROOT, rel)):
            continue
        seen.add(rel)
        tree = ast.parse(open(os.path.join(ROOT, rel), encoding="utf-8").read())
        for n in ast.walk(tree):
            names = []
            if isinstance(n, ast.Import):
                names = [x.name.split(".")[0] for x in n.names]
            elif isinstance(n, ast.ImportFrom) and n.level == 0 and n.module:
                names = [n.module.split(".")[0]]
            elif isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "__import__" and n.args \
                    and isinstance(n.args[0], ast.Constant):
                names = [str(n.args[0].value).split(".")[0]]
            todo += [f"{m}.py" for m in names if m in local]
    return sorted(seen)


# ------------------------------------------------------------------------------------------------------------ 1. unit
print("1. The service template: the code read-only, data/ the only writable folder")
tmpl = open(service_unit.TEMPLATE, encoding="utf-8").read()
d = service_unit.directives(tmpl)
one = lambda k: (d.get(k) or [""])[-1]        # noqa: E731
ok("the service runs as the installing user, in the installed folder", one("User") == "@USER@" and one("WorkingDirectory") == "@PROJECT@")
ok("ProtectSystem=strict (the whole file system read-only for the service)", one("ProtectSystem") == "strict")
ok("ProtectHome=read-only (home folders read-only, a folder there still readable)", one("ProtectHome") == "read-only")
ok("ReadOnlyPaths= names the installed folder (read-only even if ProtectSystem changes)",
   "@PROJECT@" in service_unit.paths_of(d, "ReadOnlyPaths"))
ok(f"ReadWritePaths= is exactly {', '.join(WRITABLE)}", sorted(service_unit.paths_of(d, "ReadWritePaths")) == sorted(WRITABLE),
   str(service_unit.paths_of(d, "ReadWritePaths")))
ok("nothing in the writable folder may be run (NoExecPaths=)", all(w in service_unit.paths_of(d, "NoExecPaths") for w in WRITABLE))
ok("no writable folder is the code folder or holds code",
   not any(p.rstrip("/") in ("@PROJECT@", "@PROJECT@/.venv", "@PROJECT@/.venvs") or not p.startswith("@PROJECT@/data")
           for p in service_unit.paths_of(d, "ReadWritePaths")))
for k, v in (("NoNewPrivileges", "true"), ("PrivateTmp", "true"), ("RestrictSUIDSGID", "true")):
    ok(f"{k}={v}", one(k) == v)
ok("no capability to get round file permissions (CapabilityBoundingSet empty)", one("CapabilityBoundingSet") == "")
ok("its Python and libraries come from the read-only folder", one("ExecStart").startswith("@PROJECT@/.venv/bin/"))
ok("no user name or folder written into the template", not re.search(r"/home/[a-z]|User=[a-z]", tmpl))

# ------------------------------------------------------------------------------------------------- 2. service_unit.py
print("2. deploy/service_unit.py writes the service file and finds an older installed copy")
r = service_unit.render(tmpl, "csirt", "/opt/lg/platform", "127.0.0.1:5000")
rd = service_unit.directives(r)
ok("rendered: data/ of that folder is the only writable path", service_unit.paths_of(rd, "ReadWritePaths") == ["/opt/lg/platform/data"])
ok("rendered: the folder read-only, data/ not executable",
   service_unit.paths_of(rd, "ReadOnlyPaths") == ["/opt/lg/platform"] and service_unit.paths_of(rd, "NoExecPaths") == ["/opt/lg/platform/data"])
ok("rendered: no @...@ left", not re.search(r"@[A-Z]+@", r))
ok("port 5000: no capability", (rd.get("CapabilityBoundingSet") or [""])[-1] == "")
r443 = service_unit.directives(service_unit.render(tmpl, "csirt", "/opt/lg/platform", "0.0.0.0:443"))
ok("port 443: CAP_NET_BIND_SERVICE only", r443["CapabilityBoundingSet"] == ["CAP_NET_BIND_SERVICE"]
   and r443["AmbientCapabilities"] == ["CAP_NET_BIND_SERVICE"])
for bad in (("csirt", "/opt/x\nExecStartPre=/bin/sh", "127.0.0.1:5000"), ("csirt", "/opt/x", "127.0.0.1"), ("", "/opt/x", "127.0.0.1:5000")):
    try:
        service_unit.render(tmpl, *bad)
        refused = False
    except ValueError:
        refused = True
    ok(f"refuses a value a service file cannot carry ({bad!r:.60})", refused)
ok("installed values read back (user, folder, address)",
   service_unit.installed_values(r) == ("csirt", "/opt/lg/platform", "127.0.0.1:5000"))


def check_with(unit_text, name="lgcheck"):
    with tempfile.TemporaryDirectory() as t:
        if unit_text is not None:
            with open(os.path.join(t, f"{name}.service"), "w", encoding="utf-8") as f:
                f.write(unit_text)
        p = subprocess.run([sys.executable, os.path.join(ROOT, "deploy", "service_unit.py"), "check", "--name", name],
                           capture_output=True, text=True, env=dict(os.environ, LG_SYSTEMD_DIR=t), timeout=60)
        return p.returncode, p.stdout + p.stderr


current = service_unit.render(tmpl, "csirt", ROOT, "127.0.0.1:5000")
rc, out = check_with(current)
ok("check: an installed copy of this release is up to date (exit 0)", rc == 0 and "up to date" in out, out[-200:])
older = re.sub(r"(?m)^(ReadOnlyPaths|NoExecPaths)=.*\n", "", current)
rc, out = check_with(older)
ok("check: a copy from before this release is out of date (exit 3) and says what to run",
   rc == 3 and "out of date" in out and "deploy/service_unit.py install --name lgcheck" in out and "+ReadOnlyPaths=" in out, out[-300:])
rc, out = check_with(service_unit.render(tmpl, "csirt", "/somewhere/else", "127.0.0.1:5000"))
ok("check: another folder's service is not compared (exit 4)", rc == 4 and "not this folder" in out, out[-200:])
rc, out = check_with(None)
ok("check: no installed service (a developer copy) says so (exit 4), nothing else", rc == 4 and "not installed here" in out, out[-200:])


def install_with_fakes(old_text, answer_yes=True):
    """deploy/service_unit.py install in a copy of deploy/ (a temporary folder), with sudo, systemctl and
    systemd-analyze replaced by stand-ins that only record what they were asked: no root, nothing in /etc."""
    import shutil
    with tempfile.TemporaryDirectory() as t:
        proj, sysd, fake = (os.path.join(t, n) for n in ("proj", "sys", "bin"))
        for p in (os.path.join(proj, "deploy"), sysd, fake):
            os.makedirs(p)
        for n in ("service_unit.py", "looking-glass.service.template"):
            shutil.copy(os.path.join(ROOT, "deploy", n), os.path.join(proj, "deploy", n))
        log = os.path.join(t, "calls.log")
        for n, body in (("sudo", f'echo "sudo $*" >> {log}; [ "$1" = install ] && exec "$@"; exit 0'),
                        ("systemctl", f'echo "systemctl $*" >> {log}; exit 0'), ("systemd-analyze", "exit 0")):
            with open(os.path.join(fake, n), "w") as f:
                f.write(f"#!/bin/sh\n{body}\n")
            os.chmod(os.path.join(fake, n), 0o755)
        unit = os.path.join(sysd, "lgcheck.service")
        with open(unit, "w", encoding="utf-8") as f:
            f.write(old_text.replace(ROOT, proj))
        p = subprocess.run([sys.executable, os.path.join(proj, "deploy", "service_unit.py"), "install", "--name", "lgcheck"]
                           + (["--yes"] if answer_yes else []), capture_output=True, text=True, stdin=subprocess.DEVNULL,
                           env=dict(os.environ, LG_SYSTEMD_DIR=sysd, PATH=fake + os.pathsep + os.environ.get("PATH", "")), timeout=120)
        calls = open(log).read() if os.path.exists(log) else ""
        now = open(unit, encoding="utf-8").read()
        kept = [os.path.join(dp, f) for dp, _, fs in os.walk(os.path.join(proj, "backups")) for f in fs]
        kept_text = open(kept[0], encoding="utf-8").read() if kept else ""
        return p.returncode, p.stdout + p.stderr, calls, now.replace(proj, ROOT), kept_text.replace(proj, ROOT)


rc, out, calls, now, kept = install_with_fakes(older)
ok("install: replaces the old service file with this release's, keeps the old one in backups/",
   rc == 0 and now == current and kept == older, out[-300:])
ok("install: then reloads systemd and restarts that service (and nothing else)",
   calls.count("sudo ") == 3 and "sudo systemctl daemon-reload" in calls and "sudo systemctl restart lgcheck" in calls, calls)
rc, out, calls, now, kept = install_with_fakes(older, answer_yes=False)
ok("install: not on a terminal and without --yes it changes nothing", rc == 1 and now == older and not calls and not kept, out[-200:])
inst = open(os.path.join(ROOT, "deploy", "install.sh"), encoding="utf-8").read()
upd = open(os.path.join(ROOT, "deploy", "update_libraries.sh"), encoding="utf-8").read()
ok("deploy/install.sh writes the service file with it (one place)", "deploy/service_unit.py render" in inst and "@PROJECT@" not in inst)
ok("deploy/update_libraries.sh checks the installed copy after an update, without sudo",
   "deploy/service_unit.py check" in upd and "sudo" not in upd.split("deploy/service_unit.py check")[1].split("\n")[0])
su = open(os.path.join(ROOT, "deploy", "service_unit.py"), encoding="utf-8").read()
ok("only 'install' uses sudo, and asks first unless --yes", su.count('"sudo"') == 3 and "Type yes" in su and "--yes" in su)

# -------------------------------------------------------------------------------------------------- 3. write inventory
print("3. Every write in the code the service runs goes to data/ (or a temporary file)")
files = runtime_files()
found = {}
loaders = []
for rel in files:
    sites, tree = writes_in(rel)
    for q, line, kind, path in sites:
        found.setdefault(f"{rel}::{q}", []).append((line, kind, path))
    for n in ast.walk(tree):
        if isinstance(n, (ast.Import, ast.ImportFrom)):
            mods = [x.name.split(".")[0] for x in n.names] if isinstance(n, ast.Import) else [(n.module or "").split(".")[0]]
            loaders += [f"{rel}:{n.lineno} imports {m}" for m in mods if m in CODE_LOADERS]
        elif isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id in ("exec", "eval", "compile"):
            loaders.append(f"{rel}:{n.lineno} calls {n.func.id}()")

if "--list" in sys.argv:
    for key in sorted(found):
        print(f"    {key!r}: ({len(found[key])}, \"?\"),")
        for line, kind, path in found[key]:
            print(f"        # {line}: {kind}  {path}")
    sys.exit(0)

ok(f"the service's code was found ({len(files)} files, {sum(len(v) for v in found.values())} writes)",
   len(files) > 50 and "app.py" in files and "config_page.py" in files and STARTED[0] in files)
new = [f"{k}:{line} {kind} {path}" for k, v in sorted(found.items()) if len(v) != INVENTORY.get(k, (0, ""))[0]
       for line, kind, path in v]
ok("every write is in the list with where it goes (a new one: make sure it writes under data/, then add it)",
   not new, "; ".join(new[:8]) + (f" (+{len(new) - 8} more)" if len(new) > 8 else ""))
gone = sorted(set(INVENTORY) - set(found))
ok("every entry in the list still exists (no stale entries)", not gone, ", ".join(gone[:8]))
KINDS = ("data", "tmp", "copy", "runs", "memory", "cli", "none", "refused")
where_bad = sorted(k for k, (n, w) in INVENTORY.items() if w.split(":")[0] not in KINDS)
ok(f"every entry says where it writes: {', '.join(KINDS)}", not where_bad, ", ".join(where_bad[:8]))


def beside_code(kind, path, where="data"):
    """A write whose path is built from the code folder and does not go into data/."""
    return (not kind.startswith(("subprocess.", "os.system", "os.popen", "os.exec", "os.spawn")) and where.split(":")[0] != "tmp"
            and bool(CODE_ROOT_WORDS.search(path)) and "data" not in path)


beside = [f"{k}:{line} {path}" for k, v in sorted(found.items()) for line, kind, path in v
          if beside_code(kind, path, INVENTORY.get(k, (0, "data"))[1])]
ok("nothing writes a path built from the code folder outside data/", not beside, "; ".join(beside[:6]))
ok("nothing the service runs loads code from a file (pickle, marshal, shelve, exec, eval)", not loaders, "; ".join(loaders[:6]))

# ------------------------------------------------------------------------------------- 4. the scan finds what it should
print("4. The scan itself: it finds writes, ignores reads, and catches a write beside the code")
SAMPLE = '''import os, json, shutil, tempfile, sqlite3
from pathlib import Path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
def beside():
    with open(os.path.join(BASE_DIR, "notes.json"), "w") as f:
        json.dump({}, f)
def into_data():
    os.replace("x.tmp", os.path.join(BASE_DIR, "data", "x.json"))
def reads(p):
    with open(p) as f:
        return f.read()
def static_copy():
    shutil.copy2("a", os.path.join(BASE_DIR, "static", "x.js"))
def temp():
    return tempfile.mkstemp()
def read_db():
    return sqlite3.connect("file:x?mode=ro", uri=True)
def pathlib_write():
    Path(BASE_DIR, "templates", "x.html").write_text("x")
'''
got = {q: (kind, path) for q, _line, kind, path in writes_in("sample.py", SAMPLE)[0]}
ok("finds open(..., 'w'), os.replace, shutil.copy2, tempfile and Path.write_text",
   set(got) == {"beside", "into_data", "static_copy", "temp", "pathlib_write"}, str(sorted(got)))
ok("ignores reads (open(p), a read-only database)", "reads" not in got and "read_db" not in got)
ok("a write built from the code folder outside data/ is caught (three of them)",
   all(beside_code(*got[q]) for q in ("beside", "static_copy", "pathlib_write")) and not beside_code(*got["into_data"]))
ok("the import walk reaches modules imported inside functions (features.py, auth.py, management.py, name_sources.py)",
   "app.py" in files and all(f"{m}.py" in files for m in ("features", "auth", "management", "name_sources")))

print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {', '.join(fails)}" if fails else ""))
sys.exit(1 if fails else 0)
