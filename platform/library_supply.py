"""Library files refused at installation (suspected tampering), in the audit log and the administrators' bell.

deploy/safe_libraries.py installs every Python library only when its file matches the sha256 value in the lock
(requirements.lock). A file that does not match is refused and written to suspected-packages.json (and .txt) in the
installation folder: the top of the Looking Glass folder for the guided installer, else the part's own folder. This
module reads those reports (the platform's folder, the folder above it, the database pipeline's), and:
  - writes each event once into the audit log, as a system event (library_suspected), when the service starts;
  - shows administrators one bell alert for the newest events (system_alerts.py), until they clear it.
Nothing here holds an address or a report's content; the events name a library, a version, a source and two hashes.
"""
import calendar
import json
import os
import threading
import time

import pipeline_link

REPORT = "suspected-packages.json"
SEEN = "suspected_packages_audited.json"
SYSTEM_USER = "looking-glass"
SHOW_DAYS = 30                       # an alert for events newer than this


def report_dirs(base_dir):
    """Where installations write their report: the platform's folder, the Looking Glass folder above it, the pipeline's."""
    out = [base_dir]
    top = os.path.dirname(os.path.abspath(base_dir))
    if os.path.isfile(os.path.join(top, "install.sh")):
        out.append(top)
    try:
        pdir = pipeline_link.find_dir(base_dir)
    except Exception:                    # noqa: BLE001  (no pipeline here)
        pdir = None
    if pdir:
        out.append(str(pdir))
    return list(dict.fromkeys(os.path.abspath(d) for d in out))


def events(base_dir):
    """Every recorded event, oldest first, each once (by its id)."""
    seen, out = set(), []
    for d in report_dirs(base_dir):
        try:
            with open(os.path.join(d, REPORT), encoding="utf-8") as f:
                evs = (json.load(f) or {}).get("events") or []
        except (OSError, ValueError, AttributeError):
            continue
        for e in evs:
            if isinstance(e, dict) and e.get("id") and e["id"] not in seen:
                seen.add(e["id"])
                out.append(e)
    return sorted(out, key=lambda e: str(e.get("time", "")))


def _ts(e):
    """The event's time (written in UTC) as seconds."""
    try:
        return float(calendar.timegm(time.strptime(str(e.get("time", ""))[:19], "%Y-%m-%dT%H:%M:%S")))
    except ValueError:
        return 0.0


def bell(base_dir, now=None):
    """One alert for the events of the last SHOW_DAYS days, for system_alerts.Alerts (administrators only)."""
    now = now or time.time()
    recent = [e for e in events(base_dir) if now - _ts(e) < SHOW_DAYS * 86400]
    if not recent:
        return []
    last = recent[-1]
    libs = sorted({f"{e.get('library')} {e.get('version')}" for e in recent})
    stopped = any(str(e.get("outcome", "")).startswith("stopped") for e in recent)
    what = (", ".join(libs[:3]) + (f" and {len(libs) - 3} more" if len(libs) > 3 else ""))
    return [{"key": f"suspected-packages:{last['id']}", "problem": True,
             "title": "A library file did not match its lock (suspected tampering)",
             "text": (f"{len(recent)} library file(s) were refused during an installation or update since "
                      f"{time.strftime('%Y-%m-%d', time.gmtime(_ts(recent[0])))}: {what}, from {last.get('source', 'a source')}. "
                      + ("Nothing was changed when no source had a matching file. " if stopped
                         else "A matching copy from another source was installed. ")
                      + "suspected-packages.txt in the installation folder lists the hashes; please report it "
                        "(docs/INSTALLATION.md, 'When a library file does not match')."),
             "at": _ts(last), "link": "/audit", "perms": ("settings",)}]


def audit_new(base_dir, audit):
    """Each event not yet in the audit log, once (the ids written are kept in data/suspected_packages_audited.json)."""
    path = os.path.join(base_dir, "data", SEEN)
    try:
        with open(path, encoding="utf-8") as f:
            done = set(json.load(f).get("ids") or [])
    except (OSError, ValueError, AttributeError):
        done = set()
    new = [e for e in events(base_dir) if e["id"] not in done]
    for e in new:
        audit.add("library_suspected", user=SYSTEM_USER, target=f"{e.get('library')} {e.get('version')}",
                  detail=(f"{e.get('source')} ({e.get('source_url', '')}): file {e.get('file')} has sha256 "
                          f"{e.get('received')}, not one of the {len(e.get('expected') or [])} in {e.get('lock', 'the lock')}; "
                          f"{e.get('outcome', '')}"), ip="", ua="safe_libraries")
        done.add(e["id"])
    if new:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        tmp = f"{path}.{os.getpid()}.tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump({"ids": sorted(done)}, f)
        os.replace(tmp, path)
    return len(new)


def install(app, ctx):
    """ctx: base_dir, audit, serving, logger. In the running service only: the new events into the audit log, a minute
    after the start (an installation or update ends with a restart)."""
    def later():
        time.sleep(60)
        try:
            audit_new(ctx["base_dir"], ctx["audit"])
        except Exception:                # noqa: BLE001  (logged; tried again at the next start)
            if ctx.get("logger"):
                ctx["logger"].exception("suspected library files: not written to the audit log")
    if ctx.get("serving"):
        threading.Thread(target=later, daemon=True, name="library-supply").start()
    return {"events": lambda: events(ctx["base_dir"]), "audit_new": lambda: audit_new(ctx["base_dir"], ctx["audit"])}
