#!/bin/sh
# runs itself with the project's own Python (.venv), from wherever it is called
''''exec "$(dirname -- "$0")/../.venv/bin/python" "$0" "$@" # '''
"""Download the offline name sources (offline_names.py) into data/: MISP Galaxy clusters (malpedia, botnet, tool) and
MITRE ATT&CK (enterprise, mobile, ICS; malware and tools only). Only compact indexes are kept:
data/names_misp_galaxy.json and data/names_attack.json. The downloaded files themselves are not kept.

This is the only time these sources are contacted: look-ups read the files in data/ and send nothing anywhere. The
requests are plain downloads of public files from raw.githubusercontent.com; they carry no name, host or report.

At most once a week: a source downloaded less than 7 days ago is skipped (use --force to download it anyway).
A download is used only if it is valid JSON with enough entries and not suddenly much smaller (under 70%) than the copy
in use; otherwise the old copy stays and the reason is logged (data/names_refresh.log, data/names_refresh.json). Every
refresh is in the audit log with its date, counts and the ATT&CK version.
Usage: manage/fetch_offline_names.py [--force] [--only misp|attack] [--by NAME] [--status] [--schedule | --unschedule]
  --schedule adds the weekly refresh to this user's crontab (Mondays 04:17), --unschedule removes it.
"""
import json
import os
import sys
import tempfile
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
import offline_names as ON  # noqa: E402
import attack_map as AM  # noqa: E402

DATA = os.environ.get("LG_OFFLINE_NAMES_DIR") or os.path.join(ROOT, "data")
MAX_BYTES = 200 * 1024 * 1024           # ATT&CK enterprise is about 55 MB; anything far larger is not what we expect
TIMEOUT = 60
ON_STATUS = "names_refresh.json"        # the last refresh: when, by whom, counts, why it failed (Definitions page)
LOG_FILE = "names_refresh.log"          # every message, kept to the last 500 lines
LOG_KEEP = 500


def log(msg):
    print(msg, flush=True)
    try:
        path = os.path.join(DATA, LOG_FILE)
        lines = []
        if os.path.exists(path):
            with open(path, encoding="utf-8") as f:
                lines = f.read().splitlines()[-(LOG_KEEP - 1):]
        lines.append(f"{datetime.now(timezone.utc).isoformat(timespec='seconds')} {msg}")
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
        os.chmod(path, 0o640)
    except OSError:
        pass


def download(url):
    """A public file, streamed to a temporary file (size-capped), parsed as JSON; the temporary file is removed."""
    req = urllib.request.Request(url, headers={"User-Agent": "LookingGlass/1.0 (offline name sources)", "Accept": "application/json"})
    fd, tmp = tempfile.mkstemp(prefix=".lg-dl-", dir=DATA)
    try:
        size = 0
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r, os.fdopen(fd, "wb") as out:
            if not r.geturl().startswith("https://"):
                raise RuntimeError(f"redirected away from https: {r.geturl()}")
            while True:
                chunk = r.read(1 << 20)
                if not chunk:
                    break
                size += len(chunk)
                if size > MAX_BYTES:
                    raise RuntimeError(f"{url} is larger than {MAX_BYTES // (1 << 20)} MB: refused")
                out.write(chunk)
        with open(tmp, encoding="utf-8") as f:
            return json.load(f)
    finally:
        try:
            os.remove(tmp)
        except OSError:
            pass


def age_days(fname):
    try:
        with open(os.path.join(DATA, fname), encoding="utf-8") as f:
            at = json.load(f).get("fetched", "")
        return (datetime.now(timezone.utc) - datetime.fromisoformat(at)).total_seconds() / 86400
    except (OSError, ValueError, TypeError):
        return None


def save(fname, doc):
    doc["fetched"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    path = os.path.join(DATA, fname)
    tmp = f"{path}.{os.getpid()}.tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False, separators=(",", ":"))
    os.chmod(tmp, 0o640)
    os.replace(tmp, path)
    log(f"  saved {path} ({len(doc['entries'])} entries, {os.path.getsize(path) // 1024} KB)")


MIN_ENTRIES = 100            # fewer than this: not the file we expect
MIN_KEV = 50                 # CVEs in the KEV mappings below which the file is not what we expect
MIN_SHARE = 0.7              # a new copy with fewer than 70% of the old copy's entries is refused ("suddenly much smaller")


def old_count(fname):
    try:
        with open(os.path.join(DATA, fname), encoding="utf-8") as f:
            return len(json.load(f).get("entries") or [])
    except (OSError, ValueError, AttributeError):
        return 0


def check(title, fname, doc):
    """The download is used only if it looks right: enough entries, and not suddenly much smaller than the copy in
    use. Otherwise the old copy stays and the reason is logged (and in the audit log)."""
    n, old = len(doc.get("entries") or []), old_count(fname)
    if n < MIN_ENTRIES:
        raise RuntimeError(f"{title} gave only {n} entries: not used")
    if old and n < old * MIN_SHARE:
        raise RuntimeError(f"{title} gave {n} entries, far fewer than the {old} in use: not used")
    return n


def fetch_misp():
    clusters = {}
    for c in ON.MISP_CLUSTERS:
        url = ON.MISP_URL.format(c)
        log(f"  downloading {url}")
        clusters[c] = download(url)
    doc = ON.build_misp(clusters)
    check("MISP Galaxy", ON.MISP_FILE, doc)
    save(ON.MISP_FILE, doc)
    return {"entries": len(doc["entries"]), "versions": doc.get("versions") or {}}


def fetch_attack():
    bundles = {}
    for dom, url in ON.ATTACK_URLS.items():
        log(f"  downloading {url}")
        bundles[dom] = download(url)
    doc = ON.build_attack(bundles)
    full = doc.pop("full", {})                        # full descriptions: their own file, read only when one is expanded
    check("MITRE ATT&CK", ON.ATTACK_FILE, doc)
    try:                                              # the copy in use, to compare the new version with
        with open(os.path.join(DATA, ON.ATTACK_FILE), encoding="utf-8") as f:
            old = json.load(f)
    except (OSError, ValueError):
        old = {}
    save(ON.ATTACK_FILE, doc)
    p = os.path.join(DATA, ON.FULL_FILE)
    tmp = f"{p}.{os.getpid()}.tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump({"versions": doc.get("versions") or {}, "fetched": doc.get("fetched"), "descriptions": full}, f, ensure_ascii=False, separators=(",", ":"))
    os.chmod(tmp, 0o640)
    os.replace(tmp, p)
    out = {"entries": len(doc["entries"]), "versions": doc.get("versions") or {},
           "techniques": sum(1 for t in (doc.get("techniques") or {}).values() if t.get("state") == "active")}
    try:                                              # a new ATT&CK version: affected mappings to "please check"
        update = AM.apply_update(DATA, old, doc)
    except (OSError, ValueError) as exc:
        update = None
        log(f"  the mappings could not be compared with the new version: {exc}")
    if update:
        log(f"  {update['text']}")
        out["update"] = {k: update[k] for k in ("from", "to", "to_check", "new_techniques", "renamed", "retired", "split", "software_updated", "text")}
    return out


def fetch_kev():
    """MITRE CTID Mappings Explorer: CISA KEV -> ATT&CK (Apache 2.0). The newest enterprise file in the repository."""
    log(f"  listing {AM.KEV_TREE}")
    path = AM.latest_kev_path(download(AM.KEV_TREE))
    if not path:
        raise RuntimeError("no KEV mapping file found in the repository listing")
    log(f"  downloading {AM.KEV_RAW + path}")
    kev = AM.build_kev(download(AM.KEV_RAW + path), path)
    n, old = kev["count"], 0
    try:
        with open(os.path.join(DATA, AM.KEV_FILE), encoding="utf-8") as f:
            old = json.load(f).get("count") or 0
    except (OSError, ValueError):
        pass
    if n < MIN_KEV:
        raise RuntimeError(f"CTID KEV mappings gave only {n} CVEs: not used")
    if old and n < old * MIN_SHARE:
        raise RuntimeError(f"CTID KEV mappings gave {n} CVEs, far fewer than the {old} in use: not used")
    kev["fetched"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    p = os.path.join(DATA, AM.KEV_FILE)
    tmp = f"{p}.{os.getpid()}.tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(kev, f, separators=(",", ":"))
    os.chmod(tmp, 0o640)
    os.replace(tmp, p)
    log(f"  saved {p} ({n} CVEs, mapped with ATT&CK {kev['attack_version']}, KEV of {kev['kev_date']})")
    return {"entries": n, "versions": {"attack": kev["attack_version"], "kev": kev["kev_date"]}}


def audit(by, ok, detail):
    """Every refresh (automatic or from the button), with its date, counts and the ATT&CK version, in the platform's
    tamper-evident audit log (auth.Audit, the same file the platform writes)."""
    try:
        import auth
        auth.Audit(os.path.join(DATA, "audit.log")).add("name_sources_refreshed" if ok else "name_sources_refresh_failed",
                                                        user=by, target="MISP Galaxy, MITRE ATT&CK", detail=detail, ip="", ua="fetch_offline_names")
    except Exception as exc:                        # noqa: BLE001  (never let the log stop the refresh; say so)
        log(f"  audit log not written: {exc}")


def audit_event(by, event, target, detail):
    try:
        import auth
        auth.Audit(os.path.join(DATA, "audit.log")).add(event, user=by, target=target, detail=detail, ip="", ua="fetch_offline_names")
    except Exception as exc:                        # noqa: BLE001
        log(f"  audit log not written: {exc}")


def write_status(rec):
    path = os.path.join(DATA, ON_STATUS)
    tmp = f"{path}.{os.getpid()}.tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(rec, f, indent=1)
    os.chmod(tmp, 0o640)
    os.replace(tmp, path)


CRON_TAG = "# looking-glass-name-sources"


def schedule(on):
    """Add (or remove) the weekly refresh to this user's crontab, like the pipeline's schedule: Mondays 04:17."""
    import shutil
    import subprocess
    if not shutil.which("crontab"):
        log("crontab is not installed (Ubuntu: sudo apt install cron). The line to add by hand:")
        log(f"  17 4 * * 1  {os.path.abspath(__file__)} --by schedule >/dev/null 2>&1 {CRON_TAG}")
        return 1
    cur = subprocess.run(["crontab", "-l"], capture_output=True, text=True)
    lines = [ln for ln in (cur.stdout.splitlines() if cur.returncode == 0 else []) if CRON_TAG not in ln]
    if on:
        lines.append(f"17 4 * * 1  {os.path.abspath(__file__)} --by schedule >/dev/null 2>&1 {CRON_TAG}")
    subprocess.run(["crontab", "-"], input="\n".join(lines) + "\n", text=True, check=True)
    log("weekly refresh scheduled: Mondays at 04:17 (crontab)" if on else "weekly refresh removed from the crontab")
    return 0


def main(argv):
    force = "--force" in argv
    only = argv[argv.index("--only") + 1] if "--only" in argv and argv.index("--only") + 1 < len(argv) else ""
    by = (argv[argv.index("--by") + 1] if "--by" in argv and argv.index("--by") + 1 < len(argv) else "manage script")[:60]
    if only not in ("", "misp", "attack", "kev"):
        log("--only takes misp, attack or kev"); return 2
    os.makedirs(DATA, exist_ok=True)
    if "--schedule" in argv or "--unschedule" in argv:
        return schedule("--schedule" in argv)
    if "--status" in argv:
        for k, v in ON.OfflineNames(DATA).status().items():
            log(f"{k}: {'installed, ' + str(v['entries']) + ' entries, downloaded ' + v['fetched'] if v['installed'] else 'not installed'}"
                + (f", versions {v['versions']}" if v.get("versions") else ""))
        return 0
    rc, results, ran = 0, {}, False
    for key, fname, fn, title in (("misp", ON.MISP_FILE, fetch_misp, "MISP Galaxy"), ("attack", ON.ATTACK_FILE, fetch_attack, "MITRE ATT&CK"),
                                  ("kev", AM.KEV_FILE, fetch_kev, "CTID KEV to ATT&CK mappings")):
        if only and only != key:
            continue
        age = age_days(fname)
        if age is not None and age < ON.REFRESH_DAYS and not force:
            log(f"{title}: downloaded {age:.1f} days ago; refreshed at most once every {ON.REFRESH_DAYS} days (--force to download now)")
            continue
        ran = True
        log(f"{title}:")
        t = time.time()
        try:
            results[key] = {"ok": True, **fn()}
            log(f"  done in {time.time() - t:.0f} s")
        except (urllib.error.URLError, TimeoutError, OSError, ValueError, RuntimeError) as exc:
            log(f"  FAILED: {exc} (the copy already in data/, if any, is kept)")
            results[key] = {"ok": False, "message": str(exc)[:200], "entries": old_count(fname)}
            rc = 1
    if not ran:
        return 0
    att = (results.get("attack") or {}).get("versions") or ON.OfflineNames(DATA).status()["mitre-attack"]["versions"]
    att_v = (att or {}).get("enterprise") or next(iter((att or {}).values()), "")
    parts = []
    for key, title in (("misp", "MISP Galaxy"), ("attack", "ATT&CK"), ("kev", "KEV mappings")):
        x = results.get(key)
        if x:
            parts.append(f"{title} {x['entries']} entries" + ("" if x["ok"] else f" (refresh failed, old copy kept: {x['message']})"))
    detail = "; ".join(parts) + (f"; ATT&CK version in use {att_v}" if att_v else "")
    write_status({"at": datetime.now(timezone.utc).isoformat(timespec="seconds"), "by": by, "ok": rc == 0,
                  "message": detail, "results": results, "attack_version": att_v})
    audit(by, rc == 0, detail)
    upd = (results.get("attack") or {}).get("update")
    if upd:                                           # a new ATT&CK version: one audit entry, old and new version, counts
        audit_event(by, "attack_version_update", f"ATT&CK v{upd['from'] or '?'} → v{upd['to'] or '?'}",
                    f"{upd['text']}; retired {upd['retired']}, split {upd['split']}")
    return rc


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
