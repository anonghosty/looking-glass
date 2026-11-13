"""The database pipeline beside the platform: where it is, its .env, and its sender check (mail_auth.py).

Looking Glass installs the platform and the pipeline side by side (platform/ and database/, or ~/threatmap and
~/shadowserver). The Workers tab of Settings (pipeline_settings.py) reads the pipeline's settings and rules, and the
Audit portal's Sender check (sender_audit.py) reads its results; both go through here, read-only. PIPELINE_DIR in the platform's .env names the
folder when it is elsewhere. When the pipeline runs on another computer, nothing here finds it and both say so.
"""
import importlib.util
import os
from pathlib import Path


def find_dir(base_dir):
    """The pipeline's folder, or None."""
    cands = [os.environ.get("PIPELINE_DIR") or ""] + [str(Path(base_dir).parent / n) for n in ("database", "shadowserver")]
    for c in cands:
        if c and (Path(c) / "shadowserver_pipeline.py").exists():
            return Path(c).resolve()
    return None


def read_env(path):
    """{KEY: value} of an .env file (values as the pipeline reads them: literal, optional quotes)."""
    out = {}
    try:
        lines = Path(path).read_text(encoding="utf-8").splitlines()
    except OSError:
        return out
    for ln in lines:
        s = ln.strip()
        if s and not s.startswith("#") and "=" in s:
            k, v = s.split("=", 1)
            v = v.strip()
            if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
                v = v[1:-1]
            out.setdefault(k.strip(), v)     # a key written twice: the first counts, as in the pipeline
    return out


# (no writing here: the platform never writes the pipeline's files; changes are requests the pipeline applies,
# worker_settings.py in the pipeline's folder)
_mods = {}


def module(pdir, name):
    """One of the pipeline's own modules (one copy of its rules: the platform never re-implements them), or None.
    Only read: the platform's service may read the pipeline's folder, never write it."""
    p = Path(pdir) / f"{name}.py" if pdir else None
    if not p or not p.exists():
        return None
    key = (name, str(p), p.stat().st_mtime)
    if key not in _mods:
        spec = importlib.util.spec_from_file_location(f"lg_pipeline_{name}", p)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        for k in [k for k in _mods if k[0] == name]:
            del _mods[k]
        _mods[key] = mod
    return _mods[key]


def mail_auth(pdir):
    return module(pdir, "mail_auth")


def worker_settings(pdir):
    return module(pdir, "worker_settings")
