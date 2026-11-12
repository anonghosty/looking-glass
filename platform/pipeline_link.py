"""The database pipeline beside the platform: where it is, its .env, and its sender check (mail_auth.py).

Looking Glass installs the platform and the pipeline side by side (platform/ and database/, or ~/threatmap and
~/shadowserver). The Workers tab of Settings (pipeline_settings.py) edits the pipeline's .env, and the Audit portal's
Sender check (sender_audit.py) reads its results; both go through here. PIPELINE_DIR in the platform's .env names the
folder when it is elsewhere. When the pipeline runs on another computer, nothing here finds it and both say so.
"""
import importlib.util
import os
import re
import tempfile
from pathlib import Path

KEY_RX = re.compile(r"^[A-Z][A-Z0-9_]{1,63}$")


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
            out[k.strip()] = v
    return out


def write_env(path, updates):
    """Set KEY=value lines in place (a key not there yet is added at the end); everything else, comments and passwords
    included, stays exactly as it was. Written to a temporary file and moved over, keeping the file's mode (600)."""
    path = Path(path)
    for k, v in updates.items():
        if not KEY_RX.match(k):
            raise ValueError(f"not a setting name: {k!r}")
        if "\n" in str(v) or "\r" in str(v):
            raise ValueError(f"{k}: one line only")
    lines = path.read_text(encoding="utf-8").splitlines() if path.exists() else []
    left = dict(updates)
    for i, ln in enumerate(lines):
        m = re.match(r"^\s*([A-Z][A-Z0-9_]*)\s*=", ln)
        if m and m.group(1) in left:
            lines[i] = f"{m.group(1)}={left.pop(m.group(1))}"
    if left:
        lines += ["", "# set from Looking Glass Settings → Workers"] + [f"{k}={v}" for k, v in left.items()]
    mode = path.stat().st_mode & 0o777 if path.exists() else 0o600
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".env.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")
        os.chmod(tmp, mode or 0o600)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


_mods = {}


def mail_auth(pdir):
    """The pipeline's own mail_auth.py (one copy of the rules: the platform never re-implements them), or None."""
    p = Path(pdir) / "mail_auth.py" if pdir else None
    if not p or not p.exists():
        return None
    key = (str(p), p.stat().st_mtime)
    if key not in _mods:
        spec = importlib.util.spec_from_file_location("lg_pipeline_mail_auth", p)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        _mods.clear()
        _mods[key] = mod
    return _mods[key]
