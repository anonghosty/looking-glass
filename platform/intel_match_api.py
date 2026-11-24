# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""Explore a match of Looking Glass asks: only the records that carry the indicator, per name and report

Moved out of app.py unchanged (the app.py refactor, 2026-11-24). Every name it uses from app.py, its own included, is
read from the app module when the code runs (_A.name), so it behaves exactly as it did inside app.py: a name replaced on
app.py reaches this code too. app.py calls install() where this code was, which registers the routes and hooks in the
same order, and keeps every name defined here under its old name.
"""
_A = None          # the app module (app.py), set by install()


class _Recorder:
    """@_R.route(...) and the like: kept in order, registered on the Flask app by install()."""

    def __init__(self):
        self.calls = []

    def __getattr__(self, kind):
        def deco_or_factory(*args, **kwargs):
            if kind in ("before_request", "after_request", "teardown_request", "context_processor") and len(args) == 1 \
                    and callable(args[0]) and not kwargs:
                self.calls.append((kind, (), {}, args[0]))
                return args[0]

            def deco(fn):
                self.calls.append((kind, args, kwargs, fn))
                return fn
            return deco
        return deco_or_factory


_R = _Recorder()




def _combo_fetch(section, cols, start):
    """One day of the given reports straight from MongoDB, inside the constituency, as the day stores load them."""
    end = start + _A.timedelta(days=1)
    out = []
    if section == "infections":
        for s in _A.registry.get():
            if s["name"] not in cols:
                continue
            rows, _ = _A.store._fetch_collection(s, start, end)
            if _A.settings.restricted:
                rows = [e for e in rows if _A.settings.in_scope(e["src_asn"], e["src_ip"]) or _A.settings.in_scope(e["dst_asn"], e["dst_ip"])]
            for e in rows:
                for f, v in list(e.items()):
                    if isinstance(v, _A.datetime):
                        e[f] = _A.iso(v)
            out += rows
    else:
        st = _A.svc["store"]
        for s in _A.svc["registry"].get():
            if s["name"] not in cols:
                continue
            rows, _ = st._fetch(s, start, end)
            if _A.settings.restricted:
                rows = [e for e in rows if _A.settings.in_scope(e["asn"], e["ip"])]
            out += rows
    return out


def _combo_explain(section, name):
    try:
        return _A.issue_resolve(name, fetch=False) if section == "issues" else _A.mp_resolve(name)[0]
    except Exception:                    # noqa: BLE001  (an explanation is a nice-to-have in the PDF)
        return None


def _adm1_shapes():
    """The country's first-level regions (static/data/adm1/<country>.json), as the Executive report draws them; None if absent."""
    p = _A.os.path.join(_A.app.static_folder, "data", "adm1", f"{_A.settings.data['country']}.json")
    try:
        with open(p, encoding="utf-8") as f:
            return _A.json.load(f)
    except (OSError, ValueError):
        return None


def _combo_pdf(spec):
    import reports_pdf
    return reports_pdf.build(spec)


def _people_of(kind):
    """The active accounts that do a job, by what their role may do (roles are configurable): managers (management),
    researchers (definitions), analysts (see addresses and export). Names only, for the "send to" lists."""
    need = {"management": {"management"}, "researcher": {"definitions"}, "analyst": {"unmasked", "export"}, "advisor": {"advisory"}}[kind]
    out = []
    for name, u in _A.AUTH["users"].all().items():
        if (u or {}).get("status") != "active" or name.startswith(_A.auth.TEST_PREFIX):
            continue
        if need <= set(_A.AUTH["roles"].perms(u.get("role") or "")):
            out.append({"user": name, "name": _A.people.name(name), "role": u.get("role") or ""})
    return sorted(out, key=lambda p: p["name"].lower())


def _day_for(platform, iso):
    """A day of either platform: the copy in memory, or loaded from MongoDB and kept a few minutes (recent_days.py:
    an analyst code's page and its counts share one load instead of loading the day again each time)."""
    st = _A.store if platform == "comms" else _A.svc["store"]
    try:
        start = _A.datetime.fromisoformat(iso).replace(tzinfo=_A.timezone.utc)
    except (TypeError, ValueError):
        return None
    d = st.days.get(start)
    if d is not None:
        return d
    # the version a kept copy is valid for: the constituency (settings) and the stored data (the store's generation)
    version = (getattr(getattr(st, "settings", None) or _A.settings, "version", 0), getattr(st, "gen", 0))

    def load():
        try:
            return st._load(start)
        except Exception:                # noqa: BLE001  (an unreadable day: the code has no records)
            _A.app.logger.exception("Analyst code: day %s could not be loaded", iso)
            return None
    return _A.RECENT_DAYS.get((platform, iso), version, load)


def _site_demo():
    """Demo mode for the site (public demo or ?demo=1), not a role without addresses: advisors and admins write here."""
    return bool(_A.PUBLIC_DEMO or _A.request.args.get("demo") == "1")


def install(flask_app, app_module):
    """Register this code's routes and hooks on the Flask app, in their order, and use app_module for its names."""
    global _A
    _A = app_module
    for kind, args, kwargs, fn in _R.calls:
        target = getattr(flask_app, kind)
        if args or kwargs or kind not in ("before_request", "after_request", "teardown_request", "context_processor"):
            target(*args, **kwargs)(fn)
        else:
            target(fn)
