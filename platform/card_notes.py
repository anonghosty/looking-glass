# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""The researchers' notes on every explanation card (map, services, Executive, PDF)

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




def _noted(card, section, name):
    n = vars(_A).get("NOTES")
    return n.attach(card, section, name) if n else card


def mp_resolve(name):  # noqa: F811
    card, r = _A._mp_resolve_plain(name)
    return _A._noted(card, "infections", name), r


def _with_attack(card, name):
    """ATT&CK techniques of a CVE, or of the CVEs an issue names (CTID's KEV mappings, local copy; attack_map.py)."""
    try:
        att = _A.ATTACK.issue_attack(card, name)
    except Exception:                              # noqa: BLE001  (a damaged copy must never break a look-up)
        att = None
    if att:
        card = dict(card, attack=att)
    return card


def issue_resolve(name, fetch=True):  # noqa: F811
    return _A._with_attack(_A._noted(_A._issue_resolve_plain(name, fetch=fetch), "issues", name), name)


def issues_resolve(names, budget=15.0, progress=None, stop=None):  # noqa: F811
    return {n: _A._with_attack(_A._noted(c, "issues", n), n)
            for n, c in _A._issues_resolve_plain(names, budget=budget, progress=progress, stop=stop).items()}


@_R.route("/api/malpedia/batch")
def api_malpedia_batch():
    """Enrich a list of infections / categories: each unique name is looked up once (cached for a week, so repeated
    lists cost no Malpedia calls). ?values=a,b,c (at most 80). For each: the matching Malpedia family, or why none."""
    if not _A.AUTH["has_perm"]("malpedia"):
        return _A.jsonify(error="Your role cannot use Malpedia lookups (permission 'malpedia')."), 403
    names = []                                       # without a Malpedia token the researchers' definitions answer
    for v in (_A.request.args.get("values") or "").split(","):
        v = v.strip()
        if v and len(v) <= 100 and v.lower() not in {n.lower() for n in names}:
            names.append(v)
    if len(names) > 80:
        return _A.jsonify(error="At most 80 names at a time."), 400
    out, pending = {}, 0
    for v in names:
        if _A.is_demo() and v.startswith("ref:"):          # masked references are not names
            continue
        try:
            out[v] = _A.mp_resolve(v)[0]
            continue
        except ValueError as exc:
            out[v] = {"found": False, "reason": _A.security.public_error(exc)}
            continue
        except RuntimeError as exc:                     # rate limit or Malpedia unreachable: try again later
            pending += 1
            out[v] = {"found": False, "pending": True, "reason": f"Not checked yet: {_A.security.public_error(exc, 'Malpedia did not answer')}. Try again in a minute."}
    return _A.jsonify(results=out, looked_up=len(names), pending=pending, malpedia=_A.malpedia.enabled)


@_R.route("/api/malpedia")
def api_malpedia():
    """Look up a field value on Malpedia: ?field=infection|tag|family|md5|sha256&value=... (token stays here)."""
    if not _A.AUTH["has_perm"]("malpedia"):          # permission first: the answer must not depend on the set-up
        return _A.jsonify(error="Your role cannot use Malpedia lookups (permission 'malpedia')."), 403
    field = _A.request.args.get("field", "infection")
    value = _A.request.args.get("value", "")
    if not _A.malpedia.enabled and field not in ("infection", "tag"):     # names still get the researchers' definitions
        return _A.jsonify(error="Malpedia lookups are not set up (MALPEDIA_TOKEN in .env)."), 503
    if field not in _A.MALPEDIA_FIELDS:
        return _A.jsonify(error=f"field must be one of {', '.join(_A.MALPEDIA_FIELDS)}"), 400
    try:
        if field in ("infection", "tag"):
            card, r = _A.mp_resolve(value)
            r = dict(r)
            r["card"] = card                         # the whole card, all sources (name_sources.py): the page shows it as is
            if card.get("kind") == "actor":
                r["actor_card"] = card
            elif card.get("curated"):
                r["curated"] = card
            elif not card.get("found"):
                r["explain"] = card
            elif card.get("curated_references"):
                r["curated_references"] = card["curated_references"]
                if card.get("matched_by") == "the administrator's definition":
                    r["matches"] = [{"id": card["family"], "matched_by": card["matched_by"], "alt_names": []}]
        else:
            r = _A.malpedia.lookup(field, value)
    except ValueError as e:
        return _A.jsonify(error=_A.security.public_error(e)), 400
    except RuntimeError as e:
        return _A.jsonify(error=_A.security.public_error(e, "Malpedia did not answer. Try again in a minute.")), 429 if "Too many" in str(e) else 502
    return _A.jsonify(r)


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
