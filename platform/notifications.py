"""Notifications: what changed in the findings a person takes part in, for the bell in every page's header
(static/js/notifications.js).

What a person is notified of: every finding (and case) whose channel they are in (findings.py participants; an admin
too only where they take part, not every finding they may oversee), when someone else moved it since they last
cleared it: a hand-over, a decision, a reply, an advisory drafted or sent, a case closing. A finding waiting for them
(they hold it now) is marked as such. Each notification leads to the place to act: the advisory page for the advisor
who holds it, the review page for the manager deciding a review, else the finding on the Findings page.

Clearing is per person: one notification (opened from the bell) or all of them. Kept in data/notifications.json
(user -> finding -> the time it was cleared up to; run-time data, owner-only file, never shipped).

No address is ever in a notification: findings hold none. The texts are the findings' own (titles, comments), shown
as text by the page, never as HTML.

Administrators also get the system's alerts (system_alerts.py: restarts, pipeline runs, disk, the name refresh), first
in the list, cleared the same way.

API: GET /api/notifications · POST /api/notifications/clear {ids: [...]} or {all: true}. Installed from app.py.
"""
import json
import os
import threading
import time

from flask import g, jsonify, request

MAX_ITEMS = 40
TEXT_MAX = 160


class Seen:
    """Per person, per finding: the time their notifications were cleared up to."""

    def __init__(self, path):
        self.path = path
        self.lock = threading.Lock()

    def _load(self):
        try:
            with open(self.path, encoding="utf-8") as fh:
                d = json.load(fh)
            return d if isinstance(d, dict) else {}
        except (OSError, ValueError):
            return {}

    def of(self, user):
        with self.lock:
            return dict(self._load().get(user) or {})

    def clear(self, user, upto):
        """upto: {finding id: time}; later times only (a clear never brings an old one back)."""
        with self.lock:
            d = self._load()
            mine = d.setdefault(user, {})
            for fid, t in upto.items():
                mine[str(fid)] = max(float(mine.get(str(fid)) or 0), float(t))
            os.makedirs(os.path.dirname(self.path), exist_ok=True)
            tmp = f"{self.path}.{os.getpid()}.tmp"
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(d, fh)
            os.replace(tmp, self.path)


def install(app, ctx):
    """ctx: base_dir, findings (findings.Findings), has_perm(p), csrf_ok(), people_name(user), labels (status -> label)."""
    F, hp = ctx["findings"], ctx["has_perm"]
    seen = Seen(os.path.join(ctx["base_dir"], "data", "notifications.json"))
    label = ctx["labels"]
    system = ctx.get("system")                  # system_alerts.Alerts: restarts, pipeline runs, disk, name refresh

    def system_for(user):
        """Administrators only ('settings'): the system's alerts, first (system_alerts.py)."""
        if not system or not hp("settings"):
            return []
        try:
            return system.for_user(user)
        except Exception:  # noqa: BLE001  (an unreadable status file never breaks the bell)
            return []

    def me():
        return (getattr(g, "user", None) or {}).get("user", "")

    def what(h):
        """One history entry in a few words (the entry's own words, cut at a word)."""
        kind = h.get("kind") or "status"
        if kind == "reply":
            head = "replied" + (" (no combination of interest: closed)" if h.get("none_found") else "")
        elif kind == "decision":
            head = "approved" if h.get("decision") == "accepted" else "rejected"
        elif kind == "advisory_sent":
            head = "advisory sent"
        elif kind == "case":
            head = "case " + ("closed" if h.get("status") == "closed" else "updated")
        else:
            head = "moved it to " + label(h.get("status", ""))
        c = " ".join(str(h.get("comment") or "").split())
        if len(c) > TEXT_MAX:
            c = c[:TEXT_MAX].rsplit(" ", 1)[0] + "…"
        return head + (f": {c}" if c else "")

    def link(x, user):
        """Where to act on it: the advisory for its advisor, the review for the manager deciding it, else the finding."""
        fid = x["id"]
        holds = x.get("assignee") == user and x["status"] not in ("closed", "advisory")
        if holds and x["status"] == "advisor" and x.get("kind") != "case" and hp("advisory"):
            return f"/advisory/{fid}"
        if holds and x.get("review") and not x["review"].get("decision") and hp("management"):
            return f"/review/{fid}"
        return f"/findings#f{fid}"

    def items_for(user):
        cleared = seen.of(user)
        with F.lock:
            F._load()
            mine = [x for x in F.data["items"].values() if user in (x.get("participants") or [])]
        out = []
        for x in mine:
            since = float(cleared.get(x["id"]) or 0)
            news = [h for h in x.get("history") or [] if h.get("user") != user and float(h.get("at") or 0) > since]
            if not news:
                continue
            h = news[-1]
            waiting = x.get("assignee") == user and x["status"] not in ("closed", "advisory") and x.get("kind") != "case"
            out.append({"id": x["id"], "number": f"#{x['id']}", "case": x.get("kind") == "case", "network": x.get("network") or "",
                        "title": x["title"], "status": x["status"], "status_label": label(x["status"]),
                        "by": ctx["people_name"](h.get("user", "")), "text": what(h), "updates": len(news),
                        "at": float(h.get("at") or 0), "when": time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(float(h.get("at") or 0))),
                        "waiting": waiting, "link": link(x, user)})
        out.sort(key=lambda n: (not n["waiting"], -n["at"]))
        return out

    @app.route("/api/notifications")
    def api_notifications():
        user = me()
        if not user:
            return jsonify(error="Sign in."), 401
        if (getattr(g, "user", None) or {}).get("peace"):       # Peace of mind: no findings notification comes in
            return jsonify(count=0, waiting=0, items=[], peace=True)
        items = system_for(user) + items_for(user)
        return jsonify(count=len(items), waiting=sum(1 for n in items if n["waiting"]), items=items[:MAX_ITEMS])

    @app.route("/api/notifications/clear", methods=["POST"])
    def api_notifications_clear():
        """Clear one (opened from the bell), several, or all of this person's notifications: up to now, for them only."""
        user = me()
        if not user:
            return jsonify(error="Sign in."), 401
        if not ctx["csrf_ok"]():
            return jsonify(error="Refused (the request did not come from this page)."), 403
        b = request.get_json(silent=True) or {}
        current = {n["id"]: n["at"] for n in items_for(user)}
        sys_now = [n["id"] for n in system_for(user)]
        if b.get("all"):
            ids = list(current) + sys_now
        else:
            ids = [str(i) for i in (b.get("ids") or [])][:200]
        upto = {i: current[i] for i in ids if i in current}          # only their own notifications, never another finding
        if upto:
            seen.clear(user, upto)
        n_sys = system.clear(user, [i for i in ids if i in sys_now]) if system else 0
        upto.update({i: 0 for i in ids if i in sys_now and n_sys})
        left = system_for(user) + items_for(user)
        return jsonify(ok=True, cleared=len(upto), count=len(left), waiting=sum(1 for n in left if n["waiting"]))

    return seen
