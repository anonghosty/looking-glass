"""Findings: a researcher's note the team follows up, from the first look to the advisory.

The workflow behind it: a researcher finds something (Intel gathered, "Looking Glass asks") and writes a note with the
exact combinations it is about (combination codes); management weighs it against the trends; an analyst pulls the devices
behind the codes (the Combinations page), enriches them and writes the advisory. The mails between them stay as they
are; this keeps the state in one place, so nobody has to search their mailbox to know where a finding stands.

A finding is made from a note ("Track as a finding" in the Notes window). It has a number (#1, #2 …), a title, the note's
text and codes (a copy: removing the note later does not lose the finding), and a status with its history: who moved it,
when, with what comment. Statuses: New · With management · Back with the researcher · With the analyst · Advisory sent ·
Closed. No address is ever part of a finding, so researchers, management, analysts and admins all see the same page
(/findings). Every change is in the audit log. Kept in data/findings.json (run-time data, never shipped).

API: GET /api/findings?state=open|all, POST /api/findings/<id>/status {status, comment}.
Made by notes.py (POST /api/notes with finding: {title}). Installed from app.py: findings.install(app, ctx).
"""
import json
import os
import threading
import time

from flask import g, jsonify, render_template, request

STATUSES = [("new", "New"), ("management", "With management"), ("researcher", "Back with the researcher"),
            ("analyst", "With the analyst"), ("advisory", "Advisory sent"), ("closed", "Closed")]
LABEL = dict(STATUSES)
OPEN = {"new", "management", "researcher", "analyst"}
ROLE_LABEL = {"researcher": "Researcher", "admin": "Administrator", "analyst": "Analyst", "management": "Management"}
MAX_TITLE, MAX_COMMENT = 140, 1000


class Findings:
    def __init__(self, path, people, logger=None):
        self.path, self.people, self.log = path, people, logger
        self.lock = threading.Lock()
        self.mtime, self.data = None, {"seq": 0, "items": {}}

    def _load(self):
        try:
            m = os.path.getmtime(self.path)
        except OSError:
            return
        if m == self.mtime:
            return
        try:
            with open(self.path, encoding="utf-8") as f:
                d = json.load(f)
            self.data = {"seq": int(d.get("seq") or 0), "items": d.get("items") or {}}
            self.mtime = m
        except (OSError, ValueError) as exc:
            if self.log:
                self.log.warning("findings not read: %s", exc)

    def _save(self):
        tmp = f"{self.path}.{os.getpid()}.tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(self.data, f, indent=1, ensure_ascii=False)
        os.replace(tmp, self.path)
        self.mtime = os.path.getmtime(self.path)

    def create(self, note, section, name, title, user, role):
        """A finding from a saved note (notes.Notes.add's raw note: id, text, codes)."""
        now = round(time.time(), 3)
        with self.lock:
            self._load()
            self.data["seq"] += 1
            fid = str(self.data["seq"])
            item = {"id": fid, "note": note["id"], "section": section, "name": name, "title": (title or "").strip()[:MAX_TITLE] or name,
                    "text": note.get("text", ""), "codes": list(note.get("codes") or []), "user": user, "role": role,
                    "at": now, "status": "new", "history": [{"status": "new", "user": user, "role": role, "at": now, "comment": ""}]}
            self.data["items"][fid] = item
            self._save()
        return item

    def create_analyst(self, code, section, label, title, text, user, role):
        """A finding made by an analyst from an analysis selection (acodes.py): its code is an analyst code."""
        now = round(time.time(), 3)
        with self.lock:
            self._load()
            self.data["seq"] += 1
            fid = str(self.data["seq"])
            item = {"id": fid, "note": None, "origin": "analyst", "section": section, "name": label, "title": title[:MAX_TITLE],
                    "text": text, "codes": [code], "user": user, "role": role, "at": now, "status": "new",
                    "history": [{"status": "new", "user": user, "role": role, "at": now, "comment": ""}]}
            self.data["items"][fid] = item
            self._save()
        return item

    def of_code(self, code):
        """The finding a code belongs to (the first one that carries it)."""
        with self.lock:
            self._load()
            return next((x for x in sorted(self.data["items"].values(), key=lambda x: x["at"]) if code in (x.get("codes") or [])), None)

    def reply(self, fid, text, codes, user, role):
        """A reply on a finding (a researcher answering an analyst's code, an analyst answering a researcher…), with
        its own codes. The status stays; the reply is in the history."""
        with self.lock:
            self._load()
            item = self.data["items"].get(str(fid))
            if not item:
                return None, "No such finding."
            item["history"].append({"status": item["status"], "kind": "reply", "user": user, "role": role, "at": round(time.time(), 3),
                                    "comment": text[:MAX_COMMENT], "codes": list(codes)})
            self._save()
            return item, ""

    def set_status(self, fid, status, comment, user, role):
        with self.lock:
            self._load()
            item = self.data["items"].get(str(fid))
            if not item:
                return None, "No such finding."
            if status not in LABEL:
                return None, "Unknown status."
            if status == item["status"] and not comment:
                return None, "It already has that status; add a comment to note something."
            item["status"] = status
            item["history"].append({"status": status, "user": user, "role": role, "at": round(time.time(), 3), "comment": comment[:MAX_COMMENT]})
            self._save()
            return item, ""

    def of_note(self, note_id):
        with self.lock:
            self._load()
            return next((x for x in self.data["items"].values() if x.get("note") == note_id), None)

    def shown(self, x, describe=None):
        """As people see it: names in full, dates readable, codes with what they mean. No address in any field."""
        who = lambda u, r: {"by": self.people.name(u, ""), "role": ROLE_LABEL.get(r, "Researcher")}
        day = lambda t: time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(t)) if t else ""
        return {"id": x["id"], "number": f"#{x['id']}", "section": x["section"], "name": x["name"], "title": x["title"], "text": x["text"],
                "codes": [{"code": c, "text": (describe(c) if describe else "") or ""} for c in x.get("codes") or []],
                "status": x["status"], "status_label": LABEL.get(x["status"], x["status"]), "open": x["status"] in OPEN,
                "created": day(x["at"]), **who(x["user"], x["role"]), "origin": x.get("origin", "researcher"),
                "replies": sum(1 for h in x["history"] if h.get("kind") == "reply"),
                "history": [{"status": h["status"], "status_label": LABEL.get(h["status"], h["status"]), "at": day(h["at"]),
                             "kind": h.get("kind", "status"), "comment": h.get("comment", ""),
                             "codes": [{"code": c, "text": (describe(c) if describe else "") or ""} for c in h.get("codes") or []],
                             **who(h["user"], h["role"])} for h in x["history"]],
                "updated": day(x["history"][-1]["at"])}

    def list(self, open_only, describe=None):
        with self.lock:
            self._load()
            items = list(self.data["items"].values())
        if open_only:
            items = [x for x in items if x["status"] in OPEN]
        items.sort(key=lambda x: -x["history"][-1]["at"])
        return [self.shown(x, describe) for x in items]


def install(app, ctx):
    """ctx: people, audit, fresh(), csrf_ok(), has_perm(p), describe(code) -> text, base_dir, logger."""
    f = Findings(os.path.join(ctx["base_dir"], "data", "findings.json"), ctx["people"], ctx.get("logger"))
    hp = ctx["has_perm"]

    def allowed():
        """Researchers, management, analysts (who see addresses) and admins: no address is ever on the page."""
        return hp("definitions") or hp("management") or hp("settings") or (hp("unmasked") and hp("export"))

    def me():
        u = getattr(g, "user", None) or {}
        return u.get("user", ""), u.get("role", "")

    @app.route("/findings")
    def findings_page():
        if not allowed():
            return render_template("denied.html", message="Findings are for researchers, management, analysts and admins."), 403
        return render_template("findings.html", statuses=STATUSES)

    @app.route("/api/findings")
    def api_findings():
        if not allowed():
            return jsonify(error="Findings are for researchers, management, analysts and admins."), 403
        items = f.list(request.args.get("state") != "all", ctx["describe"])
        return jsonify(findings=items, statuses=[{"key": k, "label": v, "open": k in OPEN} for k, v in STATUSES],
                       can_search=bool(hp("unmasked") and hp("export")), can_portal=bool(hp("management")),
                       can_research=bool(hp("definitions") or hp("settings")))

    @app.route("/api/findings/<fid>/status", methods=["POST"])
    def api_findings_status(fid):
        if not allowed():
            return jsonify(error="Findings are for researchers, management, analysts and admins."), 403
        if not ctx["csrf_ok"]():
            return jsonify(error="Refused (the request did not come from this page)."), 403
        if not ctx["fresh"]():
            return jsonify(error="Sign in again to make changes (your session is older than 12 hours)."), 403
        b = request.get_json(silent=True) or {}
        status = str(b.get("status") or "")
        comment = str(b.get("comment") or "").replace("\r", "").strip()[:MAX_COMMENT]
        user, role = me()
        item, err = f.set_status(fid, status, comment, user, role)
        if not item:
            return jsonify(error=err), 404 if "No such" in err else 400
        ctx["audit"].add("finding_status", user=user, target=f"#{fid} {item['name']}",
                         detail=f"{LABEL.get(status, status)}" + (f" · {comment[:100]}" if comment else ""))
        return jsonify(finding=f.shown(item, ctx["describe"]))

    @app.route("/api/findings/<fid>/reply", methods=["POST"])
    def api_findings_reply(fid):
        """A reply on a finding with its own codes: a researcher answers an analyst's code with combination codes."""
        if not allowed():
            return jsonify(error="Findings are for researchers, management, analysts and admins."), 403
        if not ctx["csrf_ok"]():
            return jsonify(error="Refused (the request did not come from this page)."), 403
        if not ctx["fresh"]():
            return jsonify(error="Sign in again to make changes (your session is older than 12 hours)."), 403
        b = request.get_json(silent=True) or {}
        text = str(b.get("text") or "").replace("\r", "").strip()[:MAX_COMMENT]
        codes = list(dict.fromkeys(str(c).strip().upper() for c in (b.get("codes") or []) if str(c).strip()))[:10]
        if not text and not codes:
            return jsonify(error="Write a reply or attach a code."), 400
        for c in codes:
            if not ctx["known"](c):
                return jsonify(error=f"{c} is not a code known here."), 400
        user, role = me()
        item, err = f.reply(fid, text, codes, user, role)
        if not item:
            return jsonify(error=err), 404
        ctx["audit"].add("finding_reply", user=user, target=f"#{fid} {item['name'][:60]}", detail=(text[:100] + (f" · {', '.join(codes)}" if codes else "")))
        return jsonify(finding=f.shown(item, ctx["describe"]))

    return f
