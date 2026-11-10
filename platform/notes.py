"""Researchers' notes on an infection / category or an issue: new findings, kept apart from the definitions.

A definition says what a name is (and ships with Looking Glass); a note records what a researcher found on this site
("the C2 moved to …", "seen together with … since Monday"). Notes are kept in data/notes.json (run-time data: never
shipped, never overwritten by an update), each with its author (username, role and full name at the time) and date.

Every explanation card (map, services, Executive, the PDF reports) carries the notes of its name, newest first, shown
as "Notes shared by Researcher: <full name>". Researchers and admins add notes; the author or an admin removes one.
A note can carry combination codes (LG-C-…, LG-X-…; combos.py): the exact combinations the researcher points at, which an
analyst pastes on the Combinations page to get exactly those devices. They are printed with the note.
API: GET /api/notes?section=&name=, POST /api/notes {section, name, text, codes?}, POST /api/notes/delete {id}.
Installed from app.py: notes.install(app, ctx); app.py wraps its look-ups with NOTES.attach().
"""
import json
import os
import re
import secrets
import threading
import time

from flask import g, jsonify, request

ROLE_LABEL = {"researcher": "Researcher", "admin": "Administrator", "analyst": "Analyst", "management": "Management"}
MAX_LEN = 2000
MAX_CODES = 10                 # combination codes on one note (combos.py)
CODE_RX = re.compile(r"^LG-[CX]-[0-9A-F]{8}$")


class Notes:
    def __init__(self, path, people, logger=None):
        self.path, self.people, self.log = path, people, logger
        self.lock = threading.Lock()
        self.mtime, self.data = None, {"infections": {}, "issues": {}}

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
            self.data = {"infections": d.get("infections") or {}, "issues": d.get("issues") or {}}
            self.mtime = m
        except (OSError, ValueError) as exc:
            if self.log:
                self.log.warning("notes not read: %s", exc)

    def _save(self):
        tmp = f"{self.path}.{os.getpid()}.tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(self.data, f, indent=1, ensure_ascii=False)
        os.replace(tmp, self.path)
        self.mtime = os.path.getmtime(self.path)

    @staticmethod
    def _key(name):
        return (name or "").strip().lower()

    def shown(self, n):
        """A note as people see it: the author's current full name (the saved one if the account is gone) and role."""
        who = self.people.name(n.get("user", ""), n.get("name", ""))
        book = getattr(self, "codes", None)
        codes = [{"code": c, "text": (book.describe(c) if book else "") or ""} for c in n.get("codes") or []]
        out = {"id": n["id"], "text": n["text"], "date": n.get("date", ""), "by": who,
               "role": ROLE_LABEL.get(n.get("role", ""), "Researcher"), "user": n.get("user", ""), "codes": codes}
        track = getattr(self, "findings", None)
        f = track.of_note(n["id"]) if track else None
        if f:                              # tracked as a finding: its number and where it stands (findings.py)
            from findings import LABEL
            out["finding"] = {"number": f"#{f['id']}", "status": f["status"], "status_label": LABEL.get(f["status"], f["status"])}
        return out

    def list(self, section, name):
        with self.lock:
            self._load()
            items = list(self.data.get(section, {}).get(self._key(name), []))
        return [self.shown(n) for n in sorted(items, key=lambda n: n.get("at", 0), reverse=True)]

    def add(self, section, name, text, user, role, codes=()):
        n = {"id": secrets.token_hex(6), "text": text, "user": user, "role": role, "name": self.people.full_name(user),
             "at": round(time.time(), 3), "date": time.strftime("%Y-%m-%d", time.gmtime())}
        if codes:
            n["codes"] = list(codes)
        with self.lock:
            self._load()
            self.data.setdefault(section, {}).setdefault(self._key(name), []).append(n)
            self._save()
        return self.shown(n)

    def delete(self, note_id, user, is_admin):
        with self.lock:
            self._load()
            for sec in self.data.values():
                for key, items in list(sec.items()):
                    for n in items:
                        if n["id"] == note_id:
                            if n.get("user") != user and not is_admin:
                                return None, "Only its author or an administrator can remove a note."
                            items.remove(n)
                            if not items:
                                del sec[key]
                            self._save()
                            return (key, n), ""
        return None, "No such note."

    def attach(self, card, section, name):
        """A copy of an explanation card with the name's notes (newest first) as card['notes']."""
        if not isinstance(card, dict):
            return card
        notes = self.list(section, name)
        if not notes and "notes" not in card:
            return card
        out = dict(card)
        out["notes"] = [{k: v for k, v in n.items() if k not in ("user",)} for n in notes]
        return out


def install(app, ctx):
    """ctx: people, audit, allowed() (may read: researchers, admins), change_allowed() (may write, with CSRF),
    fresh() (recent sign-in), base_dir, logger."""
    notes = Notes(os.path.join(ctx["base_dir"], "data", "notes.json"), ctx["people"], ctx.get("logger"))

    def me():
        u = getattr(g, "user", None) or {}
        return u.get("user", "admin"), u.get("role", ""), "users" in (u.get("perms") or ())

    @app.route("/api/notes", methods=["GET", "POST"])
    def api_notes():
        if request.method == "GET":
            if not ctx["allowed"]():
                return jsonify(error="Notes are for researchers and admins."), 403
            section = "issues" if request.args.get("section") == "issues" else "infections"
            name = (request.args.get("name") or "").strip()[:120]
            return jsonify(notes=notes.list(section, name))
        if not ctx["change_allowed"]():
            return jsonify(error="Only researchers and admins can add notes."), 403
        if not ctx["fresh"]():
            return jsonify(error="Sign in again to make changes (your session is older than 12 hours)."), 403
        b = request.get_json(silent=True) or {}
        section = "issues" if b.get("section") == "issues" else "infections"
        name = str(b.get("name") or "").strip()[:120]
        text = str(b.get("text") or "").replace("\r", "").strip()[:MAX_LEN]
        if not name or not text:
            return jsonify(error="Write the note first."), 400
        # combination codes attached to the note: each must be one this platform knows (combos.py)
        codes = list(dict.fromkeys(str(c).strip().upper() for c in (b.get("codes") or []) if str(c).strip()))
        if len(codes) > MAX_CODES:
            return jsonify(error=f"At most {MAX_CODES} combinations on one note."), 400
        book = getattr(notes, "codes", None)
        for c in codes:
            if not CODE_RX.match(c) or not (book and book.resolve(c)):
                return jsonify(error=f"{c} is not a combination code known here."), 400
        user, role, _ = me()
        n = notes.add(section, name, text, user, role, codes)
        ctx["audit"].add("note_added", user=user, target=f"{'issue:' if section == 'issues' else ''}{name}",
                         detail=text[:120] + (f" · {', '.join(codes)}" if codes else ""))
        fnd = b.get("finding")
        track = getattr(notes, "findings", None)
        if fnd and track:                  # "Track as a finding": the team follows it up on the Findings page (findings.py)
            title = str((fnd or {}).get("title") or "").strip() if isinstance(fnd, dict) else ""
            item = track.create({"id": n["id"], "text": text, "codes": codes}, section, name, title, user, role)
            ctx["audit"].add("finding_created", user=user, target=f"#{item['id']} {name}", detail=item["title"][:120])
        return jsonify(saved=True, note=n, notes=notes.list(section, name))

    @app.route("/api/notes/delete", methods=["POST"])
    def api_notes_delete():
        if not ctx["change_allowed"]():
            return jsonify(error="Only researchers and admins can remove notes."), 403
        if not ctx["fresh"]():
            return jsonify(error="Sign in again to make changes (your session is older than 12 hours)."), 403
        b = request.get_json(silent=True) or {}
        user, _, admin = me()
        hit, err = notes.delete(str(b.get("id") or ""), user, admin)
        if not hit:
            return jsonify(error=err), 403 if "author" in err else 404
        ctx["audit"].add("note_removed", user=user, target=hit[0], detail=hit[1]["text"][:120])
        return jsonify(removed=True)

    return notes
