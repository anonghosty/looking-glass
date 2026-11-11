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

import finding_rules

STATUSES = [("new", "New"), ("management", "With management"), ("approved", "Approved by management"),
            ("researcher", "Back with the researcher"), ("analyst", "With the analyst"), ("advisor", "With the advisor"),
            ("advisory", "Advisory sent"), ("closed", "Closed")]
LABEL = dict(STATUSES)
OPEN = {"new", "management", "approved", "researcher", "analyst", "advisor"}
ROLE_LABEL = {"researcher": "Researcher", "admin": "Administrator", "analyst": "Analyst", "management": "Management"}
MAX_TITLE, MAX_COMMENT = 140, 1000
# a finding is a channel, like a ticket: whoever sends it on names the person it goes to (a manager, a researcher, an
# analyst), and only the people who took part see it and its trail (admins too, for oversight). The status a hand-over
# leads to, per kind of person:
TO_STATUS = {"management": "management", "researcher": "researcher", "analyst": "analyst", "advisor": "advisor"}
KIND_LABEL = {"management": "a manager", "researcher": "a researcher", "analyst": "an analyst", "advisor": "an advisor"}
ROLE_LABEL["advisor"] = "Advisor"
NONE_FOUND = "Looked into the selection: no combination of interest found. The request is closed."


class Findings:
    def __init__(self, path, people, logger=None):
        self.path, self.people, self.log = path, people, logger
        self.lock = threading.Lock()
        self.mtime, self.data = None, {"seq": 0, "items": {}}
        self.people_of = lambda kind: []          # app.py: the active accounts that do that job (manager, researcher, analyst)
        self.title_of = lambda n: n               # app.py: a services report's readable title
        self.advisories_of = lambda fid: []       # advisory.py: a finding's advisories (no address)
        self.asked_of = lambda code: ""           # acodes.py: what an analyst's code asks the researchers for

    # ---- the channel
    def recipient(self, kind, to):
        """(username, "") when `to` is an active account of that kind, else (None, error)."""
        to = str(to or "").strip()
        if kind not in TO_STATUS:
            return None, "Unknown kind of recipient."
        if not to:
            return None, f"Choose {KIND_LABEL[kind]} to send it to."
        if to not in {p["user"] for p in self.people_of(kind)}:
            return None, f"{to} is not {KIND_LABEL[kind]} here."
        return to, ""

    @staticmethod
    def sees(x, user, admin, strict=False):
        """Only the people in the channel (and admins); a finding made before channels is open to the team roles, as it
        was, never to the other roles (strict)."""
        return admin or user in (x.get("participants") or []) or (not x.get("participants") and not strict)

    @staticmethod
    def _join(item, to):
        if to:
            item.setdefault("participants", [item["user"]])
            if to not in item["participants"]:
                item["participants"].append(to)
            item["assignee"] = to

    def get(self, fid):
        with self.lock:
            self._load()
            return self.data["items"].get(str(fid))

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

    def create(self, note, section, name, title, user, role, to=None, kind="management"):
        """A finding from a saved note (notes.Notes.add's raw note: id, text, codes), sent to `to` (a manager)."""
        now = round(time.time(), 3)
        status = TO_STATUS.get(kind, "new") if to else "new"
        with self.lock:
            self._load()
            self.data["seq"] += 1
            fid = str(self.data["seq"])
            item = {"id": fid, "note": note["id"], "section": section, "name": name, "title": (title or "").strip()[:MAX_TITLE] or name,
                    "text": note.get("text", ""), "codes": list(note.get("codes") or []), "user": user, "role": role,
                    "at": now, "status": status, "history": [{"status": status, "user": user, "role": role, "at": now, "comment": "", "to": to or ""}]}
            self._join(item, to)
            self.data["items"][fid] = item
            self._save()
        return item

    def create_analyst(self, code, section, label, title, text, user, role, to=None, kind="researcher", comment=""):
        """A finding made by an analyst from an analysis selection (acodes.py): its code is an analyst code; sent to `to`
        (a researcher for the analysis, or a manager)."""
        now = round(time.time(), 3)
        status = TO_STATUS.get(kind, "new") if to else "new"
        with self.lock:
            self._load()
            self.data["seq"] += 1
            fid = str(self.data["seq"])
            item = {"id": fid, "note": None, "origin": "analyst", "section": section, "name": label, "title": title[:MAX_TITLE],
                    "text": text, "codes": [code], "user": user, "role": role, "at": now, "status": status,
                    "history": [{"status": status, "user": user, "role": role, "at": now, "comment": comment[:MAX_COMMENT], "to": to or ""}]}
            self._join(item, to)
            self.data["items"][fid] = item
            self._save()
        return item

    # ---- an analyst's across-report views, for management to decide on (combo_review.py)
    def create_review(self, code, section, label, title, text, user, role, to, review):
        """A finding asking management which views the report on `code` carries: the researcher's (the combination) or
        the analyst's too (the ticked cross-report patterns). review: {source, codes, researcher, analyst} (counts only)."""
        now = round(time.time(), 3)
        with self.lock:
            self._load()
            self.data["seq"] += 1
            fid = str(self.data["seq"])
            item = {"id": fid, "note": None, "origin": "analyst", "kind": "review", "section": section, "name": label,
                    "title": title[:MAX_TITLE], "text": text, "codes": [code] + [c for c in review.get("codes", []) if c != code],
                    "user": user, "role": role, "at": now, "status": "management", "review": dict(review, decision=None),
                    "history": [{"status": "management", "user": user, "role": role, "at": now, "to": to,
                                 "comment": (f"Across-report views for {code}: {len(review.get('codes', []))} pattern(s) ticked." if review.get("codes")
                                             else f"{code} for the advisory: no across-report data (the researcher's view).")}]}
            self._join(item, to)
            self.data["items"][fid] = item
            self._save()
        return item

    def create_case(self, code, section, label, title, text, user, role, to, subs):
        """A case: the analyst's request on several organisations (networks) at once. The case is the overview; under
        it one sub-finding per network (a review of its own, which management decides and sends to an advisor).
        subs: [(network, review)]. Returns (case, [sub-findings])."""
        now = round(time.time(), 3)
        with self.lock:
            self._load()
            self.data["seq"] += 1
            pid = str(self.data["seq"])
            case = {"id": pid, "note": None, "origin": "analyst", "kind": "case", "section": section, "name": label,
                    "title": title[:MAX_TITLE], "text": text, "codes": [code], "user": user, "role": role, "at": now,
                    "status": "management", "children": [],
                    "history": [{"status": "management", "user": user, "role": role, "at": now, "to": to,
                                 "comment": f"A case on {code}: {len(subs)} organisation(s), one sub-finding each."}]}
            self._join(case, to)
            kids = []
            for net, review in subs:
                self.data["seq"] += 1
                fid = str(self.data["seq"])
                item = {"id": fid, "note": None, "origin": "analyst", "kind": "review", "parent": pid, "network": net, "section": section,
                        "name": label, "title": f"{title[:MAX_TITLE - 40]} · {net}"[:MAX_TITLE], "text": text,
                        "codes": [code] + [c for c in review.get("codes", []) if c != code], "user": user, "role": role, "at": now,
                        "status": "management", "review": dict(review, decision=None),
                        "history": [{"status": "management", "user": user, "role": role, "at": now, "to": to,
                                     "comment": f"Sub-finding of case #{pid} for {net}: "
                                                + (f"{len(review.get('codes', []))} across-report pattern(s)." if review.get("codes") else "the researcher's view.")}]}
                self._join(item, to)
                self.data["items"][fid] = item
                case["children"].append(fid)
                kids.append(item)
            self.data["items"][pid] = case
            self._save()
        return case, kids

    def _sync_case(self, item):
        """A case follows its sub-findings: with management while any is; with the advisor while any is; closed once
        every one is closed (its advisory sent, or rejected), which is logged on the case. Call under the lock."""
        pid = item.get("parent")
        case = self.data["items"].get(str(pid)) if pid else None
        if not case:
            return
        kids = [self.data["items"][k] for k in case.get("children") or [] if k in self.data["items"]]
        sts = {k["status"] for k in kids}
        new = ("management" if "management" in sts else "advisor" if "advisor" in sts else
               "analyst" if sts & {"analyst", "researcher", "approved", "new"} else "closed")
        if new != case["status"]:
            case["status"] = new
            sent = sum(1 for k in kids if any(h.get("kind") == "advisory_sent" for h in k["history"]))
            note = (f"Every sub-finding is closed ({sent} with its advisory sent, {len(kids) - sent} without): the case is closed."
                    if new == "closed" else f"Follows its sub-findings ({len(kids)}).")
            case["history"].append({"status": new, "kind": "case", "user": item["history"][-1]["user"], "role": item["history"][-1]["role"],
                                    "at": round(time.time(), 3), "to": "", "comment": note})
        for u in item.get("participants") or []:          # whoever joins a sub-finding sees the case too
            case.setdefault("participants", [case["user"]])
            if u not in case["participants"]:
                case["participants"].append(u)

    def decide_review(self, fid, choice, text, user, role, to):
        """Management: add the analyst's views to the report ("both") or use the researcher's view only ("researcher").
        It goes to the advisor management names (`to`), who writes the advisory and generates the report."""
        with self.lock:
            self._load()
            item = self.data["items"].get(str(fid))
            if not item or not item.get("review"):
                return None, "No such finding."
            if item["review"].get("decision"):
                return None, "Already decided."
            if item["status"] not in OPEN:                 # closed some other way: there is nothing left to decide
                return None, "This finding is closed: there is nothing to decide."
            if choice == "both" and not item["review"].get("codes"):
                choice = "researcher"          # sent without across-report patterns: there is no analyst's view to add
            item["review"].update(decision="rejected" if choice == "reject" else choice, by=user, at=round(time.time(), 3), comment=text[:MAX_COMMENT])
            if choice == "reject":             # rejected: closed, with the reason; no advisory
                item["status"] = "closed"
                item["history"].append({"status": "closed", "kind": "decision", "decision": "rejected", "user": user, "role": role,
                                        "at": round(time.time(), 3), "to": "", "comment": text[:MAX_COMMENT]})
                self._sync_case(item)
                self._save()
                return item, ""
            item["status"] = "advisor"
            item["history"].append({"status": "advisor", "kind": "decision", "decision": "accepted", "user": user, "role": role,
                                    "at": round(time.time(), 3), "to": to,
                                    "comment": ("Add the analyst's views: " if choice == "both" else "Use the researcher's view only: ") + text[:MAX_COMMENT]})
            self._join(item, to)
            self._sync_case(item)
            self._save()
            return item, ""

    def advisory_sent(self, fid, comment, close, user, role):
        """The advisor marked an advisory of this finding as sent: logged; the finding closes when nothing else of it is
        waiting (close), and its case follows."""
        with self.lock:
            self._load()
            item = self.data["items"].get(str(fid))
            if not item:
                return None, "No such finding."
            if close:
                item["status"] = "closed"
            item["history"].append({"status": item["status"], "kind": "advisory_sent", "user": user, "role": role,
                                    "at": round(time.time(), 3), "to": "", "comment": comment[:MAX_COMMENT]
                                    + (" The finding is closed." if close else "")})
            self._sync_case(item)
            self._save()
            return item, ""

    def reviews_for(self, code, user, admin):
        """Every review on `code` this user is in (sub-findings of a case each count), oldest first."""
        with self.lock:
            self._load()
            mine = [x for x in self.data["items"].values() if (x.get("review") or {}).get("source") == code and self.sees(x, user, admin)]
        return sorted(mine, key=lambda x: x["at"])

    def review_for(self, code, user, admin):
        """The latest decided review on `code` this user is in (the report follows it), else the latest pending one, else None."""
        mine = self.reviews_for(code, user, admin)
        decided = [x for x in mine if x["review"].get("decision")]
        return (decided or mine or [None])[-1]

    def of_code(self, code):
        """The finding a code belongs to (the first one that carries it)."""
        with self.lock:
            self._load()
            return next((x for x in sorted(self.data["items"].values(), key=lambda x: x["at"]) if code in (x.get("codes") or [])), None)

    def reply(self, fid, text, codes, user, role, none_found=False):
        """A reply on a finding (a researcher answering an analyst's code, an analyst answering a researcher…), with
        its own codes. The status stays; the reply is in the history. none_found: the researcher looked and found no
        combination of interest in the selection, which answers the request: the finding is closed with that reply."""
        with self.lock:
            self._load()
            item = self.data["items"].get(str(fid))
            if not item:
                return None, "No such finding."
            back = None
            if item.get("status") not in OPEN:
                return None, "This finding is closed: it takes no more replies."
            if none_found:
                err = finding_rules.can_close_none_found(item, user)
                if err:
                    return None, err
                item["status"] = "closed"
            elif item.get("origin") == "analyst" and item["status"] == "researcher" and user != item["user"]:
                # the researcher answers the analyst's code: it goes back to the analyst who asked, with the codes
                back = item["user"]
                item["status"] = "analyst"
                self._join(item, back)
            h = {"status": item["status"], "kind": "reply", "user": user, "role": role, "at": round(time.time(), 3),
                 "comment": text[:MAX_COMMENT], "codes": list(codes), "to": back or ""}
            if none_found:
                h["none_found"] = True
            item["history"].append(h)
            self._save()
            return item, ""

    def decide(self, fid, accept, text, user, role, to=None):
        """Management's decision on a finding: approved, with its comment (the directive), going straight to the analyst
        named (`to`; status "With the analyst"), or rejected, with the reason (it is closed). Kept in the history as a
        decision. (Without `to`, an approval stays "Approved", as findings approved before this rule were.)"""
        with self.lock:
            self._load()
            item = self.data["items"].get(str(fid))
            if not item:
                return None, "No such finding."
            if item["status"] not in OPEN:
                return None, "This finding is no longer open."
            if item["status"] == "approved":
                return None, "It is already approved: move it on to the person it goes to."
            if item["status"] not in ("new", "management"):
                return None, "It is not with management: there is nothing to decide."
            if item.get("kind") == "case":
                return None, "A case is decided organisation by organisation: decide each of its sub-findings."
            item["status"] = ("analyst" if to else "approved") if accept else "closed"
            item["history"].append({"status": item["status"], "kind": "decision", "decision": "accepted" if accept else "rejected",
                                    "user": user, "role": role, "at": round(time.time(), 3), "comment": text[:MAX_COMMENT], "to": to or ""})
            self._join(item, to if accept else None)
            self._save()
            return item, ""

    def set_status(self, fid, status, comment, user, role, to=None, is_manager=False):
        """Moving a finding by hand: management's or an administrator's only (finding_rules.py)."""
        with self.lock:
            self._load()
            item = self.data["items"].get(str(fid))
            if not item:
                return None, "No such finding."
            if status not in LABEL:
                return None, "Unknown status."
            err = finding_rules.can_move(item, status, is_manager, OPEN)
            if err:
                return None, err
            if status == item["status"] and not comment and not to:
                return None, "It already has that status; add a comment to note something."
            item["status"] = status
            h = {"status": status, "user": user, "role": role, "at": round(time.time(), 3), "comment": comment[:MAX_COMMENT], "to": to or ""}
            if status == "advisor":
                h["approval"] = True                       # management sent it to the advisor: its approval (finding_rules.py)
            item["history"].append(h)
            self._join(item, to)
            self._sync_case(item)
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
                "codes": [{"code": c, "text": (describe(c) if describe else "") or "", "asked": self.asked_of(c) or ""}
                          for c in x.get("codes") or []],
                "status": x["status"], "status_label": LABEL.get(x["status"], x["status"]), "open": x["status"] in OPEN,
                "created": day(x["at"]), **who(x["user"], x["role"]), "origin": x.get("origin", "researcher"),
                "replies": sum(1 for h in x["history"] if h.get("kind") == "reply"),
                "history": [{"status": h["status"], "status_label": LABEL.get(h["status"], h["status"]), "at": day(h["at"]),
                             "kind": h.get("kind", "status"), "comment": h.get("comment", ""), "decision": h.get("decision", ""),
                             "to": self.people.name(h["to"]) if h.get("to") else "",
                             "codes": [{"code": c, "text": (describe(c) if describe else "") or ""} for c in h.get("codes") or []],
                             **who(h["user"], h["role"])} for h in x["history"]],
                "updated": day(x["history"][-1]["at"]),
                "display_name": self.title_of(x["name"]) if x.get("section") == "services" else x["name"],
                # the review without "sent" (the devices' addresses, kept for the analyst's report only: never on this page)
                "review": ({k: v for k, v in x["review"].items() if k not in ("by", "sent")} | {"by": self.people.name(x["review"]["by"]) if x["review"].get("by") else ""})
                          if x.get("review") else None,
                "assignee": self.people.name(x["assignee"]) if x.get("assignee") else "",
                "channel": [self.people.name(u) for u in x.get("participants") or []],
                # a case and its sub-findings (one per organisation): the page shows them as one ticket
                "kind": x.get("kind") or "", "parent": x.get("parent") or "", "network": x.get("network") or "",
                "children": list(x.get("children") or []),
                # its advisories (advisory.py): reference, organisation, state; the advisor marks a drafted one as sent here
                "advisories": self.advisories_of(x["id"]) if x.get("review") else []}

    def list(self, open_only, describe=None, user=None, admin=True, strict=False):
        with self.lock:
            self._load()
            items = [x for x in self.data["items"].values() if self.sees(x, user, admin, strict)]
        if open_only:
            # an open case brings all its sub-findings along, the closed ones too: the page folds them into the case
            open_cases = {x["id"] for x in items if x.get("kind") == "case" and x["status"] in OPEN}
            items = [x for x in items if x["status"] in OPEN or x.get("parent") in open_cases]
        items.sort(key=lambda x: -x["history"][-1]["at"])
        return [self.shown(x, describe) for x in items]


def install(app, ctx):
    """ctx: people, audit, fresh(), csrf_ok(), has_perm(p), describe(code) -> text, base_dir, logger."""
    f = Findings(os.path.join(ctx["base_dir"], "data", "findings.json"), ctx["people"], ctx.get("logger"))
    hp = ctx["has_perm"]

    def team():
        """The roles that work the findings: researchers, management, analysts (who see addresses), advisors and admins."""
        return hp("definitions") or hp("management") or hp("settings") or (hp("unmasked") and hp("export")) or hp("advisory")

    def allowed():
        """Every role opens the Findings page (the findings whose channel it is in; no address is ever on it)."""
        return bool((getattr(g, "user", None) or {}).get("user"))

    def me():
        u = getattr(g, "user", None) or {}
        return u.get("user", ""), u.get("role", "")

    f.people_of = ctx.get("people_of") or f.people_of
    admin = lambda: hp("settings")

    def in_channel(fid):
        """The finding when this user is in its channel (or an admin), else None: the same answer as an unknown one."""
        x = f.get(fid)
        return x if x and f.sees(x, me()[0], admin(), strict=not team()) else None

    @app.route("/api/findings/people")
    def api_findings_people():
        """Whom a finding can be sent to: the active managers, researchers or analysts (names, never more)."""
        if not allowed():
            return jsonify(error="Findings are for researchers, management, analysts and admins."), 403
        kind = request.args.get("kind") or ""
        if kind not in TO_STATUS:
            return jsonify(error="kind is management, researcher or analyst."), 400
        mine = me()[0]
        return jsonify(kind=kind, people=[{"user": p["user"], "name": p["name"], "role": p.get("role", "")}
                                          for p in f.people_of(kind) if p["user"] != mine])

    @app.route("/findings")
    def findings_page():
        if not allowed():
            return render_template("denied.html", message="Findings are for researchers, management, analysts and admins."), 403
        return render_template("findings.html", statuses=STATUSES)

    @app.route("/api/findings")
    def api_findings():
        if not allowed():
            return jsonify(error="Findings are for researchers, management, analysts and admins."), 403
        items = f.list(request.args.get("state") != "all", ctx["describe"], me()[0], admin(), strict=not team())
        return jsonify(findings=items, statuses=[{"key": k, "label": v, "open": k in OPEN} for k, v in STATUSES],
                       can_search=bool(hp("unmasked") and hp("export")), can_portal=bool(hp("management")),
                       can_decide=bool(hp("management") or hp("settings")), can_advise=bool(hp("advisory")),
                       can_research=bool(hp("definitions") or hp("settings")))

    @app.route("/api/findings/<fid>/status", methods=["POST"])
    def api_findings_status(fid):
        if not allowed():
            return jsonify(error="Findings are for researchers, management, analysts and admins."), 403
        if not ctx["csrf_ok"]():
            return jsonify(error="Refused (the request did not come from this page)."), 403
        if not ctx["fresh"]():
            return jsonify(error="Sign in again to make changes (your session is older than 12 hours)."), 403
        if not in_channel(fid):
            return jsonify(error="No such finding."), 404
        b = request.get_json(silent=True) or {}
        status = str(b.get("status") or "")
        comment = str(b.get("comment") or "").replace("\r", "").strip()[:MAX_COMMENT]
        to = None
        kind = next((k for k, s in TO_STATUS.items() if s == status), None)
        if kind:                                           # a hand-over names the person it goes to
            to, err = f.recipient(kind, b.get("to"))
            if not to:
                return jsonify(error=err), 400
        user, role = me()
        item, err = f.set_status(fid, status, comment, user, role, to, is_manager=bool(hp("management") or hp("settings")))
        if not item:
            return jsonify(error=err), 404 if "No such" in err else 403 if err == finding_rules.NOT_YOURS else 400
        ctx["audit"].add("finding_status", user=user, target=f"#{fid} {item['name']}",
                         detail=f"{LABEL.get(status, status)}" + (f" · to {to}" if to else "") + (f" · {comment[:100]}" if comment else ""))
        return jsonify(finding=f.shown(item, ctx["describe"]))

    @app.route("/api/findings/<fid>/decision", methods=["POST"])
    def api_findings_decision(fid):
        """Management decides: approves a finding with a comment (the directive) and it goes straight to the analyst named
        (`to`), or rejects it with the reason (it is closed)."""
        if not (hp("management") or hp("settings")):
            return jsonify(error="Management decides on findings."), 403
        if not ctx["csrf_ok"]():
            return jsonify(error="Refused (the request did not come from this page)."), 403
        if not ctx["fresh"]():
            return jsonify(error="Sign in again to make changes (your session is older than 12 hours)."), 403
        b = request.get_json(silent=True) or {}
        accept = b.get("decision") == "accept"
        if b.get("decision") not in ("accept", "reject"):
            return jsonify(error="Accept or reject."), 400
        text = str(b.get("text") or "").replace("\r", "").strip()[:MAX_COMMENT]
        if not text:
            return jsonify(error="Give your comment (the directive)." if accept else "Give the reason for rejecting it."), 400
        if not in_channel(fid):
            return jsonify(error="No such finding."), 404
        to = None
        if accept:
            to, err = f.recipient("analyst", b.get("to"))
            if not to:
                return jsonify(error=err), 400
        user, role = me()
        item, err = f.decide(fid, accept, text, user, role, to)
        if not item:
            return jsonify(error=err), 404 if "No such" in err else 400
        ctx["audit"].add("finding_decision", user=user, target=f"#{fid} {item['name'][:60]}",
                         detail=("approved · " if accept else "rejected · ") + text[:100])
        return jsonify(finding=f.shown(item, ctx["describe"]))

    @app.route("/api/findings/<fid>/review-decision", methods=["POST"])
    def api_findings_review_decision(fid):
        """Management decides which views the analyst's report carries; it goes back to the analyst."""
        if not (hp("management") or hp("settings")):
            return jsonify(error="Management decides on the report's views."), 403
        if not ctx["csrf_ok"]():
            return jsonify(error="Refused (the request did not come from this page)."), 403
        if not ctx["fresh"]():
            return jsonify(error="Sign in again to make changes (your session is older than 12 hours)."), 403
        if not in_channel(fid):
            return jsonify(error="No such finding."), 404
        b = request.get_json(silent=True) or {}
        choice = b.get("choice")
        if choice not in ("both", "researcher", "reject"):
            return jsonify(error="Add the analyst's views, use the researcher's view only, or reject it."), 400
        text = str(b.get("text") or "").replace("\r", "").strip()[:MAX_COMMENT]
        if not text:
            return jsonify(error="Give the reason for rejecting it." if choice == "reject" else "Give your comment (the directive for the report)."), 400
        to = None
        if choice != "reject":
            to, err = f.recipient("advisor", b.get("to"))      # the advisor who writes the advisory and generates the report
            if not to:
                return jsonify(error=err), 400
        user, role = me()
        item, err = f.decide_review(fid, choice, text, user, role, to)
        if not item:
            return jsonify(error=err), 404 if "No such" in err else 400
        ctx["audit"].add("finding_review_decision", user=user, target=f"#{fid} {item['review'].get('source', '')}",
                         detail=f"{choice} · to the advisor {to} · {text[:100]}")
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
        none_found = bool(b.get("none_found"))
        if none_found and codes:
            return jsonify(error="“No combination of interest” and ticked codes do not go together: untick one."), 400
        if none_found:
            text = text or NONE_FOUND
        if not text and not codes:
            return jsonify(error="Write a reply or attach a code."), 400
        for c in codes:
            if not ctx["known"](c):
                return jsonify(error=f"{c} is not a code known here."), 400
        if not in_channel(fid):
            return jsonify(error="No such finding."), 404
        user, role = me()
        item, err = f.reply(fid, text, codes, user, role, none_found)
        if not item:
            return jsonify(error=err), 404 if "No such" in err else 409 if "closed" in err else 403
        ctx["audit"].add("finding_reply", user=user, target=f"#{fid} {item['name'][:60]}",
                         detail=("no combination of interest, closed · " if none_found else "") + text[:100] + (f" · {', '.join(codes)}" if codes else ""))
        return jsonify(finding=f.shown(item, ctx["describe"]))

    return f
