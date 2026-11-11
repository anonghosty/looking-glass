"""The organisation behind this Looking Glass: its name and logo, set by an admin on the Settings page. Advisories
(advisory.py) carry them: the name in the title, the logo in its section on the first page.

Stored in data/organisation.json (name, logo as base64, its type). The logo is a PNG or JPEG of at most 40 KB (it
travels inside a JSON request, and requests are capped at 64 KB).

API: GET /api/organisation (admins and advisors) · POST /api/organisation {name, logo: data URL | "" to remove}
(admins) · GET /organisation/logo (the image). Installed from app.py.
"""
import base64
import json
import os
import re
import threading

from flask import Response, g, jsonify, request

MAX_NAME = 120
MAX_LOGO = 40 * 1024
KINDS = {"image/png": b"\x89PNG\r\n\x1a\n", "image/jpeg": b"\xff\xd8\xff"}


class Organisation:
    def __init__(self, path):
        self.path = path
        self.lock = threading.Lock()

    def get(self):
        """{"name", "logo" (bytes or None), "logo_type"}."""
        try:
            with open(self.path, encoding="utf-8") as fh:
                d = json.load(fh)
        except (OSError, ValueError):
            d = {}
        logo = None
        if d.get("logo"):
            try:
                logo = base64.b64decode(d["logo"], validate=True)
            except ValueError:
                logo = None
        return {"name": str(d.get("name") or ""), "logo": logo, "logo_type": d.get("logo_type") or ""}

    @staticmethod
    def check_logo(data_url):
        """(bytes, type) of a PNG / JPEG data URL, or (None, error)."""
        m = re.fullmatch(r"data:(image/(?:png|jpeg));base64,([A-Za-z0-9+/=\s]+)", str(data_url or ""))
        if not m:
            return None, "The logo must be a PNG or JPEG image."
        try:
            raw = base64.b64decode(re.sub(r"\s", "", m.group(2)), validate=True)
        except ValueError:
            return None, "The logo could not be read."
        if not raw.startswith(KINDS[m.group(1)]):
            return None, "The file is not the image it claims to be (PNG or JPEG)."
        if len(raw) > MAX_LOGO:
            return None, f"The logo is {len(raw) // 1024} KB: at most {MAX_LOGO // 1024} KB, please (a smaller or compressed image)."
        return (raw, m.group(1)), ""

    def save(self, name, logo):
        """logo: (bytes, type) to set, "" to remove, None to keep."""
        with self.lock:
            cur = self.get()
            d = {"name": name}
            if logo is None and cur["logo"]:
                d.update(logo=base64.b64encode(cur["logo"]).decode(), logo_type=cur["logo_type"])
            elif logo:
                d.update(logo=base64.b64encode(logo[0]).decode(), logo_type=logo[1])
            os.makedirs(os.path.dirname(self.path), exist_ok=True)
            tmp = self.path + ".tmp"
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(d, fh)
            os.replace(tmp, self.path)


def install(app, ctx):
    """ctx: base_dir, has_perm, csrf_ok, fresh, is_demo, audit."""
    org = Organisation(os.path.join(ctx["base_dir"], "data", "organisation.json"))
    hp = ctx["has_perm"]

    def who():
        return (getattr(g, "user", None) or {}).get("user", "")

    @app.route("/api/organisation", methods=["GET"])
    def api_organisation():
        if not (hp("settings") or hp("advisory")):
            return jsonify(error="For admins and advisors."), 403
        o = org.get()
        return jsonify(name=o["name"], has_logo=bool(o["logo"]), can_edit=bool(hp("settings")),
                       max_logo_kb=MAX_LOGO // 1024)

    @app.route("/api/organisation", methods=["POST"])
    def api_organisation_save():
        if not hp("settings"):
            return jsonify(error="Only admins set the organisation."), 403
        if ctx["is_demo"]():
            return jsonify(error="Demo mode is on: switch it off first."), 403
        if not ctx["csrf_ok"]():
            return jsonify(error="Refused (the request did not come from this page)."), 403
        if not ctx["fresh"]():
            return jsonify(error="Sign in again to make changes (your session is older than 12 hours)."), 403
        b = request.get_json(silent=True) or {}
        name = re.sub(r"\s+", " ", str(b.get("name") or "")).strip()
        if not name:
            return jsonify(error="Give the organisation's name."), 400
        if len(name) > MAX_NAME or re.search(r"[<>\x00-\x1f]", name):
            return jsonify(error=f"The name: at most {MAX_NAME} characters, without < or >."), 400
        logo = None
        if "logo" in b:
            if b["logo"] in ("", None):
                logo = ""
            else:
                logo, err = org.check_logo(b["logo"])
                if not logo:
                    return jsonify(error=err), 400
        org.save(name, logo)
        ctx["audit"].add("organisation_set", user=who(), target=name,
                         detail="logo removed" if logo == "" else "logo set" if logo else "name only")
        o = org.get()
        return jsonify(ok=True, name=o["name"], has_logo=bool(o["logo"]))

    @app.route("/organisation/logo")
    def organisation_logo():
        if not (hp("settings") or hp("advisory")):
            return Response(status=403)
        o = org.get()
        if not o["logo"]:
            return Response(status=404)
        return Response(o["logo"], mimetype=o["logo_type"] or "image/png",
                        headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"})

    return org
