"""How accounts are named to people.

* Definitions, notes, network corrections and reports name the person by the full name they registered with
  (Users > profile > full_name), not their username. Records keep the username (it never changes and is what the
  audit log searches); the full name is looked up when shown, so a corrected name appears everywhere at once and
  entries saved before this existed show the full name too. A removed account falls back to the name saved with the
  record (curated_by_name / by_name), else the username.
* The audit log shows both: "Full Name (username)".
* Values that are not accounts ("Looking Glass", "admin", "token") are shown as they are.

Used by app.py (definitions, networks) and auth.py's audit API.
"""


class People:
    def __init__(self, users):
        self.users = users              # auth.Users

    def full_name(self, username):
        if not username:
            return ""
        try:
            u = self.users.get(username)
        except Exception:               # the accounts file is being rewritten: show the username this once
            return ""
        return str(((u or {}).get("profile") or {}).get("full_name") or "").strip()

    def name(self, username, saved=""):
        """For reports and pages: the registered full name, else the name saved with the record, else the value."""
        return self.full_name(username) or (saved or "").strip() or (username or "")

    def audit(self, username):
        """For the audit log: "Full Name (username)", or the username alone when there is no full name."""
        f = self.full_name(username)
        if f and f.lower() == (username or "").lower():
            return f                        # "Ghost", not "Ghost (ghost)": the name already is the username
        return f"{f} ({username})" if f else (username or "")

    def with_names(self, rows, key="by", saved_key="by_name"):
        """Copies of the rows with rows[key] shown as the person's name."""
        return [dict(r, **{key: self.name(r.get(key), r.get(saved_key, ""))}) if r.get(key) else r for r in rows]
