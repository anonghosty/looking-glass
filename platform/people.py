# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""How accounts are named to people.

* Definitions, notes, network corrections and reports name the person by the full name they registered with
  (Users > profile > full_name), not their username. Records keep the username (it never changes and is what the
  audit log searches); the full name is looked up when shown, so a corrected name appears everywhere at once and
  entries saved before this existed show the full name too. A removed account falls back to the name saved with the
  record (curated_by_name / by_name), else its person code, never the username (2026-11-27).
* The audit log shows both: "Full Name (username)".
* Values that are not accounts ("Looking Glass", "admin", "token") are shown as they are.

Used by app.py (definitions, networks) and auth.py's audit API.
"""


import re as _re

_SIGNIN = _re.compile(r"^[a-zA-Z0-9._-]{2,40}$")      # auth.NAME_RE: what a sign-in name can look like
SYSTEM = {"looking-glass", "automation", "token", "schedule", "lg-selftest"}   # the code's own names, not accounts


def person_label(username):
    """How to name an account to people when no full name is known: its person code (person_code.py). A value that
    cannot be a sign-in name ("Looking Glass", "manage script") or a system name is shown as it is. "an account" when
    the people codes' key is damaged."""
    v = str(username or "").strip()
    if not v or not _SIGNIN.match(v) or v.lower() in SYSTEM:
        return v
    import person_code
    try:
        return person_code.code(v)
    except RuntimeError:
        # data/person_code.key is damaged: the bell says so (person_code.bell); every alert, Findings and the bell keep
        # working, naming the person "an account", never by the sign-in name (audit 2026-11-27)
        return "an account"


_DEFAULT = []          # the app's People (app.py makes one): signed_by() reads the full names through it


def signed_by(username):
    """Who made a download, as every PDF's "Generated ... by" and every CSV stamp says it: the full name and the person
    code, or the person code alone; never the sign-in name (audit 2026-11-27: the analysis, Executive and combination
    PDFs printed it on every page). A value that is not an account is shown as it is."""
    full = _DEFAULT[-1].full_name(username) if _DEFAULT else ""
    code = person_label(username)
    if not full:
        return code
    return f"{full} ({code})" if code and code != full else full


class People:
    def __init__(self, users):
        self.users = users              # auth.Users
        _DEFAULT.append(self)
        del _DEFAULT[:-1]

    def full_name(self, username):
        if not username:
            return ""
        try:
            u = self.users.get(username)
        except Exception:               # the accounts file is being rewritten: show the username this once
            return ""
        return str(((u or {}).get("profile") or {}).get("full_name") or "").strip()

    def name(self, username, saved=""):
        """For reports and pages: the registered full name, else the name saved with the record, else, for an account,
        its person code, NEVER the sign-in name (half of what signs someone in; audit 2026-11-27: a removed account's
        sign-in name showed in findings, the bell, severity ratings). Values that are not accounts are shown as they are."""
        f = self.full_name(username) or (saved or "").strip()
        if f:
            return f
        return person_label(username)

    def code_or_value(self, username):
        """The person code of an account, a value that is not an account as it is (for answers that must name nobody)."""
        return person_label(username)

    def audit(self, username):
        """For the audit log: "Full Name (username)", or the username alone when there is no full name."""
        f = self.full_name(username)
        if f and f.lower() == (username or "").lower():
            return f                        # "Ghost", not "Ghost (ghost)": the name already is the username
        return f"{f} ({username})" if f else (username or "")

    def with_names(self, rows, key="by", saved_key="by_name"):
        """Copies of the rows with rows[key] shown as the person's name."""
        return [dict(r, **{key: self.name(r.get(key), r.get(saved_key, ""))}) if r.get(key) else r for r in rows]
