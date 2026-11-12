"""Login, accounts, roles and permissions, sessions and the audit log for Looking Glass (docs/SECURITY.md).

Every page and API needs a login; /login, /register, /logout, /healthz and the static files do not. Pages without a
login redirect to /login; API calls get 401.

Accounts (data/users.json, mode 600)
* Created on the login page ("Create an account"): name, password, then the authenticator app is set up by scanning a
  QR code, confirmed with a code; 8 one-time recovery codes are shown once. New accounts are PENDING until an admin
  approves them (and gives them a role). Exception: when no active admin exists, the first account created on this
  computer itself (127.0.0.1) becomes an active admin.
* Statuses: pending, active, disabled (revoked). Passwords: salted scrypt; at least 12 characters.
* manage/manage_users.py does the same on the server's command line (recovery, scripting).

Roles and permissions (data/roles.json): permissions are fixed (PERMS); roles are sets of permissions, editable by an
admin on /admin. admin always has every permission. Defaults: external = view (data always masked, no demo switch),
analyst = view + unmasked +
export + malpedia, admin = all. Enforced on the server: masking (no "unmasked" -> demo mode for that user), exports,
Malpedia, Settings, users, audit.

Against password guessing: 5 wrong passwords or codes for an account from one address lock that pair for 15 minutes;
20 failures from one address in an hour lock the address; registrations: 5 per address per hour.

Against session hijacking: server-side sessions (the browser holds a random 256-bit id, the server only its SHA-256);
a new id at every login; cookie HttpOnly + SameSite=Strict (+ Secure and __Host- over HTTPS); a session works only from
the address and browser it was created on; idle and absolute timeouts; logout, password change, revocation, a role
change or an admin "kick" end sessions on the server; a per-session CSRF token for every change; other computers can
only log in over HTTPS.

Audit (data/audit.log, JSON lines, mode 600, each line chained to the one before by its SHA-256 and archived, never
deleted early: audit_chain.py; read in the Audit portal, audit_portal.py): registrations, approvals, logins and failures, lockouts,
logouts, kicks, sessions ended for misuse, role / permission / status changes, MFA resets, settings changes; each with
time, account, address, location and browser.

Automation: scripts on this computer use the key in data/automation.key (header X-LG-Automation), accepted from
this computer only, with every permission.
"""
import base64
import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import struct
import threading
import time
from urllib.parse import quote, urlsplit

from flask import abort, g, jsonify, redirect, render_template, request
from werkzeug.security import check_password_hash, generate_password_hash

import throttle_prune
import password_policy

PUBLIC_PATHS = ("/login", "/register", "/forgot", "/logout", "/healthz", "/static/", "/favicon.ico")
# sign-up attempts whose e-mail domain is looked up in DNS, per address and hour (room for typing mistakes)
REGISTER_DNS_PER_HOUR = 30
NAME_RE = re.compile(r"^[a-zA-Z0-9._-]{2,40}$")
ROLE_RE = re.compile(r"^[a-z][a-z0-9_-]{1,30}$")
TEST_PREFIX = "lg-selftest-"      # reserved for security_testing/security_retest.py; cannot be registered
MIN_PASSWORD = 12
_DUMMY_HASH = generate_password_hash("not-a-real-password-" + secrets.token_hex(8))

PERMS = {
    "view": "See both platforms (real addresses, network and host names masked unless the role also has 'unmasked')",
    "unmasked": "See real IP addresses, network names and host names",
    "export": "Download CSV files and complete lists",
    "malpedia": "Look up malware (Malpedia, definitions) and vulnerabilities (CVEs: NVD, CISA KEV, EPSS)",
    "settings": "Change Settings (country, constituency) for both platforms",
    "definitions": "Define malware names Malpedia does not know and issues that are not CVEs, with references (the Definitions page)",
    "networks": "Correct network names and types (the AS-number registry), in Settings or on the Definitions page",
    "management": "The management portal: aggregated statistics, look-ups and executive reports, never individual addresses. "
                  "Only the management role (and admins, to preview it) can have it",
    "users": "Manage accounts, roles and sessions (approve, revoke, kick)",
    "audit": "The Audit portal, read only: the audit log by tab, the dashboard and control checks, the access review, who is "
             "signed in, the log's integrity and evidence exports. Ending a session needs 'users'",
    "advisory": "Write and generate advisories: the findings management sends them, the advisory page (description, "
                "recommended actions) and the final report with the affected devices",
}
DEFAULT_ROLES = {"external": ["view"], "analyst": ["view", "unmasked", "export", "malpedia"], "researcher": ["definitions", "networks"], "management": ["management"],
                 "advisor": ["advisory"], "auditor": ["audit"], "admin": list(PERMS)}
# the auditor role (audit_portal.py): exactly 'audit', fixed like the management role. No one can widen, narrow or remove
# it, so what an auditor may do never depends on the people being audited. Administrators only give people the role.
AUDITOR_ROLE, AUDITOR_PERMS = "auditor", ["audit"]
# Permanent roles with fixed permissions (2026-11-11): no one can remove them or change what they may do; administrators
# only give people these roles. admin always has every permission (handled apart).
FIXED_ROLES = {"management": ["management"], AUDITOR_ROLE: list(AUDITOR_PERMS), "advisor": ["advisory"],
               "researcher": ["definitions", "networks"], "external": ["view"]}   # external: masked viewing only, never more
# Permissions that belong to one role only (and admin): they cannot be ticked onto any other role.
EXCLUSIVE_PERMS = {"management": "management", "definitions": "researcher", "advisory": "advisor", "users": "admin"}
AUDIT_PATHS = ("/audit", "/api/audit/", "/api/admin/audit", "/api/admin/sessions", "/overview", "/api/notifications")   # all an auditor opens
ADVISORY_PATHS = ("/findings", "/api/findings", "/advisory", "/api/advisory", "/api/organisation", "/organisation/logo", "/api/notifications", "/overview")    # all the advisor role (no 'view') can open
DEFINITIONS_PATHS = ("/definitions", "/api/kb/", "/api/networks", "/api/lookups", "/api/intel", "/api/notes", "/api/combo-codes/",
                     "/findings", "/api/findings", "/intel/", "/api/notifications", "/overview")
MANAGEMENT_PATHS = ("/management", "/api/mgmt/", "/api/lookups", "/api/combo-codes/", "/findings", "/api/findings",
                    "/intel/", "/api/intel/acode/", "/review/", "/api/review/", "/api/notifications", "/overview")  # all the management role can open
MANAGEMENT_ONLY = "management"            # the permission (and role) that cannot be given to any other role   # all a researcher (no 'view') can open
LOWEST_ROLE = "external"
# "Peace of mind" (peace.py): an admin who ticks it keeps only the admin and audit duties and Settings; the platforms,
# the findings, the portals and their notifications are out of their way. Applied to the permissions on every request.
PEACE_PERMS = {"users", "audit", "settings", "view"}      # view: the platforms' Overview, to keep an eye on the database
# the work they step out of, by its addresses: the platforms, the findings and the portals (pages and their data)
PEACE_CLOSED = ("/services", "/findings", "/api/findings", "/advisory", "/api/advisory", "/management", "/api/mgmt/", "/review/",
                "/api/review/", "/combinations", "/api/combos", "/definitions", "/api/kb/", "/api/notes", "/intel/", "/api/intel",
                "/api/analyst-codes", "/api/combo-codes/")
PEACE_PATHS = ("/settings", "/api/settings", "/api/asns/identify", "/api/networks", "/api/clock", "/api/svc/clock",
               "/api/organisation", "/organisation/logo", "/overview", "/api/peace", "/api/notifications", "/audit")
PEACE = {"of": lambda user: False}           # peace.py: whether this admin has Peace of mind on
# what each built-in role is for (shown on the admin page; custom roles are described by their permissions)
ROLE_INFO = {
    "external": "People outside the security team, such as partners or visitors. They see both platforms with IP addresses, "
                "network names and host names always masked, cannot switch masking off (no Demo button), and cannot export, "
                "use Malpedia or change anything.",
    "analyst": "CSIRT analysts. They see all data unmasked to analyse it, can export lists and CSV files, look up malware on "
               "Malpedia, and switch Demo mode on for presentations. They cannot change Settings or manage users.",
    "management": "Managers and executives. They use the management portal only: aggregated statistics of both platforms "
                  "(infections, issues, regions, sectors, networks, trends), explanations of infections (Malpedia) and "
                  "vulnerabilities (CVE), and polished executive reports for the filters they choose. They never see individual "
                  "addresses or host lists, and no other role can be given this portal.",
    "researcher": "Security researchers of the organisation. They work only on the Definitions page: the malware names "
                  "Malpedia does not know and the issues that are not CVEs, which they research and define with references "
                  "(evidence); the CVEs found, with their NVD / CISA KEV / EPSS status; and the network names (AS-number "
                  "registry), which they correct. They do not see the platforms or the host addresses.",
    "advisor": "Advisors. They turn a finding management has decided on into the advisory: the organisation's title and logo, "
               "the affected CVEs, issues and categories, the impact, the recommended actions, and the full report with the "
               "affected devices underneath. They work on the Findings and advisory pages only.",
    "auditor": "Auditors (internal or external, e.g. a CISA-certified auditor). They use the Audit portal only, read only: the "
               "audit log in its tabs, the dashboard and control checks, the access review of every account, the log's "
               "integrity check and exports for a period. They never see the platforms or any host data, and cannot change "
               "anything. The role's permissions are fixed: no one can change them.",
    "admin": "Administrators. Everything an analyst can do, plus Settings (country, constituency), malware definitions, accounts, roles and "
             "permissions, sessions and the audit log.",
}
EXPORT_PATHS = ("/api/svc/hosts.csv",)


def _now():
    return time.time()


def _h(token):
    return hashlib.sha256((token or "").encode()).hexdigest()


def _secure_write(path, data, mode="w"):
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, mode, encoding="utf-8") as f:
        json.dump(data, f, indent=1)
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


# ---------------------------------------------------------------- MFA: time-based one-time codes (RFC 6238)
def totp_new_secret():
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def totp_at(secret, counter):
    key = base64.b32decode(secret + "=" * (-len(secret) % 8), casefold=True)
    d = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    o = d[-1] & 0x0F
    return f"{(struct.unpack('>I', d[o:o + 4])[0] & 0x7FFFFFFF) % 1_000_000:06d}"


def totp_check(secret, code, last_counter=None, now=None):
    """The matching 30-second step (to store as 'last used'), or None. Rejects codes already used (replay)."""
    code = re.sub(r"\s", "", code or "")
    if not re.fullmatch(r"\d{6}", code) or not secret:
        return None
    c = int((now or time.time()) // 30)
    for step in (c, c - 1, c + 1):
        if hmac.compare_digest(totp_at(secret, step), code) and (last_counter is None or step > last_counter):
            return step
    return None


def totp_uri(secret, name, issuer="Looking Glass"):
    return f"otpauth://totp/{quote(issuer)}:{quote(name)}?secret={secret}&issuer={quote(issuer)}&algorithm=SHA1&digits=6&period=30"


def new_recovery_codes(n=8):
    codes = ["-".join(secrets.token_hex(2) for _ in range(3)) for _ in range(n)]
    return codes, [generate_password_hash(c) for c in codes]


# e-mail: local part of letters, digits and . _ % + - (no dot first, last or twice in a row); domain of labels of
# letters, digits and inner hyphens; a top-level domain of 2-24 letters (or an internationalised xn-- one)
EMAIL_RE = re.compile(r"^(?=.{6,254}$)(?=[^@]{1,64}@)[A-Za-z0-9_%+\-]+(?:\.[A-Za-z0-9_%+\-]+)*@"
                      r"(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.)+(?:[A-Za-z]{2,24}|xn--[A-Za-z0-9\-]{2,59})$")
LETTER_RE = re.compile(r"[^\W\d_]")      # at least one letter (any alphabet)


def email_domain_problem(email):
    """The domain must exist and be able to receive mail (an MX record, or an address record as the fallback MX).
    DNS that does not answer (offline server, firewall) is not held against the person: only a definite 'no such
    domain' / 'no mail' answer is."""
    domain = email.rsplit("@", 1)[-1].lower()
    if domain in ("example.com", "example.net", "example.org") or domain.endswith(
            (".example.com", ".example.net", ".example.org", ".example", ".test", ".invalid", ".localhost", ".local")):
        return f"{domain} is reserved for examples and tests, not real mail. Use your own email address."
    try:
        import dns.exception
        import dns.resolver
    except ImportError:
        return None
    r = dns.resolver.Resolver()
    r.timeout, r.lifetime = 3, 5
    try:
        mx = r.resolve(domain, "MX")
        if all(str(a.exchange) in (".", "") for a in mx):     # "null MX" (RFC 7505): the domain takes no mail
            return f"The domain {domain} does not accept email. Check the email address."
        return None
    except dns.resolver.NXDOMAIN:
        return f"The domain {domain} does not exist. Check the email address."
    except (dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        pass
    except dns.exception.DNSException:
        return None                     # DNS not reachable from this server: do not block
    for rr in ("A", "AAAA"):
        try:
            r.resolve(domain, rr)
            return None
        except dns.resolver.NXDOMAIN:
            return f"The domain {domain} does not exist. Check the email address."
        except (dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            continue
        except dns.exception.DNSException:
            return None
    return f"The domain {domain} cannot receive email. Check the email address."
PERSON_RE = re.compile(r"^[^\x00-\x1f<>\"`{}\\]{2,100}$")


def load_countries():
    """[(ISO 3166-1 alpha-2, name)] from the system's iso-codes package; the 54 African countries as a fallback."""
    try:
        with open("/usr/share/iso-codes/json/iso_3166-1.json", encoding="utf-8") as f:
            rows = json.load(f)["3166-1"]
        return sorted(((r["alpha_2"], r.get("common_name") or r["name"]) for r in rows), key=lambda x: x[1])
    except (OSError, ValueError, KeyError):
        p = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static", "data", "adm1", "index.json")
        try:
            with open(p, encoding="utf-8") as f:
                return sorted(((k, v["country"]) for k, v in json.load(f)["countries"].items()), key=lambda x: x[1])
        except (OSError, ValueError, KeyError):
            return [("GH", "Ghana")]


def profile_problem(full_name, org, email, country, countries, check_domain=True):
    if not PERSON_RE.match(full_name or "") or len(LETTER_RE.findall(full_name)) < 2:
        return "Enter your full name (2-100 characters, with letters)."
    if not PERSON_RE.match(org or "") or len(org) > 120 or len(LETTER_RE.findall(org)) < 2:
        return "Enter your organisation (2-100 characters, with letters)."
    if not EMAIL_RE.match(email or ""):
        return "Enter a valid email address, like name@organisation.org."
    problem = email_domain_problem(email) if check_domain else None
    if problem:
        return problem
    if country not in countries:
        return "Choose your country."
    return None


COMMON_WORDS = ("password", "passw0rd", "welcome", "admin", "qwerty", "letmein", "iloveyou", "monkey", "dragon", "master",
                 "login", "abc123", "123456", "shadowserver", "lookingglass", "looking", "glass", "changeme", "secret", "summer",
                 "winter", "football", "baseball", "sunshine", "princess", "trustno1", "csirt", "security")
PASSWORD_RULES = "At least 12 characters, with upper and lower case letters, a number and a symbol."


def password_problem(name, pw, pw2=None, avoid=()):
    """Why a password is not acceptable, or None. Rules (also shown on the page, checked live there):
    12-200 characters; upper case, lower case, a digit and a symbol; not containing the user name, the person's name
    or email name, or a common password word; no character 4 times in a row."""
    pw = pw or ""
    if len(pw) < MIN_PASSWORD:
        return f"Use at least {MIN_PASSWORD} characters. " + PASSWORD_RULES
    if len(pw) > 200:
        return "That password is too long."
    missing = [label for test, label in ((r"[a-z]", "a lower-case letter"), (r"[A-Z]", "an upper-case letter"),
                                         (r"\d", "a number"), (r"[^A-Za-z0-9]", "a symbol")) if not re.search(test, pw)]
    if missing:
        return "Add " + ", ".join(missing[:-1]) + (" and " if len(missing) > 1 else "") + missing[-1] + ". " + PASSWORD_RULES
    if re.search(r"(.)\1\1\1", pw):
        return "Do not repeat the same character four times in a row."
    low = pw.lower()
    folded = re.sub(r"[^a-z]", "", low.translate(str.maketrans("013457@$", "oleastas")))
    personal = [w.lower() for w in (name, *avoid) if w]
    parts = {p for w in personal for p in re.split(r"[^a-z0-9]+", w) if len(p) >= 4} | {w for w in personal if len(w) >= 4}
    if any(p in low for p in parts):
        return "Do not use your name, user name or email address in the password."
    if any(w in low or w in folded for w in COMMON_WORDS):
        return "That password contains a common word or pattern (like 'password', 'welcome' or '123456'). Choose something less predictable."
    if pw2 is not None and pw != pw2:
        return "The two passwords differ."
    return None


# ---------------------------------------------------------------- location of an address (offline only)
_GEO = {"reader": None, "tried": False}


def location(ip):
    """'This computer', 'Local network', or 'Internet' (+ country / city if data/GeoLite2-City.mmdb and the maxminddb
    package are installed). Addresses are never sent to an online service."""
    try:
        a = ipaddress.ip_address(ip or "")
    except ValueError:
        return "Unknown"
    if a.is_loopback:
        return "This computer"
    if a.is_private or a.is_link_local:
        return "Local network"
    if not _GEO["tried"]:
        _GEO["tried"] = True
        try:
            import maxminddb  # optional
            p = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "GeoLite2-City.mmdb")
            _GEO["reader"] = maxminddb.open_database(p) if os.path.exists(p) else None
        except Exception:
            _GEO["reader"] = None
    r = _GEO["reader"]
    if r:
        try:
            rec = r.get(str(a)) or {}
            city = (rec.get("city") or {}).get("names", {}).get("en", "")
            country = (rec.get("country") or {}).get("names", {}).get("en", "")
            return "Internet · " + ", ".join(x for x in (city, country) if x) if (city or country) else "Internet"
        except Exception:
            pass
    return "Internet"


# ---------------------------------------------------------------- storage
class Users:
    """data/users.json: {"users": {name: {...}}}. Re-read when the file changes."""

    def __init__(self, path):
        self.path, self.mtime, self.data, self.lock = path, None, {"users": {}}, threading.RLock()

    def _load(self):
        try:
            m = os.path.getmtime(self.path)
        except OSError:
            self.data, self.mtime = {"users": {}}, None
            return
        if m != self.mtime:
            with self.lock:
                try:
                    with open(self.path, encoding="utf-8") as f:
                        self.data = json.load(f)
                    self.data.setdefault("users", {})
                    self.mtime = m
                except (OSError, ValueError):
                    pass

    def all(self):
        self._load()
        return self.data.get("users", {})

    def get(self, name):
        return self.all().get(name)

    def save(self):
        with self.lock:
            _secure_write(self.path, self.data)
            self.mtime = os.path.getmtime(self.path)

    def set_password(self, name, password, role=None, status=None):
        with self.lock:
            self._load()
            u = self.data.setdefault("users", {}).setdefault(name, {"role": role or LOWEST_ROLE, "created": int(_now()), "status": status or "active"})
            u["hash"] = generate_password_hash(password)
            u["changed"] = int(_now())
            u["pw_set_at"] = int(_now())                # when this password was set (password_policy.py)
            if role:
                u["role"] = role
            if status:
                u["status"] = status
            self.save()


class Roles:
    def __init__(self, path):
        self.path = path
        self.lock = threading.Lock()
        try:
            with open(path, encoding="utf-8") as f:
                self.roles = json.load(f)
        except (OSError, ValueError):
            self.roles = dict(DEFAULT_ROLES)
        self.roles.setdefault("researcher", list(DEFAULT_ROLES["researcher"]))    # added in a later version
        self.roles.setdefault("advisor", list(DEFAULT_ROLES["advisor"]))          # added later still (advisories)
        # once: researchers also correct network names (added after the role). A marker file makes it run only once, so
        # an administrator who later removes the permission keeps that choice.
        marker = os.path.join(os.path.dirname(path), ".roles_networks_added")
        if not os.path.exists(marker):
            if "networks" not in self.roles["researcher"]:
                self.roles["researcher"] = sorted(set(self.roles["researcher"]) | {"networks"})
                try:
                    _secure_write(path, {r: (list(PERMS) if r == "admin" else p) for r, p in self.roles.items()})
                except OSError:
                    pass
            try:
                with open(marker, "w") as f:
                    f.write("researcher role given the 'networks' permission\n")
            except OSError:
                pass
        for r, ps in FIXED_ROLES.items():                # fixed: whatever roles.json says
            self.roles[r] = list(ps)
        self._exclusive()
        self.roles["admin"] = list(PERMS)

    def _exclusive(self):
        """Exclusive permissions stay on their own role (and admin) only; fixed roles keep exactly their permissions."""
        for r in list(self.roles):
            if r == "admin" or r in FIXED_ROLES:
                continue
            self.roles[r] = [p for p in self.roles[r] if EXCLUSIVE_PERMS.get(p, r) == r]

    def perms(self, role):
        if role == "admin":
            return set(PERMS)
        return {p for p in self.roles.get(role, []) if p in PERMS}

    def save(self, roles):
        with self.lock:
            clean = {"admin": list(PERMS)}
            for r, ps in roles.items():
                if r != "admin":                         # exclusive permissions only on their own role
                    clean[r] = sorted({p for p in ps if p in PERMS and EXCLUSIVE_PERMS.get(p, r) == r})
            for r, ps in FIXED_ROLES.items():            # permanent roles: always exactly these, never removed
                clean[r] = list(ps)
            self.roles = clean
            _secure_write(self.path, clean)


class Audit:
    def __init__(self, path, logger=None):
        self.path, self.log, self.lock = path, logger, threading.Lock()
        import audit_chain                      # tamper-evident lines, archives kept for the retention (audit_chain.py)
        self.chain = audit_chain.Chain(path)

    def add(self, event, user="", target="", detail="", ip=None, ua=None):
        try:
            ip = ip if ip is not None else (request.remote_addr or "")
            ua = ua if ua is not None else request.headers.get("User-Agent", "")
        except RuntimeError:                    # outside a request
            ip, ua = ip or "", ua or ""
        rec = {"t": round(_now(), 3), "event": event, "user": user or "", "target": target or "", "detail": str(detail)[:300],
               "ip": ip, "location": location(ip), "ua": (ua or "")[:200]}
        with self.lock:
            try:
                self.chain.append(rec)          # chained to the line before; rotated into the archive, never deleted early
            except OSError:
                pass
        if self.log:
            self.log.warning("audit %s user=%s target=%s ip=%s %s", event, user, target, ip, rec["detail"])

    def records(self):
        """Every entry kept (the archives within the retention, then the current file), oldest first."""
        rows = []
        for line in self.chain.lines():
            try:
                rows.append(json.loads(line))
            except ValueError:
                pass
        return rows

    @staticmethod
    def is_selftest(r):
        """Made by the built-in security test (installer, security_retest.py): its temporary lg-selftest-* accounts
        and its own client name. Kept in the log like everything else; hidden by default on the Admin page."""
        return (r.get("user") or "").startswith(TEST_PREFIX) or (r.get("target") or "").startswith(TEST_PREFIX) \
            or (r.get("ua") or "").startswith("LookingGlass-retest")

    def read(self, limit=200, q="", offset=0, selftests=True, label=None):
        """(total shown, rows, self-test events hidden). label(username) names accounts "Full Name (username)"
        (people.py); the search then also finds a person by their name."""
        rows = self.records()
        rows.reverse()
        if label:
            names = {}
            for r in rows:
                for k in ("user", "target"):
                    v = r.get(k) or ""
                    if v and v not in names:
                        names[v] = label(v)
                    if v and names[v] != v:
                        r[k + "_label"] = names[v]
        if q:
            ql = q.lower()
            rows = [r for r in rows if ql in json.dumps(r).lower()]
        hidden = 0
        if selftests:
            for r in rows:
                if self.is_selftest(r):
                    r["selftest"] = True
        else:
            kept = [r for r in rows if not self.is_selftest(r)]
            hidden, rows = len(rows) - len(kept), kept
        return len(rows), rows[offset:offset + limit], hidden


class Sessions:
    def __init__(self, path, idle, maximum):
        self.path, self.idle, self.max = path, idle, maximum
        self.lock = threading.Lock()
        self._dirty_at = 0
        try:
            with open(path, encoding="utf-8") as f:
                self.s = json.load(f)
        except (OSError, ValueError):
            self.s = {}

    def _persist(self, force=False):
        if force or _now() - self._dirty_at > 30:
            self._dirty_at = _now()
            try:
                _secure_write(self.path, self.s)
            except OSError:
                pass

    PERSIST_MAX = 5 * 86400        # "Stay signed in": at most 5 days, whatever the settings say
    ROTATE_EVERY = 12 * 3600       # long sessions get a new id every 12 hours (a copied cookie stops working)

    def limits(self, s):
        """(idle, maximum) seconds for this session: long sessions (stay signed in) 5 days; others the settings."""
        if s.get("persist"):
            return self.PERSIST_MAX, self.PERSIST_MAX
        return self.idle, self.max

    def create(self, user, ip, ua, persist=False):
        token = secrets.token_urlsafe(32)                     # 256 bits
        with self.lock:
            now = _now()
            self.s[_h(token)] = {"user": user, "ip": ip, "ua": _h(ua), "ua_text": (ua or "")[:200], "location": location(ip),
                                 "created": now, "seen": now, "rotated": now, "persist": bool(persist), "csrf": secrets.token_urlsafe(24)}
            self._persist(force=True)
        return token

    def rotate(self, key):
        """Give a session a new id (same login, same CSRF token); the old id stops working at once."""
        token = secrets.token_urlsafe(32)
        with self.lock:
            s = self.s.pop(key, None)
            if not s:
                return None
            s["rotated"] = _now()
            self.s[_h(token)] = s
            self._persist(force=True)
        return token

    def check(self, token, ip, ua):
        """(session or None, reason it was ended or None)."""
        if not token:
            return None, None
        k = _h(token)
        with self.lock:
            s = self.s.get(k)
            if not s:
                return None, None
            now = _now()
            idle, maximum = self.limits(s)
            why = ("idle timeout" if now - s["seen"] > idle else "maximum age" if now - s["created"] > maximum
                   else "used from another address" if s["ip"] != ip else "used from another browser" if s["ua"] != _h(ua) else None)
            if why:
                self.s.pop(k, None)
                self._persist(force=True)
                return None, (why, s)
            s["seen"] = now
            self._persist()
            return dict(s, key=k), None

    def end(self, token=None, key=None):
        with self.lock:
            s = self.s.pop(key or _h(token or ""), None)
            self._persist(force=True)
            return s

    def end_user(self, user):
        with self.lock:
            ks = [k for k, v in self.s.items() if v["user"] == user]
            for k in ks:
                self.s.pop(k, None)
            self._persist(force=True)
            return len(ks)

    def list(self):
        now = _now()
        with self.lock:
            return [{"id": k[:16], "user": v["user"], "ip": v["ip"], "location": v.get("location", ""), "browser": v.get("ua_text", ""),
                     "created": v["created"], "seen": v["seen"], "idle_s": round(now - v["seen"]), "persist": bool(v.get("persist")),
                     "expires": round(min(v["seen"] + self.limits(v)[0], v["created"] + self.limits(v)[1]))} for k, v in self.s.items()]

    def end_id(self, sid):
        with self.lock:
            k = next((k for k in self.s if k[:16] == sid), None)
            s = self.s.pop(k, None) if k else None
            self._persist(force=True)
            return s

    def prune(self):
        now = _now()
        with self.lock:
            for k in [k for k, v in self.s.items() if now - v["seen"] > self.limits(v)[0] or now - v["created"] > self.limits(v)[1]]:
                self.s.pop(k, None)


class Throttle:
    def __init__(self):
        self.fail, self.lock = {}, threading.Lock()
        self.sweeper = throttle_prune.Sweeper()     # old records are cleared out (throttle_prune.py)

    def _recent(self, key, window):
        now = _now()
        kept = [t for t in self.fail.get(key, []) if now - t < window]
        if kept:
            self.fail[key] = kept
        else:
            self.fail.pop(key, None)                # a look-up alone leaves no empty record behind
        return kept

    def locked(self, ip, name):
        with self.lock:
            return len(self._recent((ip, (name or "").lower()), 900)) >= 5 or len(self._recent((ip, None), 3600)) >= 20

    def left(self, ip, name):
        """Attempts left before the 15-minute lock for this name from this address."""
        with self.lock:
            return max(0, min(5 - len(self._recent((ip, (name or "").lower()), 900)), 20 - len(self._recent((ip, None), 3600))))

    def failed(self, ip, name):
        with self.lock:
            now = _now()
            self.fail.setdefault((ip, (name or "").lower()), []).append(now)
            self.fail.setdefault((ip, None), []).append(now)
            self.sweeper.maybe(self.fail, now)

    def ok(self, ip, name):
        with self.lock:
            self.fail.pop((ip, (name or "").lower()), None)

    def clear_address(self, ip):
        """Forget every failure counted for one address (retest_reset.py: this computer's own, after the self-test)."""
        with self.lock:
            gone = [k for k in self.fail if ip in (k[0], k[1])]
            for k in gone:
                del self.fail[k]
            return len(gone)

    def count(self, key, window, add=False):
        with self.lock:
            r = self._recent(key, window)
            if add:
                now = _now()
                r.append(now)
                self.fail[key] = r
                self.sweeper.maybe(self.fail, now)
            return len(r)


def _is_loopback(addr):
    try:
        return ipaddress.ip_address(addr or "").is_loopback
    except ValueError:
        return False


def _safe_next(n):
    """Only same-site paths after login (no open redirect to another site)."""
    if not n or not n.startswith("/") or n.startswith("//") or n.startswith("/\\"):
        return "/"
    parts = urlsplit(n)
    return n if not parts.scheme and not parts.netloc else "/"


# ---------------------------------------------------------------- the app side
def install(app, base_dir, logger):
    data_dir = os.path.join(base_dir, "data")
    users = Users(os.path.join(data_dir, "users.json"))
    roles = Roles(os.path.join(data_dir, "roles.json"))
    # the lowest role used to be called "viewer": rename it to "external" (roles and accounts), once
    if "viewer" in roles.roles:
        r = dict(roles.roles); r.setdefault("external", r.pop("viewer")); r.pop("viewer", None); roles.save(r)
    _u = Users(os.path.join(data_dir, "users.json")); _u._load()
    if any(v.get("role") == "viewer" for v in _u.data.get("users", {}).values()):
        for v in _u.data["users"].values():
            if v.get("role") == "viewer":
                v["role"] = "external"
        _u.save()
    audit = Audit(os.path.join(data_dir, "audit.log"), logger)
    sessions = Sessions(os.path.join(data_dir, "sessions.json"),
                        idle=int(os.environ.get("SESSION_IDLE_MINUTES", "60")) * 60,
                        maximum=int(os.environ.get("SESSION_MAX_HOURS", "12")) * 3600)
    throttle = Throttle()
    pw_policy = password_policy.Policy(data_dir)        # password expiry (Settings → Password policy)
    insecure_remote = os.environ.get("ALLOW_INSECURE_REMOTE_LOGIN") == "1"
    mfa_required = os.environ.get("MFA_REQUIRED", "1") != "0"
    registration_open = os.environ.get("REGISTRATION", "1") != "0"
    key_path = os.path.join(data_dir, "automation.key")
    if not os.path.exists(key_path):
        fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(secrets.token_urlsafe(32))
    with open(key_path) as f:
        automation_key = f.read().strip()
    pending = {}            # second login step / enrolment: sha256(token) -> {...}
    plock = threading.Lock()
    countries = load_countries()
    country_codes = {c for c, _ in countries}
    default_country = (os.environ.get("COUNTRY") or "GH").upper()

    def cookie_name():
        return "__Host-lg_session" if request.is_secure else "lg_session"

    def client():
        return request.remote_addr or "", request.headers.get("User-Agent", "")

    def perms_of(name):
        u = users.get(name) or {}
        return roles.perms(u.get("role", LOWEST_ROLE)) if u.get("status") == "active" else set()

    def has_perm(p):
        u = getattr(g, "user", None)
        return bool(u and p in u.get("perms", ()))

    def active_admins():
        # the temporary accounts of security_testing/security_retest.py never count: the first-run page stays as it is while
        # the retest runs on a server that has no administrator yet
        return [n for n, u in users.all().items() if u.get("status") == "active" and "users" in roles.perms(u.get("role", ""))
                and not n.startswith(TEST_PREFIX)]

    # the first administrator also needs the one-time setup code from data/setup_code (first_run.py)
    import first_run
    setup = first_run.SetupCode(data_dir)
    setup.sync(not active_admins())

    # ---------------- every request
    @app.before_request
    def _require_login():
        g.user = None
        p = request.path
        if p.startswith(PUBLIC_PATHS):
            return None
        ip, ua = client()
        key = request.headers.get("X-LG-Automation")
        if key and _is_loopback(ip) and hmac.compare_digest(key, automation_key):
            g.user = {"user": "automation", "role": "admin", "perms": set(PERMS), "csrf": None, "automation": True}
            return None
        s, ended = sessions.check(request.cookies.get(cookie_name()) or request.cookies.get("lg_session"), ip, ua)
        if ended and "another" in ended[0]:
            audit.add("session_misuse", user=ended[1]["user"], detail=f"{ended[0]} (session of {ended[1]['ip']})")
        if s:
            u = users.get(s["user"])
            # account removed, revoked, or its password changed after this login: the session ends
            if not u or u.get("status") != "active" or u.get("changed", 0) > s["created"]:
                sessions.end(key=s["key"])
            else:
                g.user = dict(s, role=u.get("role", LOWEST_ROLE), perms=roles.perms(u.get("role", LOWEST_ROLE)))
                if "users" in g.user["perms"] and PEACE["of"](s["user"]):
                    g.user["perms"], g.user["peace"] = set(g.user["perms"]) & PEACE_PERMS, True
                # long sessions get a new id every 12 hours: a copied cookie stops working on its own
                if s.get("persist") and _now() - s.get("rotated", s["created"]) > sessions.ROTATE_EVERY:
                    new_tok = sessions.rotate(s["key"])
                    if new_tok:
                        g.rotated_token, g.user["key"] = new_tok, _h(new_tok)
                # Peace of mind: Admin, the audit log, Settings and the platforms' Overview (to keep an eye on the database);
                # the platforms themselves, the findings and the portals are closed, pages and data alike
                if g.user.get("peace") and not p.startswith(("/api/me", "/admin", "/api/admin", "/audit")):
                    if p.startswith(PEACE_CLOSED):
                        if p.startswith("/api/"):
                            return jsonify(error="Peace of mind is on: Admin, the audit log, Settings and the Overview only."), 403
                        return redirect("/?intro=1")
                    if p == "/" and request.args.get("intro") != "1":
                        return redirect("/?intro=1")           # the Overview, never the map
                    return None
                if not p.startswith(("/api/me", "/admin", "/api/admin", "/audit")) and "view" not in g.user["perms"]:
                    # management: only the management portal (the start page sends them there)
                    if MANAGEMENT_ONLY in g.user["perms"] and not ({"definitions", "networks"} & g.user["perms"]):
                        if p.startswith(MANAGEMENT_PATHS):
                            return None
                        if p in ("/", "/services", "/definitions", "/settings"):
                            return redirect("/management")
                        abort(403)
                    # advisors: their portal, the advisory pages and Findings (the start page sends them to their portal)
                    if "advisory" in g.user["perms"] and not ({"definitions", "networks"} & g.user["perms"]):
                        if p.startswith(ADVISORY_PATHS):
                            return None
                        if p in ("/", "/services", "/definitions", "/settings", "/management"):
                            return redirect("/advisory")
                        abort(403)
                    # auditors: the Audit portal only, read only (the start page sends them there)
                    if g.user.get("role") == AUDITOR_ROLE:
                        if p.startswith(AUDIT_PATHS):
                            return None
                        if p in ("/", "/services", "/definitions", "/settings", "/management", "/findings", "/advisory"):
                            return redirect("/audit")
                        abort(403)
                    # researchers: only the Definitions page (and the start page sends them there)
                    portal = {"definitions", "networks"} & g.user["perms"]
                    if portal and p.startswith(DEFINITIONS_PATHS):
                        return None
                    if portal and p in ("/", "/services"):
                        return redirect("/definitions")
                    abort(403)
                if (p in EXPORT_PATHS or request.args.get("all") == "1") and "export" not in g.user["perms"]:
                    return jsonify(error="Your role cannot export full lists (permission 'export')."), 403
                return None
        if p.startswith("/api/"):
            return jsonify(error="Login required", login="/login"), 401
        return redirect("/login?next=" + quote(_safe_next(request.full_path.rstrip("?")), safe="/"))

    @app.after_request
    def _no_store(resp):
        if request.path.startswith(("/api/", "/login", "/register", "/forgot", "/settings", "/admin", "/audit")):
            resp.headers["Cache-Control"] = "no-store"
        elif resp.mimetype == "text/html" and "Cache-Control" not in resp.headers:
            # every page: the browser asks again each time, so what it shows is always the page as it is now
            resp.headers["Cache-Control"] = "no-cache"
        tok = getattr(g, "rotated_token", None)
        if tok:
            s = g.user
            resp.set_cookie(cookie_name(), tok, httponly=True, samesite="Strict", secure=request.is_secure, path="/",
                            max_age=max(60, int(s["created"] + sessions.PERSIST_MAX - _now())))
        return resp

    def fresh():
        """Changes (admin actions, Settings) need a sign-in from the last 12 hours; a long "stay signed in" session can
        keep viewing, but must sign in again to change anything. Automation and short sessions are always fresh."""
        u = getattr(g, "user", None) or {}
        return bool(u.get("automation")) or not u.get("persist") or _now() - u.get("created", 0) < 12 * 3600

    @app.context_processor
    def _user():
        u = getattr(g, "user", None) or {}
        return {"lg_user": u.get("user", ""), "lg_role": u.get("role", ""), "lg_csrf": u.get("csrf") or "",
                "lg_perms": sorted(u.get("perms", ())), "lg_peace": bool(u.get("peace"))}

    def attempts_msg(base, ip, name):
        n = throttle.left(ip, name)
        if n <= 0:
            return "Too many failed attempts. Try again in 15 minutes."
        return f"{base} {n} attempt{'s' if n != 1 else ''} left before a 15-minute lock."

    def remote_needs_tls():
        ip, _ = client()
        return not _is_loopback(ip) and not request.is_secure and not insecure_remote

    def page(tpl, code=200, **kw):
        kw.setdefault("error", "")
        kw.setdefault("tls", not remote_needs_tls())
        kw.setdefault("registration", registration_open)
        kw.setdefault("no_admin", not active_admins())
        setup.sync(kw["no_admin"])          # a code while there is no administrator, none once there is
        kw.setdefault("local", _is_loopback(client()[0]))
        kw.setdefault("view", "choice")
        kw.setdefault("form", {})
        kw.setdefault("countries", countries)
        kw.setdefault("default_country", default_country)
        return render_template(tpl, **kw), code

    def start_session(name, nxt, persist=False):
        ip, ua = client()
        old = request.cookies.get(cookie_name())
        if old:
            sessions.end(old)                                   # a new id at every login (no session fixation)
        token = sessions.create(name, ip, ua, persist=persist)
        with users.lock:
            users._load()
            users.data["users"][name]["last_login"] = {"at": int(_now()), "ip": ip, "location": location(ip), "ua": ua[:200]}
            users.save()
        audit.add("login", user=name, detail="stay signed in (5 days)" if persist else "")
        resp = redirect(nxt)
        # stay signed in: a 5-day cookie; otherwise a browser-session cookie (gone when the browser closes)
        resp.set_cookie(cookie_name(), token, httponly=True, samesite="Strict", secure=request.is_secure, path="/",
                        max_age=sessions.PERSIST_MAX if persist else None)
        resp.delete_cookie("lg_step", path="/")
        return resp

    def finish_login(name, nxt, persist=False):
        """After the password and the authenticator: open the session, unless the password has expired
        (password_policy.py); then the sign-in asks for a new password first, and opens the session once it is set."""
        expired, why = pw_policy.expired(users.get(name) or {})
        if not expired:
            return start_session(name, nxt, persist=persist)
        tok = new_step({"kind": "expired", "user": name, "remember": persist})
        audit.add("password_expired", user=name, detail=why)
        return step_response(page("login.html", next=nxt, view="expired", reason=why), tok)

    def new_step(data):
        tok = secrets.token_urlsafe(32)
        with plock:
            for k in [k for k, v in pending.items() if _now() - v["t"] > 600]:
                pending.pop(k, None)
            pending[_h(tok)] = dict(data, t=_now(), tries=0, ip=client()[0], ua=_h(client()[1]))
        return tok

    def get_step(kind):
        tok = request.cookies.get("lg_step") or ""
        with plock:
            st = pending.get(_h(tok))
        if not st or st["kind"] != kind or st["ip"] != client()[0] or st["ua"] != _h(client()[1]) or _now() - st["t"] > 600:
            return None, tok
        return st, tok

    def drop_step(tok):
        with plock:
            pending.pop(_h(tok), None)

    def step_response(body_code, tok):
        body, code = body_code
        resp = app.make_response((body, code))
        resp.set_cookie("lg_step", tok, httponly=True, samesite="Strict", secure=request.is_secure, path="/", max_age=600)
        return resp

    def enrol_page(name, secret, nxt, error="", code=200):
        return page("enrol.html", code, name=name, secret=secret, uri=totp_uri(secret, name), next=nxt, error=error)

    # ---------------- login
    @app.route("/login", methods=["GET", "POST"])
    def login():
        nxt = _safe_next(request.values.get("next"))
        if request.method == "GET":
            notice = request.args.get("notice", "")[:200]
            view = request.args.get("form") if request.args.get("form") in ("signin", "register") else ("signin" if notice else "choice")
            return page("login.html", next=nxt, view=view, notice=notice)
        if remote_needs_tls():
            return page("login.html", 403, next=nxt, view="signin", error="Log in over HTTPS from other computers (see docs/INSTALLATION.md).")
        ip, ua = client()
        step = request.form.get("step")
        if step == "mfa":
            st, tok = get_step("mfa")
            if not st:
                return page("login.html", 401, next=nxt, view="signin", error="The login step expired. Enter your name and password again.")
            name = st["user"]; u = users.get(name)
            if not u or throttle.locked(ip, name):
                return page("login.html", 429, next=nxt, view="signin", error="Too many failed attempts. Try again in 15 minutes.")
            code = (request.form.get("code") or "").strip()
            stp = totp_check(u.get("totp"), code, u.get("totp_last"))
            used_recovery = False
            if stp is None and re.fullmatch(r"[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}", code.lower()):
                for i, hsh in enumerate(u.get("recovery", [])):
                    if check_password_hash(hsh, code.lower()):
                        used_recovery = i
                        break
            if stp is None and used_recovery is False:
                throttle.failed(ip, name)
                st["tries"] += 1
                if st["tries"] >= 5:
                    drop_step(tok)
                audit.add("login_failed", user=name, detail="wrong or reused authenticator code")
                return step_response(page("login.html", 401, next=nxt, view="mfa", error=attempts_msg("Wrong or already used code.", ip, name)), tok)
            drop_step(tok)
            with users.lock:
                users._load()
                uu = users.data["users"][name]
                if stp is not None:
                    uu["totp_last"] = stp                       # each code works once
                else:
                    uu["recovery"].pop(used_recovery)
                    audit.add("recovery_code_used", user=name, detail=f"{len(uu['recovery'])} left")
                users.save()
            throttle.ok(ip, name)
            return finish_login(name, nxt, persist=st.get("remember", False))
        if step == "expired":                                   # the password expired: a new one before the session
            return expired_submit(nxt)
        if step == "enrol":                                     # after an admin reset the authenticator
            return enrol_submit(nxt)
        # ---- name and password
        name = (request.form.get("username") or "").strip()[:40]
        pw = request.form.get("password") or ""
        remember = request.form.get("remember") == "1"      # stay signed in for 5 days
        if throttle.locked(ip, name):
            audit.add("login_locked", user=name)
            return page("login.html", 429, next=nxt, view="signin", error="Too many failed attempts. Try again in 15 minutes.")
        u = users.get(name) if NAME_RE.match(name) else None
        ok = check_password_hash(u["hash"], pw) if u and u.get("hash") else (check_password_hash(_DUMMY_HASH, pw) and False)
        if not ok:
            throttle.failed(ip, name)
            audit.add("login_failed", user=name if u else "", detail="wrong name or password" + ("" if u else f" (unknown name {name[:40]!r})"))
            return page("login.html", 401, next=nxt, view="signin", error=attempts_msg("Wrong name or password.", ip, name), username=name)
        status = u.get("status", "active")
        if status == "disabled":
            audit.add("login_refused", user=name, detail="account revoked")
            return page("login.html", 403, next=nxt, view="signin", error="This account has been revoked. Contact an admin.")
        if not u.get("totp"):
            if not mfa_required and status == "active":
                throttle.ok(ip, name)
                return finish_login(name, nxt, persist=remember)
            secret = totp_new_secret()
            tok = new_step({"kind": "enrol", "user": name, "secret": secret, "reset": True})
            return step_response(enrol_page(name, secret, nxt), tok)
        if status == "pending":
            audit.add("login_refused", user=name, detail="awaiting approval")
            return page("login.html", 403, next=nxt, view="signin", error="Your account is waiting for an admin to approve it.")
        tok = new_step({"kind": "mfa", "user": name, "remember": remember})
        return step_response(page("login.html", next=nxt, view="mfa"), tok)

    def expired_submit(nxt):
        """The new password for an expired one: the usual rules, not the expired one again. Then the session opens
        (no second sign-in) and the account's other sessions end."""
        st, tok = get_step("expired")
        if not st:
            return page("login.html", 401, next=nxt, view="signin", error="The sign-in step expired. Enter your name and password again.")
        ip, _ = client()
        name = st["user"]
        u = users.get(name)
        if not u or throttle.locked(ip, name):
            return page("login.html", 429, next=nxt, view="signin", error="Too many failed attempts. Try again in 15 minutes.")
        pw, pw2 = request.form.get("password") or "", request.form.get("password2") or ""
        prof = u.get("profile") or {}
        problem = password_problem(name, pw, pw2, avoid=(prof.get("full_name", ""), (prof.get("email") or "").split("@")[0],
                                                         prof.get("organisation", "")))
        if not problem and u.get("hash") and check_password_hash(u["hash"], pw):
            problem = "Choose a new password: not the one that expired."
        if problem:
            st["tries"] += 1
            if st["tries"] >= 5:
                drop_step(tok)
                return page("login.html", 401, next=nxt, view="signin", error="Too many tries. Sign in again.")
            return step_response(page("login.html", 400, next=nxt, view="expired", error=problem,
                                      reason="Your password has expired."), tok)
        drop_step(tok)
        with users.lock:
            users._load()
            uu = users.data["users"][name]
            uu["hash"] = generate_password_hash(pw)
            uu["pw_set_at"] = int(_now())
            users.save()
        sessions.end_user(name)                                 # every other session of this account ends
        audit.add("password_changed", user=name, detail="expired password replaced at sign-in")
        return start_session(name, nxt, persist=st.get("remember", False))

    def enrol_submit(nxt):
        """Confirm the authenticator (registration, or after an admin reset): store it, show the recovery codes."""
        st, tok = get_step("enrol")
        if not st:
            return page("login.html", 401, next=nxt, view="signin", error="The set-up step expired. Start again.")
        ip, _ = client()
        if throttle.locked(ip, st["user"]):
            return page("login.html", 429, next=nxt, view="signin", error="Too many failed attempts. Try again in 15 minutes.")
        stp = totp_check(st["secret"], request.form.get("code"))
        if stp is None:
            throttle.failed(ip, st["user"])
            st["tries"] += 1
            if st["tries"] >= 5:
                drop_step(tok)
            return step_response(enrol_page(st["user"], st["secret"], nxt, "That code does not match. Check the phone's clock and try the next code.", 401), tok)
        drop_step(tok)
        codes, hashes = new_recovery_codes()
        name = st["user"]
        with users.lock:
            users._load()
            if st.get("reset"):
                u = users.data["users"].get(name)
                if not u:
                    return page("login.html", 401, next=nxt, view="signin", error="Account not found.")
                u.update(totp=st["secret"], totp_last=stp, recovery=hashes)
                # after an admin reset the account is checked again by an admin, unless it is the only admin
                if u.get("status") == "active" and active_admins() != [name]:
                    u["status"] = "pending"
                users.save()
                audit.add("mfa_enrolled", user=name, detail="after reset")
                status = u["status"]
            else:
                if name in users.data["users"]:
                    return page("login.html", 409, view="register", error="That name was taken meanwhile. Choose another.")
                # the setup code (checked at the first step) is the proof of access to the server, not "this computer":
                # behind a reverse proxy the administrator comes through the proxy, over HTTPS (remote_needs_tls)
                first_admin = (not active_admins() and bool(st.get("setup"))
                               and not name.lower().startswith(TEST_PREFIX))
                users.data["users"][name] = {"hash": st["hash"], "role": "admin" if first_admin else LOWEST_ROLE,
                                             "status": "active" if first_admin else "pending", "created": int(_now()),
                                             "pw_set_at": int(_now()),
                                             "profile": st.get("profile", {}),
                                             "changed": int(_now()), "totp": st["secret"], "totp_last": stp, "recovery": hashes,
                                             "registered": {"at": int(_now()), "ip": ip, "location": location(ip),
                                                            "ua": request.headers.get("User-Agent", "")[:200]}}
                users.save()
                if first_admin:
                    setup.discard()             # used: an administrator exists now
                audit.add("registered", user=name, detail="first admin (setup code)" if first_admin else "awaiting approval")
                status = users.data["users"][name]["status"]
        return page("enrol_done.html", name=name, codes=codes, status=status)

    # ---------------- registration
    @app.route("/register", methods=["GET", "POST"])
    def register():
        if not registration_open:
            return page("login.html", 403, next="/", view="signin", error="Registration is closed. Ask an admin for an account.")
        if request.method == "GET":
            return page("login.html", view="register")
        # what was typed comes back with an error (never the passwords)
        f = {k: (request.form.get(k) or "").strip()[:254] for k in ("username", "full_name", "organisation", "email", "country")}
        f["email"] = f["email"].lower(); f["country"] = f["country"].upper()

        def fail(code, msg):
            return page("login.html", code, view="register", error=msg, form=f)
        if remote_needs_tls():
            return fail(403, "Create accounts over HTTPS from other computers (see docs/INSTALLATION.md).")
        if request.form.get("step") == "enrol":
            return enrol_submit("/")
        ip, _ = client()
        if throttle.count(("register", ip), 3600) >= 5:
            audit.add("register_limited")
            return fail(429, "Too many new accounts from this address. Try again later.")
        name = f["username"]
        pw, pw2 = request.form.get("password") or "", request.form.get("password2") or ""
        is_test = name.lower().startswith(TEST_PREFIX)
        test_key_ok = _is_loopback(ip) and hmac.compare_digest(request.headers.get("X-LG-Automation", ""), automation_key)
        if not NAME_RE.match(name) or (is_test and not test_key_ok):
            return fail(400, "User name: 2-40 letters, digits, dot, dash or underscore.")
        # the first administrator: "this computer" is not proof enough (a reverse proxy set up wrongly makes every
        # visitor look local), so the one-time setup code from the server is needed too (first_run.py)
        first = not active_admins() and not is_test
        if first:
            if throttle.count(("setup", ip), 3600) >= 10:
                return fail(429, "Too many wrong setup codes from this address. Try again in an hour.")
            if not setup.matches(request.form.get("setup_code")):
                throttle.count(("setup", ip), 3600, add=True)
                audit.add("setup_code_wrong")
                return fail(403, "That setup code is not right. Read it on the server: cat data/setup_code "
                                 "in the platform folder (the installer showed the command).")
        # the local self-tests (reserved test prefix + automation key) use example addresses: format checked, DNS not
        check_domain = not (is_test and test_key_ok)
        # every e-mail domain looked up counts (external review, 2026-11-12): only sign-ups that reached the
        # authenticator step were counted, so anyone could make this server look up made-up domains without end
        if check_domain:
            if throttle.count(("register-dns", ip), 3600) >= REGISTER_DNS_PER_HOUR:
                return fail(429, "Too many sign-up attempts from this address. Try again in an hour.")
            if throttle.count(("register-dns", ip), 3600, add=True) == REGISTER_DNS_PER_HOUR:
                audit.add("register_limited", detail="e-mail domain look-ups")     # once, when the limit is reached
        problem = profile_problem(f["full_name"], f["organisation"], f["email"], f["country"], country_codes,
                                  check_domain=check_domain)
        if problem:
            return fail(400, problem)
        if users.get(name):
            return fail(409, "That user name is taken. Choose another.")
        if any((u.get("profile") or {}).get("email") == f["email"] for u in users.all().values()):
            return fail(409, "An account with this email address already exists. Use Forgot password, or ask an administrator.")
        if sum(1 for u in users.all().values() if u.get("status") == "pending") >= 100:
            return fail(429, "Too many accounts are waiting for approval. Try again later.")
        problem = password_problem(name, pw, pw2, avoid=(f["full_name"], f["email"].split("@")[0], f["organisation"]))
        if problem:
            return fail(400, problem)
        throttle.count(("register", ip), 3600, add=True)     # only registrations that reach the authenticator step count
        secret = totp_new_secret()
        tok = new_step({"kind": "enrol", "user": name, "secret": secret, "hash": generate_password_hash(pw), "setup": first,
                        "profile": {"full_name": f["full_name"], "organisation": f["organisation"], "email": f["email"], "country": f["country"]}})
        return step_response(enrol_page(name, secret, "/"), tok)

    # ---------------- forgotten password
    # Two ways, both audited, both end the account's sessions:
    #  * with the authenticator: name + a code from the app + one recovery code (two separate things the user has,
    #    so a stolen phone alone is not enough) -> new password;
    #  * ask an administrator: the request shows on /admin; the admin allows a reset for 24 hours, after which the
    #    authenticator code alone is enough to set a new password.
    # The answers never reveal whether a name exists.
    @app.route("/forgot", methods=["GET", "POST"])
    def forgot():
        mode = request.values.get("mode", "self")
        mode = mode if mode in ("self", "ask") else "self"
        if request.method == "GET":
            return page("forgot.html", mode=mode)
        if remote_needs_tls():
            return page("forgot.html", 403, mode=mode, error="Use HTTPS from other computers (see docs/INSTALLATION.md).")
        ip, ua = client()
        name = (request.form.get("username") or "").strip()[:40]
        if mode == "ask":
            if throttle.count(("forgot-ask", ip), 3600, add=True) > 5:
                return page("forgot.html", 429, mode=mode, error="Too many requests from this address. Try again later.")
            u = users.get(name) if NAME_RE.match(name) else None
            if u and u.get("status") != "disabled":
                with users.lock:
                    users._load()
                    users.data["users"][name]["reset_requested"] = {"at": int(_now()), "ip": ip, "location": location(ip), "ua": ua[:200]}
                    users.save()
                audit.add("reset_requested", user=name)
            else:
                audit.add("reset_requested", detail=f"unknown or revoked name {name!r}")
            return page("forgot.html", mode="done", notice="If the account exists, the administrators have been notified. "
                                                           "Once they allow it, come back here and use your authenticator.")
        # ---- reset with the authenticator
        if throttle.locked(ip, name):
            return page("forgot.html", 429, mode=mode, error="Too many failed attempts. Try again in 15 minutes.")
        pw, pw2 = request.form.get("password") or "", request.form.get("password2") or ""
        prof = (users.get(name) or {}).get("profile") or {} if NAME_RE.match(name) else {}
        problem = password_problem(name or "x", pw, pw2, avoid=(prof.get("full_name", ""), (prof.get("email") or "").split("@")[0]))
        if problem:
            return page("forgot.html", 400, mode=mode, error=problem, username=name)
        u = users.get(name) if NAME_RE.match(name) else None
        code = (request.form.get("code") or "").strip()
        rec = (request.form.get("recovery") or "").strip().lower()
        ok, used_rec, step = False, None, None
        if u and u.get("status") == "active" and u.get("totp"):
            step = totp_check(u.get("totp"), code, u.get("totp_last"))
            admin_allowed = u.get("reset_allowed_until", 0) > _now()
            if step is not None and not admin_allowed and re.fullmatch(r"[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}", rec):
                used_rec = next((i for i, hsh in enumerate(u.get("recovery", [])) if check_password_hash(hsh, rec)), None)
            ok = step is not None and (admin_allowed or used_rec is not None)
        else:
            check_password_hash(_DUMMY_HASH, pw)                # same work for unknown names
        if not ok:
            throttle.failed(ip, name)
            audit.add("reset_failed", user=name if u else "", detail="" if u else f"unknown name {name!r}")
            return page("forgot.html", 401, mode=mode, username=name,
                        error=attempts_msg("The name, authenticator code or recovery code is not right.", ip, name))
        with users.lock:
            users._load()
            uu = users.data["users"][name]
            uu["hash"] = generate_password_hash(pw)
            uu["pw_set_at"] = int(_now())                       # a new password: its age starts now (password_policy.py)
            uu["changed"] = int(_now())                         # ends every session of the account
            uu["totp_last"] = step
            how = "administrator-approved" if uu.get("reset_allowed_until", 0) > _now() else "with a recovery code"
            if used_rec is not None:
                uu["recovery"].pop(used_rec)
            uu.pop("reset_requested", None); uu.pop("reset_allowed_until", None)
            users.save()
        sessions.end_user(name)
        throttle.ok(ip, name)
        audit.add("password_reset", user=name, detail=how)
        return redirect("/login?notice=" + quote("Password changed. Log in with the new password."))

    @app.route("/logout", methods=["POST", "GET"])
    def logout():
        if request.method == "GET":                             # a link cannot log you out (no cross-site logout)
            return redirect("/login")
        tok = request.cookies.get(cookie_name())
        if tok:
            s = sessions.end(tok)
            if s:
                audit.add("logout", user=s["user"])
        resp = redirect("/login")
        resp.delete_cookie(cookie_name(), path="/")
        return resp

    @app.route("/api/me")
    def me():
        u = g.user or {}
        return jsonify(user=u.get("user"), role=u.get("role"), perms=sorted(u.get("perms", ())), csrf=u.get("csrf"))

    # ---------------- admin: users, sessions, audit, roles
    def csrf_ok():
        u = getattr(g, "user", None) or {}
        if u.get("automation"):
            return True
        t = request.headers.get("X-CSRF-Token", "")
        return bool(u.get("csrf")) and hmac.compare_digest(t, u["csrf"])

    def need(perm, change=False):
        if not has_perm(perm):
            abort(403)
        if change:
            if request.mimetype != "application/json" or not csrf_ok():
                abort(403)
            if not fresh():
                from flask import make_response
                abort(make_response(jsonify(error="For your security, sign out and sign in again to make changes (stay-signed-in sessions older than 12 hours can only view).", reauth=True), 403))

    @app.route("/admin")
    def admin_page():
        if not (has_perm("users") or has_perm("audit")):
            return render_template("denied.html", message="The admin pages are for accounts with the 'users' or 'audit' permission."), 403
        if not has_perm("users"):                    # audit only (the auditor): their portal is /audit
            return redirect("/audit")
        return render_template("admin.html", perms_catalog=PERMS)

    @app.route("/api/admin/users")
    def admin_users():
        need("users")
        drop_orphans()
        live = {}
        for s in sessions.list():
            live[s["user"]] = live.get(s["user"], 0) + 1
        out = []
        for n, u in sorted(users.all().items()):
            out.append({"name": n, "role": u.get("role", LOWEST_ROLE), "status": u.get("status", "active"), "created": u.get("created"),
                        "mfa": bool(u.get("totp")), "recovery_left": len(u.get("recovery", [])), "registered": u.get("registered", {}),
                        "last_login": u.get("last_login", {}), "approved_by": u.get("approved_by", ""), "sessions": live.get(n, 0),
                        "reset_requested": u.get("reset_requested") or None, "profile": u.get("profile") or {},
                        "reset_allowed": u.get("reset_allowed_until", 0) > _now(),
                        "you": n == g.user.get("user")})
        return jsonify(users=out, roles=sorted(roles.roles, key=lambda r: (r != LOWEST_ROLE, r == "admin", r)), me=g.user.get("user"),
                       info={r: ROLE_INFO.get(r) or ("Custom role: " + ", ".join(roles.roles.get(r, [])) if r in roles.roles else "") for r in roles.roles})

    @app.route("/api/admin/users/<name>", methods=["POST"])
    def admin_user_action(name):
        need("users", change=True)
        body = request.get_json(silent=True)
        if not isinstance(body, dict):
            return jsonify(error="JSON object expected"), 400
        action, me_ = body.get("action"), g.user.get("user")
        with users.lock:
            users._load()
            u = users.data["users"].get(name)
            if not u:
                return jsonify(error="No such account"), 404
            admins = active_admins()
            losing_admin = name in admins and len(admins) == 1
            if action in ("revoke", "delete", "reset_mfa") and name == me_:
                return jsonify(error="You cannot do that to your own account."), 400
            if action == "approve":
                # only an account waiting for approval (external review, 2026-11-12: approve on an active account changed
                # its role past the last-admin check, so the only admin could be turned into an external)
                if u.get("status") != "pending":
                    return jsonify(error="Only an account waiting for approval is approved: change an active account's role with Role."), 400
                role = body.get("role") or u.get("role", LOWEST_ROLE)
                if role not in roles.roles:
                    return jsonify(error="Unknown role"), 400
                if not u.get("totp"):
                    return jsonify(error="This account has not set up its authenticator yet."), 400
                u.update(status="active", role=role, approved_by=me_, approved_at=int(_now()))
                detail = f"role {role}"
            elif action == "role":
                role = body.get("role")
                if role not in roles.roles:
                    return jsonify(error="Unknown role"), 400
                if losing_admin and "users" not in roles.perms(role):
                    return jsonify(error="This is the last admin: give another account the admin role first."), 400
                old = u.get("role"); u["role"] = role; u["changed"] = int(_now())   # sessions restart with the new role
                detail = f"{old} -> {role}"
            elif action == "revoke":
                if losing_admin:
                    return jsonify(error="This is the last admin."), 400
                u["status"] = "disabled"; u["changed"] = int(_now()); detail = "account revoked"
            elif action == "restore":
                u["status"] = "active" if u.get("totp") else "pending"; detail = f"status {u['status']}"
            elif action == "reset_mfa":
                if losing_admin:
                    return jsonify(error="This is the last admin."), 400
                u.update(totp=None, totp_last=None, recovery=[], changed=int(_now())); detail = "authenticator removed; set up again at next login"
            elif action == "allow_reset":
                if not u.get("totp"):
                    return jsonify(error="This account has no authenticator: use 'Reset authenticator' instead."), 400
                u["reset_allowed_until"] = int(_now()) + 86400; u.pop("reset_requested", None)
                detail = "password reset allowed for 24 hours (authenticator code required)"
            elif action == "kick":
                n = sessions.end_user(name)
                audit.add("kicked", user=me_, target=name, detail=f"{n} session(s) ended")
                return jsonify(ok=True, ended=n)
            elif action == "delete":
                if losing_admin:
                    return jsonify(error="This is the last admin."), 400
                users.data["users"].pop(name, None); detail = "account deleted"
            else:
                return jsonify(error="Unknown action"), 400
            users.save()
        if action in ("revoke", "delete", "reset_mfa", "role"):
            sessions.end_user(name)
        audit.add(f"user_{action}", user=me_, target=name, detail=detail)
        return jsonify(ok=True)

    def drop_orphans():
        """Sessions of accounts that were deleted or are no longer active (e.g. changed by manage/manage_users.py)."""
        live = {n for n, u in users.all().items() if u.get("status") == "active"}
        for s in sessions.list():
            if s["user"] not in live:
                sessions.end_id(s["id"])

    @app.route("/api/admin/sessions")
    def admin_sessions():
        if not (has_perm("users") or has_perm("audit")):      # the Audit portal reads them; ending one needs 'users'
            abort(403)
        drop_orphans()
        mine = g.user.get("key", "")[:16]
        return jsonify(sessions=sorted([dict(s, current=s["id"] == mine) for s in sessions.list()], key=lambda s: -s["seen"]),
                       can_end=has_perm("users"))

    @app.route("/api/admin/sessions/<sid>/end", methods=["POST"])
    def admin_end_session(sid):
        need("users", change=True)
        if not re.fullmatch(r"[0-9a-f]{16}", sid):
            return jsonify(error="bad id"), 400
        s = sessions.end_id(sid)
        if not s:
            return jsonify(error="No such session"), 404
        audit.add("kicked", user=g.user.get("user"), target=s["user"], detail=f"session from {s['ip']} ({s.get('location', '')})")
        return jsonify(ok=True)

    @app.route("/api/admin/audit")
    def admin_audit():
        need("audit")
        try:
            limit = max(1, min(int(request.args.get("limit", 200)), 1000)); offset = max(0, int(request.args.get("offset", 0)))
        except ValueError:
            limit, offset = 200, 0
        from people import People               # "Full Name (username)" for every account in the log
        total, rows, hidden = audit.read(limit, (request.args.get("q") or "")[:100], offset,
                                         selftests=request.args.get("selftests") == "1", label=People(users).audit)
        return jsonify(total=total, rows=rows, selftests_hidden=hidden)

    @app.route("/api/admin/roles", methods=["GET", "POST"])
    def admin_roles():
        need("users", change=request.method == "POST")
        if request.method == "GET":
            return jsonify(roles=roles.roles, perms=PERMS, info=ROLE_INFO, in_use={r: sum(1 for u in users.all().values() if u.get("role") == r) for r in roles.roles},
                           fixed=sorted(["admin", *FIXED_ROLES]), exclusive=EXCLUSIVE_PERMS)
        body = request.get_json(silent=True)
        if not isinstance(body, dict) or not isinstance(body.get("roles"), dict) or len(body["roles"]) > 30:
            return jsonify(error="JSON {roles: {name: [permissions]}} expected"), 400
        new = {}
        for r, ps in body["roles"].items():
            if not ROLE_RE.match(r) or not isinstance(ps, list):
                return jsonify(error=f"Role names: lower-case letters, digits, - and _ ({r!r})"), 400
            new[r] = [p for p in ps if p in PERMS]
        used = {u.get("role") for u in users.all().values()}
        missing = [r for r in used if r and r not in new and r != "admin"]
        if missing:
            return jsonify(error=f"Roles still in use cannot be removed: {', '.join(missing)}"), 400
        before = dict(roles.roles)
        roles.save(new)
        audit.add("roles_changed", user=g.user.get("user"), detail=json.dumps({k: v for k, v in roles.roles.items() if before.get(k) != v})[:290])
        return jsonify(ok=True, roles=roles.roles)

    def prune_loop():
        while True:
            time.sleep(300)
            sessions.prune()
            try:
                drop_orphans()
            except Exception:
                pass
    threading.Thread(target=prune_loop, daemon=True, name="session-prune").start()

    return {"users": users, "sessions": sessions, "roles": roles, "audit": audit, "has_perm": has_perm, "csrf_ok": csrf_ok,
            "is_admin": lambda: has_perm("settings"), "fresh": fresh, "throttle": throttle, "password_policy": pw_policy}
