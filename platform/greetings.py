# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""The Overview's greeting: by the person's first name (their name as the admin entered it, never the username).

The first time someone opens an Overview: "Greetings, <name>! Welcome to Looking Glass". After that, one of 30
greetings (some of them for fun), picked at random every time the Overview opens. Short on purpose: each fits the title at any width.

Who has been welcomed is kept in data/greetings.json (user -> time; run-time data, owner-only file, never shipped).
Installed from app.py: the templates call lg_greeting() and show its three parts (before, the name, after).
"""
import json
import os
import secrets
import threading
import time

from flask import g

GREETINGS = [
    "Welcome back, {name}.",
    "Good to see you, {name}.",
    "Hello again, {name}. The sinkholes missed you.",
    "{name}, the botnets have been busy.",
    "Back on watch, {name}.",
    "Akwaaba, {name}!",
    "Hey {name}: coffee first, threats second.",
    "{name} has entered the glass.",
    "Welcome back, {name}. No packets were harmed.",
    "Look who's here: {name}.",
    "{name}, the map kept your seat warm.",
    "Greetings, {name}. Yesterday awaits.",
    "Hi {name}! Shall we look closer?",
    "Welcome, {name}. Zoom in, stay calm.",
    "{name}, reporting for duty?",
    "Bonjour, {name}. Ready to hunt?",
    "{name}, the data is fresh(ish).",
    "Hello {name}, the internet is still on.",
    "Welcome back, {name}. Mind port 23.",
    "{name}! The sinkholes send their regards.",
    "Nice to see you, {name}. Let's find something.",
    "{name}, your CSIRT senses are tingling.",
    "Howdy, {name}. Threats ahead.",
    "Hi {name}. One day late, always on time.",
    "{name}, the glass is polished for you.",
    "Welcome back, {name}. The bell may have news.",
    "Salut, {name}! Good hunting today.",
    "{name}, let's make yesterday make sense.",
    "Hello, {name}. Same internet, new day.",
    "Ready when you are, {name}.",
]
# each role its own 30 (user, 2026-11-14), none shared between roles; GREETINGS above for external viewers and the
# roles an admin made
ROLE_GREETINGS = {
    "admin": [
        "Welcome back, {name}. The platform is yours.", "{name}, all services are standing by.",
        "Good to see you, {name}. Keys in hand?", "Hello {name}. The accounts await your nod.",
        "{name}, the control room is open.", "Welcome back, {name}. Logs are tidy.",
        "Hi {name}. Who needs access today?", "{name}, the bell may have system news.",
        "Back at the helm, {name}.", "{name}, the servers are up and humming.",
        "{name}, roles checked, doors locked.", "Hello again, {name}. Backups first?",
        "Welcome, {name}. Everything in its place.", "{name}, the audit trail is unbroken.",
        "Hi {name}. The pipeline ran overnight.", "Admin on deck: welcome, {name}.",
        "{name}, keep calm and rotate secrets.", "Good day, {name}. Settings as you left them.",
        "{name}, the certificates still look fresh.", "Welcome back, {name}. Sessions are in order.",
        "Akwaaba, {name}! The keys are yours.", "{name}, nothing is on fire. Yet.",
        "Hello {name}. Let's keep the lights on.", "{name}, the users say hello.",
        "Hi {name}. Disk space is on your side.", "{name}, the platform missed its keeper.",
        "Welcome, {name}. Patch, check, repeat.", "{name}, the root of all good things.",
        "Back again, {name}? The dashboards approve.", "Ready to administer, {name}?"],
    "analyst": [
        "Welcome back, {name}. The addresses await.", "{name}, time to follow the devices.",
        "Hello {name}. Which combination today?", "Good to see you, {name}. Let's drill down.",
        "{name}, the patterns won't spot themselves.", "Hi {name}. Yesterday's reports are in.",
        "Akwaaba, {name}! Ready to dig?", "{name}, every host tells a story.",
        "Welcome, {name}. Search, narrow, send.", "{name}, the CSV is your canvas.",
        "Back on the trail, {name}.", "Hello again, {name}. Cross-report time?",
        "{name}, the outliers say hello.", "Hi {name}. Coffee, then correlations.",
        "{name}, one IP at a time.", "Welcome back, {name}. The sinkholes kept count.",
        "{name}, the researchers left you codes.", "Good day, {name}. Let's find the needle.",
        "{name}, the haystack is fresh today.", "Hello {name}. Data first, conclusions later.",
        "{name}, ready to connect the dots?", "Welcome, {name}. The evidence is in order.",
        "{name}, the devices are talking again.", "Hi {name}. Filters ready, eyes sharp.",
        "{name}, today's question: who repeats?", "Back again, {name}. The trend lines await.",
        "{name}, let's make the numbers speak.", "Hello {name}. Abused or compromised?",
        "Welcome, {name}. Analysis mode on.", "{name}, the drill-down is calling."],
    "researcher": [
        "Welcome back, {name}. New names to define?", "{name}, the definitions await your pen.",
        "Hello {name}. What is that malware called?", "Good to see you, {name}. Curious today?",
        "{name}, the families have grown.", "Hi {name}. Malpedia sends its regards.",
        "Akwaaba, {name}! Let's read the signs.", "{name}, every name deserves a story.",
        "Welcome, {name}. Notes, codes, insight.", "{name}, fresh intel has gathered.",
        "Back to research, {name}.", "Hello again, {name}. Which family first?",
        "{name}, the analysts may need your codes.", "Hi {name}. Context is everything.",
        "{name}, define it once, use it always.", "Welcome back, {name}. The glossary grows.",
        "{name}, the unknowns are calling.", "Good day, {name}. Let's name the threats.",
        "{name}, MITRE and MISP are standing by.", "Hello {name}. Read closely, write clearly.",
        "{name}, a good note saves a day.", "Welcome, {name}. Knowledge is the shield.",
        "{name}, the combinations are waiting.", "Hi {name}. What changed since yesterday?",
        "{name}, the reports speak in riddles.", "Back again, {name}. Time to explain.",
        "{name}, your findings start here.", "Hello {name}. Patterns, then meaning.",
        "Welcome, {name}. Research mode on.", "{name}, the sources are fresh."],
    "management": [
        "Welcome back, {name}. The big picture awaits.", "{name}, your decisions are waiting.",
        "Hello {name}. Today's risks at a glance.", "Good to see you, {name}. Shall we review?",
        "{name}, the team has findings for you.", "Hi {name}. Numbers first, then decisions.",
        "Akwaaba, {name}! The overview is ready.", "{name}, the week in one view.",
        "Welcome, {name}. Approve, guide, protect.", "{name}, the executive report is fresh.",
        "Back at the table, {name}.", "Hello again, {name}. The trends look telling.",
        "{name}, the analysts await your call.", "Hi {name}. Clarity before action.",
        "{name}, steady hands, clear view.", "Welcome back, {name}. The baseline holds.",
        "{name}, the constituency counts on you.", "Good day, {name}. Let's set the course.",
        "{name}, every advisory starts with you.", "Hello {name}. Fewer devices, better days.",
        "{name}, ready to weigh the evidence?", "Welcome, {name}. Leadership mode on.",
        "{name}, the reviews are in order.", "Hi {name}. What needs approval today?",
        "{name}, the charts tell the story.", "Back again, {name}. The trend is your friend.",
        "{name}, decide well, sleep well.", "Hello {name}. Priorities, not noise.",
        "Welcome, {name}. The briefing is ready.", "{name}, the view from the top is clear."],
    "advisor": [
        "Welcome back, {name}. Advisories to write?", "{name}, the organisations need your words.",
        "Hello {name}. Clear advice saves networks.", "Good to see you, {name}. Who do we tell?",
        "{name}, the drafts are waiting.", "Hi {name}. Plain words, real fixes.",
        "Akwaaba, {name}! Ready to advise?", "{name}, every advisory is a helping hand.",
        "Welcome, {name}. Write, check, send.", "{name}, TLP set, message ready.",
        "Back at the desk, {name}.", "Hello again, {name}. Recommendations first?",
        "{name}, management sent you work.", "Hi {name}. Impact, actions, references.",
        "{name}, the recipients are listening.", "Welcome back, {name}. The logo looks sharp.",
        "{name}, help them patch today.", "Good day, {name}. Let's reach out.",
        "{name}, a good advisory is a short one.", "Hello {name}. Facts in, advice out.",
        "{name}, the report is ready to attach.", "Welcome, {name}. Advisory mode on.",
        "{name}, guide them to safety.", "Hi {name}. Which organisation first?",
        "{name}, the devices need their owners.", "Back again, {name}. Time to inform.",
        "{name}, your words close findings.", "Hello {name}. Calm advice, clear steps.",
        "Welcome, {name}. The outbox awaits.", "{name}, make every sentence count."],
    "auditor": [
        "Welcome back, {name}. The trail is intact.", "{name}, the evidence is sealed.",
        "Hello {name}. Controls to check today?", "Good to see you, {name}. Trust, but verify.",
        "{name}, every action left a record.", "Hi {name}. The audit log awaits.",
        "Akwaaba, {name}! Ready to verify?", "{name}, the checkpoints are signed.",
        "Welcome, {name}. Read only, eyes wide.", "{name}, the controls stand mapped.",
        "Back on review, {name}.", "Hello again, {name}. NIST or CIS first?",
        "{name}, the seal holds.", "Hi {name}. Evidence before opinion.",
        "{name}, who did what, and when.", "Welcome back, {name}. Nothing was rewritten.",
        "{name}, the hash chain says hello.", "Good day, {name}. Let's sample the logs.",
        "{name}, compliance is a habit.", "Hello {name}. Findings, not faults.",
        "{name}, ready to test the controls?", "Welcome, {name}. Audit mode on.",
        "{name}, the records are in order.", "Hi {name}. Independent eyes welcome.",
        "{name}, the exports were logged.", "Back again, {name}. Every gap matters.",
        "{name}, assurance starts here.", "Hello {name}. Verify, then sign.",
        "Welcome, {name}. The portal is read only.", "{name}, the logs never forget."],
}
FIRST = "Greetings, {name}! Welcome to Looking Glass"


def for_role(role):
    """The 30 greetings of a role (an external viewer's, or a role an admin made: the general ones)."""
    return ROLE_GREETINGS.get(str(role or ""), GREETINGS)


class Welcomed:
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

    def first_time(self, user):
        """True the first time (and remembers it), False after."""
        with self.lock:
            d = self._load()
            if user in d:
                return False
            d[user] = round(time.time(), 3)
            os.makedirs(os.path.dirname(self.path), exist_ok=True)
            tmp = f"{self.path}.{os.getpid()}.tmp"
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(d, fh)
            os.replace(tmp, self.path)
            return True


def split(text, name):
    """(before, name, after) of a greeting, so the page can show the name in its own colour."""
    i = text.index("{name}")
    return text[:i], name, text[i + len("{name}"):]


def install(app, ctx):
    """ctx: base_dir, people_name(user) -> the person's name as entered."""
    welcomed = Welcomed(os.path.join(ctx["base_dir"], "data", "greetings.json"))

    def first_name(user):
        full = (ctx["people_name"](user) or "").strip()
        if not full or full == user:
            return "there"                     # no name entered: never the username
        return full.split()[0][:40]

    def lg_greeting():
        """(before, name, after, first) for the signed-in person; called by the Overview templates."""
        u = getattr(g, "user", None) or {}
        user = u.get("user", "")
        name = first_name(user) if user and not u.get("automation") else "there"
        if user and not u.get("automation") and welcomed.first_time(user):
            return (*split(FIRST, name), True)
        text = secrets.choice(for_role(u.get("role")))           # a new one every time the Overview opens, the role's own
        return (*split(text, name), False)

    app.jinja_env.globals["lg_greeting"] = lg_greeting
    return welcomed
