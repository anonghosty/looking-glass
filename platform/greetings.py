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
FIRST = "Greetings, {name}! Welcome to Looking Glass"


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
        text = secrets.choice(GREETINGS)                        # a new one every time the Overview opens
        return (*split(text, name), False)

    app.jinja_env.globals["lg_greeting"] = lg_greeting
    return welcomed
