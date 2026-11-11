"""The Traffic Light Protocol (TLP 2.0, FIRST): how far an advisory may be shared. The advisor picks a level for each
advisory (advisory.py); the report carries it on every page, top and bottom, and the JSON export carries it too. The
Definitions page and the advisory page explain the colours (templates/_tlp_card.html).

The wording is Looking Glass's own summary of the standard; the colours are FIRST's (on a black background).
Reference: https://www.first.org/tlp/
"""

LEVELS = [
    {"key": "TLP:RED", "colour": "#FF2B2B", "cls": "tlp-red", "short": "Named recipients only",
     "text": "For the people it is addressed to only, and only in the meeting or exchange it was given in. Not to be "
             "passed on to anyone else, not even within their own organisation.",
     "when": "Sharing it further could harm privacy, reputation or operations, and the recipients cannot act on it with others."},
    {"key": "TLP:AMBER+STRICT", "colour": "#FFC000", "cls": "tlp-amber", "short": "The recipient's organisation only",
     "text": "May be shared only within the recipient's own organisation, with those who need to know to act on it.",
     "when": "Acting on it needs the recipient's own staff, and sharing it outside their organisation carries risk."},
    {"key": "TLP:AMBER", "colour": "#FFC000", "cls": "tlp-amber", "short": "The organisation and its clients",
     "text": "May be shared within the recipient's organisation and with its clients (customers), with those who need "
             "to know to protect themselves or prevent further harm.",
     "when": "The recipient needs others, such as its customers, to act on it, but it must not go wider."},
    {"key": "TLP:GREEN", "colour": "#33FF00", "cls": "tlp-green", "short": "The community",
     "text": "May be shared with peers and partner organisations within the recipient's community, but not published "
             "or posted where anyone can read it.",
     "when": "It is useful for raising awareness across the community the recipient belongs to."},
    {"key": "TLP:CLEAR", "colour": "#FFFFFF", "cls": "tlp-clear", "short": "No limit",
     "text": "May be shared freely and published, subject to copyright. Nothing in it is sensitive.",
     "when": "It carries minimal or no risk of misuse."},
]
BY_KEY = {x["key"]: x for x in LEVELS}
DEFAULT = "TLP:AMBER"              # an advisory lists the organisation's addresses: no wider than its organisation and clients
URL = "https://www.first.org/tlp/"


def of(key):
    """The level of a key (TLP:WHITE, the older name of TLP:CLEAR, read as CLEAR); None when unknown."""
    k = str(key or "").strip().upper().replace(" ", "")
    if k == "TLP:WHITE":
        k = "TLP:CLEAR"
    return BY_KEY.get(k)


def install(app):
    """The levels for the templates (the Definitions page's card)."""
    app.jinja_env.globals["TLP_LEVELS"] = LEVELS
    app.jinja_env.globals["TLP_URL"] = URL
