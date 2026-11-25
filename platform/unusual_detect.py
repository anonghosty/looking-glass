# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""Unusual activity, the arithmetic (the user, 2026-11-24: levels 1 and 2, decisions 1a and 6a). No database, no files:
unusual_worker.py feeds it, unusual.py shows what it finds, tests/check_unusual.py checks it.

The idea is an orb-weaver's web: each thread knows its normal vibration, and a thread vibrating well above it is worth a
look. Two kinds of thread:
- level 1: a network and a report (AS64514 x Sinkhole HTTP), and a report over the whole constituency ("*"): how many
  devices it has each day;
- level 2: two reports the same devices are in on the same day (report pairs only, decision 6a).

Normal is the median of the thread's last WINDOW days (decision 1a), with a robust spread (the median absolute
deviation, scaled to a standard deviation), so one odd day does not move it. A day is suggested only when it is well
above normal AND above a minimum size: a network going from 1 device to 3 is not news. Every suggestion says itself in
plain words, with the numbers.

A day summary: {"day", "n_devices", "reports": {report: {"devices", "platform"}}, "threads": {"asn|report": devices},
"pairs": {"reportA|reportB": devices}}; counts only, never an address.
"""
import hashlib
import statistics

MAX_REPORTS_PER_DEVICE = 30          # pairs of one device: a device in more reports than this counts only its first 30


class Day:
    """Collects one report day, device by device, into a summary (counts only)."""

    def __init__(self, day):
        self.day = day
        self.reports = {}                # report -> {"platform", "devices": set()}
        self.threads = {}                # (asn, report) -> set(ip)
        self.device_reports = {}         # ip -> set(report)

    def add(self, report, platform, ip, asn):
        r = self.reports.setdefault(report, {"platform": platform, "devices": set()})
        r["devices"].add(ip)
        if asn not in (None, ""):
            self.threads.setdefault((str(asn), report), set()).add(ip)
        self.device_reports.setdefault(ip, set()).add(report)

    def summary(self):
        pairs = {}
        for reps in self.device_reports.values():
            rs = sorted(reps)[:MAX_REPORTS_PER_DEVICE]
            for i in range(len(rs)):
                for j in range(i + 1, len(rs)):
                    k = f"{rs[i]}|{rs[j]}"
                    pairs[k] = pairs.get(k, 0) + 1
        return {"day": self.day, "n_devices": len(self.device_reports),
                "reports": {r: {"devices": len(v["devices"]), "platform": v["platform"]} for r, v in self.reports.items()},
                "threads": {f"{a}|{r}": len(s) for (a, r), s in self.threads.items()},
                "pairs": pairs}


FIELDS = {"src_ip": 1, "src_asn": 1, "dst_ip": 1, "dst_asn": 1, "ip": 1, "asn": 1, "filename": 1}


def device_of(r, settings):
    """The constituency's device on one record: (ip, asn, platform), or None. Communications: the source when it is in
    the constituency, else the destination (as the map keeps a record if either side is); services: the host. Special
    reports stay out, as on the platforms."""
    if "special" in str(r.get("filename", "")):
        return None
    restricted = bool(getattr(settings, "restricted", False))
    if r.get("src_ip"):
        ip, asn = r.get("src_ip"), r.get("src_asn")
        if restricted and not settings.in_scope(asn, ip):
            ip, asn = r.get("dst_ip"), r.get("dst_asn")
            if not ip or not settings.in_scope(asn, ip):
                return None
        return str(ip), asn, "comms"
    if r.get("ip"):
        if restricted and not settings.in_scope(r.get("asn"), r.get("ip")):
            return None
        return str(r["ip"]), r.get("asn"), "services"
    return None


def thread_id(kind, key):
    return hashlib.sha256(f"{kind}|{key}".encode()).hexdigest()[:12]


def normal(values):
    """(median, spread): the spread is the median absolute deviation scaled to a standard deviation, at least 1 and at
    least the square root of the median (counts vary by about that much by chance)."""
    m = statistics.median(values)
    mad = statistics.median(abs(v - m) for v in values)
    return m, max(1.4826 * mad, m ** 0.5, 1.0)


def _history(key, field, history, needs):
    """The thread's value on each earlier day whose report(s) arrived; 0 when they arrived without it."""
    out = []
    for s in history:
        if all(r in s.get("reports", {}) for r in needs):
            out.append((s["day"], int(s.get(field, {}).get(key, 0))))
    return out


STEP, LOWEST, HIGHEST = 0.25, 0.75, 2.0     # how far one decision moves a report's bar, and its bounds


def sensitivity(learned, report):
    """How much higher (or lower) the bar is for one report, learned from the team's decisions on its threads (decision
    2a): each Dismiss raises it a step, each Confirm lowers it, within LOWEST..HIGHEST. learned: {report: {"dismissed",
    "confirmed"}}. Returns (factor, dismissed, confirmed)."""
    x = (learned or {}).get(report) or {}
    d, c = int(x.get("dismissed", 0)), int(x.get("confirmed", 0))
    return max(LOWEST, min(HIGHEST, 1 + STEP * (d - c))), d, c


def detect(today, history, cfg, learned=None):
    """The suggestions for `today` (a summary) against `history` (earlier summaries, any order). cfg: window,
    min_devices, ratio, z, min_history (min_lift for pairs). learned: the team's decisions per report (sensitivity).
    Returns a list of dicts, strongest first."""
    history = sorted((s for s in history if s["day"] < today["day"]), key=lambda s: s["day"])[-cfg["window"]:]
    out = []
    reports = today.get("reports", {})
    whole = {f"*|{r}": v["devices"] for r, v in reports.items()}
    for field, items, kind in (("threads", today.get("threads", {}), "network"), ("whole", whole, "report"),
                               ("pairs", today.get("pairs", {}), "pair")):
        for key, value in items.items():
            if value < cfg["min_devices"]:
                continue
            if kind == "pair":
                needs = key.split("|")
                hist = _history(key, "pairs", history, needs)
            elif kind == "report":
                needs = [key.split("|", 1)[1]]
                hist = [(s["day"], int(s.get("reports", {}).get(needs[0], {}).get("devices", 0))) for s in history
                        if needs[0] in s.get("reports", {})]
            else:
                needs = [key.split("|", 1)[1]]
                hist = _history(key, "threads", history, needs)
            if len(hist) < cfg["min_history"]:
                continue
            m, spread = normal([v for _, v in hist])
            z = (value - m) / spread
            factor = max(sensitivity(learned, r)[0] for r in needs)
            if value < cfg["ratio"] * factor * max(m, 1) or z < cfg["z"] * factor:
                continue
            lift = None
            if kind == "pair":
                # how much more often than chance the two reports share devices; a pair that grew only because both
                # reports grew (lift about 1 or below) is not travelling together, and is not suggested
                a, b = (reports.get(r, {}).get("devices", 0) for r in needs)
                n = today.get("n_devices") or 0
                lift = round(value * n / (a * b), 1) if a and b and n else None
                if lift is None or lift < cfg.get("min_lift", 2.0):
                    continue
            s = {"id": thread_id(kind, key), "kind": kind, "key": key, "day": today["day"], "value": value,
                 "normal": round(m, 1), "ratio": round(value / max(m, 1), 1), "z": round(z, 1), "new": m == 0,
                 "history": hist + [(today["day"], value)],
                 "first_day": next((d for d, v in hist if v > 0), today["day"]),
                 "days_above": sum(1 for _, v in hist if v >= cfg["min_devices"]),
                 "factor": factor, "asked_from": round(cfg["ratio"] * factor, 2)}
            if kind == "network":
                s["asn"], s["reports"] = key.split("|", 1)[0], [key.split("|", 1)[1]]
            elif kind == "report":
                s["asn"], s["reports"] = "*", needs
            else:
                s["asn"], s["reports"], s["lift"] = "*", needs, lift
            out.append(s)
    out.sort(key=lambda s: (-s["z"], -s["value"]))
    return out


def words(s, title, network):
    """A suggestion in plain words. title(report) -> the report's readable name; network(asn) -> the network's name."""
    if s["kind"] == "pair":
        a, b = (title(r) for r in s["reports"])
        txt = f"{s['value']} devices were in both {a} and {b}"
        txt += ", where this pair is normally rare" if s["new"] else f", normally about {s['normal']:g} ({s['ratio']:g}x)"
        if s.get("lift"):
            txt += f"; together {s['lift']:g} times more often than chance"
        return txt + "."
    who = "the whole constituency" if s["asn"] == "*" else network(s["asn"])
    txt = f"{who}, {title(s['reports'][0])}: {s['value']} devices"
    return txt + (", normally none." if s["new"] else f", normally about {s['normal']:g} ({s['ratio']:g}x).")


def learned_words(s, learned, title):
    """Why the bar for this suggestion's report(s) is where it is, in words; '' when the team has not moved it."""
    out = []
    for r in s.get("reports") or []:
        f, d, c = sensitivity(learned, r)
        if d or c:
            out.append(f"asks from {s.get('asked_from', 0):g}x its normal for {title(r)}, "
                       f"after {d} dismissal(s) and {c} confirmation(s) by your team")
    return ("Looking Glass " + "; ".join(out) + ".") if out else ""


def series(key, kind, history):
    """A thread's values over the summaries given (oldest first): [(day, value)]; for a watched thread's chart."""
    out = []
    for s in sorted(history, key=lambda x: x["day"]):
        if kind == "pair":
            if all(r in s.get("reports", {}) for r in key.split("|")):
                out.append((s["day"], int(s.get("pairs", {}).get(key, 0))))
        elif kind == "report":
            r = key.split("|", 1)[1]
            if r in s.get("reports", {}):
                out.append((s["day"], int(s["reports"][r].get("devices", 0))))
        else:
            r = key.split("|", 1)[1]
            if r in s.get("reports", {}):
                out.append((s["day"], int(s.get("threads", {}).get(key, 0))))
    return out
