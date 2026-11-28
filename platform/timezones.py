# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""The time zone a CSIRT reads its times in (Settings > Country). Display only.

Shadowserver writes every timestamp in UTC, and a moment is the same moment in every country, so the platform keeps
storing, loading and comparing in UTC, and a day stays 00:00 to 24:00 UTC, as Shadowserver sorts its reports. What
changes is how a time is shown: next to UTC, the same moment in the zone chosen here (for example 15:15 Nairobi time
for 12:15 UTC), worked out by the IANA time-zone database, so daylight saving (Egypt, Morocco's Ramadan change) is
right on every date.

ZONES     ISO country code -> its zones, the usual one first (DR Congo has two): the 54 African countries, checked
          by hand. Every other country (2026-11-15: the whole world) takes its zones from the IANA database's own
          country table (zone.tab), in its order; "UTC" can always be chosen too.
default_zone(country), valid(country, zone), info(zone, at) -> {"zone", "city", "offset_minutes", "offset", "abbr",
"same_as_utc"}, local(dt, zone), label(zone, at) -> "Nairobi time (UTC+3)".
"""
import os
from datetime import datetime, timezone

try:
    from zoneinfo import ZoneInfo, ZoneInfoNotFoundError
except ImportError:          # pragma: no cover  (Python 3.9+ always has it)
    ZoneInfo, ZoneInfoNotFoundError = None, Exception

ZONES = {
    "AO": ["Africa/Luanda"], "BF": ["Africa/Ouagadougou"], "BI": ["Africa/Bujumbura"], "BJ": ["Africa/Porto-Novo"],
    "BW": ["Africa/Gaborone"], "CD": ["Africa/Kinshasa", "Africa/Lubumbashi"], "CF": ["Africa/Bangui"],
    "CG": ["Africa/Brazzaville"], "CI": ["Africa/Abidjan"], "CM": ["Africa/Douala"], "CV": ["Atlantic/Cape_Verde"],
    "DJ": ["Africa/Djibouti"], "DZ": ["Africa/Algiers"], "EG": ["Africa/Cairo"], "ER": ["Africa/Asmara"],
    "ET": ["Africa/Addis_Ababa"], "GA": ["Africa/Libreville"], "GH": ["Africa/Accra"], "GM": ["Africa/Banjul"],
    "GN": ["Africa/Conakry"], "GQ": ["Africa/Malabo"], "GW": ["Africa/Bissau"], "KE": ["Africa/Nairobi"],
    "KM": ["Indian/Comoro"], "LR": ["Africa/Monrovia"], "LS": ["Africa/Maseru"], "LY": ["Africa/Tripoli"],
    "MA": ["Africa/Casablanca"], "MG": ["Indian/Antananarivo"], "ML": ["Africa/Bamako"], "MR": ["Africa/Nouakchott"],
    "MU": ["Indian/Mauritius"], "MW": ["Africa/Blantyre"], "MZ": ["Africa/Maputo"], "NA": ["Africa/Windhoek"],
    "NE": ["Africa/Niamey"], "NG": ["Africa/Lagos"], "RW": ["Africa/Kigali"], "SC": ["Indian/Mahe"],
    "SD": ["Africa/Khartoum"], "SL": ["Africa/Freetown"], "SN": ["Africa/Dakar"], "SO": ["Africa/Mogadishu"],
    "SS": ["Africa/Juba"], "ST": ["Africa/Sao_Tome"], "SZ": ["Africa/Mbabane"], "TD": ["Africa/Ndjamena"],
    "TG": ["Africa/Lome"], "TN": ["Africa/Tunis"], "TZ": ["Africa/Dar_es_Salaam"], "UG": ["Africa/Kampala"],
    "ZA": ["Africa/Johannesburg"], "ZM": ["Africa/Lusaka"], "ZW": ["Africa/Harare"],
}
UTC_NAME = "UTC"
_WORLD = None


def _world():
    """{ISO2: [zones]} from the IANA database's zone.tab (the system's, else the tzdata package's), read once."""
    global _WORLD
    if _WORLD is None:
        # filled in a dictionary of its own and published whole: a request arriving while another thread was still
        # reading the file found an empty or half-filled table and offered UTC only (audit 2026-11-27, 8-13)
        world = {}
        paths = ["/usr/share/zoneinfo/zone.tab"]
        try:
            import tzdata
            paths.append(os.path.join(os.path.dirname(tzdata.__file__), "zoneinfo", "zone.tab"))
        except ImportError:
            pass
        for p in paths:
            try:
                with open(p, encoding="utf-8") as fh:
                    for line in fh:
                        if line.startswith("#") or not line.strip():
                            continue
                        parts = line.split("\t")
                        if len(parts) >= 3:
                            world.setdefault(parts[0].strip().upper(), []).append(parts[2].strip())
                break
            except OSError:
                world = {}                             # a file that failed half-way: start again with the next one
                continue
        _WORLD = world
    return _WORLD


# countries with several zones where zone.tab does not list the capital's first: the capital's zone is the default
CAPITAL = {"RU": "Europe/Moscow", "AU": "Australia/Sydney", "BR": "America/Sao_Paulo", "CA": "America/Toronto",
           "MX": "America/Mexico_City", "ID": "Asia/Jakarta", "KZ": "Asia/Almaty", "CN": "Asia/Shanghai",
           "AR": "America/Argentina/Buenos_Aires", "CL": "America/Santiago", "ES": "Europe/Madrid", "PT": "Europe/Lisbon",
           "EC": "America/Guayaquil", "UA": "Europe/Kyiv", "MN": "Asia/Ulaanbaatar", "NZ": "Pacific/Auckland",
           "US": "America/New_York", "DE": "Europe/Berlin", "MY": "Asia/Kuala_Lumpur", "UZ": "Asia/Tashkent",
           "CY": "Asia/Nicosia", "PS": "Asia/Hebron", "FM": "Pacific/Pohnpei", "KI": "Pacific/Tarawa", "PF": "Pacific/Tahiti",
           "GL": "America/Nuuk", "AQ": "Antarctica/McMurdo"}
# places zone.tab does not list: Kosovo keeps Belgrade's time; Heard and McDonald Islands are UTC+5. Bouvet Island
# (uninhabited) has UTC only.
EXTRA = {"XK": ["Europe/Belgrade"], "HM": ["Indian/Kerguelen"]}


def zones_of(country):
    c = str(country or "").upper()
    z = list(ZONES.get(c) or _world().get(c) or EXTRA.get(c) or [])
    cap = CAPITAL.get(c)
    if cap in z:
        z.remove(cap); z.insert(0, cap)
    return z


def choices(country):
    """The zones offered for a country: its own, then UTC."""
    return zones_of(country) + [UTC_NAME]


def default_zone(country):
    return (zones_of(country) or [UTC_NAME])[0]


def valid(country, zone):
    return zone in choices(country) and _zone(zone) is not None


def _zone(name):
    if name == UTC_NAME:
        return timezone.utc
    if ZoneInfo is None:
        return None
    try:
        return ZoneInfo(name)
    except (ZoneInfoNotFoundError, ValueError, OSError):
        return None


def city(name):
    """'Africa/Dar_es_Salaam' -> 'Dar es Salaam'; 'UTC' -> 'UTC'."""
    return UTC_NAME if name == UTC_NAME else name.rsplit("/", 1)[-1].replace("_", " ")


def _aware(at):
    if at is None:
        return datetime.now(timezone.utc)
    if isinstance(at, (int, float)):
        return datetime.fromtimestamp(at, timezone.utc)
    return at if at.tzinfo else at.replace(tzinfo=timezone.utc)      # naive = UTC, as the reports write it


def local(at, name):
    """The same moment in the zone (a UTC datetime, naive UTC datetime or epoch seconds in)."""
    z = _zone(name) or timezone.utc
    return _aware(at).astimezone(z)


def offset_text(minutes):
    if not minutes:
        return "UTC"
    sign = "+" if minutes > 0 else "-"
    h, m = divmod(abs(minutes), 60)
    return f"UTC{sign}{h}" + (f":{m:02d}" if m else "")


def info(name, at=None):
    """What a page needs to show the zone at a moment (the offset can differ by date: daylight saving)."""
    z = _zone(name)
    if z is None:
        name, z = UTC_NAME, timezone.utc
    t = _aware(at).astimezone(z)
    mins = int(t.utcoffset().total_seconds() // 60)
    return {"zone": name, "city": city(name), "offset_minutes": mins, "offset": offset_text(mins),
            "abbr": t.tzname() or offset_text(mins), "same_as_utc": mins == 0}


def label(name, at=None):
    """'Nairobi time (UTC+3)'; for a zone at UTC+0 that day: 'UTC'."""
    i = info(name, at)
    return UTC_NAME if i["same_as_utc"] else f"{i['city']} time ({i['offset']})"


def hour_range(hour_utc, name, day_start):
    """'15:00 to 16:00 Nairobi time' for the UTC hour slot of a day; '' when the zone is UTC that day."""
    from datetime import timedelta
    a = _aware(day_start) + timedelta(hours=hour_utc)
    i = info(name, a)
    if i["same_as_utc"]:
        return ""
    la, lb = local(a, name), local(a + timedelta(hours=1), name)
    return f"{la:%H:%M} to {lb:%H:%M} {i['city']} time"
