"""The time zone a CSIRT reads its times in (Settings > Country). Display only.

Shadowserver writes every timestamp in UTC, and a moment is the same moment in every country, so the platform keeps
storing, loading and comparing in UTC, and a day stays 00:00 to 24:00 UTC, as Shadowserver sorts its reports. What
changes is how a time is shown: next to UTC, the same moment in the zone chosen here (for example 15:15 Nairobi time
for 12:15 UTC), worked out by the IANA time-zone database, so daylight saving (Egypt, Morocco's Ramadan change) is
right on every date.

ZONES     ISO country code -> its zones, the usual one first (DR Congo has two). Every one of the 54 countries with a
          region map (static/data/adm1) is here; "UTC" can always be chosen too.
default_zone(country), valid(country, zone), info(zone, at) -> {"zone", "city", "offset_minutes", "offset", "abbr",
"same_as_utc"}, local(dt, zone), label(zone, at) -> "Nairobi time (UTC+3)".
"""
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


def choices(country):
    """The zones offered for a country: its own, then UTC."""
    return list(ZONES.get(str(country or "").upper(), [])) + [UTC_NAME]


def default_zone(country):
    return (ZONES.get(str(country or "").upper()) or [UTC_NAME])[0]


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
