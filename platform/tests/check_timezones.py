#!/usr/bin/env python3
"""Display time zones (timezones.py, Settings > Country): every country in the world with a map has a zone that loads
(the capital's first, Kosovo and the half-hour and UTC+14 zones included), each
conversion is right (whole-hour zones, daylight saving in Egypt, Morocco's Ramadan change, Cape Verde behind UTC, DR
Congo's two zones), Settings accepts only a country's own zones, and a settings file from before time zones gets the
country's usual zone. Shadowserver's times are UTC: the day and every stored time stay UTC; only the display changes.
No database needed.  Run: .venv/bin/python tests/check_timezones.py"""
import json
import os
import sys
import tempfile
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
import timezones as T  # noqa: E402
from settings import Settings  # noqa: E402

checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info and not cond else ""))


U = lambda s: datetime.fromisoformat(s).replace(tzinfo=timezone.utc)

print("Every country with a region map has its zone, and every zone loads")
ADM1 = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "static", "data", "adm1")
countries = sorted(f[:-5] for f in os.listdir(ADM1) if len(f) == 7 and f.endswith(".json"))
no_zone = [c for c in countries if not T.zones_of(c)]
ok(f"{len(countries)} countries with maps all have zones (Bouvet Island, uninhabited, has UTC only)",
   set(no_zone) <= {"BV"}, str(no_zone))
ok("the 54 African countries keep their hand-checked zones", len(T.ZONES) == 54 and all(T.zones_of(c) == T.ZONES[c] for c in T.ZONES))
broken = [z for c in countries for z in T.zones_of(c) if T._zone(z) is None]
ok("every zone is in this computer's time-zone database", not broken, str(broken))
ok("UTC can always be chosen", all(T.choices(c)[-1] == "UTC" for c in countries))

print("The whole world: the capital's zone comes first")
for cc, want in (("BR", "America/Sao_Paulo"), ("RU", "Europe/Moscow"), ("AU", "Australia/Sydney"), ("US", "America/New_York"),
                 ("CA", "America/Toronto"), ("ID", "Asia/Jakarta"), ("IN", "Asia/Kolkata"), ("GB", "Europe/London"),
                 ("NZ", "Pacific/Auckland"), ("KI", "Pacific/Tarawa"), ("XK", "Europe/Belgrade"), ("JM", "America/Jamaica")):
    ok(f"{cc}: usual zone {want}", T.default_zone(cc) == want, T.default_zone(cc))
ok("Brazil offers its other zones too (Manaus)", "America/Manaus" in T.choices("BR"))
ok("Bouvet Island: UTC", T.default_zone("BV") == "UTC")
t0 = U("2026-11-11T12:15:41")
kir = T.info("Pacific/Kiritimati", t0)
ok("Kiribati's Line Islands are UTC+14 (the date ahead of UTC)", kir["offset"] == "UTC+14", kir["offset"])
ok("New York: UTC-5 in winter, UTC-4 in summer", (T.info("America/New_York", U("2026-01-15T12:00:00"))["offset"],
   T.info("America/New_York", U("2026-07-15T12:00:00"))["offset"]) == ("UTC-5", "UTC-4"))
ok("Kolkata's half hour: UTC+5:30", T.info("Asia/Kolkata", t0)["offset"] in ("UTC+5:30", "UTC+05:30"), T.info("Asia/Kolkata", t0)["offset"])

print("Conversions (a Shadowserver time is UTC; the same moment shown locally)")
t = U("2026-11-11T12:15:41")
for zone, want, off in (("Africa/Accra", "12:15:41", "UTC"), ("Africa/Lagos", "13:15:41", "UTC+1"),
                        ("Africa/Johannesburg", "14:15:41", "UTC+2"), ("Africa/Nairobi", "15:15:41", "UTC+3"),
                        ("Indian/Mauritius", "16:15:41", "UTC+4"), ("Atlantic/Cape_Verde", "11:15:41", "UTC-1"),
                        ("Africa/Kinshasa", "13:15:41", "UTC+1"), ("Africa/Lubumbashi", "14:15:41", "UTC+2")):
    got = T.local(t, zone)
    ok(f"{zone}: 12:15:41 UTC is {want} ({off})", got.strftime("%H:%M:%S") == want and T.info(zone, t)["offset"] == off,
       f"{got:%H:%M:%S} {T.info(zone, t)['offset']}")
ok("a naive time is read as UTC (as the reports write it)", T.local(datetime(2026, 11, 11, 12, 15, 41), "Africa/Nairobi").hour == 15)
ok("epoch seconds work too", T.local(t.timestamp(), "Africa/Nairobi").strftime("%H:%M") == "15:15")
ok("the date changes across midnight (23:30 UTC is 02:30 the next day in Nairobi)",
   T.local(U("2026-11-11T23:30:00"), "Africa/Nairobi").strftime("%Y-%m-%d %H:%M") == "2026-11-12 02:30")
ok("…and back (00:30 UTC is 23:30 the day before in Cape Verde)",
   T.local(U("2026-11-11T00:30:00"), "Atlantic/Cape_Verde").strftime("%Y-%m-%d %H:%M") == "2026-11-10 23:30")
cairo_w, cairo_s = T.info("Africa/Cairo", U("2026-01-15T12:00:00")), T.info("Africa/Cairo", U("2026-07-15T12:00:00"))
ok("Egypt: UTC+2 in winter, UTC+3 in summer (daylight saving)", (cairo_w["offset"], cairo_s["offset"]) == ("UTC+2", "UTC+3"),
   f"{cairo_w['offset']} / {cairo_s['offset']}")
casa = {T.info("Africa/Casablanca", U(d))["offset"] for d in ("2026-03-01T12:00:00", "2026-07-15T12:00:00")}
ok("Morocco: UTC+1, but UTC during Ramadan (the offset differs by date)", casa == {"UTC", "UTC+1"}, str(casa))
ok("Ghana is UTC all year: nothing extra is shown", T.info("Africa/Accra", t)["same_as_utc"] and T.label("Africa/Accra", t) == "UTC")
ok("label: 'Nairobi time (UTC+3)'", T.label("Africa/Nairobi", t) == "Nairobi time (UTC+3)", T.label("Africa/Nairobi", t))
ok("city names read well: Dar es Salaam", T.city("Africa/Dar_es_Salaam") == "Dar es Salaam")
day = U("2026-11-11T00:00:00")
ok("hour slot 12:00-13:00 UTC is '15:00 to 16:00 Nairobi time'", T.hour_range(12, "Africa/Nairobi", day) == "15:00 to 16:00 Nairobi time",
   T.hour_range(12, "Africa/Nairobi", day))
ok("…and nothing extra for a zone at UTC", T.hour_range(12, "Africa/Accra", day) == "")
ok("an unknown zone falls back to UTC, never an error", T.info("Mars/Olympus")["zone"] == "UTC")

print("Settings accept only the country's own zones")
v = lambda d: Settings.validate(d, countries=set(countries))
c, e = v({"country": "KE", "timezone": "Africa/Nairobi", "networks": [], "cidrs": []})
ok("Kenya + Nairobi accepted", not e and c["timezone"] == "Africa/Nairobi", str(e))
c, e = v({"country": "KE", "timezone": "Africa/Lagos", "networks": [], "cidrs": []})
ok("Kenya + Lagos refused", bool(e) and "time zone" in e[0], str(e))
c, e = v({"country": "KE", "timezone": "UTC", "networks": [], "cidrs": []})
ok("Kenya + UTC accepted", not e and c["timezone"] == "UTC", str(e))
c, e = v({"country": "CD", "timezone": "Africa/Lubumbashi", "networks": [], "cidrs": []})
ok("DR Congo + Lubumbashi (its second zone) accepted", not e, str(e))
c, e = v({"country": "NG", "networks": [], "cidrs": []})
ok("no zone given: the country's usual one (Nigeria: Lagos)", not e and c["timezone"] == "Africa/Lagos", str(c))
for bad in (["Africa/Nairobi"], 3, "../../etc/passwd", "Africa/Nairobi\n"):
    c, e = v({"country": "KE", "timezone": bad, "networks": [], "cidrs": []})
    ok(f"odd zone {bad!r} refused", bool(e))

print("A settings file from before time zones")
with tempfile.TemporaryDirectory() as d:
    p = os.path.join(d, "settings.json")
    json.dump({"country": "TZ", "networks": [], "cidrs": []}, open(p, "w"))
    s = Settings(p)
    ok("gets the country's usual zone (Tanzania: Dar es Salaam)", s.data["timezone"] == "Africa/Dar_es_Salaam", s.data["timezone"])
    json.dump({"country": "GH", "timezone": "Africa/Nairobi", "networks": [], "cidrs": []}, open(p, "w"))
    ok("a zone that does not belong to the country is replaced", Settings(p).data["timezone"] == "Africa/Accra")
    s = Settings(p)
    clean, e = Settings.validate({"country": "ZA", "timezone": "Africa/Johannesburg", "networks": [], "cidrs": []}, set(countries))
    s.save(clean)
    ok("saved and read back", json.load(open(p))["timezone"] == "Africa/Johannesburg" and Settings(p).tz(t)["offset"] == "UTC+2")

print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {', '.join(fails)}" if fails else ""))
sys.exit(1 if fails else 0)
