/* Local times next to UTC (Settings > Country > Time zone; timezones.py on the server).
 *
 * Shadowserver writes every time in UTC and a day runs 00:00 to 24:00 UTC, as its reports do: the platform keeps that.
 * This only SHOWS the same moment in the CSIRT's zone as well, worked out by the browser's own time-zone database (so
 * daylight saving is right on every date). When the zone is UTC that day (Ghana, for example) nothing extra is shown.
 *
 *   LGTime.set(tz)            tz from /api/clock, /api/svc/clock or the Executive data: {zone, city, offset, same_as_utc}
 *   LGTime.on()               true when there is a local time worth showing
 *   LGTime.time(t)            "15:15:41"            (t: an ISO time, a Date or milliseconds)
 *   LGTime.dateTime(t)        "2026-11-11 15:15:41"
 *   LGTime.hm(t)              "15:15"
 *   LGTime.place()            "Nairobi time"
 *   LGTime.tag()              "Nairobi, UTC+3"
 *   LGTime.also(t, seconds)   " (15:15:41 Nairobi time)" or ""     — after a UTC time
 *   LGTime.slot(a, b)         " (15:00 to 16:00 Nairobi time)" or "" — after a UTC range; a, b: times
 */
(function () {
  "use strict";
  const T = { tz: null };
  const fmts = new Map();
  function fmt(zone) {
    if (!fmts.has(zone)) {
      try {
        fmts.set(zone, new Intl.DateTimeFormat("en-GB", { timeZone: zone, year: "numeric", month: "2-digit", day: "2-digit",
          hour: "2-digit", minute: "2-digit", second: "2-digit", hourCycle: "h23" }));
      } catch { fmts.set(zone, null); }        // a browser without this zone: UTC only, never an error
    }
    return fmts.get(zone);
  }
  function ms(t) {
    if (t instanceof Date) return t.getTime();
    if (typeof t === "number") return t;
    const s = String(t || "");
    return Date.parse(/[zZ]|[+-]\d\d:?\d\d$/.test(s) ? s : `${s.replace(" ", "T")}Z`);   // reports' times are UTC
  }
  function parts(t) {
    const f = T.tz && fmt(T.tz.zone), m = ms(t);
    if (!f || !Number.isFinite(m)) return null;
    const p = {}; for (const x of f.formatToParts(new Date(m))) p[x.type] = x.value;
    return p;
  }
  T.set = (tz) => { if (tz && tz.zone) T.tz = tz; return T; };
  T.on = () => !!(T.tz && T.tz.zone && !T.tz.same_as_utc && fmt(T.tz.zone));
  T.place = () => (T.tz ? `${T.tz.city} time` : "UTC");
  T.tag = () => (T.tz ? `${T.tz.city}, ${T.tz.offset}` : "UTC");
  T.time = (t) => { const p = parts(t); return p ? `${p.hour}:${p.minute}:${p.second}` : ""; };
  T.hm = (t) => { const p = parts(t); return p ? `${p.hour}:${p.minute}` : ""; };
  T.dateTime = (t) => { const p = parts(t); return p ? `${p.year}-${p.month}-${p.day} ${p.hour}:${p.minute}:${p.second}` : ""; };
  T.also = (t, seconds = true) => (T.on() && Number.isFinite(ms(t)) ? ` (${seconds ? T.time(t) : T.hm(t)} ${T.place()})` : "");
  T.slot = (a, b) => (T.on() && Number.isFinite(ms(a)) ? ` (${T.hm(a)} to ${T.hm(b)} ${T.place()})` : "");
  window.LGTime = T;
})();
