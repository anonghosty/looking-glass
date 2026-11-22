/* SPDX-License-Identifier: AGPL-3.0-only
   SPDX-FileCopyrightText: the Looking Glass contributors */
/* Looking Glass · region names and labels for the country maps (services regions map and Settings preview).

   The reports' region names come from IP geolocation (ISO 3166-2 names, often local: "Alger", "Al Qāhirah", or English:
   "Algiers", "Cairo Governorate"); the maps come from geoBoundaries. manage/region_aliases.py stores, for every region
   of every country's map, its ISO codes, aliases (other names, sub-units, newer subdivisions carved out of it) and a
   label point well inside it. This file matches report names to map regions through those aliases and places labels
   that don't overlap. A country drawn as one area (file.whole: no first-level regions in the open data, 2026-11-15)
   takes every record, whatever region the report names. */
(() => {
  "use strict";
  const SUFFIXES = [" REGION", " PROVINCE", " STATE", " GOVERNORATE", " COUNTY", " DISTRICT", " PREFECTURE", " DEPARTMENT", " WILAYA", " ATOLL"];
  // the same as norm() in manage/region_aliases.py: no accents or other non-ASCII marks, upper case, common suffixes removed
  function norm(n) {
    let s = String(n || "").normalize("NFKD").replace(/[̀-ͯ]/g, "").replace(/[^\x00-\x7f]/g, "").toUpperCase().trim();
    for (const x of SUFFIXES) if (s.endsWith(x)) s = s.slice(0, -x.length).trim();
    return s;
  }
  const flat = (s) => norm(s).replace(/[^A-Z]/g, "");
  /** lookup for one country file: report region name -> map region key (or null) */
  /** chosen: the administrator's matches {report name: map key | "__country__"} (region_matches.py, Settings) */
  function index(file, chosen) {
    const mine = new Map(Object.entries(chosen || {}).map(([k, v]) => [norm(k), v]));
    if (file && file.whole) {                       // one area: the whole country, every record lands on it
      const only = Object.keys(file.regions || {})[0] || null;
      return (name) => { const c = mine.get(norm(name)); return c && c !== "__country__" ? c : only; };
    }
    const exact = new Map(), loose = new Map();
    const regs = Object.entries((file && file.regions) || {});
    // keys first, then names, then aliases: a region's own name wins over another region's alias (Latvia's
    // "Jelgavas novads" county against the city of Jelgava)
    for (const pick of [(k) => [k], (k, r) => [norm(r.name)], (k, r) => r.aliases || []]) {
      for (const [key, reg] of regs) {
        for (const a of pick(key, reg)) {
          if (!a) continue;
          if (!exact.has(a)) exact.set(a, key);
          const f = a.replace(/[^A-Z]/g, ""); if (f && !loose.has(f)) loose.set(f, key);
        }
      }
    }
    return (name) => {
      if (!name) return null;
      const n = norm(name), c = mine.get(n);
      if (c) return c === "__country__" ? null : c;          // the administrator's choice comes first
      return exact.get(n) || loose.get(flat(name)) || null;
    };
  }
  /** keep the labels that fit: items [{x, y, lines:[text...], size, prio}] -> the ones to draw (highest prio first, no overlaps) */
  function placeLabels(items, bounds) {
    const placed = [], out = [];
    for (const it of items.slice().sort((a, b) => b.prio - a.prio)) {
      const w = Math.max(...it.lines.map((t) => t.length)) * it.size * 0.58 + 6, h = it.lines.length * it.size * 1.25 + 2;
      const box = { x0: it.x - w / 2, x1: it.x + w / 2, y0: it.y - h / 2, y1: it.y + h / 2 };
      if (bounds && (box.x0 < bounds.x0 || box.x1 > bounds.x1 || box.y0 < bounds.y0 || box.y1 > bounds.y1)) continue;
      if (placed.some((p) => box.x0 < p.x1 && box.x1 > p.x0 && box.y0 < p.y1 && box.y1 > p.y0)) continue;
      placed.push(box); out.push(it);
    }
    return out;
  }
  /** display name of a map region: as written in the boundary file, without a trailing "Region"/"Province"... word */
  const shortName = (name) => String(name || "").replace(/ (Region|Province|State|Governorate|District|County|Prefecture|Department|Wilaya)$/i, "");
  /** is this report region "the whole country" (empty, or the country's own name in any spelling the index lists)? */
  function isCountry(name, info) {
    const n = norm(name);
    if (!n) return true;
    const chosen = (info && info.matches) || {};
    if (Object.entries(chosen).some(([k, v]) => v === "__country__" && norm(k) === n)) return true;
    if (Object.entries(chosen).some(([k, v]) => v !== "__country__" && norm(k) === n)) return false;
    // a region of the map named like the country (Belize District, Djibouti, the State of Mexico) is that region
    if (info && info.regionNames && info.regionNames.has(n)) return false;
    return [info && info.country, ...((info && info.names) || [])].some((c) => c && norm(c) === n);
  }
  /** every name that is a region of the map (keys, names, aliases); empty for a one-area map */
  function regionNames(file) {
    const out = new Set();
    if (!file || file.whole) return out;
    for (const [key, reg] of Object.entries(file.regions || {})) for (const a of [key, norm(reg.name), ...(reg.aliases || [])]) if (a) out.add(a);
    return out;
  }
  /** the default frame of a map: the regions holding 98% of the records, when that is clearly smaller than the whole
   *  country (islands far apart: Seychelles, Kiribati, the Bahamas), so they are readable without zooming.
   *  counts {map key: records}. Returns {bbox: [west, south, east, north], zoomed}. The same rule as
   *  focus_bbox() in region_matches.py (Executive PDF). */
  function focusBox(file, counts) {
    const full = file && file.bbox;
    if (!full || file.whole) return { bbox: full, zoomed: false };
    const rows = Object.entries(counts || {}).filter(([k, n]) => n > 0 && file.regions[k]).sort((a, b) => b[1] - a[1]);
    const tot = rows.reduce((s, [, n]) => s + n, 0);
    if (!tot) return { bbox: full, zoomed: false };
    let w = Infinity, s = Infinity, e = -Infinity, n = -Infinity, cum = 0;
    for (const [k, c] of rows) {
      for (const poly of file.regions[k].polys || []) for (const [x, y] of poly[0] || []) { if (x < w) w = x; if (x > e) e = x; if (y < s) s = y; if (y > n) n = y; }
      cum += c; if (cum >= 0.98 * tot) break;
    }
    if (!(e > w && n > s)) return { bbox: full, zoomed: false };
    const FW = full[2] - full[0], FH = full[3] - full[1];
    const minW = Math.max(0.25, FW * 0.03), minH = Math.max(0.25, FH * 0.03);
    let cx = (w + e) / 2, cy = (s + n) / 2, hw = Math.max((e - w) * 1.12, minW) / 2, hh = Math.max((n - s) * 1.12, minH) / 2;
    const box = [cx - hw, cy - hh, cx + hw, cy + hh];
    if ((box[2] - box[0]) * (box[3] - box[1]) >= 0.35 * FW * FH) return { bbox: full, zoomed: false };
    return { bbox: box, zoomed: true };
  }
  window.LGRegions = { norm, index, placeLabels, shortName, isCountry, regionNames, focusBox };
})();
