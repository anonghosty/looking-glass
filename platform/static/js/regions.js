/* Looking Glass · region names and labels for the country maps (services regions map and Settings preview).

   The reports' region names come from IP geolocation (ISO 3166-2 names, often local: "Alger", "Al Qāhirah", or English:
   "Algiers", "Cairo Governorate"); the maps come from geoBoundaries. manage/region_aliases.py stores, for every region
   of the 54 African maps, its ISO codes, aliases (other names, sub-units, newer subdivisions carved out of it) and a
   label point well inside it. This file matches report names to map regions through those aliases and places labels
   that don't overlap. */
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
  function index(file) {
    const exact = new Map(), loose = new Map();
    for (const [key, reg] of Object.entries((file && file.regions) || {})) {
      for (const a of [key, norm(reg.name), ...(reg.aliases || [])]) {
        if (!exact.has(a)) exact.set(a, key);
        const f = a.replace(/[^A-Z]/g, ""); if (f && !loose.has(f)) loose.set(f, key);
      }
    }
    return (name) => { if (!name) return null; const n = norm(name); return exact.get(n) || loose.get(flat(name)) || null; };
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
  window.LGRegions = { norm, index, placeLabels, shortName };
})();
