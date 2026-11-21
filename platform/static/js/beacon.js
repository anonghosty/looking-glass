/* The "Decoded beacon" block of the communication-detail window (beacon_decode.py), for analysts and admins.
 *
 * A bot that encodes its check-in into one query value (the CLogin check-in: GET /CLogin?key=<Base64>) is decoded on
 * the server: POST /api/beacon/decode with the request line, so it stays out of URLs and access logs. The block shows
 * the format, operator, version, OS, the recovered XOR key, the notes (cpuid as text, what the MAC prefix means, the
 * name it contradicts) and the whole JSON. In masked views (demo, external role) the request line already reads
 * "<clogin beacon>" and no block is asked for. Known families that cannot be decoded are named, with what they are. Called from app.js: LGBeacon.section(ev, still).
 */
(function () {
  "use strict";
  const el = (tag, cls, text) => { const e = document.createElement(tag); if (cls) e.className = cls; if (text != null) e.textContent = text; return e; };
  const csrf = () => document.querySelector('meta[name="csrf-token"]')?.content || "";
  // the same first look as the server's (beacon_decode._PREFILTER): a query value of 40 or more Base64 characters
  // (16: the families that cannot be decoded are named from 16 characters on)
  const CANDIDATE = /[?&;][^=&\s]{1,40}=[A-Za-z0-9+/%=_-]{16,}/;
  const OS = { android: "Android", windows: "Windows", linux: "Linux", macos: "macOS", ios: "iOS" };

  function rows(dl, list) {
    for (const [k, v] of list) {
      dl.append(el("dt", null, k));
      const dd = el("dd", v ? null : "empty", v || "Not recorded");
      dl.append(dd);
    }
  }

  function one(b, name) {
    const box = el("div", "bc-one");
    if (b.decoded === false) {          // a known family that cannot be decoded from the request: named, and why
      const dl = el("dl");
      // what the value is: encrypted, not decoded yet, or not encoded at all (a hash, an ID, a token)
      rows(dl, [["Family", `${b.title} (${b.status || "not decoded"})`], ["Found in", b.param && `query value "${b.param}"`], ["What it is", b.what]]);
      box.append(dl);
      // not decoded yet, or a known format whose value did not decode: it can be sent for decoding automation
      if (b.unknown || ["unknown", "cut"].includes(b.state)) {
        const a = el("a", "bh-ask", "Ask to send it for decoding (Findings page) ›");
        a.href = "/findings#beaconUnknown";
        box.append(a);
      }
      return box;
    }
    if (b.generic) {                    // the generic fallback: how it came off, and what it says
      const dl = el("dl");
      rows(dl, [["Decoded by", "the generic fallback (not a known format)"], ["Layers", (b.method || []).join(" → ")],
                ["Found in", b.param && `query value "${b.param}"`]]);
      box.append(dl);
      if (b.notes?.length) { const ul = el("ul", "bc-notes"); b.notes.forEach((n) => ul.append(el("li", null, n))); box.append(ul); }
      box.append(el("div", "bc-h", b.json ? "Decoded JSON" : "Decoded text"), el("pre", null, b.json ? JSON.stringify(b.json, null, 2) : b.text));
      if (name && window.LGBeaconHandover) box.append(window.LGBeaconHandover.button({ name, format: "generic" }, "Hand over these values"));
      return box;
    }
    const dl = el("dl");
    const os = [b.os, b.os_family && OS[b.os_family] && `(${OS[b.os_family]})`].filter(Boolean).join(" ");
    rows(dl, [["Format", b.title || b.format], ["Operator", b.operator], ["Version", b.version], ["Operating system", os],
              ["XOR key", b.key], ["Found in", b.param && `query value "${b.param}"`]]);
    box.append(dl);
    if (b.notes?.length) {
      const ul = el("ul", "bc-notes");
      for (const n of b.notes) ul.append(el("li", null, n));
      box.append(el("div", "bc-h", "Notes"), ul);
    }
    box.append(el("div", "bc-h", "Decoded JSON"), el("pre", null, JSON.stringify(b.json, null, 2)));
    // every record of the same beacon under this name, to an analyst or a manager as a finding (beacon-handover.js)
    if (name && window.LGBeaconHandover)
      box.append(window.LGBeaconHandover.button({ name, format: b.format, operator: b.operator, version: b.version, os_family: b.os_family },
        "Hand over these beacons"));
    return box;
  }

  // the block: added at once with a loading line when the request carries a candidate, removed when nothing decodes
  function section(ev, still) {
    const url = ev && ev.http_url;
    if (!url || ev.demo || !CANDIDATE.test(url)) return null;
    const s = el("section", "m-sec wide bc-sec");
    s.append(el("h3", null, "Decoded beacon"), el("div", "lg-loading", "Decoding the request…"));
    (async () => {
      try {
        const r = await fetch("/api/beacon/decode", { method: "POST", credentials: "same-origin",
          headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf() }, body: JSON.stringify({ url, name: ev.infection || "", host: ev.http_host || "", agent: ev.http_agent || "" }) });
        const d = await r.json().catch(() => ({}));
        if (!still()) return;
        if (!r.ok) { s.replaceChildren(el("h3", null, "Decoded beacon"), el("p", "bc-msg", d.error || `Could not decode (${r.status}).`)); return; }
        if (!d.beacons?.length) { s.remove(); return; }       // a long value that is no known beacon: nothing to show
        const n = d.beacons.filter((b) => b.decoded !== false).length;
        const plain = !n && d.beacons.every((b) => ["hash", "id", "token"].includes(b.state));     // nothing encoded in it
        s.replaceChildren(el("h3", null, n ? (d.beacons.length > 1 ? `Decoded beacon (${d.beacons.length} values)` : "Decoded beacon")
          : plain ? "Request value (not encoded)" : "Encoded request (not decoded)"));
        for (const b of d.beacons) s.append(one(b, ev.infection || ""));
      } catch (err) {
        if (still()) s.replaceChildren(el("h3", null, "Decoded beacon"), el("p", "bc-msg", `Could not decode: ${window.LGLoader.errorText(err)}`));
      }
    })();
    return s;
  }

  window.LGBeacon = { section };
})();
