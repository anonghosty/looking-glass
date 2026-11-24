/* SPDX-License-Identifier: AGPL-3.0-only
   SPDX-FileCopyrightText: the Looking Glass contributors */
/* Readable labels for the fields of Shadowserver's reports (static/data/field_labels.json, approved 2026-11-23).
   LGFields.label("ip_header_urg") -> "IP header: URG flag". The file is read once per page; until it has arrived, or
   for a field it does not know, the name is shown with spaces and a capital first letter (field_labels.py does the same). */
(() => {
  const plain = (k) => String(k || "").replace(/_/g, " ").trim().replace(/^\w/, (c) => c.toUpperCase());
  let labels = {};
  const ready = fetch("/static/data/field_labels.json", { credentials: "same-origin" })
    .then((r) => (r.ok ? r.json() : null))
    .then((d) => { if (d && d.labels && typeof d.labels === "object") labels = d.labels; return true; })
    .catch(() => false);
  const label = (k) => {
    const key = String(k || "").replace(/^x:/, "");
    const v = Object.prototype.hasOwnProperty.call(labels, key) ? labels[key] : "";
    return typeof v === "string" && v.trim() ? v : plain(key);
  };
  window.LGFields = { ready, label, plain };
})();
