# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""What a connector sends (the user, 2026-11-24): Looking Glass's own analysis of a report day, never Shadowserver's raw
rows (the platforms' own Shadowserver connectors and IntelMQ carry those).

Per device (an address in what the target receives): one group of the day's reports it is in, and per report the
relation to the device (matched, same-infection, other-infection, services, other-category), the impact flags, the
infections with Looking Glass's description and recommended action, the ATT&CK techniques with Looking Glass's reason
and certainty ("suggested" while a researcher has not confirmed them) and MITRE's mitigations, the CVE ids, the decoded beacon's family and format (no operator ids or versions), how many days the device was
seen in the report and the day it was first reported. Never: findings, names of people, notes, time to act, and
Looking Glass's combination codes (they stay in Looking Glass; dropped here even if a caller passes them).

Two shapes of the same content:
- stix_bundle(): STIX 2.1 for OpenCTI (grouping per device, observed-data per report, notes, sightings, malware,
  attack-pattern, course-of-action, vulnerability, relationships; ids stable, so a change updates in place);
- misp_event(): one MISP event per report day per target (MISP's standard ip-port objects, tags, galaxy tags for
  ATT&CK, an event report with the notes), unpublished, "Your organisation only", to_ids off (the devices are victims).
devices: [{"ip", "asn", "asn_name", "reports": {report: {"count", "first", "last", "infections", "tags",
"beacons": [(family, format)], "cves", "days_seen", "first_reported"}}}]; know: the knowledge (know_from(base_dir)).
"""
import json
import os
import uuid

FORMAT = "14"          # raised when what is sent changes shape: every day is sent again with the next run
SCO_NS = uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7")      # STIX 2.1 section 2.9
LG_NS = uuid.uuid5(uuid.NAMESPACE_URL, "https://github.com/anonghosty/looking-glass")
MATCHED = "event4_sinkhole_http"
# STIX's predefined TLP 1.0 markings, and OASIS's TLP 2.0 marking for AMBER+STRICT (with its extension)
TLP_STIX = {"clear": "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
            "green": "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da",
            "amber": "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
            "red": "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed",
            "amber+strict": "marking-definition--939a9414-2ddd-4d32-a0cd-375ea402b003"}
TLP2_EXT = "extension-definition--60a3c5c5-0d10-413e-aab3-9e08dde9e88d"
CERTAINTY = {"observed": 85, "likely": 60, "possible": 30}


def _sco_id(t, props):
    props = {k: v for k, v in props.items() if v not in (None, "", [], {})}
    return f"{t}--{uuid.uuid5(SCO_NS, json.dumps(props, sort_keys=True, separators=(',', ':'), ensure_ascii=False))}"


def _id(t, *parts):
    """UUIDv4-shaped and stable: the same analysis sent again updates the same object."""
    return f"{t}--{uuid.UUID(bytes=uuid.uuid5(LG_NS, '|'.join([t, *map(str, parts)])).bytes, version=4)}"


def mitre_obj(t, mitre_id, name, url, now):
    """A MITRE ATT&CK technique or mitigation as OpenCTI's MITRE data holds it: OpenCTI's id for that MITRE id (uuid5 of
    {"x_mitre_id": <lower case>} in the STIX namespace, as OpenCTI makes it: checked against OpenCTI 7.261119's own
    MITRE entries), so it merges with the platform's MITRE entry."""
    return {"type": t, "spec_version": "2.1", "id": _sco_id(t, {"x_mitre_id": mitre_id.lower()}), "created": now, "modified": now,
            "name": name, "x_mitre_id": mitre_id,
            "external_references": [{"source_name": "mitre-attack", "external_id": mitre_id, **({"url": url} if url else {})}]}


def _json(base_dir, name):
    try:
        with open(os.path.join(base_dir, "data", name), encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def know_from(base_dir, impact=None):
    """The knowledge the payload explains with: report facts, ATT&CK mapping and names, the infection knowledge base,
    impact flags (advisory.Impact when given), the organisation's name."""
    kb = dict((_json(base_dir, "infections.json").get("infections") or {}))
    kb.update(_json(base_dir, "definitions.json").get("infections") or {})
    return {"facts": _json(base_dir, "report_map.json").get("facts") or {},
            "amap": _json(base_dir, "attack_mappings.json").get("reports") or {},
            "attack": _json(base_dir, "names_attack.json"), "kb": {k.lower(): v for k, v in kb.items()},
            "flags": _json(base_dir, "report_impact.json").get("flags") or {},
            "impact": impact, "org": _json(base_dir, "organisation.json").get("name") or "CSIRT"}


def flags_of(know, report):
    imp = know.get("impact")
    if imp is None:
        return []
    k, e = imp.entry(report)
    return imp.flags_of(k or report, e)


def relation(report, infections, matched):
    if report == MATCHED:
        return "matched"
    if report.startswith("event"):
        return "same-infection" if matched and matched & set(infections) else "other-infection"
    if report.startswith(("blocklist", "compromised")):
        return "other-category"
    return "services"


def _kb_line(ent):
    """The knowledge base's confidence and status under a recommended action (they were labels before)."""
    parts = [f"{k} {ent[k]}" for k in ("confidence", "status") if ent.get(k)]
    return f"\n\nLooking Glass knowledge base: {', '.join(parts)}." if parts else ""


# the only labels sent to OpenCTI: an OpenCTI administrator creates them once (Settings -> Taxonomies -> Labels)
LABELS = ("looking-glass", "victim-device", "looking-glass-analysis")


def _labels(report, rel, flags, r):
    """MISP tags only (looking-glass:...); OpenCTI gets the fixed LABELS."""
    return list(dict.fromkeys(
        ["shadowserver", f"report:{report}", f"relation:{rel}"] + [f"impact:{f}" for f in flags]
        + [f"infection:{i}" for i in r.get("infections") or []]
        + [f"cve:{c}" for c in r.get("cves") or []] + [f"beacon:{fmt}" for _, fmt in r.get("beacons") or []]
        + [f"repeat-days:{r.get('days_seen', 1)}", f"first-reported:{r.get('first_reported', '')}"]))


def note_text(ip, day, title, rel, r, flags, know, report=None):
    """The note's content in Markdown (OpenCTI shows it formatted): one fact per bullet, like the MISP event report."""
    fc = know["facts"].get(report) or {} if report else {}
    name = f"[{title}]({fc['url']})" if fc.get("url") else title
    lines = [f"**Shadowserver report:** {name}", "",
             f"- **Device:** {ip}", f"- **Report day:** {day}", f"- **Records:** {r.get('count', 0)}",
             f"- **Relation to this device:** {rel}",
             f"- **Seen in this report:** {r.get('days_seen', 1)} day(s) since {r.get('first_reported', day)} (first reported)"]
    if flags:
        lines.append("- **Impact:**")
        lines += [f"    - **{(know['flags'].get(f) or {}).get('label', f)}.** {str((know['flags'].get(f) or {}).get('text', '')).strip()}"
                  for f in flags]
    if r.get("infections"):
        lines.append("- **Infection(s):** " + ", ".join(r["infections"]))
    if r.get("beacons"):
        lines.append("- **Decoded check-in:** " + ", ".join(f"{fmt} ({fam})" for fam, fmt in r["beacons"]) + " (family and format only)")
    if r.get("cves"):
        lines.append("- **CVEs reported:** " + ", ".join(r["cves"]))
    m = (know.get("amap") or {}).get(report) or {} if report else {}
    if m.get("techniques"):
        lines.append(f"- **ATT&CK ({m.get('status', 'suggested')}, {m.get('certainty', 'possible')}):**")
        lines += [f"    - {tid} {((know.get('attack') or {}).get('techniques') or {}).get(tid, {}).get('name', '')}".rstrip()
                  for tid in m["techniques"]]
        if m.get("why"):
            lines.append(f"    - Why: {m['why']}")
    for inf in r.get("infections") or []:
        ent = (know.get("kb") or {}).get(inf.lower()) or {}
        if ent.get("action"):
            lines.append(f"- **Recommended action ({ent.get('title') or inf}):** {ent['action']}")
    return "\n".join(lines)


def stix_bundle(devices, day, tlp, know, now):
    """A STIX 2.1 bundle of the analysis of these devices on that day."""
    marking = TLP_STIX[tlp]
    objs, ids = [], set()

    def add(o):
        if o["id"] not in ids:
            ids.add(o["id"])
            objs.append(o)
        return o["id"]
    if tlp == "amber+strict":
        add({"type": "marking-definition", "spec_version": "2.1", "id": marking, "created": "2022-10-01T00:00:00.000Z",
             "name": "TLP:AMBER+STRICT", "extensions": {TLP2_EXT: {"extension_type": "property-extension", "tlp_2_0": "amber+strict"}}})
    ident = add({"type": "identity", "spec_version": "2.1", "id": _id("identity", "csirt"), "created": now, "modified": now,
                 "name": know["org"], "identity_class": "organization"})

    def common(o):
        # revoked: false said outright: an object revoked earlier (its device left the target's scope) and sent again
        # when the device comes back is then current again in OpenCTI
        return {"spec_version": "2.1", "created_by_ref": ident, "created": now, "modified": now, "object_marking_refs": [marking],
                "revoked": False, **o}
    for d in devices:
        ip = d["ip"]
        # the address and network carry the TLP, the author, a fixed description and labels (OpenCTI's x_opencti_
        # properties), so the device's page is not blank; no score on purpose: OpenCTI's score means "how malicious",
        # and the device is a victim, never something to block
        sco = {"spec_version": "2.1", "object_marking_refs": [marking], "x_opencti_created_by_ref": ident}
        dev = add({"type": "ipv6-addr" if ":" in ip else "ipv4-addr", **sco,
                   "id": _sco_id("ipv6-addr" if ":" in ip else "ipv4-addr", {"value": ip}), "value": ip,
                   "x_opencti_description": f"A device in {know['org']}'s constituency, analysed by Looking Glass from "
                                            "Shadowserver reports. It is a victim: its address is not an indicator to block.",
                   "x_opencti_labels": ["looking-glass", "victim-device"]})
        grp = [dev]
        asn_ref = None
        if d.get("asn"):
            asn_ref = add({"type": "autonomous-system", **sco, "id": _sco_id("autonomous-system", {"number": int(d["asn"])}),
                           "number": int(d["asn"]), **({"name": d["asn_name"]} if d.get("asn_name") else {}),
                           "x_opencti_description": f"A network in {know['org']}'s constituency (Looking Glass)."})
            grp.append(asn_ref)
        matched = set((d["reports"].get(MATCHED) or {}).get("infections") or [])
        for report, r in sorted(d["reports"].items(), key=lambda x: (x[0] != MATCHED, x[0])):
            fc = know["facts"].get(report) or {}
            title = fc.get("title") or report
            rel = relation(report, r.get("infections") or [], matched)
            flags = flags_of(know, report)
            # OpenCTI labels: only the fixed LABELS (an OpenCTI administrator creates them once; making new labels needs
            # OpenCTI's "Manage labels" right, which the connector's user should not have: the user, 2026-11-24). The
            # details (report, relation, impact, infections, CVEs, days seen) are in the notes and descriptions.
            refs = [dev] + ([asn_ref] if asn_ref else [])
            od = add(common({"type": "observed-data", "id": _id("observed-data", ip, report, day), "first_observed": r["first"],
                             "last_observed": r["last"], "number_observed": max(1, int(r.get("count") or 1)), "object_refs": refs,
                             "labels": ["looking-glass"], "external_references": [{"source_name": "Shadowserver", "external_id": report,
                                                                        "description": title, **({"url": fc["url"]} if fc.get("url") else {})}]}))
            grp.append(od)
            grp.append(add(common({"type": "note", "id": _id("note", ip, report, day), "abstract": f"Looking Glass: {title}",
                                   # the address too: the note then shows on the device's own page and in its graph
                                   "content": note_text(ip, day, title, rel, r, flags, know, report), "object_refs": [od, dev],
                                   "note_types": ["analysis"],
                                   "labels": ["looking-glass-analysis"]})))
            for cve in r.get("cves") or []:
                v = add(common({"type": "vulnerability", "id": _id("vulnerability", cve), "name": cve,
                                "external_references": [{"source_name": "cve", "external_id": cve}]}))
                # links start at the device's address: OpenCTI's graph then centres on the device (an observed-data's
                # contents are not drawn as links there)
                grp += [v, add(common({"type": "relationship", "id": _id("relationship", dev, "related-to", v), "relationship_type": "related-to",
                                       "source_ref": dev, "target_ref": v, "description": f"{title} reports {cve} for this device."}))]
            mal = None
            for inf in r.get("infections") or []:
                ent = know["kb"].get(inf.lower()) or {}
                mal = add(common({"type": "malware", "id": _id("malware", inf.lower()), "name": inf, "is_family": True,
                                  **({"description": ent["description"]} if ent.get("description") else {}),
                                  **({"aliases": ent["aliases"]} if ent.get("aliases") else {}),
                                  **({"external_references": [{"source_name": "malpedia", "external_id": ent["malpedia"],
                                                               "url": f"https://malpedia.caad.fkie.fraunhofer.de/details/{ent['malpedia']}"}]}
                                     if ent.get("malpedia") else {})}))
                grp += [mal, add(common({"type": "relationship", "id": _id("relationship", dev, "related-to", mal), "relationship_type": "related-to",
                                         "source_ref": dev, "target_ref": mal,
                                         "description": f"{ip} seen with {inf} in Shadowserver's {title} report."}))]
                if ent.get("action"):
                    coa = add(common({"type": "course-of-action", "id": _id("course-of-action", "lg-action", inf.lower()),
                                      "name": f"Recommended action: {ent.get('title') or inf}",
                                      "description": ent["action"] + _kb_line(ent),
                                      "labels": ["looking-glass"]}))
                    grp += [coa, add(common({"type": "relationship", "id": _id("relationship", coa, "mitigates", mal),
                                             "relationship_type": "mitigates", "source_ref": coa, "target_ref": mal}))]
                grp.append(add(common({"type": "sighting", "id": _id("sighting", ip, report, day, inf), "sighting_of_ref": mal,
                                       "observed_data_refs": [od], "where_sighted_refs": [ident], "count": max(1, int(r.get("count") or 1)),
                                       "first_seen": r["first"], "last_seen": r["last"],
                                       "description": f"{ip} seen with {inf} in Shadowserver's {title} report.", "labels": ["looking-glass"]})))
            m = know["amap"].get(report) or {}
            for tid in m.get("techniques") or []:
                t = (know["attack"].get("techniques") or {}).get(tid) or {}
                # MITRE's own knowledge (the technique, its mitigations, the link between them) merges onto the platform's
                # MITRE ATT&CK data: OpenCTI's id for the MITRE id, x_mitre_id, and no TLP, author or kill chain phases,
                # so the shared MITRE entries are neither restricted to this TLP nor changed (checked on OpenCTI 7.261119:
                # a TLP:AMBER copy would mark the shared technique AMBER; phases need SETTINGS_SETKILLCHAINPHASES).
                # Only Looking Glass's own analysis below carries the target's TLP.
                ap = add(mitre_obj("attack-pattern", tid, t.get("name") or tid, t.get("url"), now))
                for mid, _how in t.get("mitigations", []):
                    mm = (know["attack"].get("mitigations") or {}).get(mid) or {}
                    c = add(mitre_obj("course-of-action", mid, mm.get("name") or mid, mm.get("url"), now))
                    add({"type": "relationship", "spec_version": "2.1", "id": _id("relationship", c, "mitigates", ap), "created": now,
                         "modified": now, "relationship_type": "mitigates", "source_ref": c, "target_ref": ap})
                src, rtype = (mal, "uses") if (mal and m.get("role") == "used") else (dev, "related-to")
                certainty = m.get("certainty", "possible")
                grp.append(ap)
                grp.append(add(common({"type": "relationship", "id": _id("relationship", src, rtype, ap, report), "relationship_type": rtype,
                                       "source_ref": src, "target_ref": ap,
                                       "description": f"Looking Glass maps Shadowserver's {title} report to {tid} "
                                                      f"({m.get('status', 'suggested')}, {certainty}): {m.get('why', '')}",
                                       "labels": ["looking-glass"],
                                       "confidence": CERTAINTY.get(certainty, 30)})))
        add(common({"type": "grouping", "id": _id("grouping", ip, day), "name": f"{ip}: {len(d['reports'])} report(s) on {day}",
                    "context": "suspicious-activity", "labels": ["looking-glass", "victim-device"],
                    "description": "Looking Glass ties this address's records in different Shadowserver reports of the day together: "
                                   + "; ".join(f"{(know['facts'].get(k) or {}).get('title') or k} ({v.get('count', 0)} record(s))"
                                               for k, v in d["reports"].items()) + ".",
                    "object_refs": list(dict.fromkeys(grp))}))
    return {"type": "bundle", "id": _id("bundle", day, *sorted(d["ip"] for d in devices)), "objects": objs}


def _cell(text):
    """Text for a Markdown table cell: a pipe or a line break would end the cell."""
    return str(text).replace("|", "\\|").replace("\n", " ")


def _when(iso):
    """2026-11-23T00:24:26.000Z -> 2026-11-23 00:24:26 UTC."""
    s = str(iso)
    return f"{s[:10]} {s[11:19]} UTC" if len(s) >= 19 and s[10] == "T" else s


def _tag(name, colour=None):
    return {"name": name, **({"colour": colour} if colour else {})}


def misp_event(devices, day, tlp, know, target_id):
    """One MISP event for a report day and a target: MISP's ip-port object per device (the address with to_ids off:
    the devices are victims, never indicators to block), tags for the analysis, ATT&CK as MISP galaxy tags, and an
    event report with every device's notes, recommended actions and the ATT&CK reasons."""
    ev_uuid = str(uuid.uuid5(LG_NS, f"misp-event|{target_id}|{day}"))
    objects, techniques, summary, sections = [], {}, [], []
    for d in devices:
        ip = d["ip"]
        ip_uuid = str(uuid.uuid5(LG_NS, f"misp-attr|{target_id}|{day}|{ip}|ip-src"))
        matched = set((d["reports"].get(MATCHED) or {}).get("infections") or [])
        tags = {"looking-glass:device"}
        firsts, lasts = [], []
        net = f"AS{d['asn']}{' ' + d['asn_name'] if d.get('asn_name') else ''}" if d.get("asn") else "Unknown network"
        rows, details, dev_impacts, dev_tids = [], [], {}, {}
        for report, r in sorted(d["reports"].items(), key=lambda x: (x[0] != MATCHED, x[0])):
            fc = know["facts"].get(report) or {}
            title = fc.get("title") or report
            rel = relation(report, r.get("infections") or [], matched)
            flags = flags_of(know, report)
            firsts.append(r["first"])
            lasts.append(r["last"])
            # categorical tags only: counts and dates (repeat-days, first-reported) would make a new MISP tag for almost
            # every value; they stay in the event report
            tags.update(f'looking-glass:{x.split(":", 1)[0]}="{x.split(":", 1)[1]}"' for x in _labels(report, rel, flags, r)
                        if x != "shadowserver" and ":" in x and not x.startswith(("repeat-days:", "first-reported:")))
            rows.append(f"| {_cell(title)} | {r.get('count', 0)} | {rel} | {r.get('days_seen', 1)} | {r.get('first_reported', day)} |")
            lines = []
            for f in flags:
                fl = know["flags"].get(f) or {}
                dev_impacts[fl.get("label", f)] = 1
                lines.append(f"- **Impact:** {fl.get('label', f)}. {str(fl.get('text', '')).strip()}")
            if r.get("infections"):
                lines.append("- **Infection(s):** " + ", ".join(r["infections"]))
            if r.get("beacons"):
                lines.append("- **Decoded check-in:** " + ", ".join(f"{fmt} ({fam})" for fam, fmt in r["beacons"]) + " (family and format only)")
            if r.get("cves"):
                lines.append("- **CVEs reported:** " + ", ".join(r["cves"]))
            m = know["amap"].get(report) or {}
            for tid in m.get("techniques") or []:
                t = (know["attack"].get("techniques") or {}).get(tid) or {}
                name = t.get("name") or tid
                techniques[tid] = name
                dev_tids[f"{tid} {name}"] = 1
                lines.append(f'- **ATT&CK ({m.get("status", "suggested")}, {m.get("certainty", "possible")}):** '
                             f'@[tag](misp-galaxy:mitre-attack-pattern="{name} - {tid}") {m.get("why", "")}')
            for inf in r.get("infections") or []:
                ent = know["kb"].get(inf.lower()) or {}
                if ent.get("action"):
                    lines.append(f"- **Recommended action ({ent.get('title') or inf}):** {ent['action']}")
            if lines:
                details += [f"#### {title}", ""] + lines + [""]
        # MISP shows a table cell's line breaks as text: the summary is a bulleted list, one device per entry
        summary += [f"- @[attribute]({ip_uuid}) {net}, {len(d['reports'])} report(s)",
                    "    - **Impact:**"] + [f"        - {x}" for x in dev_impacts or ["None listed"]] + \
                   ["    - **ATT&CK (suggested):**"] + [f"        - {x}" for x in dev_tids or ["None"]]
        sections += [f"### {ip}", "", f"- **Network:** {net}", f"- **First seen:** {_when(min(firsts))}",
                     f"- **Last seen:** {_when(max(lasts))}", "",
                     "| Report | Records | Relation | Days seen | First reported |", "|---|---:|---|---:|---|"] + rows + [""] + details
        # MISP's ip-port template (v11): the device is the source (ip-src); every attribute names its category, which
        # MISP does not infer for datetime and text (checked on MISP 2.5.52, 2026-11-24)
        attrs = [{"object_relation": "ip-src", "type": "ip-src", "category": "Network activity", "value": ip, "to_ids": False,
                  "distribution": "5", "Tag": [_tag(t) for t in sorted(tags)], "comment": f"Looking Glass: {len(d['reports'])} report(s) on {day}"},
                 {"object_relation": "first-seen", "type": "datetime", "category": "Other", "value": min(firsts), "to_ids": False, "distribution": "5"},
                 {"object_relation": "last-seen", "type": "datetime", "category": "Other", "value": max(lasts), "to_ids": False, "distribution": "5"},
                 {"object_relation": "text", "type": "text", "category": "Other", "to_ids": False, "distribution": "5",
                  "value": "; ".join(f"{k}: {v.get('count', 0)} record(s)" for k, v in d["reports"].items())}]
        if d.get("asn"):
            attrs.append({"object_relation": "AS", "type": "AS", "category": "Network activity", "value": f"AS{d['asn']}", "to_ids": False,
                          "distribution": "5"})
        # fixed uuids: sent again, MISP updates these attributes instead of adding a second copy (checked on MISP 2.5.52)
        for a in attrs:
            a["uuid"] = str(uuid.uuid5(LG_NS, f"misp-attr|{target_id}|{day}|{ip}|{a['object_relation']}"))
        # MISP's own ip-port template (misp-objects), named by its uuid and version: MISP refuses an object without them
        objects.append({"name": "ip-port", "meta-category": "network", "distribution": "5", "comment": f"Looking Glass device {ip}",
                        "template_uuid": "9f8cea74-16fe-4968-a2b4-026676949ac6", "template_version": "11",
                        "description": "An IP address (or domain or hostname) and a port seen as a tuple (or as a triple) in a specific time frame.",
                        "uuid": str(uuid.uuid5(LG_NS, f"misp-object|{target_id}|{day}|{ip}")), "Attribute": attrs})
    report_md = ([f"# Looking Glass analysis of {day}", "",
                  f"**{len(devices)} device(s)** in what this MISP receives. The devices are victims: their addresses are not "
                  "indicators to block. Each address below links to its object in this event; each ATT&CK entry to its galaxy.", "",
                  "## Summary", ""] + summary + ["", "## Devices", ""] + sections)
    tags = [_tag(f"tlp:{tlp}"), _tag("looking-glass")] + [_tag(f'misp-galaxy:mitre-attack-pattern="{n} - {tid}"') for tid, n in sorted(techniques.items())]
    return {"Event": {"uuid": ev_uuid, "info": f"Looking Glass analysis {day}: {len(devices)} device(s)", "date": day,
                      "distribution": "0", "threat_level_id": "4", "analysis": "2", "published": False,
                      "Tag": tags, "Object": objects,
                      # a fixed uuid: sent again, the report is replaced, not added a second time
                      "EventReport": [{"uuid": str(uuid.uuid5(LG_NS, f"misp-report|{target_id}|{day}")), "name": f"Looking Glass analysis {day}",
                                       "content": "\n".join(report_md), "distribution": "5"}]}}


def test_objects(tlp, now="2026-01-01T00:00:00.000Z"):
    """The test send: one note saying it is a test, marked with the target's TLP."""
    marking = TLP_STIX[tlp]
    objs = []
    if tlp == "amber+strict":
        objs.append({"type": "marking-definition", "spec_version": "2.1", "id": marking, "created": "2022-10-01T00:00:00.000Z",
                     "name": "TLP:AMBER+STRICT", "extensions": {TLP2_EXT: {"extension_type": "property-extension", "tlp_2_0": "amber+strict"}}})
    # its own id: the CSIRT's identity id under another name makes OpenCTI hold two entities for one id and refuse
    # everything the CSIRT's identity signs (ELEMENT_ID_COLLISION, seen on OpenCTI 7.261119)
    ident = _id("identity", "looking-glass-connector-test")
    objs.append({"type": "identity", "spec_version": "2.1", "id": ident, "created": now, "modified": now, "name": "Looking Glass", "identity_class": "system"})
    objs.append({"type": "note", "spec_version": "2.1", "id": _id("note", "connector-test"), "created": now, "modified": now,
                 "created_by_ref": ident, "abstract": "Looking Glass connector test",
                 "content": "A test from Looking Glass's Settings -> Connectors: this target accepts what Looking Glass sends.",
                 "object_refs": [ident], "object_marking_refs": [marking]})
    return {"type": "bundle", "id": _id("bundle", "connector-test"), "objects": objs}


def misp_test_event(tlp):
    return {"Event": {"info": "Looking Glass connector test", "distribution": "0", "threat_level_id": "4", "analysis": "2",
                      "published": False, "Tag": [_tag(f"tlp:{tlp}"), _tag("looking-glass:test")]}}
