"""New features install themselves here, so app.py does not keep growing (the user, 2026-11-16).

app.py calls install(app, core) once, at the end, with the platform's shared parts. A new feature lives in its own
module with its own install(app, ctx), and gets one entry below, built from `core`. Nothing else in app.py changes.

core: db (the reports database, read only), registry (the communications reports), store (the communications day
store), settings (the constituency), svc (the services platform: its "registry" and "store"), replay_now(),
day_start(dt), AUTH (has_perm, csrf_ok, audit, ...), app_logger, findings (findings.Findings), acodes (acodes.install's api).
Returns {name: what each feature's install returned}, for tests and for other modules.
"""


def _held(store, version):
    """A day the store holds, loaded under this constituency: {start: {report: rows}}, else None."""
    def loaded(start):
        day = store.days.get(start)
        if day is None or getattr(day, "by_src", None) is None:
            return None
        if getattr(day, "settings_version", None) != version() or getattr(day, "gen", 0) != getattr(store, "gen", 0):
            return None
        return {n: b.get("rows") or [] for n, b in day.by_src.items()}
    return loaded


def install(app, core):
    out = {}

    # the spike notice on the Overview's buttons: the latest report day against the day before, counted as each
    # platform shows a day (spike_notice.py)
    import spike_notice
    st, store = core["settings"], core["store"]
    svc_store = core["svc"]["store"]
    svc_st = getattr(svc_store, "settings", None) or st
    version = lambda: getattr(st, "version", 0)                # noqa: E731
    svc_version = lambda: getattr(svc_st, "version", 0)        # noqa: E731
    out["spikes"] = spike_notice.install(app, {
        "platforms": {
            "comms": {"sources": lambda: core["registry"].get(), "signature": store.signature,
                      "fetch": store._fetch_collection, "loaded": _held(store, version), "version": version,
                      # as the map keeps an event: its source or its destination host in the constituency (asked at
                      # every count, so a constituency set later applies at once)
                      "in_scope": lambda e: not getattr(st, "restricted", False) or st.in_scope(e.get("src_asn"), e.get("src_ip"))
                      or st.in_scope(e.get("dst_asn"), e.get("dst_ip")),
                      "by_infection": True},
            "services": {"sources": lambda: core["svc"]["registry"].get(), "signature": svc_store.signature,
                         "fetch": svc_store._fetch, "loaded": _held(svc_store, svc_version), "version": svc_version,
                         "in_scope": lambda e: not getattr(svc_st, "restricted", False) or svc_st.in_scope(e.get("asn"), e.get("ip")),
                         "by_infection": False}},
        "day_of": lambda platform: core["day_start"](core["replay_now"]()),
        "has_perm": core["AUTH"]["has_perm"], "logger": core.get("app_logger")})

    # Settings → Configuration: every non-secret setting, the tuning ones editable (config_page.py; applied at start
    # by gunicorn.conf.py)
    import os
    import config_page
    A = core["AUTH"]
    if all(k in A for k in ("has_perm", "csrf_ok", "fresh", "audit")):     # the platform always; a check's cut-down core not
        out["config"] = config_page.install(app, {"base_dir": os.path.dirname(os.path.abspath(__file__)), "has_perm": A["has_perm"],
                                                   "csrf_ok": A["csrf_ok"], "fresh": A["fresh"], "audit": A["audit"]})

    # the Findings pages keep up on their own: a fingerprint of what each person sees, asked every 15 s
    # (findings_live.py, static/js/findings-live.js)
    if core.get("findings") is not None and "has_perm" in A:
        import findings_live
        out["findings_live"] = findings_live.install(app, {"findings": core["findings"], "has_perm": A["has_perm"]})

    # the PDFs' References section (pdf_refs.py): the analysis and Executive reports order their names by the severity
    # Shadowserver gave the records of the days in memory, of their platform
    import pdf_refs
    pdf_refs.DAYS.update(comms=lambda: list(store.days.values()), services=lambda: list(svc_store.days.values()))
    # …and, once, every name's level from all the reports' records, not only the days in memory (name_levels_catchup.py)
    if core.get("db") is not None:
        import name_levels_catchup

        def report_collections():
            regs = [x["name"] for x in (core["registry"].get() or [])] + [x["name"] for x in (core["svc"]["registry"].get() or [])]
            return list(dict.fromkeys(regs))
        out["name_levels"] = name_levels_catchup.install(app, {"db": core["db"], "collections": report_collections,
                                                               "base_dir": os.path.dirname(os.path.abspath(__file__)),
                                                               "logger": core.get("app_logger")})

    # the severity map on the Definitions page: every infection and issue with its criticality, Shadowserver's or, for a
    # name no record rates, a researcher's (severity_map.py; researchers and administrators only)
    if all(k in A for k in ("has_perm", "csrf_ok", "audit")):
        import severity_map
        from people import People
        people_name = People(A["users"]).full_name if "users" in A else None
        out["severity_map"] = severity_map.install(app, {"base_dir": os.path.dirname(os.path.abspath(__file__)),
                                                         "has_perm": A["has_perm"], "csrf_ok": A["csrf_ok"],
                                                         "audit": A["audit"], "people_name": people_name})

    # the insider package (insider.py, the user 2026-11-18): copies recorded before they happen, copies and downloads
    # sealed with keyed fingerprints, Trace a leak in the Audit portal, the person's full name in every header
    if all(k in A for k in ("has_perm", "csrf_ok", "audit")):
        import insider
        out["insider"] = insider.install(app, {"base_dir": os.path.dirname(os.path.abspath(__file__)), "has_perm": A["has_perm"],
                                               "csrf_ok": A["csrf_ok"], "audit": A["audit"], "people_name": people_name})

    # Add a person: one-time sign-up links made on the Admin page (invites.py, the user 2026-11-19); auth.py reads them at
    # sign-up through auth.INVITE
    if all(k in A for k in ("has_perm", "csrf_ok", "fresh", "audit", "roles")):
        import auth as _auth
        import invites
        out["invites"] = invites.install(app, {"base_dir": os.path.dirname(os.path.abspath(__file__)), "has_perm": A["has_perm"],
                                               "csrf_ok": A["csrf_ok"], "fresh": A["fresh"], "audit": A["audit"],
                                               "roles": lambda: sorted(A["roles"].roles), "perms_of": A["roles"].perms,
                                               "hook": _auth.INVITE,
                                               "people_name": people_name if "users" in A else None})

    # what someone not signed in can learn about the server: as little as possible (neutral.py, anti-fingerprinting):
    # plain status lines and error pages, neutral file tags, a short policy before sign-in, /healthz for this computer
    # only, the sign-in pages' logo as an administrator chooses it (the organisation's by default)
    if all(k in A for k in ("has_perm", "csrf_ok", "fresh", "audit")):
        import neutral
        from organisation import Organisation
        base = os.path.dirname(os.path.abspath(__file__))
        out["neutral"] = neutral.install(app, {"base_dir": base, "has_perm": A["has_perm"], "csrf_ok": A["csrf_ok"],
                                               "fresh": A["fresh"], "audit": A["audit"],
                                               "org": Organisation(os.path.join(base, "data", "organisation.json"))})

    # right after signing in: the dive into the globe, the logo, then the page (signin_welcome.py, the user 2026-11-19);
    # behind the sign-in, so nobody signed out sees the product's logo
    import signin_welcome
    from auth import _safe_next
    out["signin_welcome"] = signin_welcome.install(app, {"safe_next": _safe_next})

    # Settings → Constituency: pick address blocks (/24) from the reports, with their records and network
    # (address_blocks.py, the user 2026-11-19); counted by both day loaders before the constituency
    if "has_perm" in A and core.get("asns") is not None:
        import address_blocks
        asns = core["asns"]

        def blocks_days():
            start = core["day_start"](core["replay_now"]())
            return [d for d in (store.days.get(start), svc_store.days.get(start)) if d is not None]
        out["address_blocks"] = address_blocks.install(app, {
            "has_perm": A["has_perm"], "settings": st, "days": blocks_days,
            "company": lambda asn: asns.company(asn, False), "day": lambda: core["day_start"](core["replay_now"]()).date().isoformat()})

    # the analyst codes' device counts worked out ahead after a start, so the Findings page does not wait for them
    # (acode_warm.py; only in the running service)
    if core.get("acodes") is not None:
        import acode_warm
        out["acode_warm"] = acode_warm.install(app, {"acodes": core["acodes"], "logger": core.get("app_logger")})

    return out
