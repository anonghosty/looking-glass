"""New features install themselves here, so app.py does not keep growing (the user, 2026-11-16).

app.py calls install(app, core) once, at the end, with the platform's shared parts. A new feature lives in its own
module with its own install(app, ctx), and gets one entry below, built from `core`. Nothing else in app.py changes.

core: db (the reports database, read only), registry (the communications reports), svc (the services platform: its
"registry" and "store"), replay_now(), day_start(dt), AUTH (has_perm, csrf_ok, audit, ...), app_logger.
Returns {name: what each feature's install returned}, for tests and for other modules.
"""


def install(app, core):
    out = {}

    # the spike notice on the Overview's buttons: the latest report day against the day before (spike_notice.py)
    import spike_notice
    out["spikes"] = spike_notice.install(app, {
        "db": core["db"],
        "comms_sources": lambda: core["registry"].get(),
        "svc_sources": lambda: core["svc"]["registry"].get(),
        "day_of": lambda platform: core["day_start"](core["replay_now"]()),
        "has_perm": core["AUTH"]["has_perm"]})

    return out
