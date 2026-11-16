"""Shadowserver report file names, read for people (the user, 2026-11-15: held-back reports are listed by their
Shadowserver file names, so an administrator sees exactly which reports they are about to process).

Shadowserver names every report file the same way: the day, the report, then the recipient and the kind of list,
for example 2026-11-15-scan_http-ghana-geo.csv (an e-mail attachment may be the same name zipped: .csv.zip or .zip).
The report part is lowercase letters, digits and underscores, as the pipeline requires (database/report_names.py).
A file named any other way did not come from Shadowserver's report service as it is: it is shown, but flagged.

parse(name, labels=None) -> {"file", "date", "report", "label", "shadowserver"}
"""
import re

NAME = re.compile(r"^(?P<date>\d{4}-\d{2}-\d{2})-(?P<report>[a-z0-9][a-z0-9_]{0,63})-(?P<rest>[A-Za-z0-9_.-]+?)"
                  r"\.(?:csv|csv\.zip|zip)$")


def parse(name, labels=None):
    """What a report file name says. labels: {report name: readable name} (the report registry), so an administrator
    reads "Accessible HTTP" rather than scan_http; without one, the report name itself."""
    name = str(name or "")[:255]
    m = NAME.match(name)
    if not m:
        return {"file": name, "date": "", "report": "", "label": "", "shadowserver": False}
    report = m.group("report")
    label = (labels or {}).get(report) or report
    return {"file": name, "date": m.group("date"), "report": report, "label": label, "shadowserver": True}
