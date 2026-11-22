# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""For checks that drive the advisory routes with a made-up finding: give that finding what a real one has, its devices
kept with it and a report that comes back as the advisory PDF AND its devices CSV (the rule, 2026-11-18: Generate report
always gives both; a finding that keeps no devices is refused). Not a test on its own.
    restore = keep_devices(A.COMBOS, "1") ... restore()
The advisory is then for the finding's one organisation (organisation(A)), never "all networks"."""
import io
import zipfile


ASN = "64500"


def organisation(app_module):
    """The organisation the made-up kept record is in, named as advisory.py names it (asn_registry, else Unknown)."""
    return app_module.asn_registry.company(ASN, False) or "Unknown"


def keep_devices(book, fid="1"):
    names = ("review_kept", "review_records", "review_report_of")
    saved = {n: getattr(book, n, None) for n in names}

    def kept(f):
        return str(f) == fid or bool(saved["review_kept"] and saved["review_kept"](f))

    def records(f):
        if str(f) == fid:
            # one made-up kept record (a documentation address, a private AS number): the finding then has one
            # organisation to write the advisory for, as a real one does; the check's own fixtures fill in the rest
            return {"entry": {"section": "services", "name": "scan_rdp", "code": "LG-C-00000000", "kind": "c"},
                    "found": [{"ip": "192.0.2.1", "asn": ASN, "report": "scan_rdp", "port": 3389}]}, ""
        return saved["review_records"](f)

    def report_of(f, user, a, network=None, file_base="report", asns=None):
        if str(f) != fid:
            return saved["review_report_of"](f, user, a, network=network, file_base=file_base, asns=asns)
        import advisory_pdf
        pdf = advisory_pdf.alone(dict(a), {"platform_label": "Advisory", "scope": "s", "header": a.get("header") or "h",
                                           "selection": "s", "day": "", "generated_by": user})
        z = io.BytesIO()
        with zipfile.ZipFile(z, "w") as zf:
            zf.writestr(f"{file_base}.pdf", pdf)
            zf.writestr(f"{file_base}_devices.csv", "ip,host_name,ports\n192.0.2.1,,3389\n")
        return (f"{file_base}.zip", z.getvalue(), f"{file_base}.pdf", pdf), ""

    book.review_kept, book.review_records, book.review_report_of = kept, records, report_of

    def restore():
        for n in names:
            if saved[n] is None:
                if hasattr(book, n):
                    delattr(book, n)
            else:
                setattr(book, n, saved[n])
    return restore
