# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""Drop-down counts that follow the other filters (the user, 2026-11-19: "when i filter from other sections the
numbers should reflect everywhere including the dropdowns so its easier to drill down more than guess").

Faceted search: each filter's choices are counted over the records that match every OTHER filter, so a filter's own
choice never hides its alternatives (pick one city: the other cities still show how many records they would give),
while every other filter narrows its counts.

One pass over the day's records: a record that fails no filter counts for every field; a record that fails exactly one
filter counts only for that filter's own field; a record that fails two or more counts nowhere.

pools(events, flt, value) -> Pools; Pools.of(field) gives the records to count that field's choices over. value(ev,
field) gives a record's value for a filter; or pass test=(ev, field, vals) -> bool where a filter is not a plain
"value in vals" (the services platform: tags and issues are lists, masked banners).

overlap(pool, name, device) -> rows: the map's infection list while infections are ticked: how many of the matching
devices also carry each infection (2026-11-20). carriers(events, name, device, values) -> the devices carrying every
one of the ticked infections (two or more ticked narrow to those devices).
"""


class Pools:
    def __init__(self, passed, missed, total):
        self.passed = passed          # records matching every filter
        self.missed = missed          # field -> records failing that filter only
        self.total = total            # records matching every filter (len(passed))

    def of(self, field):
        """The records a field's choices are counted over: those matching every filter but (possibly) this one."""
        extra = self.missed.get(field)
        return self.passed + extra if extra else self.passed


def pools(events, flt, value=None, test=None):
    """events: the day's records; flt: {field: set(values)} (app.parse_filters); value(ev, field): a record's value
    for a filter field (the stored field, or a computed one such as the decoded beacon's label); or test(ev, field,
    vals): whether the record passes that one filter."""
    if not flt:
        return Pools(events, {}, len(events))
    if test is None:
        test = lambda ev, f, vals: value(ev, f) in vals        # noqa: E731
    passed, missed = [], {f: [] for f in flt}
    items = list(flt.items())
    for ev in events:
        failed = None
        for f, vals in items:
            if not test(ev, f, vals):
                if failed is not None:        # a second filter fails: counted nowhere
                    failed = False
                    break
                failed = f
        if failed is None:
            passed.append(ev)
        elif failed:
            missed[failed].append(ev)
    return Pools(passed, missed, len(passed))


def carriers(events, name, device, values):
    """The devices with records of every one of `values` (the user, 2026-11-20: two infections ticked "narrow to
    devices carrying both"). -> set of devices"""
    want = set(values)
    have = {}
    for e in events:
        n = name(e)
        if n in want:
            d = device(e)
            if d:
                have.setdefault(d, set()).add(n)
    return {d for d, s in have.items() if s >= want}


def overlap(pool, name, device, field="infection", limit=300):
    """A list filter with its own choice ticked, counted as what else the matching devices carry (the user, 2026-11-20:
    "when i filter it doesnt reflect on the other infections"; chose "overlap counts").

    The matching devices are the devices (device(ev)) of the records that pass every filter. Each choice of the field
    (name(ev)) is counted as how many of those devices also have a record with it (among the records every OTHER filter
    lets through), so the ticked choices count their own devices and the rest how many of them they share. A choice
    none of them carries stays listed with 0, so it can still be ticked. Most first, then by name.
    -> [{"value", "count"}]"""
    devices = {device(e) for e in pool.passed if device(e)}
    pairs, names = set(), set()
    for e in pool.of(field):
        n = name(e)
        if not n:
            continue
        names.add(n)
        d = device(e)
        if d in devices:
            pairs.add((n, d))
    counts = {}
    for n, _ in pairs:
        counts[n] = counts.get(n, 0) + 1
    rows = sorted(({"value": n, "count": counts.get(n, 0)} for n in names), key=lambda r: (-r["count"], r["value"].lower()))
    return rows[:limit]
