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
