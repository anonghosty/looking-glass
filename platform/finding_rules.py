"""Who may move a finding, and where (external review, 2026-11-11).

Before, POST /api/findings/<id>/status took any status from anyone in the finding's channel: a researcher could send
their own finding straight to an advisor, and the advisory page took "it was with an advisor once" as management's
approval. The audit log showed it, but nothing stopped it. The rules now:

* Moving a finding by hand (the "Move it on" bar) is management's (or an administrator's). Everyone else moves a finding
  by its own steps: sending it to a manager, an analyst's request, a researcher's reply, an advisory marked as sent.
* Even management only moves an OPEN finding, never to "Approved" (that is the Decide step) and never to "Advisory sent"
  (that is the advisory itself).
* "No combination of interest" closes a request only for the researcher it was sent to, while it waits for them.
* A review management has not decided is decided only while it is open.
* An advisory may be written only after a real approval by management: a decision recorded as accepted, or a hand-over
  to the advisor made by management or an administrator.
"""

HAND_MOVES = {"management", "researcher", "analyst", "advisor", "closed"}   # where "Move it on" may send a finding
MANAGER_ROLES = {"management", "admin"}        # history entries made before the step recorded `approval`

NOT_YOURS = ("Findings move by their own steps (sent to a manager, a decision, a reply, an advisory sent); "
             "moving one by hand is for management or an administrator.")


def can_move(item, status, is_manager, open_statuses):
    """"" when this person may move `item` to `status` by hand; else the reason."""
    if not is_manager:
        return NOT_YOURS
    if item.get("status") not in open_statuses:
        return "This finding is closed: it is not moved on any more."
    if status == "approved":
        return "Approving is a decision: use Decide (approve with your comment)."
    if status == "advisory":
        return "“Advisory sent” is set when the advisor marks the advisory as sent."
    if status not in HAND_MOVES:
        return "Unknown status."
    return ""


def can_close_none_found(item, user):
    """"" when `user` may answer "no combination of interest" and close the request; else the reason."""
    if item.get("origin") != "analyst" or item.get("status") != "researcher":
        return "“No combination of interest” answers an analyst's request while it waits for a researcher."
    if user == item.get("user") or user != item.get("assignee"):
        return "Only the researcher the request was sent to can close it this way."
    return ""


def management_approved(item):
    """True when management approved this finding for an advisory: an accepted decision in its history, or a
    hand-over to the advisor made by management (or an administrator)."""
    for h in item.get("history") or []:
        if h.get("kind") == "decision" and h.get("decision") == "accepted":
            return True
        if h.get("status") == "advisor" and not h.get("kind") and (h.get("approval") or h.get("role") in MANAGER_ROLES):
            return True
    return False
