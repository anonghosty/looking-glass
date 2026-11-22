# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""The one sentence Looking Glass shows wherever it links reports by device (external review follow-up, 2026-11-14).

Shadowserver reports devices by IP address, and Looking Glass follows a device from one report to another by that
address: Across reports (Combinations, an analyst code's page), the Executive portal's "Devices in two reports" and
cross-report cards, and the Executive and advisory PDFs. One address can sometimes be several devices behind it, so
those places say so. The pages take the same text from static/js/loader.js (LG_DEVICE_NOTE);
tests/check_device_note.py keeps the two equal and checks every place shows it."""

DEVICE_IP_NOTE = ("Devices are matched by IP address, as Shadowserver reports them: one address can sometimes be several "
                  "devices (NAT, shared mobile connections).")
