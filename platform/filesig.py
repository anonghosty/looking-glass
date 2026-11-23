# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""The one way Looking Glass tells whether a file it keeps in memory has changed (2026-11-23).

A file's modification time alone is not enough: Linux moves it in coarse ticks (a few milliseconds), so a file written
twice within one tick keeps the same time and a cache keyed on it would keep the old contents (tests/check_cov_lookups.py
failed this way on a fast server). The signature adds the time in nanoseconds, the size and the file's inode (a file
replaced by os.replace gets a new one), so a change is seen even within the same tick.

sig(path) raises OSError for a missing file, exactly as os.path.getmtime did, so the callers' handling is unchanged.
Use it only to compare (==, !=); for an age or a date, use the modification time itself."""
import os


def sig(path):
    """(modification time in ns, size, inode) of the file at path; OSError when it is missing."""
    s = os.stat(path)
    return (s.st_mtime_ns, s.st_size, s.st_ino)
