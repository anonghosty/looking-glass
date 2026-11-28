# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""Shared by the checks with a maintainer's part that reads PDFs (2026-11-26). Not a check itself.

pypdfium2 is a test tool, never one of the platform's libraries (requirements.txt, the locks): the platform's .venv
does not have it. The maintainer's machines keep it in ~/lg-shots/venv (with Playwright); GitHub's checks install it
into the Python that runs them. find_pypdfium2() makes it importable from there, put at the END of sys.path, so the
platform's own locked libraries are always the ones imported first; only a copy built for this same Python is used."""
import glob
import os
import sys


def find_pypdfium2():
    """The pypdfium2 module, or None when this machine has none for this Python."""
    try:
        import pypdfium2
        return pypdfium2
    except ImportError:
        pass
    ver = f"python{sys.version_info.major}.{sys.version_info.minor}"
    for site in sorted(glob.glob(os.path.expanduser(f"~/lg-shots/venv/lib/{ver}/site-packages"))):
        if os.path.isdir(os.path.join(site, "pypdfium2")) and site not in sys.path:
            sys.path.append(site)
    try:
        import pypdfium2
        return pypdfium2
    except ImportError:
        return None
