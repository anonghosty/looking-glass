"""The one-time setup code for the first administrator.

While no administrator exists, the first account created on this computer becomes one. "This computer" alone is not
enough proof: a reverse proxy set up wrongly can make every visitor look local. So the first administrator must also
type a setup code that only someone with access to the server can read: it is written to data/setup_code (mode 600)
when the app starts with no administrator, shown by the installer as a command to read it, and deleted as soon as an
administrator exists. It is never logged and never shown in a page.

SetupCode(data_dir).sync(no_admin) -> creates or removes the file.  .matches(text) -> bool (constant time).
"""
import hmac
import os
import secrets

ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"     # no 0/O, 1/I: read off a terminal and typed by hand


def _new():
    raw = "".join(secrets.choice(ALPHABET) for _ in range(16))       # 80 bits
    return "-".join(raw[i:i + 4] for i in range(0, 16, 4))


def _norm(text):
    return "".join(c for c in (text or "").upper() if c.isalnum())


class SetupCode:
    def __init__(self, data_dir):
        self.path = os.path.join(data_dir, "setup_code")

    def sync(self, no_admin):
        """No administrator: make sure a code exists. An administrator exists: the code is gone."""
        if not no_admin:
            self.discard()
            return
        if os.path.exists(self.path):
            return
        try:
            fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:            # another worker made it at the same moment
            return
        with os.fdopen(fd, "w") as f:
            f.write(_new() + "\n")

    def read(self):
        try:
            with open(self.path) as f:
                return f.read().strip()
        except OSError:
            return ""

    def matches(self, text):
        code = _norm(self.read())
        return bool(code) and hmac.compare_digest(code.encode(), _norm(text).encode())

    def discard(self):
        try:
            os.remove(self.path)
        except FileNotFoundError:
            pass
