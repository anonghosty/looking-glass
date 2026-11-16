"""Made-up CLogin check-ins for the beacon tests (check_beacon_decode.py, check_beacon_findings.py): every device value
is invented here and encoded the way the sinkhole data shows the check-in is encoded. No real victim data."""
import base64
import json
import random

rnd = random.Random(20261115)
TRAILER = "".join(rnd.choice("0123456789abcdef") for _ in range(52))     # as long as the trailers seen (46-52)


def made_up(i=0, os_name="windows", operator="zckypc", version="zckypc:4.4.3"):
    """A made-up check-in: every device value invented here."""
    h = lambda n: "".join(rnd.choice("0123456789abcdef") for _ in range(n))   # noqa: E731
    return {"operator": operator, "os": os_name, "cpumd5": h(32), "cpu": "Windows 7 Ultimate" if os_name == "windows" else "ARMv8",
            "cpuid": "GenuineIntel".encode().hex(), "mem": str(2048 + i), "mac": "00:ff:" + ":".join(h(2) for _ in range(4)),
            "version": version, "spare1": f"{h(8)}-{h(4)}-{h(4)}-{h(4)}-{h(12)}", "bandwidth": "0", "spare2": "", "spare3": "",
            "spare4": "", "spare5": ""}


def encode(obj, key, trailer=TRAILER):
    """Base64 text of the JSON, then the trailer (hex characters XORed with 0x72), both under the repeating key, then
    Base64."""
    mid = base64.b64encode(json.dumps(obj, separators=(",", ":")).encode()) + bytes(b ^ 0x72 for b in trailer.encode())
    x = bytes(b ^ key.encode()[i % len(key)] for i, b in enumerate(mid))
    return base64.b64encode(x).decode()


def rkey():
    return "".join(rnd.choice("0123456789abcdef") for _ in range(32))


def line(blob, path="/CLogin", param="key"):
    return f"GET {path}?{param}={blob} HTTP/1.1"
