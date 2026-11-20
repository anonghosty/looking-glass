"""Beacon decoder: encoded C2 check-ins inside the HTTP request a sinkhole report carries.

Some bots put everything they know about the machine into one query value of their check-in (the "beacon"), encoded
so it does not read as text. Shadowserver's Sinkhole HTTP report keeps the request line, so the beacon is in the
record's http_url. This module finds candidate strings in the query values, tries the known beacon formats on them and,
when one fits, returns what the beacon says.

The first format, the CLogin check-in (filed as android.badbox2: "GET /CLogin?key=<Base64> HTTP/1.1", User-Agent
"Lingjiang"; operators zckypc, WT, PKS and HTM seen), has these layers, outer to inner:

    Base64  ->  repeating-key XOR with a 32-character ASCII hex key (a new key per check-in)
            ->  Base64 text of the JSON, then a trailer (a hex string, each character XORed with 0x72)

The key is not sent with the beacon, but it can be recovered from the beacon alone: the plaintext of the XOR layer is
Base64 text and the key is hex text, so for each key position only a few hex characters map every ciphertext byte of
that column into the Base64 alphabet (judged up to the trailer, which is not Base64: boundary_columns). Base64 works in
groups of 4 characters and the key length is a multiple of 4, so the few choices left are settled per 4-character group
of the key, by scoring the bytes they decode to as JSON-like text, then against the whole text (valid JSON, the
format's field names, hex values that stay hex).

Other request families in the sinkhole reports cannot be decoded from the request alone (encrypted with a key the app
keeps, a one-way hash, an opaque device ID). They are in OPAQUE: recognised and named for analysts ("seen, not
decoded"), masked like a beacon in every masked view.

Everything here is a pure function: no network, no files, input length and time bounded (MAX_URL, MAX_BLOB,
TIME_BUDGET), results cached by the request line. Who sees what is decided by the callers:

* analysts and admins (who see hosts): decode() / api_decode(), the whole JSON, the key and the notes;
* researchers and every masked view: public() and mask_url() only. The MAC, hardware UUID, cpuid, cpumd5 and memory
  identify one device and never leave the server for them; intel.py shows the beacon kinds (KINDS) only when
  MIN_HOSTS (5) or more devices carry a value.

Installed from app.py: beacon_decode.install(app, ctx) adds POST /api/beacon/decode (analysts and admins).
"""
import base64
import binascii
import collections
import json
import re
import threading
import time
import urllib.parse
import zlib

MAX_URL = 16384            # a request line longer than this is not looked at
MAX_BLOB = 8192            # nor a query value longer than this
MIN_BLOB = 40              # shorter values are ids and tokens, not beacons
MAX_CANDIDATES = 4         # query values tried per request line
TIME_BUDGET = 0.25         # seconds per request line, all formats together: of this thread's own work (_now)
# the budget counts the decoding thread's CPU time, not the clock: on a busy server (the warm-up after a reload, several
# people at once) a decode waits for the others, and that wait used to use up its budget, so a check-in that decodes in
# 20 ms was reported "did not decode" (2026-11-17: two CLogin records)
_now = time.thread_time
MAX_COMBOS = 4096          # key choices scored per 4-character group; more than this and the format does not fit

B64_CHARS = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
B64_SET = frozenset(B64_CHARS + b"=")
SEXTET = {c: i for i, c in enumerate(B64_CHARS)}
# bytes JSON text is made of: letters, digits, quotes, separators, brackets, space
JSONISH = frozenset(b'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"{}[]:,._- ')

# the indicator kinds intel.py adds to Intel gathered for a decoded beacon (all threat-side, shown to researchers only
# when 5 or more devices carry the value). Not the XOR key: the CLogin check-in draws a new key for every check-in, so
# a key is never shared and says nothing across records; it stays in the analysts' view of each record.
KINDS = ("Beacon format", "Beacon operator", "Beacon version", "Beacon OS")
FIELD_OF_KIND = {"Beacon format": "format", "Beacon operator": "operator", "Beacon version": "version",
                 "Beacon OS": "os_family"}
# what identifies one device: never in public(), never in a masked view
DEVICE_FIELDS = ("mac", "spare1", "cpuid", "cpumd5", "mem")


class Format:
    """One known beacon format: where it is (path, query parameter), how it is encoded, what its JSON must carry."""

    def __init__(self, name, title, path, params, key_len, key_alphabet, trailer_xor, required, describe, vocab=(),
                 known_start=b""):
        self.name, self.title = name, title
        self.known_start = known_start             # how the JSON always starts (known_start_key), b"" when it varies
        self.path = re.compile(path, re.I)
        self.params = {p.lower() for p in params}
        self.key_len, self.key_alphabet, self.trailer_xor = key_len, key_alphabet, trailer_xor
        self.required = required
        self.vocab = frozenset(x for group in required for x in group) | frozenset(vocab)
        self.describe = describe

    def at(self, path, param):
        """The request is where this format is expected (the format is still tried elsewhere)."""
        return bool(self.path.search(path or "")) and (param or "").lower() in self.params


# ---------------------------------------------------------------- the notes analysts get

# MAC prefixes of virtual adapters: a beacon from one of these is a VPN client, a virtual machine or a sandbox
MAC_NOTES = (
    ("00:ff:", "a TAP-Windows virtual adapter (OpenVPN and other VPN clients): not a physical network card; the machine "
               "may sit behind a VPN"),
    ("08:00:27:", "a VirtualBox virtual machine"),
    ("00:0c:29:", "a VMware virtual machine"), ("00:50:56:", "a VMware virtual machine"), ("00:05:69:", "a VMware virtual machine"),
    ("00:15:5d:", "a Hyper-V virtual machine"), ("52:54:00:", "a QEMU/KVM virtual machine"), ("00:16:3e:", "a Xen virtual machine"),
)


def _mac_note(mac):
    m = re.sub(r"[^0-9a-f]", "", str(mac or "").lower())
    if len(m) != 12:
        return ""
    norm = ":".join(m[i:i + 2] for i in range(0, 12, 2))
    for prefix, what in MAC_NOTES:
        if norm.startswith(prefix):
            return f"MAC prefix {prefix.rstrip(':').upper()}: {what}."
    return ""


def _hex_ascii(v):
    """A hex string that spells printable ASCII, as that text ("" when it does not)."""
    s = str(v or "").strip()
    if len(s) < 2 or len(s) % 2 or not re.fullmatch(r"[0-9a-fA-F]+", s):
        return ""
    try:
        t = bytes.fromhex(s).decode("ascii")
    except (ValueError, UnicodeDecodeError):
        return ""
    t = t.strip("\x00 ")
    return t if t and all(32 <= ord(c) < 127 for c in t) else ""


def os_family(text):
    """'Windows 7 Ultimate' -> 'windows'; '' when it says nothing known."""
    s = str(text or "").lower()
    for fam, rx in (("android", r"android"), ("windows", r"\bwin(dows|32|64|\b)"), ("ios", r"\b(ios|iphone|ipad)\b"),
                    ("macos", r"\b(mac ?os|os ?x|darwin)\b"), ("linux", r"\b(linux|ubuntu|debian|centos)\b")):
        if re.search(rx, s):
            return fam
    return ""


# the operating system a malware name points to: its parts ("android.badbox2" -> android), or a family known to run on
# one system only
NAME_OS = (
    ("android", re.compile(r"(^|[._\-\s/])(android|andr|badbox\d*|triada|hiddad|joker|vo1d|pandoraspy)([._\-\s/]|\d|$)", re.I)),
    ("windows", re.compile(r"(^|[._\-\s/])(win|win32|win64|windows|msil)([._\-\s/]|$)", re.I)),
    ("linux", re.compile(r"(^|[._\-\s/])(linux|elf)([._\-\s/]|$)", re.I)),
    ("macos", re.compile(r"(^|[._\-\s/])(osx|macos)([._\-\s/]|$)", re.I)),
    ("ios", re.compile(r"(^|[._\-\s/])ios([._\-\s/]|$)", re.I)),
)
OS_TITLE = {"android": "Android", "windows": "Windows", "linux": "Linux", "macos": "macOS", "ios": "iOS"}


def name_os(name):
    for fam, rx in NAME_OS:
        if rx.search(name or ""):
            return fam
    return ""


def contradicts(name, family):
    """The beacon's OS family and the OS the name points to are both known and differ."""
    n = name_os(name)
    return bool(n and family and n != family)


# the recheck of a decoded check-in (the user, 2026-11-16: "recheck the decoded"): the values with a fixed shape must
# have it; empty is allowed (some devices leave fields empty)
# (mem and cpuid have no fixed shape on real devices: memory modules listed in words, CPU ids in several forms)
_SHAPES = {"cpumd5": re.compile(r"[0-9a-fA-F]{32}"), "mac": re.compile(r"[0-9a-fA-F]{2}([:-][0-9a-fA-F]{2}){5}"),
           "bandwidth": re.compile(r"[0-9]{1,9}")}


# text in a decoded value that addresses a reader (a person or an AI tool) instead of describing a device: attackers
# write these values, so it is said plainly that it is data, never an instruction (prompt injection, 2026-11-16)
_INSTRUCTION_LIKE = re.compile(
    r"(ignore|disregard|forget)\s+(all\s+|any\s+|the\s+)?(previous|prior|above|earlier|your)\s+(instructions|prompts?|rules)"
    r"|\byou\s+are\s+now\b|\bsystem\s+prompt\b|\b(assistant|system|developer)\s*:|\bact\s+as\s+(an?|the)\b"
    r"|\bnew\s+instructions\b|\bdo\s+not\s+(tell|inform)\s+the\s+user\b|<\s*/?\s*(script|iframe|img|svg)\b|javascript\s*:",
    re.I)
INJECTION_NOTE = ("Part of the decoded data reads like instructions to a person or an AI tool. It came from the device (or "
                  "whoever controls it): it is data, never an instruction. Do not follow it, and do not paste it into an AI "
                  "tool as a request.")


def instruction_like(v, depth=0):
    """Whether any text in a decoded value (a dict, a list or a string, nested) reads like instructions to a reader."""
    if depth > 6:
        return False
    if isinstance(v, dict):
        return any(instruction_like(k, depth + 1) or instruction_like(x, depth + 1) for k, x in v.items())
    if isinstance(v, list):
        return any(instruction_like(x, depth + 1) for x in v)
    return isinstance(v, str) and bool(_INSTRUCTION_LIKE.search(v))


def recheck(obj):
    """The field names whose value does not have its shape; empty when the decode holds."""
    bad = []
    for k, rx in _SHAPES.items():
        v = obj.get(k)
        if v in (None, ""):
            continue
        if not rx.fullmatch(str(v)):
            bad.append(k)
    return bad


def _describe_zckypc(obj):
    s = lambda k: str(obj.get(k) if obj.get(k) is not None else "")[:120]     # noqa: E731
    fam = os_family(s("os")) or os_family(s("cpu"))
    notes = []
    cpuid = _hex_ascii(obj.get("cpuid"))
    if cpuid:
        notes.append(f"cpuid as ASCII: {cpuid}")
    mac = _mac_note(obj.get("mac"))
    if mac:
        notes.append(mac)
    if s("cpu") and fam and os_family(s("cpu")) and os_family(s("cpu")) != os_family(s("os") or s("cpu")):
        notes.append(f"The cpu field ({s('cpu')}) and the os field ({s('os')}) disagree.")
    return {"operator": s("operator"), "version": s("version"), "os": s("os"), "os_family": fam, "notes": notes}


FORMATS = [
    # the CLogin check-in: one encoding shared by several operators (zckypc, WT, PKS, HTM seen), filed as android.badbox2
    Format(name="clogin", title="CLogin check-in", path=r"/clogin/?$", params=("key",), key_len=32,
           key_alphabet=b"0123456789abcdef", trailer_xor=0x72,
           required=({"operator", "version"}, {"cpuid", "cpumd5", "mac", "spare1"}), describe=_describe_zckypc,
           vocab=("os", "cpu", "mem", "bandwidth", "spare2", "spare3", "spare4", "spare5"),
           known_start=b'{"operator":"'),
]


class Opaque:
    """A request family seen in the sinkhole reports whose value cannot be decoded from the request alone (encrypted
    with a key the app keeps, a one-way hash, an opaque ID): recognised, named, masked like a beacon, never decoded."""

    def __init__(self, name, title, host, path, params, what, state="unknown"):
        self.name, self.title, self.what, self.state = name, title, what, state
        self.host, self.path = re.compile(host, re.I), re.compile(path, re.I)
        self.params = {p.lower() for p in params}

    def at(self, path, param, host=None):
        return bool(self.path.search(path or "")) and (param or "").lower() in self.params and \
            (host is None or bool(self.host.search(host or "")))


# what a family's value is, in words (STATUS[state] = (short, long)): the short one follows the family's title (filter,
# Intel gathered), the long one is the Decoded beacons list's Status column
STATUS = {
    "decoded": ("decoded", "Decoded"),
    "encrypted": ("encrypted", "Encoded, cannot be decoded: encrypted with a key the app keeps"),
    "hash": ("one-way hash, not encoded", "Not encoded: a one-way hash, which cannot be reversed"),
    "id": ("device ID, not encoded", "Not encoded: an ID, with nothing in it to decode"),
    "token": ("campaign token, not encoded", "Not encoded: a campaign token, the same on every device"),
    "unknown": ("not decoded yet", "Encoded, not decoded yet"),
    "cut": ("did not decode", "Encoded in a known format, but this value did not decode (cut short, or a new variant)"),
}


def status_text(state, long=False):
    s = STATUS.get(state) or STATUS["unknown"]
    return s[1] if long else s[0]


_BLOCKS = ("whole 16-byte blocks of random-looking bytes: a block cipher (AES-like) with a key kept in the app, not in "
           "the request")
OPAQUE = [
    Opaque("ttyunos", "ttyunos API request", r"ttyunos\.com$", r"/api/(desk/getdata|language/getlist)$", ("a", "b"), _BLOCKS,
           "encrypted"),
    Opaque("weatherlive", "weatherlive widget configuration request", r"weatherlive\.world$", r"/br_(upgrade|splash)/",
           ("scsl",), _BLOCKS, "encrypted"),
    Opaque("adoverocean", "adoverocean OTA task request", r"adoverocean\.com$", r"/ota/api/tasks/v2$", ("m",),
           "32 hex characters: a hash (MD5-sized) of a device value; one-way, it cannot be decoded", "hash"),
    Opaque("pixellog", "pixellog device registration", r"pixellog\.io$", r"/regdev$", ("userid",),
           "27 random-looking bytes (URL-safe Base64): an opaque per-device ID", "id"),
    Opaque("clickby", "clickby statistics request", r"clickby\.net$", r"/s2?\.php$", ("d",),
           "the same value on every record seen: a campaign token, not device data", "token"),
    # a device check-in POSTed by android.badbox2 apps (u.php; pic.php with two more fields): the device's own values travel
    # in the other parameters (names such as emc / wmc, which read as the Ethernet and Wi-Fi MAC, sdk, aid), already masked;
    # p is a few short random-looking values, each shared by many devices, with no text under XOR: a token (the creator's
    # request to automate it, 2026-11-17; structure only was read)
    Opaque("sustat", "sustat statistics request", r"(sustat|dqmop)\.com$", r"/(u|pic)\.php$", ("p",),
           "a few short random-looking values, each shared by many devices: a campaign token, not device data (the "
           "device's details travel in the request's other parameters)", "token"),
    Opaque("plugcallinfo", "plugcallinfo terminal request", r"(ycxrl|apotube)\.com$", r"/terminal/client/plugcallinfo$", ("key",),
           _BLOCKS, "encrypted"),
    Opaque("flyermobi", "flyermobi ad SDK device ID", r"flyermobi\.com$", r"/(adbs?c|dzzb)$", ("udid",),
           "20 bytes as hex: a device ID (hash-sized), the same on every call of one device: not encoded", "id"),
]


# ---------------------------------------------------------------- finding the candidates

_TARGET = re.compile(r"^\s*(?:[A-Z]{3,8}\s+)?(\S+)")
_PREFILTER = re.compile(r"[?&;][^=&\s]{1,40}=[A-Za-z0-9+/%=_-]{" + str(MIN_BLOB) + ",}")
_BLOB = re.compile(r"[A-Za-z0-9+/_-]+=*")


def candidates(url):
    """[(path, param, value)] for the query values of a request line that could be a beacon (longest first)."""
    url = str(url or "")
    if len(url) > MAX_URL or "=" not in url or not _PREFILTER.search(url):
        return []
    m = _TARGET.match(url)
    if not m:
        return []
    target = m.group(1)
    path, _, query = target.partition("?")
    out = []
    for part in re.split(r"[&;]", query):
        k, eq, v = part.partition("=")
        if not eq:
            continue
        v = urllib.parse.unquote(v).replace(" ", "+")    # '+' may arrive as a space; never unquote_plus
        if MIN_BLOB <= len(v) <= MAX_BLOB and _BLOB.fullmatch(v):
            out.append((path, urllib.parse.unquote(k)[:40], v))
    out.sort(key=lambda x: -len(x[2]))
    return out[:MAX_CANDIDATES]


def _b64(text):
    """Strict Base64 (standard or URL-safe), padding added when it was cut off; None when it is not Base64."""
    if isinstance(text, bytes):
        text = text.decode("ascii", "replace")
    t = text.strip().replace("-", "+").replace("_", "/")
    t += "=" * (-len(t) % 4)
    try:
        return base64.b64decode(t, validate=True)
    except (binascii.Error, ValueError):
        return None


# ---------------------------------------------------------------- the XOR key

def _group_bytes(chunk):
    """Four Base64 characters to their three bytes (fewer with padding); None when they are not valid Base64."""
    if 61 in chunk:                                   # '=' padding: only in the last group
        try:
            return base64.b64decode(bytes(chunk), validate=True)
        except (binascii.Error, ValueError):
            return None
    try:
        a, b, c, d = (SEXTET[x] for x in chunk)
    except KeyError:
        return None
    n = (a << 18) | (b << 12) | (c << 6) | d
    return bytes(((n >> 16) & 255, (n >> 8) & 255, n & 255))


def _score(bs):
    if bs is None:
        return -50
    s = 0
    for b in bs:
        s += 3 if b in JSONISH else 1 if 32 <= b < 127 else -4
    return s


TOP_PER_GROUP = 12         # key choices per group kept for the whole-text pass


def boundary_columns(ct, key_len, alphabet):
    """(end, per key position the key characters that keep ct[:end] in the Base64 alphabet). A trailer after the Base64
    text (zckypc: a hex string XORed with 0x72, under the same key) is not Base64, so each key character is judged up to
    the first byte it cannot map; `end` is the longest stretch every position can keep. None when it is too short."""
    first_bad = []
    for j in range(key_len):
        col = ct[j::key_len]
        per = {}
        for k in alphabet:
            n = 0
            for c in col:
                if (c ^ k) not in B64_SET:
                    break
                n += 1
            per[k] = j + n * key_len               # the first position of ct this key character cannot map
        first_bad.append(per)
    end = min(max(per.values()) for per in first_bad)
    # a wrong key character may map a byte or two of the trailer by chance, so the stretch judged stops three key
    # lengths short of what the best characters reach: well inside the Base64 text
    end = max(key_len * 2, end - 3 * key_len)
    end -= end % 4                                 # whole Base64 groups only
    if end < key_len * 2 or end > len(ct):
        return None
    cols = [[k for k, fb in per.items() if fb >= end] for per in first_bad]
    return (end, cols) if all(cols) else None


def key_choices(ct, key_len, alphabet, deadline):
    """Per 4-character group of the key, the choices that keep every ciphertext byte in the Base64 alphabet, best first
    (scored by how JSON-like the bytes they decode to read); None when no key fits."""
    if key_len % 4 or len(ct) < key_len * 2:
        return None
    cols = boundary_columns(ct, key_len, alphabet)
    if not cols:
        return None
    end, cols = cols
    ct = ct[:end]
    groups = []
    for g in range(key_len // 4):
        if _now() > deadline:
            return None
        opts = cols[4 * g:4 * g + 4]
        if len(opts[0]) * len(opts[1]) * len(opts[2]) * len(opts[3]) > MAX_COMBOS:
            return None
        starts = range(4 * g, len(ct) - 3, key_len)
        ranked = []
        for k0 in opts[0]:
            for k1 in opts[1]:
                for k2 in opts[2]:
                    for k3 in opts[3]:
                        s = 0
                        for i in starts:
                            s += _score(_group_bytes((ct[i] ^ k0, ct[i + 1] ^ k1, ct[i + 2] ^ k2, ct[i + 3] ^ k3)))
                        ranked.append((s, bytes((k0, k1, k2, k3))))
        ranked.sort(key=lambda x: -x[0])
        groups.append([k for _, k in ranked[:TOP_PER_GROUP]])
    return groups


_HEXISH = frozenset("0123456789abcdefABCDEF-:")


def _text_score(inner, vocab):
    """How much a decoded inner layer reads like the format's JSON: valid JSON, its known field names, hex-looking
    values that stay hex (one wrong key character turns '3fa9' into '3fh9' or 'operator' into 'opesator')."""
    if inner is None:
        return -10 ** 9
    s = sum(_score(inner[i:i + 3]) for i in range(0, len(inner), 3))
    text = inner.decode("utf-8", "surrogateescape")
    # each field name of the format read correctly counts, valid JSON or not: one fixed group shows at once even when
    # another is still wrong
    s += 60 * sum(text.count(f'"{v}":') for v in vocab)
    s += 20 * len(re.findall(r'"[a-z0-9_]{1,24}":"', text))
    start = text.find("{")
    if 0 <= start <= 4:
        try:
            obj, _ = json.JSONDecoder().raw_decode(text, start)
        except ValueError:
            obj = None
        if isinstance(obj, dict):
            s += 500 + 100 * len({str(k).lower() for k in obj} & vocab)
            for v in obj.values():
                if isinstance(v, str) and len(v) >= 8 and sum(c in _HEXISH for c in v) >= 0.75 * len(v):
                    s -= 40 * sum(c not in _HEXISH for c in v)
    return s


def recover_key(ct, key_len, alphabet, deadline, vocab=frozenset()):
    """The repeating XOR key that turns ct into Base64 text whose bytes read most like the format's JSON; None when no
    key fits. Each group's best choice first, then each group's other choices tried against the whole text."""
    groups = key_choices(ct, key_len, alphabet, deadline)
    if not groups:
        return None
    key = [g[0] for g in groups]
    score = lambda ks: _text_score(_b64(split_b64(_xor(ct, b"".join(ks)))[0]), vocab)    # noqa: E731
    best = score(key)
    for _ in range(3):                                    # passes: a change in one group can settle another
        changed = False
        for gi, opts in enumerate(groups):
            for alt in opts[1:]:
                if _now() > deadline:
                    return b"".join(key)
                trial = key[:gi] + [alt] + key[gi + 1:]
                s = score(trial)
                if s > best:
                    key, best, changed = trial, s, True
        if not changed:
            break
    return b"".join(key)


def _lenient_inner(ct, key):
    """The inner bytes as far as the Base64 text reads: whole 4-character groups, a stray '=' dropped."""
    t64, _ = split_b64(_xor(ct, key))
    t64 = t64.rstrip(b"=")
    t64 = t64[: len(t64) // 4 * 4]
    try:
        return base64.b64decode(t64) if t64 else None
    except (binascii.Error, ValueError):
        return None


def _json_parses(ct, key):
    inner = _lenient_inner(ct, key)
    if not inner:
        return False
    text = inner.decode("utf-8", "surrogateescape")
    start = text.find("{")
    if start < 0 or start > 4:
        return False
    try:
        json.JSONDecoder().raw_decode(text, start)
        return True
    except ValueError:
        return False


def known_start_key(ct, key, start_text):
    """The key with the characters a known start of the JSON fixes: the Base64 text of start_text is known exactly
    (whole groups only), so ct XOR that text gives those key characters; the others stay as they are."""
    n = (len(start_text) // 3) * 4
    if n == 0 or len(ct) < n:
        return None
    prefix = base64.b64encode(start_text)[:n]
    k = bytearray(key)
    for i in range(min(n, len(k))):
        k[i] = ct[i] ^ prefix[i]
    return bytes(k)


def refine_key(ct, key, alphabet, deadline, vocab=frozenset(), fixed=0, passes=4):
    """Settle the key positions still wrong (2026-11-16: the first recovery missed one character on longer check-ins):
    each position from `fixed` on tried with every character of the alphabet, kept when the whole text reads better
    (the JSON parses first, then _text_score). Stops when the JSON parses, nothing improves, or time runs out."""
    key = bytearray(key)

    def judge(k):
        return (_json_parses(ct, k), _text_score(_lenient_inner(ct, k), vocab))
    best = judge(bytes(key))
    for _ in range(passes):
        if best[0]:
            break
        changed = False
        for j in range(fixed, len(key)):
            keep = key[j]
            for c in alphabet:
                if c == keep:
                    continue
                if _now() > deadline:
                    key[j] = keep
                    return bytes(key)
                key[j] = c
                s = judge(bytes(key))
                if s > best:
                    best, keep, changed = s, c, True
            key[j] = keep
        if not changed:
            break
    return bytes(key)


_B64_RUN = re.compile(rb"[A-Za-z0-9+/]*={0,2}")


def split_b64(pt):
    """(the Base64 text at the start, what follows it): the trailer after the text is not Base64."""
    m = _B64_RUN.match(pt)
    n = m.end()
    if pt[n - 1:n] == b"=" and n % 4:
        # an '=' that cannot be padding (2026-11-20: Base64 text that needs none, then '=' and a hex trailer): it starts
        # the trailer
        n = len(pt[:n].rstrip(b"="))
    if not pt[n - 1:n] == b"=":
        n -= n % 4                                 # unpadded: whole groups only; the rest belongs to the trailer
    return pt[:n], pt[n:]


def _xor(data, key):
    n = len(key)
    return bytes(b ^ key[i % n] for i, b in enumerate(data))


# ---------------------------------------------------------------- one format, one value

def _try(fmt, value, deadline):
    outer = _b64(value)
    if not outer:
        return None
    key = recover_key(outer, fmt.key_len, fmt.key_alphabet, deadline, fmt.vocab)
    if not key:
        return None
    r = _read(fmt, outer, key, lenient=False)
    if r is None and fmt.known_start and _now() < deadline:
        # a key nearly right (2026-11-16: longer check-ins the first recovery misses by a character): the known start
        # of the JSON fixes the first characters exactly, then each other position is settled (refine_key)
        fixed = known_start_key(outer, key, fmt.known_start)
        if fixed and all(c in fmt.key_alphabet for c in fixed):
            r = _read(fmt, outer, refine_key(outer, fixed, fmt.key_alphabet, deadline, fmt.vocab,
                                             fixed=(len(fmt.known_start) // 3) * 4), lenient=True)
    return r


def _read(fmt, outer, key, lenient=False):
    """One value under one key: the beacon, or None. lenient (after the known-start repair only): a stray '=' after the
    Base64 text, or a JSON whose very end fails, is still read."""
    pt = _xor(outer, key)
    text64, after64 = split_b64(pt)
    inner = _b64(text64) or (_lenient_inner(outer, key) if lenient else None)   # a stray '=' (2026-11-16)
    if not inner:
        return None
    text = inner.decode("utf-8", "surrogateescape")
    start = text.find("{")
    if start < 0 or start > 4:
        return None
    cut_note = ""
    try:
        obj, end = json.JSONDecoder().raw_decode(text, start)
    except ValueError as e:
        # only the very end fails (2026-11-16: where the JSON's Base64 meets the trailer): keep the complete fields
        pos = getattr(e, "pos", 0)
        last = text.rfind('","', start, pos)
        if not lenient or pos < 0.8 * len(text) or last < 0:
            return None
        try:
            obj, _ = json.JSONDecoder().raw_decode(text[:last + 1] + "}", start)
        except ValueError:
            return None
        end = last + 1
        cut_note = "The decoded data was cut short in the request: only the complete fields before the cut are shown."
    if not isinstance(obj, dict):
        return None
    keys = {str(k).lower() for k in obj}
    if not all(keys & group for group in fmt.required):
        return None
    # every field name must be one the format knows: a garbled name ("cpumd6", "banawidth") means a key that is not
    # quite right, and such a decode is never shown (2026-11-16)
    if not keys <= fmt.vocab:
        return None
    if recheck({str(k).lower(): v for k, v in obj.items()}):      # a value without its shape: not the right key
        return None
    # the trailer: after the Base64 text of the JSON in the XOR layer (as sent), or after the JSON inside it
    used = len(text[:end].encode("utf-8", "surrogateescape"))
    n64 = -(-used // 3) * 4
    trailer, trailer_kind = "", ""
    if after64[:1] == b"=" and len(after64) > 1 and not lenient:
        # 2026-11-20 (a decoding request from the creator): Base64 text that needs no padding, then '=' and the
        # trailer as it is (not XORed with one byte); a few bytes may follow the JSON inside the Base64 text
        tail = after64[1:].strip(b"\r\n\x00 ")
        trailer = "".join(chr(c) if 32 <= c < 127 else f"\\x{c:02x}" for c in tail)
        trailer_kind = "after '=', as it is" if not re.fullmatch(rb"[0-9a-f]+", tail) else "after '=', plain hex"
    else:
        tail = (pt[n64:].lstrip(b"=") or text[end:].encode("utf-8", "surrogateescape")).strip(b"\r\n\x00 ")
        if tail:
            plain = bytes(b ^ fmt.trailer_xor for b in tail) if fmt.trailer_xor is not None else tail
            if re.fullmatch(rb"[0-9a-fA-F]+", plain):
                trailer = plain.decode("ascii")
                trailer_kind = f"XOR 0x{fmt.trailer_xor:02x}" if fmt.trailer_xor is not None else "hex"
            else:
                trailer, trailer_kind = tail.hex(), "bytes, shown as hex"
    d = fmt.describe(obj)
    notes = list(d.pop("notes", []))
    if instruction_like(obj):
        notes.append(INJECTION_NOTE)
    if cut_note:
        notes.append(cut_note)
        trailer = ""
    elif trailer:
        notes.append(f"Trailer after the JSON ({trailer_kind}): {trailer}")
    return {"format": fmt.name, "title": fmt.title, "key": key.decode("ascii"), "json": obj, "trailer": trailer,
            "notes": notes, **d}


# ---------------------------------------------------------------- the generic fallback

GENERIC_MAX_OUT = 65536      # bytes a decompression may produce
GENERIC_DEPTH = 3            # layers peeled at most (Base64 -> zlib -> text, for example)
_PRINT = frozenset(range(32, 127)) | {9, 10, 13}


def _readable(b):
    """(text, json or None) when the bytes are readable text worth showing: JSON, key=value pairs, or words; else None."""
    if len(b) < 8:
        return None
    try:
        t = b.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if sum(1 for c in b if c in _PRINT or c >= 0x80) < 0.97 * len(b) or sum(1 for c in b if c < 0x80 and c not in _PRINT):
        return None
    s = t.strip()
    if s[:1] in "{[":
        try:
            obj, end = json.JSONDecoder().raw_decode(s)
            if isinstance(obj, (dict, list)) and obj:
                return t, obj
        except ValueError:
            pass
    if len(re.findall(r"(?:^|[&;\n])[A-Za-z_][\w.-]{0,30}=[^&;\n]*", s)) >= 2:
        return t, None
    words = re.findall(r"[A-Za-z]{4,}", s)
    letters = sum(c.isalpha() or c.isspace() for c in s)
    if words and letters >= 0.6 * len(s) and len(set(words)) >= 2:
        return t, None
    return None


def _layers(b):
    """The ways one more layer may come off: (name, bytes)."""
    out = []
    t = b.decode("ascii", "replace").strip()
    if re.fullmatch(r"[0-9a-fA-F]+", t) and len(t) % 2 == 0 and len(t) >= 16:
        out.append(("hex", bytes.fromhex(t)))
    elif re.fullmatch(r"[A-Za-z0-9+/_-]+=*", t) and len(t) >= 12:
        d = _b64(t)
        if d:
            out.append(("URL-safe Base64" if re.search(r"[-_]", t) else "Base64", d))
    for name, wbits in (("zlib", 15), ("gzip", 31), ("deflate", -15)):
        try:
            z = zlib.decompressobj(wbits)
            r = z.decompress(b, GENERIC_MAX_OUT)
            if r and (z.eof or len(r) >= GENERIC_MAX_OUT):
                out.append((name, r))
                break
        except zlib.error:
            pass
    if len(b) >= 16 and any(c not in _PRINT for c in b):      # binary only: XOR on text would "find" text in text
        # one key byte for the whole value: the three that leave the most text-like bytes, each kept only if it reads
        sample = b[:512]
        ranked = sorted(range(1, 256), key=lambda k: -sum(3 if (c ^ k) in JSONISH else 1 if (c ^ k) in _PRINT else -4 for c in sample))
        out.extend((f"XOR 0x{k:02x}", bytes(c ^ k for c in b)) for k in ranked[:3])
    return out


def generic(value, deadline):
    """The fallback for a long value no known format decodes: peel up to GENERIC_DEPTH layers (hex, Base64, zlib / gzip /
    deflate, a one-byte XOR), and keep the result only when it reads as JSON, key=value pairs or words. Real encryption
    (a key kept in the app) never comes out readable, and is left as it is."""
    raw = value.encode("ascii", "replace")
    todo = [([], raw)]
    seen = set()
    while todo:
        steps, b = todo.pop(0)
        if _now() > deadline or len(steps) >= GENERIC_DEPTH:
            continue
        for name, nb in _layers(b):
            if nb in seen or nb == b:
                continue
            seen.add(nb)
            got = _readable(nb)
            if got:
                text, obj = got
                return {"format": "generic", "title": f"Generic decode ({' → '.join(steps + [name])})", "generic": True,
                        "method": steps + [name],
                        "text": text[:4000], "json": obj if isinstance(obj, (dict, list)) else None, "key": "",
                        "operator": "", "version": "", "os": "", "os_family": "",
                        "notes": [f"Decoded by the generic fallback: {' → '.join(steps + [name])}. Not a known format: read it "
                                  f"with care, and treat what it says about the device as the device's own data."]
                        + ([INJECTION_NOTE] if instruction_like(text) or instruction_like(obj) else [])}
            todo.append((steps + [name], nb))
    return None


def _decode_once(url):
    """(decoded results, finished): finished is False when the budget ran out before every value was tried."""
    deadline = _now() + TIME_BUDGET
    out = []
    for path, param, value in candidates(url):
        # the format expected at this path and parameter first, then the others (the same encoding may move)
        done = False
        for fmt in sorted(FORMATS, key=lambda f: not f.at(path, param)):
            if _now() > deadline:
                return tuple(out), False
            r = _try(fmt, value, deadline)
            if r:
                out.append(json.dumps({**r, "param": param, "path": path[:200]}))
                done = True
                break
        # no known format: the generic fallback, except where a family known to be undecodable sits (OPAQUE)
        if not done and not any(f.at(path, param) for f in FORMATS) and not any(o.at(path, param) for o in OPAQUE):
            r = generic(value, deadline)
            if r:
                out.append(json.dumps({**r, "param": param, "path": path[:200]}))
    # a try that stopped on the deadline returned nothing without having finished: not an answer
    return tuple(out), _now() <= deadline


# finished answers only, by request line: a decode cut short by the budget is never kept, so it is tried again next time
# instead of being reported for the life of the process as "did not decode" (2026-11-17)
_CACHE, _CACHE_LOCK, _CACHE_MAX = collections.OrderedDict(), threading.Lock(), 4096


def _decode_cached(url):
    with _CACHE_LOCK:
        hit = _CACHE.get(url)
        if hit is not None:
            _CACHE.move_to_end(url)
            return hit
    out, finished = _decode_once(url)
    if finished:
        with _CACHE_LOCK:
            _CACHE[url] = out
            while len(_CACHE) > _CACHE_MAX:
                _CACHE.popitem(last=False)
    return out


def decode_finished(url):
    """True when this request line's decode finished (its answer is kept): only then is a value that did not decode at a
    format's own place reported as "did not decode"."""
    with _CACHE_LOCK:
        return str(url) in _CACHE


_decode_cached.cache_clear = lambda: _CACHE.clear()


SENDABLE_STATES = ("unknown", "cut")      # a known family not decoded yet, or a known format whose value did not decode


def sendable(url, host=None):
    """Every value a decoding request may carry (beacon_unknown.py): the long values nothing decodes and no family names
    (unknown()), and those of a known family that is not decoded yet or whose value did not decode (the user,
    2026-11-16: sustat could not be asked for). Encrypted values, hashes, IDs and tokens are left out: decoding cannot
    come of sending them. [{param, path, value, shape, known: the family's title or ""}]"""
    out = [dict(u, known="") for u in unknown(url, host)]
    url = str(url or "")
    if len(url) > MAX_URL:
        return out
    states = {s.get("param"): s for s in seen(url, host) if s.get("state") in SENDABLE_STATES}
    if not states:
        return out
    path, parts = _query(url)
    for param, _raw, value in parts:
        s = states.get(param)
        # an encoded-looking value only, as for unknown values: a plain-text value (spaces, words) stays masked in the
        # request line (security review of 228293b)
        if s and len(value) >= 16 and _BLOB.fullmatch(value):
            out.append({"param": param, "path": path[:200], "value": value, "shape": shape(value),
                        "known": f"{s.get('title', '')} ({status_text(s.get('state'))})"})
    return out


def unknown(url, host=None):
    """The long values of a request that nothing decodes and no known family names: [{param, path, value, shape}]. The
    value stays on the server (beacon_unknown.py groups them into families and counts them)."""
    url = str(url or "")
    if len(url) > MAX_URL or not _PREFILTER.search(url):
        return []
    done = {d.get("param") for d in decode(url)} | {s.get("param") for s in seen(url, host)}
    return [{"param": param, "path": path[:200], "value": value, "shape": shape(value)}
            for path, param, value in candidates(url) if param not in done]


def shape(value):
    """What a value looks like, never what it says: its encoding, decoded length, block alignment, randomness."""
    t = value.strip()
    if re.fullmatch(r"[0-9a-fA-F]+", t) and len(t) % 2 == 0:
        enc, b = "hex", bytes.fromhex(t)
    else:
        b = _b64(t)
        enc = ("URL-safe Base64" if re.search(r"[-_]", t) else "Base64") if b is not None else "text"
        b = b if b is not None else t.encode("ascii", "replace")
    n = len(b)
    import math
    cnt = {}
    for c in b:
        cnt[c] = cnt.get(c, 0) + 1
    ent = -sum(k / n * math.log2(k / n) for k in cnt.values()) if n else 0.0
    if n in (16, 20, 32, 64) and enc == "hex":
        hint = "hash-sized"
    elif n >= 32 and n % 16 == 0 and ent > 0.75 * min(8, math.log2(n)):
        hint = "whole 16-byte blocks, random-looking: likely a block cipher (AES-like)"
    elif ent > 0.8 * min(8, math.log2(max(n, 2))):
        hint = "random-looking bytes"
    elif all(c in _PRINT for c in b):
        hint = "readable characters, but not a known layout"
    else:
        hint = "binary with structure (low randomness): possibly a simple cipher or a custom encoding"
    return {"encoding": enc, "length": n, "blocks16": n % 16 == 0, "entropy": round(ent, 2), "hint": hint}


def decode(url):
    """Every beacon decoded from one request line: [{format, title, key, json, trailer, notes, operator, version, os,
    os_family, param, path}]. Analysts' and admins' view: it carries device identifiers (MAC, UUID, cpuid...)."""
    if not url or len(str(url)) > MAX_URL or not _PREFILTER.search(str(url)):
        return []
    return [json.loads(x) for x in _decode_cached(str(url))]       # fresh copies: callers may change them


def first(url):
    d = decode(url)
    return d[0] if d else None


def public(d):
    """What a researcher may see of a decoded beacon: the format (its readable title), operator, version and OS family.
    Not the XOR key: a new one per check-in, it would single out one record. Of a family seen but not decoded: its
    title, with what its value is in a few words, e.g. "ttyunos API request (encrypted)"; "state" says the same as a key
    (STATUS)."""
    if not d:
        return None
    state = "decoded" if d.get("decoded", True) else (d.get("state") or "unknown")
    title = d.get("title", "") if state == "decoded" else f"{d.get('title', '')} ({status_text(state)})"
    return {"format": title, "id": d.get("format", ""), "operator": d.get("operator", ""),
            "version": d.get("version", ""), "os_family": d.get("os_family", ""), "state": state}


def _query(url):
    """(path, [(param, raw part, value)]) of a request line; ("", []) when it has no query."""
    m = _TARGET.match(str(url or ""))
    if not m or "?" not in m.group(1):
        return "", []
    target = m.group(1)
    path, _, query = target.partition("?")
    if "://" in path:                              # an absolute URL in the request line: its path only
        path = urllib.parse.urlsplit(path).path
    out = []
    for part in re.split(r"[&;]", query):
        k, eq, v = part.partition("=")
        if eq:
            out.append((urllib.parse.unquote(k)[:40], part, urllib.parse.unquote(v).replace(" ", "+")))
    return path, out


def seen(url, host=None):
    """The known families a request carries that did not decode: a format's own place whose value did not decode, or a
    family that cannot be decoded from the request alone (OPAQUE). [{format, title, decoded: False, what, param}]"""
    url = str(url or "")
    if len(url) > MAX_URL or "?" not in url or "=" not in url:
        return []
    path, parts = _query(url)
    got = {d.get("param") for d in decode(url)}
    finished = decode_finished(url)           # a decode cut short by the budget says nothing about the value
    out = []
    for param, _, value in parts:
        if len(value) < 16 or param in got:
            continue
        f = next((f for f in FORMATS if f.at(path, param)), None)
        if f and not finished:
            continue                          # not "did not decode": it is tried again next time
        if f:
            out.append({"format": f.name, "title": f.title, "decoded": False, "param": param, "state": "cut",
                        "status": status_text("cut"),
                        "what": "At this format's place, but the value did not decode (cut short, or a variant not known yet)."})
            continue
        o = next((o for o in OPAQUE if o.at(path, param, host)), None)
        if o:
            out.append({"format": o.name, "title": o.title, "decoded": False, "param": param, "what": o.what,
                        "state": o.state, "status": status_text(o.state)})
    return out


_SUMMARY, _SUMMARY_MAX = collections.OrderedDict(), 16384


def _summary(url, host):
    """The public summary of a request's beacon, kept only once its decode finished (a decode cut short by the budget
    is worked out again next time, never kept as "no beacon": 2026-11-17)."""
    k = (url, host)
    with _CACHE_LOCK:
        hit = _SUMMARY.get(k)
        if hit is not None:
            return hit
    if KEEP is not None:                        # kept from before a restart (beacon_keep.py): no decoding again
        hit = KEEP.get(url, host)
        if hit is not None:
            with _CACHE_LOCK:
                _SUMMARY[k] = hit
                while len(_SUMMARY) > _SUMMARY_MAX:
                    _SUMMARY.popitem(last=False)
            return hit
    d = first(url)
    if d:
        out = tuple(sorted(public(d).items()))
    else:
        s = seen(url, host)
        out = tuple(sorted(public(s[0]).items())) if s else ()
    if decode_finished(url) or not candidates(url):
        with _CACHE_LOCK:
            _SUMMARY[k] = out
            while len(_SUMMARY) > _SUMMARY_MAX:
                _SUMMARY.popitem(last=False)
        if KEEP is not None:
            KEEP.put(url, host, out)
    return out


_summary.cache_clear = lambda: _SUMMARY.clear()
# the public answers kept across restarts (beacon_keep.py): switched on by install(), in the running platform only
KEEP = None


def field(e, name):
    """One public field of the beacon a record carries (intel.py's "beacon:<field>"), "" when it carries none. A family
    seen but not decoded gives its format only."""
    url = e.get("http_url") if isinstance(e, dict) else None
    if not url or "?" not in url or "=" not in url or len(url) > MAX_URL:
        return ""
    return dict(_summary(url, (e.get("http_host") or "").lower() or None)).get(name, "")


def mask_url(url):
    """A request line with every beacon value replaced by "<clogin beacon>", and every value of a family that cannot be
    decoded by "<ttyunos value>", for every masked view. A value at a known format's place is replaced even when it does
    not decode: it carries the device's details all the same."""
    if not url or "=" not in str(url) or "?" not in str(url):
        return url
    url = str(url)
    got = {d.get("param"): d.get("format") for d in decode(url)}
    m = _TARGET.match(url)
    if not m:
        return url
    target = m.group(1)
    head, _, query = target.partition("?")
    path = urllib.parse.urlsplit(head).path if "://" in head else head
    parts = re.split(r"([&;])", query)                  # the separators kept, so the line is rebuilt as it was
    changed = False
    for i in range(0, len(parts), 2):
        k, eq, v = parts[i].partition("=")
        if not eq:
            continue
        param = urllib.parse.unquote(k)[:40]
        value = urllib.parse.unquote(v).replace(" ", "+")
        here = next((f.name for f in FORMATS if f.at(path, param)), None)
        opaque = next((o.name for o in OPAQUE if o.at(path, param)), None)
        label = None
        if here and len(value) >= 16:                   # a known format's place: masked at any length, decoded or not
            label = f"<{here} beacon>"
        elif opaque and len(value) >= 16:               # host not known here: masked wherever its path and parameter are
            label = f"<{opaque} value>"
        elif MIN_BLOB <= len(value) <= MAX_BLOB and _BLOB.fullmatch(value):
            # decoded by a format, by the generic fallback, or by nothing yet: a long encoded value may carry the device's
            # own data, so a masked view never shows it
            label = f"<{got[param]} beacon>" if got.get(param) not in (None, "generic") else "<encoded value>"
        if label:
            parts[i] = f"{k}={label}"
            changed = True
    if not changed:
        return url
    return url[:m.start(1)] + head + "?" + "".join(parts) + url[m.end(1):]


# Windows versions Microsoft no longer supports (as of November 2026); Windows 10 only with Extended Security Updates
def view(e, name="", host=None, agent=""):
    """The analysts' "Decoded beacon" block of one record: the beacons decoded, each with the notes and the
    contradiction with the name it is filed under; then the known families seen but not decoded, with what they are."""
    url = e.get("http_url") if isinstance(e, dict) else e
    if isinstance(e, dict):
        host = host or (e.get("http_host") or "").lower() or None
        agent = agent or e.get("http_agent") or ""
    out = []
    for d in decode(url):
        d["decoded"] = True
        # what the beacon says, never what to do about it: the analysts decide (the user, 2026-11-16)
        if contradicts(name, d.get("os_family")):
            named = OS_TITLE.get(name_os(name), name_os(name))
            article = "an" if str(named)[:1].lower() in "aeiou" else "a"      # an Android name, a Windows name
            d["notes"].append(f"The beacon says {OS_TITLE.get(d['os_family'], d['os_family'])}, but the record is filed under "
                              f"{name}, {article} {named} name: a lead worth checking.")
        out.append(d)
    # a long value nothing decodes and no family names: said so, with its shape (Findings lists these as families)
    rest = [{"format": "unknown", "title": "Unknown encoding", "decoded": False, "unknown": True, "param": u["param"],
             "what": f"{u['shape']['encoding']}, {u['shape']['length']} bytes: {u['shape']['hint']}. Listed on the Findings page "
                     f"under Requests Looking Glass could not decode, where it can be sent to the Looking Glass creator."}
            for u in unknown(url, host)]
    return out + seen(url, host) + rest


# ---------------------------------------------------------------- "Looking Glass asks": the beacon contradicts its name

def contradiction_leads(by, full, min_hosts):
    """Leads for intel.py: per name and OS family, the decoded beacons whose OS contradicts the name. by is intel.py's
    index ({(section, name): {report: slot}}). Viewers who do not see hosts get a lead only when min_hosts or more
    devices carry it (the per-device rule)."""
    # one lead per OS family the beacons say (one match per kind and value, as intel_match.py looks them up), with every
    # name it contradicts
    per = {}
    for (section, name), reps in by.items():
        if section != "infections" or not name_os(name):
            continue
        for rep, slot in reps.items():
            for fam, n in (slot["kinds"].get("Beacon OS") or {}).items():
                if contradicts(name, fam):
                    p = per.setdefault(fam, {"seen": {}, "hosts": set()})
                    w = p["seen"].setdefault((section, name), {})
                    w[rep] = w.get(rep, 0) + n
                    p["hosts"].update(slot["vh"].get(("Beacon OS", fam)) or ())
    out = []
    for fam, p in sorted(per.items()):
        p["hosts"].discard("")
        if not full and len(p["hosts"]) < min_hosts:
            continue
        total = sum(n for w in p["seen"].values() for n in w.values())
        reps_ = sorted({r for w in p["seen"].values() for r in w})
        names = sorted(p["seen"])
        an = lambda w: ("an " if str(w)[:1].lower() in "aeiou" else "a ") + str(w)      # noqa: E731 - an Android name
        said = " and ".join(f"{n} ({an(OS_TITLE.get(name_os(n), name_os(n)))} name)" for _, n in names)
        out.append({"priority": 5, "kind": "Beacon OS", "value": fam, "names_key": names, "reports": reps_, "count": total,
                    "text": f"Looking Glass decoded {total:,} beacon check-in{'s' if total != 1 else ''} that say the operating "
                            f"system is {OS_TITLE.get(fam, fam)}, filed under {said} in {', '.join(reps_)}: the records may be "
                            f"filed under the wrong name, or the family runs on more than one system.",
                    "_seen": {k: dict(v) for k, v in p["seen"].items()}})
    return out


# ---------------------------------------------------------------- the analysts' API

def install(app, ctx):
    """ctx: sees_hosts() -> the viewer has the 'unmasked' permission (demo mode off); csrf_ok()."""
    from flask import jsonify, request
    global KEEP
    try:
        import os
        import beacon_keep
        import index_refresh
        # the running service only (gunicorn): a check that installs the API must never read answers an earlier run
        # kept, nor write its made-up ones into data/ (2026-11-17: a second run of check_beacon_decode found its own)
        if index_refresh.SERVING:
            here = os.path.dirname(os.path.abspath(__file__))
            KEEP = beacon_keep.SummaryStore(os.path.join(here, "data", "beacon_summaries.json"), beacon_keep.fingerprint(__file__))
    except Exception:                              # noqa: BLE001  (not kept: decoded again after a restart, as before)
        KEEP = None

    @app.route("/api/beacon/decode", methods=["POST"])
    def api_beacon_decode():
        # a POST so the request line (host data) stays out of URLs and access logs; nothing is changed or kept
        if not ctx["csrf_ok"]():
            return jsonify(error="The page's security token is missing. Reload the page."), 403
        if not ctx["sees_hosts"]():
            return jsonify(error="The decoded beacon is for analysts and admins."), 403
        b = request.get_json(silent=True) or {}
        url = str(b.get("url") or "")[:MAX_URL]
        name = str(b.get("name") or "")[:120]
        host = str(b.get("host") or "")[:253].lower() or None
        agent = str(b.get("agent") or "")[:200]
        return jsonify(beacons=view(url, name, host, agent))

    return {"decode": decode, "public": public, "mask_url": mask_url}
