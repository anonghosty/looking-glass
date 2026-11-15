#!/usr/bin/env python3
"""Signed checkpoints of the audit log and signed backup checksums (audit_checkpoint.py, review follow-up 2026-11-14),
on a throwaway log: the key is made once and recorded in the chain; a checkpoint names the head at its entry and is
signed; a copy goes to the copy folder and never replaces a file there; the verifier finds each checkpoint at its entry,
and catches what a whole chain alone cannot: the log REWRITTEN with every link recomputed, entries cut from the end,
a checkpoint altered, a signature from another key or another purpose. The proof package carries the checkpoints.
Needs ssh-keygen (openssh-client). Run: .venv/bin/python tests/check_audit_checkpoint.py"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import zipfile

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
import audit_chain  # noqa: E402
import audit_checkpoint as ac  # noqa: E402
import audit_verifier  # noqa: E402

checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info and not cond else ""))


if not ac.ssh_keygen():
    print("ssh-keygen not found (openssh-client): skipped")
    sys.exit(0)


class Audit:
    """The audit log as the service writes it (auth.Audit's entry format), on a throwaway folder."""

    def __init__(self, d):
        self.chain = audit_chain.Chain(os.path.join(d, "audit.log"))

    def add(self, event, user="", target="", detail="", ip=None, ua=None):
        import time
        self.chain.append({"t": round(time.time(), 3), "event": event, "user": user, "target": target, "detail": str(detail)[:300],
                           "ip": "", "location": "", "ua": ""})


tmp = tempfile.mkdtemp(prefix="lg-ckpt-")
data = os.path.join(tmp, "data"); os.makedirs(data)
copy = os.path.join(tmp, "elsewhere"); os.makedirs(copy)
os.environ["AUDIT_CHECKPOINT_COPY_DIR"] = copy
audit = Audit(data)
for i in range(12):
    audit.add("login_ok", user=f"user{i}", detail="signed in")
signer = ac.Signer(data)

print("The key")
line, fp = signer.ensure_key(audit)
ok("made on first use: an Ed25519 key, owner-only", line and line.startswith("ssh-ed25519 ") and oct(os.stat(signer.key).st_mode & 0o777) == "0o600",
   oct(os.stat(signer.key).st_mode & 0o777) if os.path.exists(signer.key) else "no key")
ok("…its fingerprint as ssh-keygen shows it", fp == subprocess.run(["ssh-keygen", "-lf", signer.pub], capture_output=True, text=True).stdout.split()[1])
recorded = [json.loads(x) for x in audit.chain.lines() if '"audit_signing_key"' in x]
ok("…and its public key is recorded in the chain", len(recorded) == 1 and line in recorded[0]["detail"] and recorded[0]["target"] == fp)
ok("asked again: the same key, recorded once", signer.ensure_key(audit) == (line, fp)
   and sum('"audit_signing_key"' in x for x in audit.chain.lines()) == 1)

print("A checkpoint")
ck = signer.make(audit)
ok("names the head at its entry, signed, copied away", ck and ck["signed"] and ck["copied"] == "the copy folder" and ck["key"] == fp, str(ck))
p = os.path.join(signer.dir, ck["file"])
ok("…the file and its signature are owner-only", oct(os.stat(p).st_mode & 0o777) == "0o600" and os.path.exists(p + ".sig"))
ok("…the copy folder has both", sorted(os.listdir(copy)) == sorted([ck["file"], ck["file"] + ".sig"]))
ok("…the signature is valid for checkpoints only", ac.verify_file(p, ac.CHECKPOINT_NS, [line]) == "valid"
   and ac.verify_file(p, ac.BACKUP_NS, [line]) == "INVALID")
ok("…and it is recorded in the chain", any('"audit_checkpoint"' in x and ck["head"] in x for x in audit.chain.lines()))
ok("nothing new since (only its own entry): no second checkpoint", signer.make(audit) is None)
audit.add("login_ok", user="later", detail="signed in")
ck2 = signer.make(audit)
ok("a new entry: a new checkpoint", ck2 and ck2["entry"] > ck["entry"])
r = audit_verifier.check(data)
ok("the verifier: chain whole, both checkpoints at their entry, signatures valid",
   r["ok"] and r["checkpoints"]["matched"] == 2 and r["checkpoints"]["signatures"] == {"valid": 2}, json.dumps(r["checkpoints"]))
ok("a name already taken in the copy folder: never replaced, said why",
   ac.copy_out(p, p + ".sig") == "a file of that name is already in the copy folder")

print("What the checkpoints catch")


def rewrite(lines, i, new_detail):
    """The whole log rewritten from entry i on with every link recomputed: a WHOLE chain, a different history."""
    out, prev = [], None
    for k, ln in enumerate(lines):
        rec = json.loads(ln)
        if k == i:
            rec["detail"] = new_detail
        if k >= i and "prev" in rec:
            rec["prev"] = prev
        ln2 = json.dumps(rec, ensure_ascii=False) if k >= i else ln
        out.append(ln2); prev = audit_chain.sha(ln2)
    return out


saved = open(audit.chain.path, encoding="utf-8").read()
lines = saved.splitlines()
new = rewrite(lines, 3, "signed in from somewhere else")
with open(audit.chain.path, "w", encoding="utf-8") as f:
    f.write("\n".join(new) + "\n")
with open(audit.chain.head_path, "w") as f:
    json.dump({"head": audit_chain.sha(new[-1]), "entries": len(new)}, f)
nothing = os.path.join(tmp, "no_checkpoints"); os.makedirs(nothing)
ok("the log rewritten with every link recomputed: without checkpoints the chain looks whole…",
   audit_verifier.check(data, checkpoints=nothing)["ok"])
r = audit_verifier.check(data)
ok("…but the checkpoints show it: NOT verified", not r["ok"] and r["checkpoints"]["problems"]
   and "changed or rewritten" in r["checkpoints"]["problems"][0]["what"], json.dumps(r["checkpoints"]["problems"]))
ok("…and the copies kept elsewhere show it too", audit_verifier.check(data, checkpoints=copy)["checkpoints"]["problems"] != [])
cut = lines[:ck["entry"] - 2]
with open(audit.chain.path, "w", encoding="utf-8") as f:
    f.write("\n".join(cut) + "\n")
with open(audit.chain.head_path, "w") as f:
    json.dump({"head": audit_chain.sha(cut[-1]), "entries": len(cut)}, f)
r = audit_verifier.check(data, checkpoints=copy)
ok("entries cut from the end (audit.head rewritten to match): the checkpoint is beyond the end",
   not r["ok"] and any("beyond the end" in x["what"] for x in r["checkpoints"]["problems"]), json.dumps(r["checkpoints"]["problems"]))
with open(audit.chain.path, "w", encoding="utf-8") as f:
    f.write(saved)
with open(audit.chain.head_path, "w") as f:
    json.dump({"head": audit_chain.sha(lines[-1]), "entries": len(lines)}, f)
ok("the log put back: verified again", audit_verifier.check(data)["ok"])

forged = os.path.join(tmp, "forged"); shutil.copytree(signer.dir, forged, ignore=shutil.ignore_patterns(".lock"))
fp1 = os.path.join(forged, ck["file"])
c = json.load(open(fp1)); c["made"] += 1
open(fp1, "w").write(json.dumps(c, sort_keys=True) + "\n")
r = audit_verifier.check(data, checkpoints=forged)
ok("a checkpoint altered after signing: its signature is INVALID", not r["ok"] and r["checkpoints"]["signatures"].get("INVALID") == 1)
other = os.path.join(tmp, "other_key")
subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", other], check=True)
c["made"] -= 1
open(fp1, "w").write(json.dumps(c, sort_keys=True) + "\n")
os.remove(fp1 + ".sig")
subprocess.run(["ssh-keygen", "-q", "-Y", "sign", "-f", other, "-n", ac.CHECKPOINT_NS, fp1], check=True, capture_output=True)
r = audit_verifier.check(data, checkpoints=forged)
ok("a checkpoint signed by another key: INVALID", r["checkpoints"]["signatures"].get("INVALID") == 1)
ok("…unless the auditor gives that key (--key): then that checkpoint is valid",
   audit_verifier.signature(fp1, "looking-glass-audit", [" ".join(open(other + ".pub").read().split(" ")[:2])]) == "valid")
other_pub = " ".join(open(other + ".pub").read().split(" ")[:2])
r = audit_verifier.check(data, extra_keys=[other_pub])
ok("with --key, ONLY that key is trusted: the log's own (recorded) key no longer vouches (review of d82a436)",
   r["checkpoints"]["signatures"].get("INVALID", 0) >= 1 and r["checkpoints"]["trusted"] == "the key given with --key only",
   json.dumps(r["checkpoints"]["signatures"]))
r = audit_verifier.check(data)
ok("…without --key, the keys the log records are used (and the report says which)",
   r["checkpoints"]["signatures"].get("INVALID") is None and r["checkpoints"]["trusted"] == "the keys recorded in the log")
r = audit_verifier.check(data, extra_keys=[])
ok("--key that gave no key: the log's own keys are NOT used instead (review of f6bbce9)",
   r["checkpoints"]["trusted"] == "the key given with --key only" and r["checkpoints"]["signatures"].get("valid", 0) == 0,
   json.dumps(r["checkpoints"]["signatures"]))
empty = os.path.join(tmp, "not-a-key.txt")
open(empty, "w").write("SHA256:a fingerprint, not the key itself\n")
p = subprocess.run([sys.executable, audit_verifier.__file__, data, "--key", empty], capture_output=True, text=True)
ok("…and the command refuses a --key file with no ssh-ed25519 key in it, saying why",
   p.returncode == 2 and "no signing public key" in p.stderr, p.stderr.strip()[-200:])
bom = os.path.join(tmp, "key-bom.pub")
open(bom, "w", encoding="utf-8-sig", newline="\r\n").write(other_pub + "\n")
p = subprocess.run([sys.executable, audit_verifier.__file__, data, "--key", bom, "--json"], capture_output=True, text=True)
ok("…a key file saved on Windows (byte-order mark, CR LF) is read", p.returncode in (0, 1)
   and json.loads(p.stdout)["checkpoints"]["trusted"] == "the key given with --key only", p.stderr.strip()[-200:])

print("Backups")
sums = os.path.join(tmp, "lg-20261115.tar.gz.sha256")
open(sums, "w").write("0" * 64 + "  lg-20261115.tar.gz\n")
sig = signer.sign(sums, ac.BACKUP_NS, audit)
ok("a backup checksum is signed for backups only", ac.verify_file(sums, ac.BACKUP_NS, [line]) == "valid"
   and ac.verify_file(sums, ac.CHECKPOINT_NS, [line]) == "INVALID")
open(sums, "a").write("x")
ok("…a changed checksum file fails", ac.verify_file(sums, ac.BACKUP_NS, [line]) == "INVALID")
ok("…no signature is said plainly", ac.verify_file(os.path.join(tmp, "none"), ac.BACKUP_NS, [line]) == "no signature")
try:
    signer.sign(sums, "something-else")
    ok("an unknown purpose (namespace) is refused", False)
except ValueError:
    ok("an unknown purpose (namespace) is refused", True)
bk = open(os.path.join(HERE, "manage", "backup.sh"), encoding="utf-8").read()
ok("backup.sh leaves the private key out and signs the checksum",
   'data/audit_signing/signing_key"' in bk and "--exclude" in bk and "sign-file" in bk and "looking-glass-backup" in bk)
ok("verify_backup.sh and restore_check.sh check the signature", all(
    "verify-file" in open(os.path.join(HERE, "manage", n), encoding="utf-8").read() for n in ("verify_backup.sh", "restore_check.sh")))

print("The proof package")
import audit_proof  # noqa: E402
pkg, meta = audit_proof.build(audit.chain, "check")
z = zipfile.ZipFile(__import__("io").BytesIO(pkg))
names = z.namelist()
ok("carries the checkpoints and their signatures", any(n.startswith("log/audit_checkpoints/checkpoint-") and n.endswith(".sig") for n in names))
out = os.path.join(tmp, "pkg"); z.extractall(out)
res = subprocess.run([sys.executable, os.path.join(out, "verify_audit_log.py"), out], capture_output=True, text=True)
ok("the package's own verifier: RESULT verified, checkpoints found at their entry",
   res.returncode == 0 and "checkpoints" in res.stdout and "RESULT: verified" in res.stdout, res.stdout[-400:])

shutil.rmtree(tmp, ignore_errors=True)
print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {', '.join(fails)}" if fails else ""))
sys.exit(1 if fails else 0)
