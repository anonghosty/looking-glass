#!/usr/bin/env python3
"""The backup scripts as an operator runs them (manage/backup.sh, verify_backup.sh, restore_check.sh), on a throwaway
installation: a signed backup verifies and rehearses as restorable; a genuine checksum and signature placed beside
ANOTHER archive fail (the checksum is bound to the archive checked: security review of edd2d57); an archive changed
under its own name fails; an unsigned backup, or one with no public key, fails unless --allow-unsigned is given.
Needs ssh-keygen (openssh-client). Run: .venv/bin/python tests/check_backup_scripts.py"""
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info and not cond else ""))


if not shutil.which("ssh-keygen"):
    print("ssh-keygen not found (openssh-client): skipped")
    sys.exit(0)

tmp = tempfile.mkdtemp(prefix="lg-bk-")
proj = os.path.join(tmp, "platform")
os.makedirs(os.path.join(proj, "manage")); os.makedirs(os.path.join(proj, "data"))
for f in ("audit_checkpoint.py", "audit_verifier.py", "audit_chain.py"):
    shutil.copy(os.path.join(HERE, f), proj)
for f in ("backup.sh", "verify_backup.sh", "restore_check.sh", "backup_crypt.sh"):
    shutil.copy(os.path.join(HERE, "manage", f), os.path.join(proj, "manage", f))
    os.chmod(os.path.join(proj, "manage", f), 0o755)
open(os.path.join(proj, ".env"), "w").write("SECRET_KEY=test-only-not-a-secret\nPORT=5000\n")
open(os.path.join(proj, "data", "users.json"), "w").write('{"admin1": {"role": "admin"}, "ana": {"role": "analyst"}}')
for n in ("roles.json", "settings.json", "organisation.json"):
    open(os.path.join(proj, "data", n), "w").write("{}")
env = dict(os.environ, HOME=tmp)


def run(*cmd):
    r = subprocess.run(list(cmd), cwd=proj, env=env, capture_output=True, text=True, timeout=300)
    return r.returncode, r.stdout + r.stderr


def backup():
    rc, out = run("manage/backup.sh", "--unencrypted", os.path.join(tmp, "backups"))
    arch = sorted(p for p in os.listdir(os.path.join(tmp, "backups")) if p.endswith(".tar.gz"))[-1]
    return rc, out, os.path.join(tmp, "backups", arch)


print("No public key: no backup (review of d82a436)")
rc, out = run("manage/backup.sh", os.path.join(tmp, "refused"))
ok("refused with exit 3, saying how to make a key", rc == 3 and "NOT BACKED UP" in out and "age-keygen" in out, out[-400:])
ok("…and nothing written", not os.path.exists(os.path.join(tmp, "refused")) or not os.listdir(os.path.join(tmp, "refused")))

print("A signed (unencrypted, --unencrypted) backup")
rc, out, A = backup()
ok("backup.sh makes the archive, its checksum and the signature", rc == 0 and os.path.exists(A + ".sha256.sig"), out[-300:])
ok("…and records it in the audit log", '"backup_signed"' in open(os.path.join(proj, "data", "audit.log")).read())
rc, out = run("manage/verify_backup.sh", A)
ok("verify_backup.sh: valid, matches, exit 0", rc == 0 and "signature: valid" in out and "checksum: matches" in out, out)
rc, out = run("manage/restore_check.sh", A)
ok("restore_check.sh: restorable, exit 0", rc == 0 and "RESULT: restorable" in out, out[-500:])

print("A genuine checksum and signature beside another archive")
import time
time.sleep(1.1)
open(os.path.join(proj, "data", "settings.json"), "w").write('{"changed": true}')
rc, out, B = backup()

print("The newest signed backup? (an older genuine one still verifies: security review of a40f17a)")
rc, out = run("manage/verify_backup.sh", B)
ok("the newest backup: said so", rc == 0 and "freshness: the newest signed backup" in out, out)
rc, out = run("manage/verify_backup.sh", A)
ok("an older one: verifies, with a warning naming the newer one", rc == 0 and "NOT THE NEWEST" in out
   and os.path.basename(B) in out, out)
os.utime(A, None); os.utime(A + ".sha256", None)          # the attack: the old archive given a newer file date
newest_by_date = sorted((os.path.getmtime(os.path.join(tmp, "backups", p)), p) for p in os.listdir(os.path.join(tmp, "backups"))
                        if p.endswith(".tar.gz"))[-1][1]
rc, out = run("manage/verify_backup.sh")                     # the default: the newest by file date
ok("an old backup made to look newest by its file date: the warning still says it is not",
   newest_by_date == os.path.basename(A) and "NOT THE NEWEST" in out, out)
rc, out = run("manage/restore_check.sh", A)
ok("restore_check.sh: a WARN row for it, still restorable", rc == 0 and "WARN  freshness" in out and "NOT THE NEWEST" in out, out[-600:])
other = os.path.join(tmp, "elsewhere"); os.makedirs(other)
fake = os.path.join(other, os.path.basename(B))
shutil.copy(B, fake)
shutil.copy(A + ".sha256", fake + ".sha256"); shutil.copy(A + ".sha256.sig", fake + ".sha256.sig")
shutil.copy(A, os.path.join(other, os.path.basename(A)))   # the archive the checksum names is there too (the attack)
rc, out = run("manage/verify_backup.sh", fake)
ok("verify_backup.sh: refused, the checksum file is for another archive", rc == 1 and "not for this archive" in out, out)
rc, out = run("manage/restore_check.sh", fake)
ok("restore_check.sh: refused too", rc != 0 and "not for this archive" in out, out[-400:])
named = os.path.join(other, "same-name"); os.makedirs(named)
swap = os.path.join(named, os.path.basename(A))
shutil.copy(B, swap); shutil.copy(A + ".sha256", swap + ".sha256"); shutil.copy(A + ".sha256.sig", swap + ".sha256.sig")
rc, out = run("manage/verify_backup.sh", swap)
ok("another archive under the signed name: DOES NOT MATCH", rc == 1 and "DOES NOT MATCH" in out, out)
rc, out = run("manage/restore_check.sh", swap)
ok("…restore_check.sh too", rc != 0 and "does not match" in out, out[-400:])

print("Unsigned, or no key to check it")
uns = os.path.join(tmp, "unsigned"); os.makedirs(uns)
u = os.path.join(uns, os.path.basename(A)); shutil.copy(A, u); shutil.copy(A + ".sha256", u + ".sha256")
rc, out = run("manage/verify_backup.sh", u)
ok("no signature: NOT VERIFIED, exit 1", rc == 1 and "NOT VERIFIED" in out, out)
rc, out = run("manage/verify_backup.sh", "--allow-unsigned", u)
ok("…accepted with --allow-unsigned (an old backup), said so", rc == 0 and "accepted: --allow-unsigned" in out, out)
rc, out = run("manage/restore_check.sh", u)
ok("restore_check.sh: no signature fails", rc != 0 and "FAIL" in out and "unsigned backup" in out, out[-400:])
rc, out = run("manage/restore_check.sh", "--allow-unsigned", u)
ok("…and passes with --allow-unsigned", rc == 0 and "RESULT: restorable" in out, out[-400:])
rc, out = run("manage/verify_backup.sh", A, os.path.join(tmp, "no-such-key.pub"))
ok("no public key to check it: NOT VERIFIED, exit 1", rc == 1 and "NOT CHECKED" in out, out)
rc, out = run("manage/restore_check.sh", A)
ok("restore_check.sh says an unencrypted backup is not encrypted (a warning)", "WARN  encryption" in out, out[-500:])


def encrypted(kind, pub_text, identity):
    open(os.path.join(proj, "data", "backup_public_key"), "w").write(pub_text)
    time.sleep(1.1)
    d = os.path.join(tmp, "enc-" + kind)
    rc, out = run("manage/backup.sh", d)
    files = sorted(p for p in os.listdir(d) if p.endswith(".tar.gz." + kind)) if os.path.isdir(d) else []
    ok(f"{kind}: the backup is encrypted (.tar.gz.{kind}), with its checksum and signature",
       rc == 0 and files and os.path.exists(os.path.join(d, files[-1]) + ".sha256.sig"), out[-400:])
    if not files:
        return
    E = os.path.join(d, files[-1])
    raw = open(E, "rb").read()
    ok(f"{kind}: nothing readable in it (.env, accounts)", b"SECRET_KEY" not in raw and b"admin1" not in raw and not raw.startswith(b"\x1f\x8b"))
    ok(f"{kind}: only the owner may read it (0600)", oct(os.stat(E).st_mode & 0o777) == "0o600")
    rc, out = run("manage/verify_backup.sh", E)
    ok(f"{kind}: verify without the private key: signature and checksum checked, contents not opened",
       rc == 0 and "signature: valid" in out and "checksum: matches" in out and "not opened" in out, out)
    rc, out = run("manage/verify_backup.sh", "--identity", identity, E)
    ok(f"{kind}: verify with the private key: .env included and identical", rc == 0 and ".env: included and identical" in out, out)
    rc, out = run("manage/restore_check.sh", E)
    ok(f"{kind}: restore rehearsal without the key: refused, saying why", rc != 0 and "give your private key with --identity" in out, out[-400:])
    rc, out = run("manage/restore_check.sh", "--identity", identity, E)
    ok(f"{kind}: restore rehearsal with the key: restorable", rc == 0 and "RESULT: restorable" in out and "OK    encryption" in out, out[-600:])
    wrong = os.path.join(tmp, f"wrong-{kind}")
    if kind == "age":
        subprocess.run(["age-keygen", "-o", wrong], capture_output=True)
    else:
        open(wrong, "w").write("not a key")
    rc, out = run("manage/restore_check.sh", "--identity", wrong, E)
    ok(f"{kind}: the wrong key: not restorable", rc != 0 and "cannot be opened" in out, out[-300:])


print("Encrypted backups (GnuPG)")
if shutil.which("gpg"):
    gh = os.path.join(tmp, "gnupg"); os.makedirs(gh); os.chmod(gh, 0o700)
    g = lambda *a: subprocess.run(["gpg", "--homedir", gh, "--batch", *a], capture_output=True, text=True)  # noqa: E731
    g("--passphrase", "", "--pinentry-mode", "loopback", "--quick-gen-key", "LG backup test <test@example.invalid>", "default", "default", "never")
    pub = g("--export", "--armor").stdout
    sec_path = os.path.join(tmp, "secret.asc")
    open(sec_path, "w").write(g("--export-secret-keys", "--armor", "--pinentry-mode", "loopback", "--passphrase", "").stdout)
    encrypted("gpg", pub, sec_path)
else:
    print("  gpg not installed: skipped")
print("Encrypted backups (age)")
if shutil.which("age") and shutil.which("age-keygen"):
    idf = os.path.join(tmp, "age-key.txt")
    subprocess.run(["age-keygen", "-o", idf], capture_output=True)
    rec = subprocess.run(["age-keygen", "-y", idf], capture_output=True, text=True).stdout
    encrypted("age", rec, idf)
else:
    print("  age not installed here: skipped (GnuPG checked above)")
open(os.path.join(proj, "data", "backup_public_key"), "w").write("hello")
rc, out = run("manage/backup.sh", os.path.join(tmp, "badkey"))
ok("a public key file that is neither age nor GnuPG: refused", rc == 3 and "neither an age recipient" in out, out[-300:])

shutil.rmtree(tmp, ignore_errors=True)
print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {', '.join(fails)}" if fails else ""))
sys.exit(1 if fails else 0)
