#!/usr/bin/env bash
# build_wheelhouse.sh: a release's library bundle, looking-glass-libraries-<version>.tar.gz. It holds exactly the
# files the locks name (platform, database pipeline, docs site) for every supported computer: Python 3.12, 3.13 and
# 3.14 on x86_64 and aarch64 (wheels tagged manylinux_2_28, manylinux2014 or manylinux_2_17, and pure-Python ones;
# never a source package, which would have to be built), each file checked against its lock, with SHA256SUMS.
# The release attaches it to github.com/anonghosty/looking-glass-libraries; the installers use it when PyPI cannot
# give a matching file, and check every file in it against the main repository's locks again. Unpacked into
# ~/looking-glass/libraries/<version>/ it is also the local copy for a computer without internet.
#
#   tools/build_wheelhouse.sh VERSION [OUTPUT-FOLDER]     (default output: the current folder)
#
# It needs the internet (PyPI) and nothing else. It stops when a library has no file for one of the six computers.
set -euo pipefail
VERSION="${1:-}"; OUT="${2:-.}"
[[ $VERSION =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ ]] || { sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'; exit 1; }
PF="$(cd "$(dirname "$(readlink -f "$0")")/.." && pwd)"
TOP="$(dirname "$PF")"
if [ -f "$TOP/install.sh" ] && [ -d "$TOP/database" ]; then DB="$TOP/database"; DOCS="$TOP/docs"
else DB="${LG_PIPELINE_DIR:-$TOP/shadowserver}"; DOCS="$PF/tools/release_root/docs"; fi
mkdir -p "$OUT"; OUT="$(cd "$OUT" && pwd)"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
python3 -m venv "$T/v"                      # its pip only downloads; nothing is installed from here
PIP=("$T/v/bin/python" -m pip --disable-pip-version-check --no-input)
B="$T/bundle"; mkdir -p "$B/locks"
problems=0
for part in platform:"$PF" database:"$DB" docs:"$DOCS"; do
  name="${part%%:*}"; dir="${part#*:}"; lock="$dir/requirements.lock"
  [ -f "$lock" ] || { echo "$name: no $lock"; problems=1; continue; }
  cp "$lock" "$B/locks/$name.lock"
  d="$B/$name"; mkdir -p "$d"
  for py in 3.12 3.13 3.14; do for m in x86_64 aarch64; do
    tags=(--only-binary=:all: --python-version "$py" --implementation cp
          --platform "manylinux_2_28_$m" --platform "manylinux2014_$m" --platform "manylinux_2_17_$m")
    if ! "${PIP[@]}" download -q --no-cache-dir --require-hashes --no-deps -r "$lock" -d "$d" "${tags[@]}" > "$T/log" 2>&1; then
      # which libraries have no file for this computer (one by one)
      missing=$(python3 - "$PF/deploy" "$lock" <<'EOF'
import sys
sys.path.insert(0, sys.argv[1])
import safe_libraries as s
print(" ".join(f"{x['name']}=={x['version']}" for x in s.read_lock(sys.argv[2])))
EOF
)
      none=""
      for req in $missing; do
        "${PIP[@]}" download -q --no-cache-dir --no-deps "$req" -d "$T/one" "${tags[@]}" > /dev/null 2>&1 || none="$none $req"
      done
      echo "$name: NO WHEEL for Python $py on $m:${none:- (see below)}"; [ -n "$none" ] || tail -3 "$T/log" | sed 's/^/    /'
      problems=1; continue
    fi
    # every dependency is in the bundle for this computer (offline, as an installation without internet would)
    if ! "${PIP[@]}" install -q --dry-run --ignore-installed --target "$T/dry" --no-index --find-links "$d" --require-hashes \
         "${tags[@]}" -r "$lock" > "$T/log" 2>&1; then
      echo "$name: NOT COMPLETE for Python $py on $m"; tail -3 "$T/log" | sed 's/^/    /'; problems=1
    fi
  done; done
done
# every file again against its lock, and SHA256SUMS
python3 - "$PF/deploy" "$B" <<'EOF' || problems=1
import os, sys
sys.path.insert(0, sys.argv[1])
import safe_libraries as s
b, bad, sums = sys.argv[2], [], []
for part in sorted(os.listdir(b)):
    lock = os.path.join(b, "locks", f"{part}.lock")
    if part == "locks" or not os.path.isfile(lock):
        continue
    want = {x["key"]: x for x in s.read_lock(lock)}
    for f in sorted(os.listdir(os.path.join(b, part))):
        h = s.sha256(os.path.join(b, part, f))
        key, ver = s.wheel_key(f)
        x = want.get(key)
        if not x or x["version"] != ver or h not in x["hashes"]:
            bad.append(f"{part}/{f}")
        sums.append(f"{h}  {part}/{f}")
    for key, x in want.items():
        if not any(s.wheel_key(f)[0] == key for f in os.listdir(os.path.join(b, part))):
            bad.append(f"{part}: no file for {x['name']} {x['version']}")
open(os.path.join(b, "SHA256SUMS"), "w").write("\n".join(sums) + "\n")
for x in bad:
    print(f"NOT IN THE LOCK: {x}")
print(f"checked against the locks: {len(sums)} files" + (f", {len(bad)} problem(s)" if bad else ", all match"))
sys.exit(1 if bad else 0)
EOF
for part in platform database docs; do
  [ -d "$B/$part" ] && echo "$part: $(find "$B/$part" -type f | wc -l) files, $(du -sh "$B/$part" | cut -f1)"
done
[ "$problems" = 0 ] || { echo "The bundle is NOT complete (above): nothing was written."; exit 1; }
tgz="$OUT/looking-glass-libraries-$VERSION.tar.gz"
tar -C "$B" --owner=0 --group=0 --numeric-owner --sort=name -czf "$tgz" .
( cd "$OUT" && sha256sum "$(basename "$tgz")" > "$(basename "$tgz").sha256" )
echo "bundle: $tgz ($(du -h "$tgz" | cut -f1)), its sha256 beside it"
