#!/usr/bin/env bash
# Copy the latest release (~/looking-glass-release, built by tools/make_release.py) into the git working folder that is
# connected to GitHub, and commit it there. The release folder itself is rebuilt from scratch each time, so it never
# holds the git history. Nothing is pushed unless --push is given.
#
#   tools/publish_github.sh "Message for this version"            # commit only
#   tools/publish_github.sh "Message for this version" --push     # commit and push to GitHub
#
# First time: create an empty repository on GitHub, then
#   git clone https://github.com/<account>/<repo>.git ~/looking-glass-github
set -euo pipefail
REL="${RELEASE_DIR:-$HOME/looking-glass-release}"
GIT="${GITHUB_DIR:-$HOME/looking-glass-github}"
msg="${1:?usage: publish_github.sh \"commit message\" [--push]}"
push="${2:-}"

[ -f "$REL/.looking-glass-release" ] || { echo "No release in $REL: run tools/make_release.py first." >&2; exit 1; }
[ -d "$GIT/.git" ] || { echo "No git folder in $GIT: clone your GitHub repository there first (see the top of this script)." >&2; exit 1; }

# edits made on github.com must not be overwritten: stop if GitHub has commits that are not here yet
cd "$GIT"
if git remote get-url origin >/dev/null 2>&1 && git fetch -q origin 2>/dev/null; then
  ahead=$(git rev-list --count "HEAD..@{u}" 2>/dev/null || echo 0)
  if [ "$ahead" != "0" ]; then
    echo "GitHub has $ahead commit(s) that are not in $GIT (edits made on github.com):" >&2
    git log --format='  %h %an %s' "HEAD..@{u}" >&2
    git diff --stat "HEAD" "@{u}" >&2
    echo "Copy those changes into the release sources (tools/release_root, docs, ...) first, then run:" >&2
    echo "  git -C $GIT pull --rebase   and publish again. Nothing was changed." >&2
    exit 1
  fi
fi
cd - >/dev/null
# mirror the release into the git folder (its .git stays), then commit
rsync -a --delete --exclude ".git/" --exclude ".looking-glass-release" "$REL/" "$GIT/"
cd "$GIT"
# a last guard: never commit an environment file, key, report data, a run log or a stray text file
if git status --porcelain --untracked-files=all | grep -E '(^|/)\.env$|\.key$|automation\.key|/sorting_backup/|/attachments_backup/|\.log$|\.output$|\.tmp$|(^|/)logs/|\.txt$' \
   | grep -vE '(^|/)requirements\.txt$' ; then
  echo "Refusing to commit: files above must never be published." >&2; exit 1
fi
git add -A
if git diff --cached --quiet; then echo "Nothing changed since the last commit."; else git commit -q -m "$msg"; echo "Committed: $msg"; fi
git log --oneline -1
if [ "$push" = "--push" ]; then
  if git rev-parse --abbrev-ref --symbolic-full-name '@{u}' >/dev/null 2>&1; then git push; else git push -u origin HEAD; fi
fi
