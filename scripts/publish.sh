#!/usr/bin/env bash
# Publish one reviewed release to GitHub. Needs the GitHub CLI (`gh auth login`).
# Usage: bash scripts/publish.sh <reviewed commit ID>
# It publishes exactly that commit: clean checkout of main, nothing untracked, manifest already committed. It never
# commits, never moves a tag, and stops on any check that fails. Safe to rerun.
set -euo pipefail
cd "$(dirname "$0")/.."
TAG="v0.7.0"
REVIEWED="${1:-}"
stop() { echo "STOPPED: $*. Nothing pushed."; exit 1; }
[[ "$REVIEWED" =~ ^[0-9a-f]{40}$ ]] || stop "give the full 40-character commit ID that was reviewed (bash scripts/publish.sh <commit>)"
[[ "$(git rev-parse --abbrev-ref HEAD)" == "main" ]] || stop "publish from main (this checkout is on $(git rev-parse --abbrev-ref HEAD))"
[[ "$(git rev-parse HEAD)" == "$REVIEWED" ]] || stop "HEAD is $(git rev-parse HEAD), not the reviewed commit $REVIEWED"
[[ -z "$(git status --porcelain --untracked-files=all)" ]] || stop "the checkout has changed or untracked files; publish only the reviewed commit, as committed"
if grep -rlq GITHUB_OWNER --exclude-dir=.git --exclude=publish.sh .; then stop "GITHUB_OWNER placeholders are still in the release; set them, commit, and get that commit reviewed"; fi
OWNER="$(gh api user -q .login)" || stop "the GitHub CLI isn't signed in"
REPO="$OWNER/grokbot-watchtower"
echo "Publishing $REPO $TAG at $REVIEWED"
# A published tag is never moved: installed copies and template memories pin its commit.
if git rev-parse -q --verify "refs/tags/$TAG" >/dev/null || \
   { git remote get-url origin >/dev/null 2>&1 && git ls-remote --exit-code --tags origin "refs/tags/$TAG" >/dev/null 2>&1; }; then
  stop "tag $TAG already exists. Choose a new version number, set it here and in the release files"
fi
PYTHONDONTWRITEBYTECODE=1 python3 -W ignore::ResourceWarning -m unittest discover -s tests -q || stop "the tests failed"
bash scripts/make-manifest.sh
[[ -z "$(git status --porcelain --untracked-files=all)" ]] || { git checkout -q -- MANIFEST.sha256 2>/dev/null || true; stop "MANIFEST.sha256 in the reviewed commit is out of date; regenerate it, commit, and get that commit reviewed"; }
gh repo view "$REPO" >/dev/null 2>&1 || stop "$REPO doesn't exist on GitHub; create it first (this script no longer creates repos)"
git remote get-url origin >/dev/null 2>&1 || git remote add origin "https://github.com/$REPO.git"
git fetch -q origin main || stop "couldn't read main on GitHub"
git merge-base --is-ancestor origin/main "$REVIEWED" || stop "GitHub has commits on main that aren't in the reviewed commit; main is never overwritten"
[[ "$(gh repo view "$REPO" --json visibility -q .visibility)" == "PUBLIC" ]] || stop "$REPO is not public, so the installer can't reach it. Visibility is the owner's decision"
git push origin "$REVIEWED:refs/heads/main" || stop "the push to main failed"
[[ "$(git ls-remote origin refs/heads/main | cut -f1)" == "$REVIEWED" ]] || stop "main on GitHub isn't the reviewed commit after the push"
git tag -a "$TAG" "$REVIEWED" -m "Watchtower $TAG"
git push origin "refs/tags/$TAG" || stop "the tag push failed (the local tag $TAG is left for you to inspect)"
[[ "$(git ls-remote origin "refs/tags/$TAG^{}" | cut -f1)" == "$REVIEWED" ]] || stop "tag $TAG on GitHub doesn't point at the reviewed commit"
echo "Done: https://github.com/$REPO (tag $TAG = $REVIEWED; main = $REVIEWED)"
# The template's memories carry this release's tag and commit ID, so an installed copy can refuse anything else.
python3 - "$TAG" "$REVIEWED" <<'PYEOF' > "${TMPDIR:-/tmp}/template-memories-$TAG.txt"
import re, sys
tag, commit = sys.argv[1], sys.argv[2]
text = open("bot/memories.md").read().replace("{TAG}", tag).replace("{COMMIT}", commit)
for m in re.findall(r"(?m)^\d+\. (.+)$", text):
    print(m + "\n")
PYEOF
echo "Template memories for $TAG are in ${TMPDIR:-/tmp}/template-memories-$TAG.txt (outside the repo, so the checkout stays clean)."
echo "Tell your Watchtower Bot: replace the template's memories with that text, then click Update template."
