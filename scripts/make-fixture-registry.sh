#!/usr/bin/env bash
# Regenerate rules/fixture_files.json: the sha256 of every plain file ever committed under tests/ or docs/ (every commit
# `git rev-list HEAD -- tests docs` names, plus the index), whatever it holds: a shipped file can trip any gitleaks rule
# (generic-api-key, curl-auth-user, ...), not only ISR-T011, so none is left out by a hit filter. Links and submodules are not
# files and are skipped; the engine itself never recognizes a file over FIXTURE_FILE_MAX (fixture_keys.py). Hashes only: no
# path, no value. The same history and index give the same bytes. Run it before scripts/make-manifest.sh.
set -euo pipefail
cd "$(dirname "$0")/.."
python3 -I - <<'PYEOF'
import hashlib, json, subprocess


def git(*a):
    return subprocess.run(["git", *a], check=True, capture_output=True).stdout


def blobs(listing):
    """The blob IDs of the plain files in `git ls-tree -r -z` or `git ls-files -s -z` output (no links, no submodules)."""
    out = set()
    for entry in listing.split(b"\0"):
        meta = entry.split(b"\t", 1)[0].split()
        if len(meta) >= 3 and meta[0] in (b"100644", b"100755"):
            out.add(meta[1 if meta[1] != b"blob" else 2].decode())
    return out


ids = blobs(git("ls-files", "-s", "-z", "--", "tests", "docs"))
for c in git("rev-list", "HEAD", "--", "tests", "docs").decode().split():
    ids |= blobs(git("ls-tree", "-r", "-z", c, "--", "tests", "docs"))
batch = subprocess.run(["git", "cat-file", "--batch"], input="".join(i + "\n" for i in sorted(ids)).encode(),
                       check=True, capture_output=True).stdout
found, at = set(), 0
while at < len(batch):
    head_end = batch.index(b"\n", at)
    size = int(batch[at:head_end].split()[2])
    data = batch[head_end + 1:head_end + 1 + size]
    at = head_end + 1 + size + 1
    found.add(hashlib.sha256(data).hexdigest())
with open("rules/fixture_files.json", "w", encoding="utf-8") as f:
    f.write(json.dumps({"version": 1, "sha256": sorted(found)}, indent=1) + "\n")
print(f"rules/fixture_files.json: {len(found)} files of {len(ids)} blobs under tests/ and docs/")
PYEOF
