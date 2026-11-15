#!/usr/bin/env bash
# Regenerate rules/fixture_files.json: the sha256 of every file ever committed under tests/ or docs/ (every commit
# `git rev-list HEAD -- tests docs` names, plus the index) that holds at least one hit for ISR-T011's pattern
# (rules/text_rules.json) or a scheme://user:pass@ credential. Hashes only: no path, no value. The same history and index
# give the same bytes. Run it before scripts/make-manifest.sh.
set -euo pipefail
cd "$(dirname "$0")/.."
python3 -I - <<'PYEOF'
import hashlib, json, re, subprocess

URI = r"\b[A-Za-z][A-Za-z0-9+.-]*://[^\s/:@'\"]+:[^\s/@'\"]+@"   # a scheme://user:pass@ credential
rules = json.load(open("rules/text_rules.json", encoding="utf-8"))["rules"]
hit = [re.compile(next(r["pattern"] for r in rules if r["id"] == "ISR-T011")), re.compile(URI)]


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
    text = data.decode("utf-8", "replace")
    if any(rx.search(text) for rx in hit):
        found.add(hashlib.sha256(data).hexdigest())
with open("rules/fixture_files.json", "w", encoding="utf-8") as f:
    f.write(json.dumps({"version": 1, "sha256": sorted(found)}, indent=1) + "\n")
print(f"rules/fixture_files.json: {len(found)} files of {len(ids)} under tests/ and docs/")
PYEOF
