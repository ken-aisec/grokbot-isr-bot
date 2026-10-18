#!/usr/bin/env bash
# Golden-output check for the wt.py split into watchtower/wt_parts (no behavior change; D1/D2/D3).
#
#   scripts/golden-check.sh PRE_REF [quick|full] [ONLY]     PRE_REF (required): the commit before the split, 9b106b9;
#                                                           mode: full by default; ONLY: a regex of scenario names to run
#                                                           (to look at one again; one that matches none fails)
#
# Step 0 rebuilds the pre-split wt.py from the working tree and compares it byte for byte with PRE_REF's. Then PRE_REF's tree
# (twice, to calibrate) and the working tree's tracked files run the same commands from the same path in a sealed sandbox
# (unshare -rmn; scratch over /home, /workspace, /var/tmp and /tmp) and must match. quick: tier A from one folder plus one box.
# full: tier A from three folders, every box (CLI and driver), the forced crash, the state-changing commands, the installed copy
# and its tamper cases, and startup timing. Without the sandbox it fails. Everything is written under one mkdtemp folder in
# /tmp (see tests/golden_split.py).
set -euo pipefail
cd "$(dirname "$0")/.."
USAGE="usage: scripts/golden-check.sh PRE_REF [quick|full] [ONLY]   (PRE_REF is required: the commit before the split, 9b106b9)"
[[ $# -ge 1 && -n "$1" ]] || { echo "golden-check: no baseline ref given" >&2; echo "$USAGE" >&2; exit 2; }
PRE="$1"
MODE="${2:-full}"
[[ "$MODE" == quick || "$MODE" == full ]] || { echo "golden-check: the mode is quick or full, not $MODE" >&2; exit 2; }
git rev-parse --verify --quiet "$PRE^{commit}" >/dev/null || { echo "golden-check: unknown ref $PRE" >&2; exit 2; }
WT_GOLDEN_PRE="$PRE" WT_GOLDEN_TIERS="$MODE" WT_GOLDEN_ONLY="${3:-}" exec python3 -I -B -m unittest discover -s tests -p golden_split.py -v
