#!/usr/bin/env bash
# Golden-output check for the wt.py split into watchtower/wt_parts (no behavior change; D1/D2/D3), and for later changes that
# alter behavior on purpose (expect mode, batch 5).
#
#   scripts/golden-check.sh PRE_REF [quick|full] [ONLY] [--expect FILE --items A,B]
#                                                           PRE_REF (required): the commit to compare with (9b106b9 for the
#                                                           split); mode: full by default; ONLY: a regex of scenario names to run
#                                                           (to look at one again; one that matches none fails)
#
# Step 0 rebuilds the pre-split wt.py from the working tree and compares it byte for byte with PRE_REF's. Then PRE_REF's tree
# (twice, to calibrate) and the working tree's tracked files run the same commands from the same path in a sealed sandbox
# (unshare -rmn; scratch over /home, /workspace, /var/tmp and /tmp) and must match. quick: tier A from one folder plus one box.
# full: tier A from three folders, every box (CLI and driver), the forced crash, the state-changing commands, the installed copy
# and its tamper cases, and startup timing. Without the sandbox it fails. Everything is written under one mkdtemp folder in
# /tmp (see tests/golden_split.py).
#
# --expect FILE (tests/golden_expect/*.json) --items A,B: step 0 only checks that the rebuilt wt.py compiles and that PRE_REF has
# the loader block, and post may differ from pre only by lines an entry of an enabled item expects (an empty --items: none may).
# Without --expect the check is exactly the split check.
set -euo pipefail
cd "$(dirname "$0")/.."
USAGE="usage: scripts/golden-check.sh PRE_REF [quick|full] [ONLY] [--expect FILE --items A,B]   (PRE_REF is required: the commit before the split, 9b106b9)"
POS=()
EXPECT=""
ITEMS=""
HAVE_ITEMS=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --expect) [[ $# -ge 2 && -n "$2" ]] || { echo "golden-check: --expect needs a file" >&2; echo "$USAGE" >&2; exit 2; }
              EXPECT="$2"; shift 2 ;;
    --items) [[ $# -ge 2 ]] || { echo "golden-check: --items needs a list (it may be empty: --items '')" >&2; exit 2; }
             ITEMS="$2"; HAVE_ITEMS=1; shift 2 ;;
    *) POS+=("$1"); shift ;;
  esac
done
set -- ${POS[@]+"${POS[@]}"}
[[ $# -ge 1 && -n "$1" ]] || { echo "golden-check: no baseline ref given" >&2; echo "$USAGE" >&2; exit 2; }
PRE="$1"
MODE="${2:-full}"
[[ "$MODE" == quick || "$MODE" == full ]] || { echo "golden-check: the mode is quick or full, not $MODE" >&2; exit 2; }
[[ -z "$EXPECT" || -f "$EXPECT" ]] || { echo "golden-check: no expect file $EXPECT" >&2; exit 2; }
[[ -n "$EXPECT" || "$HAVE_ITEMS" == 0 ]] || { echo "golden-check: --items needs --expect FILE" >&2; exit 2; }
git rev-parse --verify --quiet "$PRE^{commit}" >/dev/null || { echo "golden-check: unknown ref $PRE" >&2; exit 2; }
ISR_GOLDEN_PRE="$PRE" ISR_GOLDEN_TIERS="$MODE" ISR_GOLDEN_ONLY="${3:-}" ISR_GOLDEN_EXPECT="$EXPECT" ISR_GOLDEN_ITEMS="$ITEMS" \
  exec python3 -I -B -m unittest discover -s tests -p golden_split.py -v
