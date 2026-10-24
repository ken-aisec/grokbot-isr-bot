#!/usr/bin/env bash
# Release drill (precision plan item 8): run a dev build read-only against the real install.
#
# Everything the dry run writes lives in one fresh sandbox folder under /tmp (outside /workspace):
# the dev code, a copy of the install's state, caches, planted decoys and the report. Inside a
# private mount namespace /workspace is read-only, the state copy sits over the install's own
# state path (so paths match), and the sandbox folder is the namespace's /tmp. Afterwards only the
# report is kept (audit.json, audit.err); the state copy and decoys are removed with the sandbox.
#
#   scripts/dry-run.sh [REF] [-- wt.py args]      default REF=HEAD, args "audit"
#
# Env: ISR_DRY_KEEP=1 keeps the whole sandbox; ISR_DRY_OUT=<dir under /tmp> sets the report folder.
# ISR_DRY_WORKSPACE / ISR_DRY_INSTALL / ISR_DRY_TMPROOT / ISR_DRY_RO exist for the tests. ISR_DRY_RO lists
# extra folders made read-only (default: the home folder and /var/tmp, where the live decoys sit).
set -euo pipefail

DEV="$(cd "$(dirname "$0")/.." && pwd)"
WS="$(realpath -m "${ISR_DRY_WORKSPACE:-/workspace}")"
INSTALL="$(realpath -m "${ISR_DRY_INSTALL:-$WS/watchtower}")"
TMPROOT="$(realpath -m "${ISR_DRY_TMPROOT:-/tmp}")"
RO="${ISR_DRY_RO-$HOME /var/tmp}"
REF="HEAD"
if [[ $# -gt 0 && "$1" != "--" ]]; then REF="$1"; shift; fi
[[ "${1:-}" == "--" ]] && shift
ARGS=("$@"); [[ ${#ARGS[@]} -eq 0 ]] && ARGS=(audit)

inside() { [[ "$1" == "$2" || "$1" == "$2"/* ]]; }
die() { echo "dry-run: $*" >&2; exit 2; }

inside "$TMPROOT" "$WS" && die "sandbox root $TMPROOT is inside $WS; a dry run must leave $WS untouched"
[[ -d "$INSTALL/state" ]] || die "no install state at $INSTALL/state"
SHA="$(git -C "$DEV" rev-parse --short "$REF^{commit}")" || die "unknown ref $REF"
OUT="$(realpath -m "${ISR_DRY_OUT:-$TMPROOT/wt-dry-report-$SHA-$(date +%Y%m%dT%H%M%S)}")"
inside "$OUT" "$WS" && die "report folder $OUT is inside $WS"
command -v unshare >/dev/null || die "unshare is missing"

B="$(mktemp -d "$TMPROOT/wt-dry.XXXXXX")"
cleanup() { [[ "${ISR_DRY_KEEP:-}" == 1 ]] || rm -rf "$B"; }
trap cleanup EXIT
mkdir -p "$B/code" "$B/state" "$B/cache" "$B/out"
git -C "$DEV" archive "$SHA" | tar -x -C "$B/code"
cp -a "$INSTALL/state/." "$B/state/"

# B is bound over /tmp last, so after that every sandbox path is /tmp/<name>.
set +e
WS="$WS" INSTALL="$INSTALL" B="$B" RO="$RO" unshare -rm --propagation private bash -s -- "${ARGS[@]}" <<'INNER'
set -e
mount --rbind "$WS" "$WS"
mount -o remount,bind,ro "$WS"
for d in $RO; do [ -d "$d" ] || continue; mount --rbind "$d" "$d"; mount -o remount,bind,ro "$d"; done
mount --bind "$B/state" "$INSTALL/state"
mount --bind "$B" /tmp
export PYTHONDONTWRITEBYTECODE=1 XDG_CACHE_HOME=/tmp/cache TMPDIR=/tmp ISR_BOT_HOME="$INSTALL"
cd /tmp
set +e
python3 -W ignore /tmp/code/watchtower/wt.py "$@" > /tmp/out/audit.json 2> /tmp/out/audit.err
rc=$?
echo "exit=$rc" >> /tmp/out/audit.err
exit $rc
INNER
rc=$?
set -e

mkdir -p "$OUT"
cp -a "$B/out/." "$OUT/"
echo "dry-run $SHA exit=$rc report=$OUT/audit.json$([[ "${ISR_DRY_KEEP:-}" == 1 ]] && echo " sandbox=$B")"
exit $rc
