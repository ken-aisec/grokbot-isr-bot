#!/usr/bin/env bash
# ISR Bot backup before an upgrade. Copies ISR Bot's own folders and leaves the decoy registry out.
# Usage: bash backup.sh [dest]   default dest /workspace/backups/isr-bot-pre-upgrade-<UTC YYYYmmdd-HHMM>
# state/canaries* holds the decoy values: a copy of it anywhere else is a decoy value copied into another file, and the
# decoy-copy check (ISR-K003) rightly calls that critical. So the backup never keeps it; after a restore, plant fresh decoys.
set -euo pipefail
ISR_HOME="${ISR_BOT_HOME:-/workspace/isr-bot}"
DEST="${1:-/workspace/backups/isr-bot-pre-upgrade-$(date -u +%Y%m%d-%H%M)}"

# Refused before anything is written
if [[ ! -d "$ISR_HOME" ]]; then echo "NOT BACKED UP - $ISR_HOME is missing"; exit 1; fi
if [[ -e "$DEST" || -L "$DEST" ]]; then echo "NOT BACKED UP - $DEST already exists; name a new folder"; exit 1; fi
HOME_REAL="$(realpath -e -- "$ISR_HOME")"; DEST_REAL="$(realpath -m -- "$DEST")"
case "$DEST_REAL/" in "$HOME_REAL"/*) echo "NOT BACKED UP - $DEST is inside $ISR_HOME"; exit 1;; esac

mkdir -p -- "$(dirname -- "$DEST")"
mkdir -m 700 -- "$DEST"                                   # a new folder of its own, private while it fills
DONE=""; trap '[[ -n "$DONE" ]] || rm -rf -- "$DEST"' EXIT   # a copy that stops part way is removed whole
COPIED=()
for e in app state exports vet reports install.sh; do       # never scanners, backups or .stage.*
  if [[ -e "$ISR_HOME/$e" || -L "$ISR_HOME/$e" ]]; then cp -a -- "$ISR_HOME/$e" "$DEST/"; COPIED+=("$e"); fi
done
# From the copy only, by the copy's path; find and rm never follow a link (a link named canaries* goes as a link)
if [[ -d "$DEST/state" && ! -L "$DEST/state" ]]; then
  find "$DEST/state" -depth -name 'canaries*' -exec rm -rf -- {} +
  if [[ -n "$(find "$DEST/state" -name 'canaries*' -print -quit)" ]]; then
    echo "NOT BACKED UP - a state/canaries* file could not be taken out of the copy; the copy was removed"; exit 1
  fi
fi
chmod 0700 -- "$DEST"
DONE=1
echo "Backup made at $DEST (only you can open it): ${COPIED[*]:-nothing was there to copy}."
echo "Left out: state/canaries* (the decoy registry). It holds the decoy values, so a copy of it in a backup trips ISR-K003, a critical alarm."
echo "After a restore, make fresh decoys: python3 -I $ISR_HOME/app/isr_bot/isr.py canary plant"
