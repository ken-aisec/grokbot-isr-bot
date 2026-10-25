#!/usr/bin/env bash
# ISR Bot installer. Pinned, checksummed, and confined to /workspace/isr-bot.
# Usage: bash install.sh v0.8.1 [commit]   install that tagged release; with a commit ID, refuse anything else
#        bash install.sh --scanners        add the optional scanners (second half of this file)
set -euo pipefail
ISR_HOME="${ISR_BOT_HOME:-/workspace/isr-bot}"
REPO="https://github.com/ken-aisec/grokbot-isr-bot"

if [[ "${1:-}" != "--scanners" ]]; then
  # ---- This is everything that runs for `bash install.sh <tag>`. It only writes inside $ISR_HOME.
  TAG="${1:?usage: install.sh <tag> [commit]  (for example v0.8.1)}"; WANT="${2:-}"
  mkdir -p "$ISR_HOME"/{state,reports,exports,vet}
  # Private staging (0700, unpredictable name, removed on any exit): nothing else can plant a link in it.
  STAGE="$(mktemp -d "$ISR_HOME/.stage.XXXXXXXX")"; chmod 700 "$STAGE"; OLD="$STAGE/old"
  # Interrupted between the two moves: put the old working copy back before the stage is removed.
  trap '[[ ! -e "$ISR_HOME/app" && -e "$OLD" ]] && /bin/mv "$OLD" "$ISR_HOME/app"; rm -rf "$STAGE"' EXIT; trap 'exit 130' INT TERM HUP
  NEW="$STAGE/app"
  git -c advice.detachedHead=false clone --quiet --depth 1 --branch "$TAG" "$REPO" "$NEW"
  GOT="$(git -C "$NEW" rev-parse HEAD)"
  # The commit ID is a checksum of every file. When the template gives one, a changed tag or repo can't slip through.
  if [[ -n "$WANT" && "$GOT" != "$WANT" ]]; then
    echo "COMMIT CHECK FAILED - not installing (wanted $WANT, the tag points at $GOT)"; exit 1
  fi
  (cd "$NEW" && sha256sum --quiet -c MANIFEST.sha256) || { echo "MANIFEST CHECK FAILED - not installing"; exit 1; }
  # Try the new copy before it replaces anything; the working copy and its commit record are only swapped after it runs.
  python3 -I "$NEW/isr_bot/isr.py" --version >/dev/null 2>&1 || { echo "ACTIVATION CHECK FAILED - the new version doesn't start here; the installed copy is unchanged"; exit 1; }
  [[ -e "$ISR_HOME/app" ]] && mv "$ISR_HOME/app" "$OLD"
  PREV="$(cat "$ISR_HOME/state/installed_commit" 2>/dev/null || true)"
  mv "$NEW" "$ISR_HOME/app"
  echo "$GOT" > "$ISR_HOME/state/installed_commit"   # isr.py checks itself against this and the manifest before every run
  if ! python3 -I "$ISR_HOME/app/isr_bot/isr.py" --version >/dev/null 2>&1; then
    rm -rf "$ISR_HOME/app"; [[ -e "$OLD" ]] && mv "$OLD" "$ISR_HOME/app"
    if [[ -n "$PREV" ]]; then echo "$PREV" > "$ISR_HOME/state/installed_commit"; else rm -f "$ISR_HOME/state/installed_commit"; fi
    echo "ACTIVATION FAILED - put the previous version back"; exit 1
  fi
  echo "ISR Bot $TAG installed at $ISR_HOME/app (commit $GOT, manifest verified$([[ -n "$WANT" ]] && echo ", commit matches the template"))."
  echo "NEXT: read $ISR_HOME/app/skills/isr-bot-setup/SKILL.md and follow it from section 2."
  echo "Your skills are the SKILL.md files under $ISR_HOME/app/skills/<name>/. Read the one you need when asked; never edit them."
  exit 0
fi

# ---- Optional scanners: bash install.sh --scanners
GITLEAKS_VERSION="8.30.1"
TRUFFLEHOG_VERSION="3.97.9"
OSV_VERSION="2.6.0"
# Claude review 1 (6): `python3 -m venv` leaves an existing scanners/bin/python* link alone, so a re-pointed one survived
# the reinstall ISR-X005 tells the owner to run, and this script's own pip ran through it. They are made new every time.
rm -f "$ISR_HOME/scanners/bin/python" "$ISR_HOME"/scanners/bin/python[0-9]*
# Claude review 2 (4): nor bin/pip, the entry points or site-packages (pip skips what is already installed), so a swapped
# skillspector survived too and a planted pip ran below. The environment is made from scratch: everything in it is installed
# again (rm -rf, not venv --clear: --clear empties the folder that a link named scanners points to).
rm -rf "$ISR_HOME/scanners"
python3 -m venv "$ISR_HOME/scanners" || { echo "This computer can't create a Python environment, so the Python scanners are skipped."; }
PIP="$ISR_HOME/scanners/bin/pip"; LOCK="$ISR_HOME/app/scripts/scanners.lock"; rm -f "$ISR_HOME/scanners/LOCKED"
SS="skillspector @ git+https://github.com/NVIDIA/SkillSpector@a50b9c93835c94f7d36329f11c6599abbb9c74ee"
# Pinned and checksummed: a security tool that installs unpinned scanners is its own supply-chain risk.
# The lock lists every package the scanners need with its checksum; pip refuses anything that doesn't match.
# If the lock can't be used, the Python scanners are not installed without it (up to v0.6.6 this fell back to unchecked
# downloads). gitleaks, TruffleHog and OSV-Scanner don't come from the lock: they still install from their own checksums,
# and the script ends with CHECKSUM LOCK FAILED and a non-zero exit so the failure is never missed.
DL="$(mktemp -d "${TMPDIR:-/tmp}/isr-bot-dl.XXXXXXXX")"; chmod 700 "$DL"; trap 'rm -rf "$DL"' EXIT   # private: no shared-/tmp link games
LOCK_ERR="$DL/isr-bot-lock.err"; LOCK_FAILED=""
if [[ -f "$LOCK" ]] && "$PIP" install --quiet --require-hashes -r "$LOCK" 2>"$LOCK_ERR" \
   && "$PIP" install --quiet --no-deps "$SS" 2>>"$LOCK_ERR"; then
  touch "$ISR_HOME/scanners/LOCKED"; echo "Scanners installed from the checksum lock."
else
  LOCK_FAILED=1
  if [[ -f "$LOCK" ]]; then
    echo "CHECKSUM LOCK FAILED - not installing the Python scanners. pip refused the checksummed packages on this computer's Python ($(python3 --version 2>&1)):"
    tail -n 5 "$LOCK_ERR" 2>/dev/null | sed 's/^/  /' || true
  else
    echo "CHECKSUM LOCK FAILED - not installing the Python scanners: $LOCK is missing."
  fi
  echo "Nothing is installed without checksums. gitleaks, TruffleHog and OSV-Scanner still install from their own checksums."
  rm -rf "$ISR_HOME/app.new"   # a staging folder left by a version before v0.6.9
fi
# Batch 3: every scanner lives in $ISR_HOME/scanners/bin, the only folder ISR Bot runs scanners from, and only when the
# program matches scripts/scanner-bins.lock. The old $ISR_HOME/bin copy of each tool is removed once the new one is in.
SB="$ISR_HOME/scanners/bin"; mkdir -p "$SB"
arch="$(uname -m)"; case "$arch" in x86_64) ga=x64;; aarch64|arm64) ga=arm64;; *) echo "skip gitleaks: $arch"; ga="";; esac
if [[ -n "$ga" ]]; then
  # Each tool installs on its own: if one download or checksum fails, that tool is not installed, the others still are,
  # and the audit says which is missing. (&& chains on purpose: nothing is unpacked unless its checksum passed.)
  tgz="gitleaks_${GITLEAKS_VERSION}_linux_${ga}.tar.gz"
  base="https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}"
  curl -fsSL -o "$DL/$tgz" "$base/$tgz" \
    && curl -fsSL -o "$DL/gitleaks_checksums.txt" "$base/gitleaks_${GITLEAKS_VERSION}_checksums.txt" \
    && (cd "$DL" && grep " $tgz\$" gitleaks_checksums.txt | sha256sum -c -) \
    && tar --no-same-owner -xzf "$DL/$tgz" -C "$SB" gitleaks && rm -f "$ISR_HOME/bin/gitleaks" \
    || echo "gitleaks did not install; ISR Bot works without it."
  # TruffleHog: tells live keys from dead ones (asks each key's own provider)
  th="trufflehog_${TRUFFLEHOG_VERSION}_linux_$( [ "$ga" = x64 ] && echo amd64 || echo arm64 ).tar.gz"
  tb="https://github.com/trufflesecurity/trufflehog/releases/download/v${TRUFFLEHOG_VERSION}"
  curl -fsSL -o "$DL/$th" "$tb/$th" \
    && curl -fsSL -o "$DL/trufflehog_checksums.txt" "$tb/trufflehog_${TRUFFLEHOG_VERSION}_checksums.txt" \
    && (cd "$DL" && grep " $th\$" trufflehog_checksums.txt | sha256sum -c -) \
    && tar --no-same-owner -xzf "$DL/$th" -C "$SB" trufflehog && rm -f "$ISR_HOME/bin/trufflehog" \
    || echo "TruffleHog did not install; ISR Bot works without it."
  # OSV-Scanner: known holes in Node, Go and other project dependencies
  ob="osv-scanner_linux_$( [ "$ga" = x64 ] && echo amd64 || echo arm64 )"
  curl -fsSL -o "$SB/osv-scanner.new" "https://github.com/google/osv-scanner/releases/download/v${OSV_VERSION}/$ob" \
    && curl -fsSL -o "$DL/osv_sums.txt" "https://github.com/google/osv-scanner/releases/download/v${OSV_VERSION}/osv-scanner_SHA256SUMS" \
    && (cd "$SB" && grep " $ob\$" "$DL/osv_sums.txt" | sed "s/$ob/osv-scanner.new/" | sha256sum -c -) \
    && chmod +x "$SB/osv-scanner.new" && mv "$SB/osv-scanner.new" "$SB/osv-scanner" && rm -f "$ISR_HOME/bin/osv-scanner" \
    || { rm -f "$SB/osv-scanner.new"; echo "OSV-Scanner did not install; ISR Bot works without it."; }
fi
[[ -z "$LOCK_FAILED" ]] && { "$ISR_HOME/scanners/bin/skillspector" --version || echo "SkillSpector did not install; ISR Bot works without it and says so in the audit."; }
[[ -x "$SB/gitleaks" ]] && "$SB/gitleaks" version || true
rm -f "$DL"/gitleaks_*_linux_*.tar.gz "$DL/gitleaks_checksums.txt" "$DL"/trufflehog_*_linux_*.tar.gz "$DL/trufflehog_checksums.txt" "$DL/osv_sums.txt" "$LOCK_ERR"
if [[ -n "$LOCK_FAILED" ]]; then
  echo "CHECKSUM LOCK FAILED - the Python scanners (SkillSpector, husk) were not installed. ISR Bot works without them and the audit says which are missing."
  exit 1
fi
echo "Scanners installed in $SB. ISR Bot runs only these programs, and only when each matches scripts/scanner-bins.lock."
