#!/usr/bin/env python3
"""ISR Bot: read-only security watch for a Grok Bot cloud computer.

Scripts find, the model judges, the human approves. Stdlib only; optional
external scanners (skillspector, husk, gitleaks, trufflehog, osv-scanner, pip-audit)
run only from ISR Bot's own scanners/bin folder, and only when each program's
sha256 is in scripts/scanner-bins.lock. A scanner on PATH is never run.

Commands
  vet FILE|-            score a template, skill, or routine text before install
  audit                 full posture audit; writes findings.json and updates state
  daily                 quick audit; prints NO_CHANGES or a compact delta
  report                weekly Markdown report + self-contained HTML dashboard
  baseline              (re)take the integrity baseline without reporting
  fix                   preview, then one-yes cleanup, upgrades, re-vet of changed skills
  diff SKILL            what changed in a skill since it was approved
  exception add SKILL   owner-confirmed 30-day exception for one security-tool skill
  doctor [--save]       a support snapshot of this computer that is safe to share

State lives in $ISR_BOT_HOME (default /workspace/isr-bot).
"""
import sys
if sys.version_info < (3, 8):   # degrade with one plain line, not a traceback (v0.6.9 old-Python profile)
    print("ISR Bot needs Python 3.8 or newer; this computer has " + ".".join(map(str, sys.version_info[:3])) + ". Nothing was run.")
    sys.exit(3)
import argparse, bisect, builtins, concurrent.futures, datetime as dt, difflib, errno, functools, gzip, hashlib, heapq, html, json, math, os, platform, re, shutil, signal, stat, subprocess, sys, tempfile, threading, time, traceback

VERSION = "0.8.1"
HERE = os.path.dirname(os.path.realpath(__file__))   # PR A, Codex round 2 (5): the file that runs, through any link to it
RULES_PATH = os.path.join(HERE, "..", "rules", "text_rules.json")
SELF_ROOT = os.path.dirname(HERE)
SEV_WEIGHT = {"critical": 25, "high": 10, "medium": 4, "low": 1, "info": 0}
SEV_ORDER = ["critical", "high", "medium", "low", "info"]
CATEGORY_CAP = 30
LOW_CAP = 5
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", ".cache", "site-packages", "proc", "sys",
             "google-chrome", "chromium", "Chrome", "BraveSoftware", "mozilla", "Cache", "Code Cache", "GPUCache",
             "Service Worker", "IndexedDB", "WasmTtsEngine", "Crashpad", ".npm", ".pnpm-store", ".cargo", ".rustup"}
SKIP_PREFIXES = ("scoped_dir", ".org.chromium", "tmp")
SKIP_PATH_PARTS = ("/go/pkg/", "/pkg/mod/", "/.local/go/", "/.config/google-chrome", "/.config/chromium", "/chrome-profile/", "/.m2/", "/.gradle/", "/dist-packages/", "/.bun/install/", "/.local/share/pnpm/")
TEXT_EXT = {".md", ".txt", ".json", ".jsonl", ".ndjson", ".log", ".yaml", ".yml", ".toml", ".py", ".sh", ".js", ".ts", ".env", ".cfg", ".ini", ".pem", ""}
# (batch 6, B5: .pem, so a key file is read on a rules-only install too; .key stays out, it is often binary or a Keynote file)
SECRET_RULE = "ISR-T011"


# >>> isr_parts loader (reassembly drops this block)
_ISR_PARTS = os.path.join(HERE, "isr_parts")


def _isr_part(name):
    """Run isr_bot/isr_parts/<name>.py in this module's namespace, compiled from its source bytes: no bytecode cache is
    read or written (a planted __pycache__ file never runs; Codex, batch 3 round 2), and nothing depends on sys.path or the
    current folder, so `python3 -I` works. A part that is missing, a link or not a plain file stops the run in one plain line."""
    path = os.path.join(_ISR_PARTS, name + ".py")
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise ValueError("not a plain file")
            with os.fdopen(fd, "rb") as f:
                fd = None
                src = f.read()
        finally:
            if fd is not None:
                os.close(fd)
        code = compile(src, path, "exec", dont_inherit=True)
    except (OSError, ValueError, SyntaxError):
        print(f"SELF-CHECK FAILED - ISR Bot stopped before doing anything. Its own file isr_bot/isr_parts/{name}.py is missing"
              " or not a plain file. Tell the owner now. Don't run ISR Bot again until they reinstall it from the release"
              " (setup skill, section 1).")
        sys.exit(4)
    exec(code, globals())   # noqa: S102 - ISR Bot's own file, from its bytes; held to MANIFEST.sha256 by self_check
# <<< isr_parts loader


_isr_part("state")


_isr_part("mask")


_isr_part("text")


_isr_part("scoring")


_isr_part("vet")


_isr_part("collect")


_isr_part("ownership")


_isr_part("platform_lock")


_isr_part("scope")


_isr_part("audit")


_isr_part("settings_lint")


_isr_part("scanners")


_isr_part("engines")


_isr_part("secrets_pkgs")


_isr_part("plugins")


_isr_part("baseline")


def cmd_audit(args):
    try:
        snap, new, fixed = run_audit(args, quick=False)
    except Busy:
        print("ERROR another ISR Bot run has been going for 15 minutes; try again when it finishes (`isr.py status`)", file=sys.stderr)
        return 2
    all_new, new = new, [f for f in new if not platform_scope(f)]   # batch 5 (d1): Grok Bot's own files are platform notes, never new
    out = {"status": snap_status(snap), "score": snap["score"], "score_line": score_line(snap), "grade": snap_grade(snap), "new": [compact(f) for f in new][:20],
           "fixed": [compact(f) for f in fixed][:10], "open_by_severity": by_sev(owners(snap["findings"])),
           "top_fixes": [compact(f) for f in snap["findings"] if (f.get("scope") != "platform" or counts(f)) and not f.get("guarded")][:3],   # round 1 (5): a counted key too
           "notes": snap["notes"], "inventory": snap["inventory"]}
    amap = load_access_map()
    if amap is not None:   # batch 5 (a): one line; `isr.py access` has the map
        out["access"] = access_summary(amap)
    # Codex, batch 4 round 2: the whole delta is kept before anything is cut, in a file of this run's own (a second run writes
    # another), and the counts say how much of it the JSON shows: `truncated` counts from the full lists, not from the first 20.
    out["new_total"], out["fixed_total"] = len(new), len(fixed)
    cut = {k: n - shown_ for k, n, shown_ in (("new", len(new), 20), ("fixed", len(fixed), 10)) if n > shown_}
    if cut:
        out["truncated"] = cut
    path = save_delta(all_new, fixed)   # the record keeps every new finding, platform notes included
    if path:
        out["delta_file"] = path
    out.update(score_change(snap, new))
    exc = exceptions_active(snap)
    if exc:
        out["security_tool_exceptions"] = exc
    if snap.get("scanners_missing"):
        out["scanners_missing"] = snap["scanners_missing"]
    if snap.get("stages_skipped"):
        out["stages_skipped"] = snap["stages_skipped"]
        out["not_checked_this_run"] = list(snap["stages_skipped"])   # DQ-025: same meaning as daily
    out["not_counted_builtin"] = sum(1 for f in snap["findings"] if not counts(f))
    look = [f for f in snap["findings"] if f.get("class") == "pattern"]
    if look:   # no severity, not scored: read each in full and try to show it's a false alarm before showing it (isr.py dismiss)
        out["worth_a_look"] = [dict(compact(f), key=f["key"]) for f in look][:15]
    tips = [f for f in snap["findings"] if f.get("class") == "tip"]
    if tips:
        out["tips"] = [compact(f) for f in tips][:10]
    warn = sum(1 for f in snap["findings"] if f.get("guarded"))
    if warn:   # batch 2 (R1): defensive wording kept as records; `isr.py breakdown` lists them
        out["warning_text_count"] = warn
    # v0.7.1 item 4: Grok Bot's own files, one line each, never scored. Batch 5 (d1): plain lines, outside every count; `platform`
    # is the same lines under the old name, for one release. Codex round 1 (9): they take only the room the owner's part leaves.
    notes = platform_notes(snap["findings"], 8, snap.get("vendor"))
    alerts = scanner_alerts(snap)
    if alerts:
        out["scanner_alerts"] = alerts
    # batch 5 (a): the access line brings its own room, so the owner's part is fitted exactly as without it (it never costs a finding)
    room = len(json.dumps(out, indent=1)) - len(json.dumps({k: v for k, v in out.items() if k != "access"}, indent=1))
    print(fit_owner_first(out, notes, limit=4096 + room, keep=("scanner_alerts",), alias=True, before="scanner_alerts"))
    return 0


DELTA_KEEP = 20   # delta files kept (newest first)


def save_delta(new, fixed):
    """This run's complete delta (every new and fixed finding, evidence masked) in state/deltas/, or None when nothing changed or
    it can't be written. The weekly retry reads it after a second run has made the first run's findings old (Codex, round 2)."""
    if not new and not fixed:
        return None
    d = state_path("deltas")
    try:
        os.makedirs(d, exist_ok=True)
        path = os.path.join(d, f"audit-{time.time_ns()}.json")
        rec = lambda f: mask_stored([dict(compact(f), key=f["key"])])[0]   # Codex, round 3: each record masked as it is written
        save_json(path, {"at": now(), "new": [rec(f) for f in new], "fixed": [rec(f) for f in fixed]})
        for old in sorted(fn for fn in os.listdir(d) if fn.startswith("audit-") and fn.endswith(".json"))[:-DELTA_KEEP]:
            os.remove(os.path.join(d, old))
    except OSError:
        return None
    return path


def scanner_alerts(snap):
    """Claude review 2 (5): every open ISR-X005 in its own list, which fit() never trims (like daily's decoys). Findings sort by
    severity, then rule, so ten new critical or high findings pushed a swapped scanner's high X005 out of `new` and `top_fixes`;
    from the next day it wasn't new, and daily never showed it again."""
    return [compact(f) for f in snap.get("findings", []) if f.get("rule") == "ISR-X005"]


def score_change(snap, new):
    """One plain line when the score falls by 10 or more, so a new user sees why instead of just a low number."""
    prev = snap.get("previous_score")
    if prev is None or prev - snap["score"] < 10:
        return {}
    big = [f for f in new if f["severity"] in ("critical", "high") and counts(f)]
    names = []
    for f in big:
        w = f["where"].split(":")[0]
        n = ("Bot " + f["where"].split(":")[1]) if f["where"].startswith("rollcall:") else skill_name(skill_root(w) or w)
        if n not in names:
            names.append(n)
    return {"score_was": prev, "why_it_dropped": f"{len(big)} new critical or high findings in {len(names)} place(s): " + ", ".join(names[:6])
            + (f" and {len(names) - 6} more" if len(names) > 6 else "") + ". Dealing with those brings the score back."}


def fit(obj, limit=4096, keep=()):
    """Keep the model handoff under `limit` bytes by trimming the longest list, never by cutting JSON. Lists named in `keep`
    are never trimmed."""
    obj = json.loads(json.dumps(obj))
    while len(json.dumps(obj, indent=1)) > limit:
        lists = [(len(v), k) for k, v in obj.items() if isinstance(v, list) and v and k not in keep]
        if not lists:
            break
        _, k = max(lists)
        obj.setdefault("truncated", {})
        obj["truncated"][k] = obj["truncated"].get(k, 0) + 1
        obj[k].pop()
    return json.dumps(obj, indent=1)


PLATFORM_NOTES_BYTES = 1536   # what platform notes may add to the owner's part (Codex round 1, 9: their own budget)


def fit_owner_first(obj, notes, limit=4096, keep=(), alias=False, before=None, budget=PLATFORM_NOTES_BYTES):
    """PR A, Codex round 1 (9, 10): platform notes never cost the owner a finding. The owner's part is fitted first, in the whole
    `limit`, exactly as fit() does without notes; then platform_notes ({count, lines[, more]}, placed before the key `before`)
    takes the room the owner's part left plus its own `budget` bytes, a line at a time (the loud ones first: platform_notes), and
    the `platform` alias (alias=True, audit) gets its copies of those lines last, so its lines go first. What doesn't fit is said:
    `more` (how many, how many of them ISR Bot would call critical or high, and `isr.py breakdown`, which lists every one) and
    `truncated` `platform`."""
    obj = json.loads(fit(obj, limit=limit, keep=keep))
    if not notes:
        return json.dumps(obj, indent=1)
    limit = max(limit, len(json.dumps(obj, indent=1))) + budget
    pn, al = {"count": notes["count"], "lines": []}, []

    def text():
        out, at = {}, before if before in obj else None
        for k, v in list(obj.items()) + [(None, None)]:
            if k == at:
                out["platform_notes"] = pn
                if alias:
                    out["platform"] = al
            if k is not None:
                out[k] = v
        return json.dumps(out, indent=1)

    def say_more():
        pn.pop("more", None)
        if pn["count"] > len(pn["lines"]):
            pn["more"] = notes_more(pn["count"], notes["loud"], len(pn["lines"]))

    for line in notes["lines"]:
        pn["lines"].append(line)
        say_more()
        if len(text()) > limit:
            pn["lines"].pop()
            break
    say_more()
    if alias:
        for line in pn["lines"]:
            al.append(line)
            if len(text()) > limit:
                al.pop()
                break
        if len(al) < len(pn["lines"]):
            obj.setdefault("truncated", {})["platform"] = len(pn["lines"]) - len(al)
    return text()


def cmd_daily(args):
    sweep_old_replies()
    try:
        snap, new, fixed = run_audit(args, quick=True)
    except Busy:
        print("BUSY another ISR Bot run is in progress; this daily check was skipped")
        return 0
    # PR A, Codex round 2 (6): a critical or high finding an earlier run had no room to name is still to be said: never NO_CHANGES
    pending = undelivered_open(snap, new)
    moved = snap.get("plugin_version_changes") or []   # DQ-047 fix round 1: a pending plugin's version bump is said, never NO_CHANGES
    if snap.get("scanners_missing") and not new and not fixed and not pending and not moved:
        print("SCANNERS_MISSING " + ", ".join(snap["scanners_missing"]) + ": run `bash /workspace/isr-bot/app/scripts/install.sh --scanners`, then `isr.py daily` again")
        return 0
    gap = list(snap.get("stages_skipped") or [])
    if not new and not fixed and not pending and not moved:
        # R04: nothing changed among what WAS checked; a stage that didn't finish is said, never hidden behind NO_CHANGES
        print(f"NO_CHANGES_BUT_NOT_CHECKED {'; '.join(gap)[:300]}: these were not checked this run (last results kept)" if gap else "NO_CHANGES")
        return 0
    out = {"score": snap["score"], "score_line": score_line(snap)}
    out["status"] = snap_status(snap)
    if snap.get("scanners_missing"):   # batch 3 (R7): said, but never in place of what is new (a decoy alarm included)
        out["scanners_missing"] = snap["scanners_missing"]
    if gap:
        out["not_checked_this_run"] = gap
    if moved:
        out["plugin_version_changes"] = moved
    out.update(score_change(snap, new))
    decoys = [compact(f) for f in new if f["rule"].startswith("ISR-K")]
    if decoys:
        out["decoys"] = decoys      # always shown, whatever else is new
    if pending:   # PR A, Codex round 2 (6): first, never cut short: what earlier runs couldn't name
        out["not_yet_reported"] = [alert_line(f) for f in pending[:PENDING_SHOWN]]
    # batch 5 (d1): a new finding in Grok Bot's own files is said in platform_notes, never in `new` (a vendor rug pull still breaks
    # NO_CHANGES). Codex round 1 (10): critical and high ones first, and any left out are counted in `more`, with the command.
    note_fs = [f for f in new if platform_scope(f)]
    notes = platform_notes(note_fs, 5)
    rest = [f for f in new if not f["rule"].startswith("ISR-K") and not platform_scope(f)]
    out["new"] = [dict(compact(f), key=f["key"]) if f.get("class") == "pattern" else compact(f) for f in rest][:10]
    if len(rest) > 10:
        out["more_new"] = f"{len(rest) - 10} more new findings not shown, none more severe than {rest[10]['severity']}. `isr.py breakdown` lists everything."
    out["fixed"] = [compact(f) for f in fixed][:10]
    alerts = scanner_alerts(snap)
    if alerts:
        out["scanner_alerts"] = alerts
    text = fit_owner_first(out, notes, limit=6000, keep=("decoys", "scanner_alerts", "not_yet_reported", "plugin_version_changes"), before="new")
    # PR A, Codex round 2 (6): every critical or high finding this output doesn't name (no room) is kept as undelivered in the
    # snapshot until a daily run names it, and is listed whole in a file the routine must read and name from, today
    said = json.loads(text)
    named = {f["key"] for f in pending[:len(said.get("not_yet_reported", []))]} | {f["key"] for f in rest[:len(said["new"])]}
    named |= {f["key"] for f in platform_note_order(note_fs)[:len((said.get("platform_notes") or {}).get("lines", []))]}
    left = []
    for f in pending + rest + platform_note_order(note_fs):
        if f["key"] not in named and is_alert(f, snap):
            named.add(f["key"])
            left.append(f)
    keep_undelivered(snap, left)
    if left:
        path = save_undelivered(left, snap)
        said = dict(list(said.items())[:3] + [("undelivered", {
            "count": len(left), "file": path,
            "next": f"{len(left)} critical or high finding{'' if len(left) == 1 else 's'} this output had no room to name. Read the file "
                    "and name every one (severity, title, where), one line each, beyond the 6-line limit. Until a daily run names one "
                    "itself, it is listed again under not_yet_reported."})] + list(said.items())[3:])
        text = json.dumps(said, indent=1)
    print(text)
    return 0


PENDING_SHOWN = 10   # PR A, Codex round 2 (6): earlier critical or high findings named per daily run (the rest wait, listed in the file)


def is_alert(f, snap):
    """A finding the daily routine must name: an owner's critical or high one, or a platform note ISR Bot would call critical or
    high. Decoys and scanner alerts are always shown whole."""
    if f["rule"].startswith("ISR-K") or f["rule"] == "ISR-X005" or f.get("guarded"):
        return False
    if platform_scope(f):
        return loud_note(f)
    return f.get("severity") in ("critical", "high")


def alert_line(f):
    """A short line naming a finding: severity (what ISR Bot would call a platform note), title, where."""
    out = {"severity": f.get("severity_was") or f["severity"], "title": f["title"], "where": f["where"]}
    if platform_scope(f):
        out["platform"] = "Grok Bot's own file, not counted: report it to Grok Bot support"
    return out


def undelivered_open(snap, new):
    """The open findings an earlier daily run had no room to name (the snapshot's `undelivered` keys, carried by run_audit), in
    their findings order. Only open findings with those keys count, so a key added to the file can only bring back an alert."""
    keys = {k for k in snap.get("undelivered") or [] if isinstance(k, str)}
    fresh = {f["key"] for f in new}
    return [f for f in shown(snap.get("findings", [])) if f["key"] in keys and f["key"] not in fresh and is_alert(f, snap)]


def keep_undelivered(snap, left):
    """Record `left` (findings the daily output didn't name) as the snapshot's `undelivered` keys."""
    keys = sorted({f["key"] for f in left})
    if keys != snap.get("undelivered", []):
        snap["undelivered"] = keys
        save_json(state_path("last_findings.json"), snap)


def save_undelivered(fs, snap):
    """Every finding in `fs` (masked, platform notes as their lines) in state/deltas/daily-<time>.json; its path, or None."""
    d = state_path("deltas")
    try:
        os.makedirs(d, exist_ok=True)
        path = os.path.join(d, f"daily-{time.time_ns()}.json")
        rec = lambda f: mask_stored([dict(compact(f), key=f["key"], **({"platform_note": platform_note_line(f)} if platform_scope(f) else {}))])[0]
        save_json(path, {"at": now(), "undelivered": [rec(f) for f in fs]})
        for old in sorted(fn for fn in os.listdir(d) if fn.startswith("daily-") and fn.endswith(".json"))[:-DELTA_KEEP]:
            os.remove(os.path.join(d, old))
    except OSError:
        return None
    return path


def cmd_baseline(args):
    _, status, _ = load_baseline()
    if status != "first" and not getattr(args, "owner_said_yes", False):   # R10: the first baseline on a box needs no yes
        print("NOT SAVED: a new baseline approves every skill and plugin file exactly as it is now, including any that changed. Show the "
              "owner what changed (`isr.py breakdown`, `isr.py diff <skill>`); only after their yes in this conversation run "
              "`isr.py baseline --owner-said-yes`.")
        return 1
    roots = args.roots or [os.path.expanduser("~"), "/workspace"]
    fs, meta = audit(roots, None, quick=True)
    save_baseline(meta["manifest"])   # v0.8.1: the manifest is the owner's files only
    n = save_approved_all(meta.get("skill_dirs", []), (), load_baseline()[0])
    ledger(dict({"event": "baseline", "files": len(meta["manifest"]), "copies": n}, **({"after_reset": True} if status == "reset" else {})))
    print(f"Baseline saved: {len(meta['manifest'])} skill and plugin files. Kept a copy of {n} skills so the next change shows as a diff.")
    return 0


def cmd_breakdown(args):
    snap = load_snapshot(None)
    if not snap:
        print("ERROR no audit yet", file=sys.stderr)
        return 2
    rows = {}
    for f in shown(snap["findings"]):
        r = rows.setdefault((f["severity"], f["rule"], f["title"]), {"n": 0, "dirs": {}})
        r["n"] += 1
        w = f["where"].split(":")[0]
        d = w if (f["rule"] == "ISR-S002" and "files under" in f["title"]) else os.path.dirname(w)
        top = "/".join(d.split("/")[:5])
        if f["where"].startswith("rollcall:"):
            top = "Bot " + f["where"].split(":")[1]
        elif not top:
            top = f["where"][:40]
        elif f["rule"] in ("ISR-X001", "ISR-X002", "ISR-X003", "ISR-X004", "ISR-I004"):
            top = "/".join(d.split("/")[:5]) + "/…/" + os.path.basename(w) if d.count("/") > 5 else w
        r["dirs"][top] = r["dirs"].get(top, 0) + 1
    # DQ-025: full list of open findings by severity (audit JSON may truncate `new`; this does not).
    for (sev, rule, title), r in sorted(rows.items(), key=lambda x: (SEV_ORDER.index(x[0][0]), -x[1]["n"])):
        dirs = ", ".join(f"{k} ×{v}" for k, v in sorted(r["dirs"].items(), key=lambda x: -x[1])[:3])
        print(f"{sev:8} {rule:8} ×{r['n']:<5} {title[:48]:48} {dirs}")
    confirmed = [f for f in owners(shown(snap["findings"])) if f.get("label") == CONFIRMED and f.get("severity") in ("critical", "high", "medium")]
    if confirmed:
        print("")
        print(f"Confirmed (critical/high/medium): {len(confirmed)}")
        for f in sorted(confirmed, key=lambda x: (SEV_ORDER.index(x["severity"]), x["rule"], x["where"]))[:200]:
            print(f"  {f['severity']:8} {f['rule']:8} {f['where'][:80]}  {f['title'][:60]}")
        if len(confirmed) > 200:
            print(f"  … and {len(confirmed) - 200} more")
    plat = [f for f in shown(snap["findings"]) if platform_scope(f)]
    if plat:   # batch 5 (d1): Grok Bot's own files are never in the Confirmed list
        print("")
        print(f"Platform notes (Grok Bot's own files, not counted): {len(plat)}. `isr.py show <rule>` lists them "
              f"({', '.join(sorted({f['rule'] for f in plat}))}).")
        for line in platform_notes(snap["findings"], len(plat))["lines"]:   # Codex round 1 (9, 10): every one, where `more` points
            print(f"  {line}")
    vend = [v for v in snap.get("vendor") or [] if isinstance(v, dict) and v.get("label") != GUARDED_LABEL]
    if vend:   # v0.8.1 (§3.5): Grok Bot's, Codex's and Claude's own files, never scored; every one, by where it is
        print("")
        print(f"Platform notes (Grok Bot's, Codex's and Claude's own files, never scored): {len(vend)}")
        for v in sorted(vend, key=lambda x: (SEV_ORDER.index(x["severity"]) if x.get("severity") in SEV_ORDER else 9, x.get("rule", ""), x.get("where", ""))):
            print(f"  {v.get('severity', ''):8} {v.get('rule', ''):8} {str(v.get('where', ''))}  {str(v.get('title', ''))[:60]}")
    return 0


_isr_part("report")


_isr_part("history")


_isr_part("canaries")


_isr_part("rollcall")


_isr_part("prepublish")


_isr_part("access")


# ---------------------------------------------------------------- OWASP Top 10 (2021) code review for code your Bots write
CODE_RULES = [
    ("A01", "Broken access control", "high", r"(?i)(@app\.route\([^)]*\)\s*\n\s*def\s+\w+\([^)]*\):(?![\s\S]{0,200}(login_required|auth|current_user))|cors\(\s*\w+\s*,\s*origins\s*=\s*['\"]\*|Access-Control-Allow-Origin['\"]?\s*[:,]\s*['\"]\*)"),
    ("A02", "Cryptographic failure", "high", r"(?i)(hashlib\.(md5|sha1)\(|createHash\(['\"](md5|sha1)|verify\s*=\s*False|rejectUnauthorized\s*:\s*false|ssl\._create_unverified_context|Math\.random\(\)[^\n]{0,40}(token|secret|password|key))"),
    ("A03", "Injection", "critical", r"(?i)((execute|executemany|raw|query)\(\s*f?['\"][^'\"]*(select|insert|update|delete)[^'\"]*['\"]\s*(%|\+|\.format)|(execute|query)\(\s*f['\"][^'\"]*\{|subprocess\.\w+\([^)]*shell\s*=\s*True|os\.system\(|child_process\.exec\(|\beval\(|new Function\(|innerHTML\s*=|dangerouslySetInnerHTML|document\.write\()"),
    ("A04", "Insecure design", "medium", r"(?i)(TODO[^\n]{0,40}(auth|security|validate)|password\s*==\s*['\"])"),
    ("A05", "Security misconfiguration", "medium", r"(?i)(debug\s*=\s*True|app\.run\([^)]*debug\s*=\s*True|DEBUG\s*=\s*True|ALLOWED_HOSTS\s*=\s*\[\s*['\"]\*|helmet\s*\(\s*\{\s*contentSecurityPolicy\s*:\s*false)"),
    ("A06", "Vulnerable component pinned loosely", "low", r"(?im)^\s*[\w.-]+\s*(>=|\*|latest)\s*$"),
    ("A07", "Identification and authentication failure", "high", r"(?i)(jwt\.decode\([^)]*verify\s*=\s*False|algorithms\s*=\s*\[\s*['\"]none|password\s*=\s*['\"][^'\"]{4,}['\"]|session\.permanent\s*=\s*True)"),
    ("A08", "Software or data integrity failure", "high", r"(?i)(pickle\.loads?\(|yaml\.load\((?![^)]*Loader\s*=\s*yaml\.SafeLoader)|marshal\.loads\(|unserialize\(|<script[^>]+src=['\"]https?://(?![^'\"]*integrity))"),
    ("A09", "Security logging failure", "low", r"(?i)except\s*(Exception)?\s*:\s*\n\s*pass\b"),
    ("A10", "Server-side request forgery", "high", r"(?i)(requests\.(get|post)\(\s*(request\.|req\.|params|url_from|user)|fetch\(\s*req\.(query|body|params)|urlopen\(\s*request\.)"),
]
CODE_EXT = {".py", ".js", ".jsx", ".ts", ".tsx", ".php", ".rb", ".go", ".java", ".html", ".txt"}


def cmd_codescan(args):
    rules = load_rules()
    out = []
    files = [p for p in walk([args.path], max_depth=10) if os.path.splitext(p)[1].lower() in CODE_EXT] if os.path.isdir(args.path) else [args.path]
    secret = next(r for r in rules["rules"] if r["id"] == SECRET_RULE)
    for p in files[:3000]:
        t = read_text(p, limit=500_000)
        if not t:
            continue
        if os.path.basename(p) not in ("requirements.txt",) and p.endswith(".txt"):
            continue
        for cid, title, sev, rx in CODE_RULES:
            if cid == "A06" and not p.endswith("requirements.txt"):
                continue
            for m in re.finditer(rx, t):
                out.append(finding(f"ISR-W{cid}", f"OWASP {cid}:2021 {title}", sev, [f"{cid}:2021"], f"{p}:{line_of(t, m.start())}",
                                   m.group(0).strip()[:120], CODE_FIX[cid]))
        for m in secret["rx"].finditer(t):
            why = secret_at(t, m)[1]   # batch 6 (B5): the shared content check; fix round 3: an example-looking one gets a note only
            f = finding("ISR-WA07s", "OWASP A07:2021 Hard-coded secret", "critical", ["A07:2021"], f"{p}:{line_of(t, m.start())}",
                        mask(m.group(0)), "Move it to an environment variable or secret store and revoke the exposed one.")
            out.append(annotate_example(f, why) if why else f)
    semgrep = tool("semgrep")
    note = "ISR Bot patterns only (semgrep isn't one of ISR Bot's checked scanners)"
    # Codex, batch 3 final review: a semgrep refused at launch (exit 126), failed (non-zero exit, time out) or with no results
    # in its output still said "semgrep found and used too". It is "used" only after a clean exit with a results list;
    # anything else is "not checked" (its findings, if any, are still listed) and a refused or changed copy is a ISR-X005.
    gap = f"semgrep NOT run: {SCANNER_PROBLEMS['semgrep'][1]}" if SCANNER_PROBLEMS.get("semgrep", (None,))[0] in ("changed", "unreadable") else None
    if semgrep:
        # Claude review 1 (7): semgrep sends usage metrics by default when its rules come from its registry; EGRESS says none.
        # Claude review 2 (7): and it checks semgrep.dev for a newer version by default; --disable-version-check stops that.
        code, so, _ = run([semgrep, "--config", "p/owasp-top-ten", "--metrics=off", "--disable-version-check", "--json", "--quiet", args.path], 900)
        try:
            res = json.loads(so)
        except ValueError:
            res = None
        results = res.get("results") if isinstance(res, dict) else None
        # Claude review 1 (5): files semgrep couldn't parse or that timed out are listed in "errors", with exit 0: not a full run
        errors = res.get("errors") if isinstance(res, dict) else None
        # Claude review 2 (8): semgrep lists warn-level partial parses there too, routine on real code; only the rest (error
        # level, or no level given) mean it didn't finish. Partial parses are said in half a line.
        partial = []
        if isinstance(errors, list):
            partial = [e for e in errors if isinstance(e, dict) and str(e.get("level", "")).lower() in ("warn", "warning", "info")]
            errors = [e for e in errors if not any(e is w for w in partial)]
        for r in results if isinstance(results, list) else []:
            if isinstance(r, dict):
                out.append(finding("ISR-WSG", f"semgrep: {r.get('check_id', '').split('.')[-1]}", (r.get("extra", {}).get("severity") or "medium").lower().replace("error", "high").replace("warning", "medium").replace("info", "low"),
                                   ["OWASP"], f"{r.get('path')}:{r.get('start', {}).get('line')}", r.get("extra", {}).get("message", "")[:120],
                                   "See the semgrep rule for the fix.", source="semgrep"))
        refused = SCANNER_PROBLEMS.get("semgrep", ())
        if len(refused) == 3:
            gap = f"semgrep NOT run: {refused[1]}"
        elif code == 124:
            gap = "semgrep did NOT finish: it timed out"
        elif code != 0 or not isinstance(results, list):
            gap = f"semgrep did NOT finish (exit {code}" + ("" if isinstance(results, list) else ", no results") + ")"
        elif errors:
            gap = (f"semgrep did NOT finish ({len(errors)} errors: files it couldn't read, parse or finish in time)" if isinstance(errors, list)
                   else "semgrep did NOT finish (it reported errors)")
        else:
            note = "semgrep found and used too"
            if partial:
                n = len({str(e.get("path") or i) for i, e in enumerate(partial)})
                note += f" ({n} file{'s' if n != 1 else ''} only partly parsed)"
    if gap:
        note = f"ISR Bot patterns only: {gap}, so its checks weren't done this time"
    x005 = scanner_x005()
    out = sort_findings(dedupe(out + x005))
    # Claude review 1 (5): criticals sort first and fit() trims the findings list, so a swapped semgrep's ISR-X005 could be cut
    # from the handoff. It is also given in its own list, which is never trimmed (like daily's decoys).
    print(fit({"files": len(files), "engine": note, **({"not_checked_this_run": [gap]} if gap else {}),
               **({"scanner_alerts": [compact(f) for f in x005]} if x005 else {}),
               "by_severity": by_sev(out), "findings": [compact(f) for f in out][:40]}, keep=("scanner_alerts",)))
    ledger({"event": "codescan", "path": args.path, "findings": len(out)})
    return 0


CODE_FIX = {
    "A01": "Check the caller's identity and permission on every route; never allow every origin.",
    "A02": "Use bcrypt/argon2 for passwords, SHA-256+ for integrity, keep TLS verification on, use `secrets` for tokens.",
    "A03": "Use parameterized queries and argument lists (no shell=True); never build HTML with innerHTML from input.",
    "A04": "Finish the security TODO before shipping; compare secrets with a constant-time check.",
    "A05": "Turn debug off in anything reachable; set explicit allowed hosts and a content-security policy.",
    "A06": "Pin exact versions and audit them (`pip-audit`, `npm audit`).",
    "A07": "Verify JWT signatures with an explicit algorithm; never hard-code passwords.",
    "A08": "Don't deserialize untrusted data with pickle/yaml.load; add integrity hashes to third-party scripts.",
    "A09": "Log the exception instead of swallowing it, so failures and attacks leave a trace.",
    "A10": "Allow-list destination hosts before fetching a URL that came from a user.",
}


_isr_part("brief")


def render_brief(b, snap, pkg, hist, tag, analyst_note=None, notes=None):
    e = html.escape
    safe = lambda u: html.escape(u) if re.match(r"(?i)^https?://", u or "") else "#"
    notes = notes or {}
    stories, more = split_stories(b)
    lvl_i, lvl, _ = threat_level(b, snap, stories)
    fs = shown((snap or {}).get("findings", []))
    score = (snap or {}).get("score")
    grade = snap_grade(snap)
    todo = needs_you(fs)
    urgent = [t for t in todo if t["severity"] in ("critical", "high")]
    fixed, cleaned = handled_this_week()
    delta, why_changed = None, ""
    if len(hist) >= 2:
        delta = hist[-1][1] - hist[-2][1]
        why_changed = " · ISR Bot updated" if len(hist[-1]) > 3 and hist[-1][3] else ""
    exp = [dict(r, area=AREA_SHORT.get(r["area"], r["area"])) for r in exposure(snap)]
    rel_kev = [k for k in b["kev"] if k["relevant"]]
    accepted = (snap or {}).get("suppressed", [])

    # status sentence: one line a non-expert can act on
    if any(t["severity"] == "critical" for t in todo):
        status, tone = f"{WORDS.get(len(urgent), str(len(urgent)))} {'thing needs' if len(urgent) == 1 else 'things need'} you this week.", "bad"
    elif urgent:
        status, tone = f"Mostly in good shape. {WORDS.get(len(urgent), str(len(urgent)))} {'thing is' if len(urgent) == 1 else 'things are'} worth a few minutes.", "warn"
    else:
        status, tone = "You're in good shape. Nothing needs you this week.", "ok"
    sub = analyst_note or (f"The biggest outside threat: {stories[0]['title']}." if stories else "No major new threats this week.")

    if delta in (None, 0):
        delta_txt = ""
    else:
        cls = "q" if why_changed else ("up" if delta > 0 else "down")
        delta_txt = f"<span class='{cls}'>{'▲' if delta > 0 else '▼'} {abs(delta)} since last check{e(why_changed)}</span>"
    dots = "".join(f"<i class='{'on' if i <= lvl_i else ''} l{lvl_i}'></i>" for i in range(5))
    metrics = (f"<div class='m'><span class='k'>Security score</span><b>{e(str(score)) if score is not None else '–'}</b><span class='s'>{e(grade)} {delta_txt}</span><span class='s'>{e(score_line(snap))}</span><span class='s'>{e(SCORE_MEANING)}</span></div>"
               f"<div class='m'><span class='k'>Threat level</span><b class='lv l{lvl_i}'>{e(lvl)}</b><span class='dots'>{dots}</span></div>"
               f"<div class='m'><span class='k'>Needs you</span><b>{len(urgent)}</b><span class='s'>{len(todo) - len(urgent)} smaller {'item' if len(todo) - len(urgent) == 1 else 'items'}</span></div>"
               f"<div class='m'><span class='k'>Handled this week</span><b>{fixed + cleaned}</b><span class='s'>fixed or cleaned up</span></div>")

    fix_prompt = "ISR Bot, fix it"   # batch 4 (R10): the owner runs it; the brief no longer offers a routine that fixes without asking

    def rows_table(t):
        rows = t.get("rows", [])
        if not rows:
            return ""
        body = "".join(f"<tr><td><b>{e(r['name'])}</b><span class='w'>{e(r['where'])}</span></td><td>{e(r['reason'])}</td>"
                       f"<td><code class='rule'>{e(r['rule'])}</code></td></tr>" for r in rows[:40])
        extra = f"<p class='quiet'>And {len(rows) - 40} more. Run <code>isr.py show {e(rows[0]['rule'])}</code> for all of them.</p>" if len(rows) > 40 else ""
        label = "Show which" if len(rows) > 1 else "Show where"
        if t.get("can_accept"):
            ok = f"Fine on purpose? Tell ISR Bot: <code>accept {e(rows[0]['rule'])} {e(rows[0]['name'])} because …</code>"
        else:   # batch 4 (R10): never suggest an accept that batch 1's gate refuses
            ok = "This one can't be marked as fine. Tell ISR Bot " + ("\"incident check\"." if t.get("decoy") else "\"fix it\".")
        return (f"<details class='dd'><summary>{label}</summary><div class='scroll'><table><tr><th>What</th><th>Why it was flagged</th><th>Rule</th></tr>{body}</table></div>"
                f"{extra}<p class='quiet'>For the exact lines: <code>isr.py show {e(rows[0]['rule'])}</code>. {ok}</p></details>")

    def todo_item(i, t):
        links = "".join(f"<a class='btn' href='{safe(u)}' target='_blank' rel='noopener'>Turn off {e(n)} keys</a>" for n, u in t.get("links", []))
        return (f"<li class='sev-{t['severity']}'><div class='tt'><small>{e(t.get('label', ''))}</small> <b>{e(t['title'])}</b>{(' <span class=n>×' + str(t['count']) + '</span>') if t['count'] > 1 else ''}"
                f"<span class='hd h-{t.get('handled', 'Only you').split()[0].lower()}'>{e(t.get('handled', ''))}</span></div>"
                f"<p>{e(t['why'])} <span class='how'>{e(t['how'])}</span></p>{('<div class=links>' + links + '</div>') if links else ''}{rows_table(t)}</li>")

    todo_html = "".join(todo_item(i, t) for i, t in enumerate(todo[:4])) or "<li class='sev-ok'><div class='tt'><b>Nothing needs you.</b></div></li>"
    rest = todo[4:]
    rest_html = ("<details><summary>" + f"{len(rest)} smaller {'item' if len(rest) == 1 else 'items'}</summary><ol class='todo small-todo'>" +
                 "".join(todo_item(0, t) for t in rest) + "</ol></details>") if rest else ""

    amap = load_access_map()

    def threat(s):
        n = notes.get(s["id"], {})
        do = n.get("do") or DO_THIS[s["category"]]
        head = (f"<li><span class='tag c-{s['category']}'>{e(s['category_label'])}</span>"
                f"<a href='{safe(s['link'])}' target='_blank' rel='noopener'>{e(s['title'])}</a>")
        if amap is None:   # an older box with no access map: exactly as before
            why = (n.get("means") or means_here(s["category"], account_context())).split(". ")[0].rstrip(".") + "."
            return head + f"<p><b>Why you care:</b> {e(why)} <b>Do:</b> {e(do)}</p></li>"
        # batch 5 (b): what the story touches here, from the access map and the release's vocabulary only; the Bot's notes after it
        why = f" <b>Why you care:</b> {e(n['means'])}" if n.get("means") else ""
        return head + f"<p><b>Here:</b> {e(story_here(s, amap, account_context()))}{why} <b>Do:</b> {e(do)}</p></li>"

    threats = "".join(threat(s) for s in stories[:3]) or "<li><p>No major threats touched setups like yours this week.</p></li>"
    later = stories[3:] + more
    later_html = ("<details><summary>" + f"{len(later)} more {'story' if len(later) == 1 else 'stories'}</summary><ul class='small'>" +
                  "".join(f"<li><a href='{safe(s['link'])}' target='_blank' rel='noopener'>{e(s['title'])}</a> <span class=q>{e(s['source'])}</span></li>" for s in later) +
                  "</ul></details>") if later else ""
    kev_line = ((f"{WORDS.get(len(rel_kev), str(len(rel_kev)))} actively exploited {'bug affects' if len(rel_kev) == 1 else 'bugs affect'} software like yours: "
                 + ", ".join(f"{e(k['vendor'] + ' ' + k['product'])} (<a href='https://nvd.nist.gov/vuln/detail/{e(k['cve'] or '')}' target='_blank' rel='noopener'>{e(k['cve'] or '')}</a>)"
                             + (f" (used here: {e(k['used_here'])})" if k.get("used_here") else "") for k in rel_kev[:3])
                 + (". The platform's next update fixes it." if len(rel_kev) == 1 else ". The platform's next updates fix them."))
                if rel_kev else "None of this week's actively exploited bugs affect software like yours.")
    exc = exceptions_active(snap or {})
    accepted = [f for f in accepted if not f.get("exception")]
    fyi_n = sum(1 for f in (snap or {}).get("findings", []) if not counts(f))
    skipped = (snap or {}).get("stages_skipped", [])
    acc_html = (f"<p class='small'><b>Skipped this run:</b> {e(', '.join(skipped))}. Their last results were kept, so the score didn't move because of it.</p>" if skipped else "")
    acc_html += (f"<p class='small'>{fyi_n} notes about built-in plugins and skills are listed for information and not counted in the score.</p>" if fyi_n else "")
    acc_html += "".join(f"<p class='small'><b>⚠ Security-tool exception:</b> {e(x['skill'])} is flagged by two scanners. You confirmed it is a security tool. "
                       f"Ends {e(x['until'])} ({x['days_left']} days) or when the skill changes.</p>" for x in exc)
    acc_html += ("<details><summary>" + f"{len(accepted)} accepted {'risk' if len(accepted) == 1 else 'risks'}</summary><ul class='small'>" +
                 "".join(f"<li>{e(plain(f)['title'])}</li>" for f in accepted) + "</ul></details>") if accepted else ""
    down = [s["name"] for s in b["sources"] if s["status"] != "ok"]
    used = (load_json(state_path("engines_used.json"), {}) or {}).get("engines", ["ISR Bot rules"])
    missing = [n for n in ("SkillSpector", "husk", "gitleaks", "TruffleHog", "pip-audit", "OSV-Scanner") if n not in used]
    engines_html = (f"<p class='engines'>Checked by {len(used)} scanners: {e(', '.join(used))}."
                    + (f" Not installed: {e(', '.join(missing))} (run setup step 2)." if missing else "") + "</p>")
    generated = dt.datetime.now(dt.timezone.utc).strftime("%-d %b %Y")
    return f"""<!doctype html><html lang='en'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>
<title>ISR Bot: {e(status)}</title><style>
:root{{--bg:#eef1f0;--card:#fff;--ink:#17202b;--soft:#5b6572;--line:#d9dfdd;--navy:#1f3a5f;--red:#b3261e;--amber:#b77900;--green:#2e7d5b;--sea:#3f6f8f;
--f:-apple-system,BlinkMacSystemFont,"Segoe UI",Inter,Roboto,"Helvetica Neue",Arial,sans-serif}}
@media(prefers-color-scheme:dark){{:root{{--bg:#0e1621;--card:#152030;--ink:#e6ecf2;--soft:#9aa7b4;--line:#263447;--navy:#8fb3dc;--red:#ff7a6e;--amber:#f2b632;--green:#5cc493;--sea:#7fb0cf}}}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--ink);font:16px/1.5 var(--f)}}a{{color:var(--navy)}}a:focus-visible,button:focus-visible,summary:focus-visible{{outline:2px solid var(--navy);outline-offset:2px}}
.wrap{{max-width:920px;margin:0 auto;padding:22px 18px 48px}}
.top{{display:flex;justify-content:space-between;align-items:baseline;color:var(--soft);font-size:14px;margin-bottom:10px}}.top b{{color:var(--ink)}}
.hero{{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:22px 24px;border-top:6px solid var(--green)}}.hero.warn{{border-top-color:var(--amber)}}.hero.bad{{border-top-color:var(--red)}}
.hero h1{{margin:0;font-size:28px;line-height:1.2;letter-spacing:-.01em}}.hero .sub{{margin:6px 0 0;color:var(--soft)}}
.metrics{{display:grid;grid-template-columns:repeat(4,1fr);gap:1px;background:var(--line);border:1px solid var(--line);border-radius:12px;overflow:hidden;margin:18px 0 0}}
.m{{background:var(--card);padding:12px 14px;display:flex;flex-direction:column;gap:2px}}.m .k{{color:var(--soft);font-size:13px}}.m b{{font-size:30px;line-height:1.1;font-variant-numeric:tabular-nums}}.m .s{{color:var(--soft);font-size:13px}}
.up{{color:var(--green);font-weight:600}}.down{{color:var(--red);font-weight:600}}
.lv.l0{{color:var(--green)}}.lv.l1{{color:var(--sea)}}.lv.l2{{color:var(--amber)}}.lv.l3,.lv.l4{{color:var(--red)}}
.dots{{display:flex;gap:4px;margin-top:4px}}.dots i{{width:18px;height:6px;border-radius:3px;background:var(--line)}}.dots i.on.l0{{background:var(--green)}}.dots i.on.l1{{background:var(--sea)}}.dots i.on.l2{{background:var(--amber)}}.dots i.on.l3,.dots i.on.l4{{background:var(--red)}}
.charts{{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-top:14px}}.panel{{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:14px 16px}}
.panel h3,.sec h2{{margin:0 0 8px;font-size:15px;color:var(--soft);font-weight:600}}
.trend{{width:100%;height:auto;display:block}}.trend .l{{fill:none;stroke:var(--navy);stroke-width:2.5;stroke-linejoin:round}}.trend .a{{fill:var(--navy);opacity:.10}}.trend .d{{fill:var(--navy)}}.trend .g{{stroke:var(--line);stroke-dasharray:3 4}}.trend .ring{{fill:var(--card);stroke:var(--amber);stroke-width:2}}
.axis{{display:flex;justify-content:space-between;color:var(--soft);font-size:12px}}
.ar{{display:grid;grid-template-columns:130px 1fr 28px;align-items:center;gap:10px;font-size:14px;margin:7px 0}}.ab{{height:10px;background:var(--line);border-radius:5px;overflow:hidden}}.ab i{{display:block;height:100%;border-radius:5px}}.ar b{{text-align:right;font-variant-numeric:tabular-nums}}
.sev-critical{{background:var(--red)}}.sev-high{{background:var(--amber)}}.sev-medium{{background:var(--sea)}}
.fix{{display:grid;grid-template-columns:1fr;gap:14px;margin-top:14px}}.fx{{background:var(--card);border:2px solid var(--navy);border-radius:12px;padding:16px}}.fx.alt{{border:1px solid var(--line)}}
.fx h3{{margin:0 0 4px;font-size:18px}}.fx p{{margin:0 0 10px;color:var(--soft);font-size:14px}}
.cmd{{display:flex;gap:8px;align-items:stretch}}.cmd code{{flex:1;background:var(--bg);border:1px solid var(--line);border-radius:8px;padding:9px 11px;font:14px/1.4 ui-monospace,Menlo,monospace;overflow-wrap:anywhere}}
button{{font:600 14px var(--f);border:0;border-radius:8px;padding:0 14px;background:var(--navy);color:var(--card);cursor:pointer;min-height:40px}}.fx.alt button{{background:var(--card);color:var(--navy);border:1px solid var(--navy)}}
.sec{{margin-top:26px}}.sec h2{{font-size:20px;color:var(--ink);margin-bottom:10px}}
ol.todo,ul.threats{{list-style:none;padding:0;margin:0;display:grid;gap:10px}}
ol.todo li{{background:var(--card);border:1px solid var(--line);border-left:5px solid var(--sea);border-radius:10px;padding:12px 14px}}ol.todo li.sev-critical{{border-left-color:var(--red);background:var(--card)}}ol.todo li.sev-high{{border-left-color:var(--amber);background:var(--card)}}ol.todo li.sev-medium{{background:var(--card)}}ol.todo li.sev-ok{{border-left-color:var(--green)}}
.tt{{font-size:17px}}.n{{color:var(--soft);font-weight:400}}ol.todo p{{margin:4px 0 0;color:var(--soft)}}.how{{color:var(--ink)}}
.links{{display:flex;flex-wrap:wrap;gap:8px;margin-top:8px}}.btn{{display:inline-block;font-size:13px;font-weight:600;padding:5px 10px;border:1px solid var(--navy);border-radius:7px;text-decoration:none}}
ul.threats li{{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px 14px}}ul.threats a{{font-weight:600;color:var(--ink);text-decoration:none;font-size:17px}}ul.threats a:hover{{text-decoration:underline}}ul.threats p{{margin:6px 0 0;color:var(--soft)}}ul.threats p b{{color:var(--ink);font-weight:600}}
.tag{{display:inline-block;font-size:12px;font-weight:600;color:var(--soft);border:1px solid var(--line);border-radius:6px;padding:1px 7px;margin-right:8px;vertical-align:2px}}
details{{margin-top:10px}}summary{{cursor:pointer;color:var(--navy);font-weight:600;font-size:14px}}ul.small{{margin:8px 0 0;padding-left:18px;color:var(--soft);font-size:14px}}ul.small li{{margin:4px 0}}ul.small b{{color:var(--ink)}}.q{{color:var(--soft)}}
.hd{{float:right;font-size:12px;font-weight:600;border-radius:6px;padding:2px 8px;background:var(--line);color:var(--soft)}}.hd.h-fix{{background:color-mix(in srgb,var(--green) 18%,transparent);color:var(--green)}}.hd.h-only{{background:color-mix(in srgb,var(--red) 16%,transparent);color:var(--red)}}
.quiet{{color:var(--soft);font-size:14px}}.hint{{margin:6px 0 0!important;font-size:13px}}
.cmd code{{user-select:all;-webkit-user-select:all;cursor:text}}.engines{{margin:14px 2px 0;color:var(--soft);font-size:13px}}
details.dd{{margin-top:8px}}details.dd summary{{font-size:13px}}.scroll{{overflow-x:auto}}details.dd table{{border-collapse:collapse;width:100%;font-size:13px;margin-top:6px}}
details.dd th,details.dd td{{text-align:left;padding:6px 8px 6px 0;border-bottom:1px solid var(--line);vertical-align:top}}details.dd th{{color:var(--soft);font-weight:600}}
details.dd td b{{display:block;color:var(--ink)}}details.dd .w{{display:block;color:var(--soft);font-size:12px;overflow-wrap:anywhere}}code.rule{{font-size:12px;color:var(--soft)}}
ol.small-todo{{margin-top:8px}}ol.small-todo li{{padding:10px 12px}}ol.small-todo .tt{{font-size:15px}}.foot{{margin-top:30px;color:var(--soft);font-size:13px;border-top:1px solid var(--line);padding-top:12px}}
@media(max-width:700px){{.metrics{{grid-template-columns:1fr 1fr}}.charts,.fix{{grid-template-columns:1fr}}.hero h1{{font-size:23px}}.ar{{grid-template-columns:110px 1fr 24px}}}}
@media print{{body{{background:#fff}}button{{display:none}}details{{display:block}}.hero,.panel,.fx,ol.todo li,ul.threats li{{break-inside:avoid}}}}
</style></head><body><div class='wrap'>
<div class='top'><span><b>ISR Bot</b> weekly report</span><span>{e(generated)}</span></div>
<header class='hero {tone}'><h1>{e(status)}</h1><p class='sub'>{e(sub)}</p><div class='metrics'>{metrics}</div></header>
<div class='charts'><div class='panel'><h3>Security score over time</h3>{svg_trend(hist)}</div><div class='panel'><h3>Where the open issues are</h3>{svg_areas(exp)}</div></div>
{engines_html}
<div class='fix'><div class='fx'><h3>Fix it all</h3><p>Paste this into your ISR Bot. It cleans up, upgrades outdated software (and undoes any upgrade that breaks something), then asks you one yes or no for everything that's fine on purpose.</p>
<div class='cmd'><code id='c1' tabindex='0'>{e(fix_prompt)}</code><button type='button' data-copy='c1' hidden>Copy</button></div><p class='hint'>Click the text to select it, then copy.</p></div></div>
<section class='sec'><h2>What needs you</h2><ol class='todo'>{todo_html}</ol>{rest_html}{acc_html}</section>
<section class='sec'><h2>Threats this week</h2><ul class='threats'>{threats}</ul>{later_html}<p class='quiet' style='margin-top:10px'>{kev_line}</p></section>
<p class='foot'>Read-only: ISR Bot changes nothing unless you run the fix. {len(b['sources']) - len(down)} of {len(b['sources'])} news sources responded{(' (' + e(', '.join(down)) + ' did not)') if 0 < len(down) <= 2 else ''}. Full details: /isr-bot-report. ISR Bot {e(VERSION)}.</p>
</div><script>
(function(){{
  function sel(el){{var r=document.createRange();r.selectNodeContents(el);var s=window.getSelection();s.removeAllRanges();s.addRange(r);}}
  function legacy(text){{var t=document.createElement('textarea');t.value=text;t.setAttribute('readonly','');t.style.position='fixed';t.style.opacity='0';
    document.body.appendChild(t);t.select();var ok=false;try{{ok=document.execCommand('copy');}}catch(e){{ok=false;}}document.body.removeChild(t);return ok;}}
  document.querySelectorAll('button[data-copy]').forEach(function(b){{
    var el=document.getElementById(b.dataset.copy); b.hidden=false;
    var hint=b.parentNode.parentNode.querySelector('.hint'); if(hint) hint.textContent='';
    b.addEventListener('click',function(){{
      var text=el.textContent, done=function(m){{b.textContent=m;setTimeout(function(){{b.textContent='Copy'}},1800);}};
      var fallback=function(){{ if(legacy(text)){{done('Copied');}} else {{sel(el); done('Press '+(/Mac|iPhone|iPad/.test(navigator.platform)?'⌘':'Ctrl')+'+C');}} }};
      try{{ if(navigator.clipboard&&window.isSecureContext){{navigator.clipboard.writeText(text).then(function(){{done('Copied');}},fallback);}} else {{fallback();}} }}catch(e){{fallback();}}
    }});
  }});
}})();
</script></body></html>"""


def cmd_brief(args):
    cfg = load_json(FEEDS_PATH, None)
    if not cfg:
        print("ERROR feeds.json missing", file=sys.stderr)
        return 2
    offline = load_json(args.offline, None) if args.offline else None
    reuse = getattr(args, "notes", None) or getattr(args, "summary", None)
    last = load_json(state_path("last_brief.json"), None)
    week = dt.date.today().isocalendar()
    tag = f"{week[0]}-W{week[1]:02d}"
    # adding analysis re-renders this week's brief from saved data instead of fetching again
    b = last if (reuse and last and last.get("tag") == tag and offline is None) else gather_brief(cfg, offline)
    for r in (b or {}).get("research", []) or []:
        r.pop("summary", None)                            # a brief saved before v0.6.8 kept article text; it is never passed on
    snap = load_snapshot(None)
    pkg = load_json(state_path("package_vulns.json"), None)
    hist = load_history()
    note = open(args.summary).read().strip() if getattr(args, "summary", None) else None
    notes = load_json(args.notes, {}) if getattr(args, "notes", None) else {}
    rdir = os.path.join(home(), "reports")
    os.makedirs(rdir, exist_ok=True)
    path = os.path.join(rdir, f"threat-brief-{tag}.html")
    with open(path, "w") as f:
        f.write(render_brief(b, snap, pkg, hist, tag, note, notes))
    save_json(state_path("last_brief.json"), dict(b, tag=tag, path=path))
    ledger({"event": "brief", "week": tag, "research": len(b["research"]), "kev": len(b["kev"])})
    top, _ = split_stories(b)
    amap = load_access_map()
    # batch 5 (b): `here` is the line the page shows for each story (story_here: the access map and the release's vocabulary only).
    # PR B, Codex round 1 (6): without a map there is no `here`, so the JSON is exactly what it was.
    here = (lambda r: {}) if amap is None else (lambda r, ctx=account_context(): {"here": story_here(r, amap, ctx)})
    print(fit({"brief": path, "threat_level": threat_level(b, snap, top)[1], "score_line": score_line(snap),
               "top_stories": [dict({"id": r["id"], "tier": r["tier"], "category": r["category_label"], "title": r["title"],
                                     "cves": r.get("cves", []), "source": r["source"]}, **here(r)) for r in top],
               "kev_relevant": [f"{k['cve']} {k['vendor']} {k['product']}" for k in b["kev"] if k["relevant"]][:6],
               "updates": b["updates"], "doc_changes": [p["name"] for p in b["pages"]],
               "sources_down": [s["name"] for s in b["sources"] if s["status"] != "ok"],
               "next_step": ("Analysis added." if notes else
                             "Required: write notes.json with 'means' and 'do' for each top_stories id (see the isr-bot-brief skill, step 2), "
                             "then run isr.py brief --notes <file>. Until then the stories show generic text." if amap is None else
                             "Optional: add notes.json with 'means' and 'do' for any top_stories id (see the isr-bot-brief skill, step 2), "
                             "then run isr.py brief --notes <file>. Each story already says what it touches here.")}, limit=6000))
    return 0


_isr_part("fixplan")


_isr_part("approved")


_isr_part("quarantine")


# ---------------------------------------------------------------- uninstall: leave nothing behind
# Only what install.sh itself leaves in /tmp. Any other file there (a saved audit-066.json, say) is not ISR Bot's: the owner's Bot saved its
# own copy of a run there (`audit --json > /tmp/...`), and v0.6.3 to v0.6.6 deleted those along with the installer's files.
TMP_LEFTOVERS = re.compile(r"^(gitleaks_.*\.tar\.gz|gitleaks_checksums\.txt|trufflehog_.*\.tar\.gz|trufflehog_checksums\.txt|osv_sums\.txt|isr-bot-lock\.err)$")
ROUTINE_NAMES = ("ISR Bot daily watch", "ISR Bot weekly audit", "ISR Bot weekly tidy", "ISR Bot monthly roll-call")


def cmd_uninstall(args):
    """Preview by default. --apply removes everything ISR Bot put outside its folder; --remove-folder then deletes the folder."""
    reg = load_json(state_path("canaries.json"), {}) or {}
    listed = [os.path.expanduser(v["path"]) for v in reg.values() if isinstance(v, dict) and v.get("path")]
    decoys = [p for p in listed if owned_path(p, "decoy", log=args.apply)]
    refused = [p for p in listed if p not in decoys]
    decoy_dirs = sorted({os.path.dirname(p) for p in decoys})
    tmp_dir = decoy_path("/tmp")                     # /tmp, or the test's own folder: a test never touches the real one
    tmp = sorted(os.path.join(tmp_dir, f) for f in (os.listdir(tmp_dir) if os.path.isdir(tmp_dir) else []) if TMP_LEFTOVERS.match(f))
    cache = os.path.expanduser("~/.cache/pip-audit")
    held = [e for e in load_json(state_path("quarantine.json"), []) if os.path.isdir(e.get("to", ""))]
    h = home()
    safe_home = os.path.basename(h.rstrip("/")) == "isr-bot" and os.path.isdir(os.path.join(h, "state")) and h not in ("/", os.path.expanduser("~")) \
        and owned_path(h, "home", log=False)
    if not args.apply:
        print(fit({"mode": "preview (nothing removed)",
                   "order": "routines first, then `isr.py uninstall --apply --remove-folder`. Any audit or daily run after the decoys are gone would not re-plant them, but a routine left on would report errors.",
                   "you_do_first_after_the_owners_yes": ["Delete these routines (or tell the owner to, under your Details tab): " + ", ".join(ROUTINE_NAMES)],
                   "this_command_removes": {"decoys": [short_path(p) for p in decoys if os.path.exists(p)],
                                            "decoy_folders_if_empty": [short_path(d) for d in decoy_dirs if os.path.isdir(d)],
                                            "installer_and_scratch_files_in_tmp": len(tmp), "scanner_cache": short_path(cache) if os.path.isdir(cache) else None,
                                            "isr_bot_folder": h + " (with --remove-folder: scanners, reports, state, vet copies)"},
                   "not_removed_outside_isr_bot": [short_path(p) for p in refused] or None,
                   "quarantined_skills": [e["name"] for e in held] or None,
                   "quarantine_note": "These go with the folder. Restore any the owner wants first (`isr.py quarantine --restore <name>`)." if held else None,
                   "only_the_owner_can": ["Keep the three Ask-first rules in Auto-review: they protect every Bot, with or without ISR Bot.",
                                          "Delete ISR Bot itself (right-click it in the sidebar → Delete). That also removes its memories and chat.",
                                          "Roll-call messages already sent to other Bots stay in those chats."],
                   "not_touched": "~/.cache/pip (shared with other tools), other Bots, their memories and routines."}, limit=6000))
        return 0
    done = []
    n = 0
    for p in decoys:
        try:
            os.remove(p); n += 1
        except OSError:
            pass
        remove_witness(os.path.dirname(p))
    save_json(state_path("canaries.json"), {})
    done.append(f"Removed {n} decoy file(s)")
    if refused:
        done.append(f"Did not remove {len(refused)} path(s) the decoy list pointed to outside the decoy places: {', '.join(short_path(p) for p in refused[:3])}")
    for d in decoy_dirs:
        try:
            os.rmdir(d)              # only if empty: never someone else's files
            done.append(f"Removed empty folder {short_path(d)}")
        except OSError:
            if os.path.isdir(d):
                done.append(f"Left {short_path(d)} in place: it has other files in it")
    t = 0
    for p in tmp:
        try:
            os.remove(p); t += 1
        except OSError:
            pass
    if t:
        done.append(f"Removed {t} installer and scratch file(s) from /tmp")
    if os.path.isdir(cache):
        shutil.rmtree(cache, ignore_errors=True)
        done.append(f"Removed the scanner cache {short_path(cache)}")
    if args.remove_folder:
        if not safe_home:
            done.append(f"Did not remove {h}: it doesn't look like an ISR Bot folder. Remove it by hand.")
        else:
            shutil.rmtree(h, ignore_errors=True)
            done.append(f"Removed {h}" + (f" (including {len(held)} quarantined skill(s))" if held else ""))
    else:
        ledger({"event": "uninstall", "steps": len(done)})
    print(json.dumps({"done": done, "left_for_the_owner": ["the three Ask-first rules in Auto-review (worth keeping)",
                                                            "deleting ISR Bot itself, which removes its memories and chat"],
                      "check": f"`ls {h}` should now fail" if args.remove_folder and safe_home else (f"remove {h} by hand" if args.remove_folder else "run again with --remove-folder to delete the ISR Bot folder")}, indent=1))
    return 0


# ---------------------------------------------------------------- doctor: what this computer looks like, safe to share
STATE_FILES = ("baseline.json", "last_findings.json", "engine_cache.json", "suppressions.json", "canaries.json", "events.json",
               "engines_used.json", "stage_times.json", "progress.json", "key_status.json", "run_windows.json")


def shareable_error(text):
    """R12: what doctor may share about the last crash: when, which command, ISR Bot's own code lines and the error's type.
    Never the error's message or any other frame: those can carry private paths, file names or content."""
    if not text.strip():
        return None
    lines = text.splitlines()
    head = re.sub(r"(isr\.py \S+).*?(\(v[\d.]+\))", r"\1 \2", lines[0])[:80]
    frames = [f"{m.group(1)}.py line {m.group(2)} in {m.group(3)}" for m in re.finditer(r'File "[^"]*?(isr|isr_parts/[a-z0-9_]+)\.py", line (\d+), in (\w+)', text)][-6:]
    kind = next((m.group(1) for l in reversed(lines) for m in [re.match(r"^([A-Za-z_][\w.]*(Error|Exception|Exit|Interrupt|Warning)|[A-Z]\w+)(:|$)", l)] if m), "error")
    return {"at_and_command": head, "where": frames, "error_type": kind.split(".")[-1]}


def cmd_doctor(args):
    """A support snapshot with no file contents, no keys and no skill names: versions, which folders exist, which scanners
    are installed, whether the state files are healthy, and how the last run went."""
    h = os.path.expanduser("~")
    def state_of(fn):
        p = state_path(fn)
        if not os.path.exists(p):
            return "missing"
        try:
            with open(p) as f:
                json.load(f)
            return "ok"
        except (OSError, ValueError):
            return "damaged (ignored and rebuilt on the next run)"
    snap = load_snapshot({}) or {}
    folders = {}
    for d in ("sand-data", "agent-data", ".agents", ".grok", ".cursor"):
        p = os.path.join(h, d)
        if os.path.lexists(p):
            folders["~/" + d] = "link" if os.path.islink(p) else "folder"
            for sub in ("workflows", "plugins", "managed-skills", "skills", "agent-transcripts"):
                q = os.path.join(p, sub)
                if os.path.isdir(q):
                    try:
                        folders[f"~/{d}/{sub}"] = f"{len(os.listdir(q))} entries"
                    except OSError:
                        folders[f"~/{d}/{sub}"] = "no permission"
    try:
        probe = state_path(".write-test")
        open(probe, "w").close(); os.remove(probe)
        writable = True
    except OSError:
        writable = False
    lock = load_json(state_path("run.lock"), None)
    out = {"isr_bot": VERSION, "python": platform.python_version(), "system": f"{platform.system()} {platform.machine()}",
           "home_is": h.replace(os.path.basename(h), "<user>") if h.count("/") > 1 else h, "isr_bot_home": home(), "can_write_state": writable,
           "workspace_exists": os.path.isdir("/workspace"), "folders": folders,
           "scanners": {n: bool(tool(t)) for n, t in (("SkillSpector", "skillspector"), ("husk", "husk"), ("gitleaks", "gitleaks"),
                                                       ("TruffleHog", "trufflehog"), ("pip-audit", "pip-audit"), ("OSV-Scanner", "osv-scanner"))},
           "scanner_check": scanner_check(),
           "scanners_from_checksum_lock": bool(scanners_python()) and os.path.isfile(os.path.join(os.path.dirname(os.path.dirname(scanners_python())), "LOCKED")),
           "tools": {t: bool(shutil.which(t)) for t in ("git", "curl", "npm", "pip3")},
           "state_files": {fn: state_of(fn) for fn in STATE_FILES},
           "run_in_progress": bool(lock),
           "last_run": {"at": snap.get("at"), "version": snap.get("version"), "score": snap.get("score"), "score_line": score_line(snap), "open_by_severity": by_sev(owners(snap.get("findings") or [])) if snap else None,   # batch 6 (B9): as audit counts
                        "inventory": snap.get("inventory"), "scanners_missing": snap.get("scanners_missing"), "stages_skipped": snap.get("stages_skipped"),
                        "notes": [re.sub(r"(/[\w.@~-]+){2,}", "<path>", n)[:160] for n in snap.get("notes", [])][:12]},
           "seconds_per_stage": load_json(state_path("stage_times.json"), None), "last_engine_run": load_json(state_path("engines.json"), None),
           "last_error": shareable_error(read_text(state_path("last_error.txt")) or "")}
    text = json.dumps(out, indent=1)
    if args.save:
        os.makedirs(os.path.join(home(), "reports"), exist_ok=True)
        p = os.path.join(home(), "reports", f"support-{dt.date.today().isoformat()}.json")
        with open(p, "w") as f:
            f.write(text)
        print(f"Saved {p}. It has no file contents, keys or skill names; read it before you share it.")
    else:
        print(text)
    return 0


# ---------------------------------------------------------------- self-check
COMMIT_FILE = "installed_commit"
SELF_CHECK_SKIP = ("doctor", "uninstall")   # so the owner can still diagnose it, or take it off


def git_head(root):
    """The commit the installed copy is at, read from its .git folder without running git."""
    try:
        head = open(os.path.join(root, ".git", "HEAD")).read().strip()
    except OSError:
        return None
    if not head.startswith("ref:"):
        return head
    ref = head[4:].strip()
    try:
        return open(os.path.join(root, ".git", ref)).read().strip()
    except OSError:
        for line in (read_text(os.path.join(root, ".git", "packed-refs")) or "").splitlines():
            if line.endswith(" " + ref):
                return line.split()[0]
    return None


def self_check():
    """Before every run, the installed copy checks itself: every file against MANIFEST.sha256, and the commit against the one
    install.sh recorded. Returns the problems found ([] when all is well, None when this is not an installed copy, such as a
    developer's checkout). An install from before v0.6.8 has no recorded commit: the current one is recorded once, and said."""
    root = installed_root()   # PR A, Codex round 1 (6): the copy this runs from, whatever ISR_BOT_HOME says
    if root is None:
        return None
    problems = []
    man = read_text(os.path.join(root, "MANIFEST.sha256"))
    remember_manifest(root, man)   # Claude review 1 (2): what the run is held to later is what was checked now
    if not man:
        return ["MANIFEST.sha256 is missing"]
    for line in man.splitlines():
        parts = line.split(None, 1)
        if len(parts) != 2:
            continue
        want, rel = parts[0], parts[1].lstrip("*").strip()
        p = os.path.join(root, rel)
        if os.path.realpath(p) != os.path.normpath(p) or not os.path.isfile(p):
            problems.append(f"{rel} is missing or not a plain file")
        elif sha256_file(p) != want:
            problems.append(f"{rel} changed since install")
    listed = {l.split(None, 1)[1].lstrip("*").strip() for l in man.splitlines() if len(l.split(None, 1)) == 2} | {"MANIFEST.sha256"}
    for dp, dns, fns in os.walk(root):                  # a file added to the release folder (red-team, v0.6.9): a skill there passes
        dns[:] = [d for d in dns if not (dp == root and d == ".git") and d != "__pycache__"]   # as ISR Bot's own
        for fn in fns:
            rel = os.path.relpath(os.path.join(dp, fn), root)
            if rel not in listed:
                problems.append(f"{rel} is not in the release")
    head = git_head(root)
    rec_path = os.path.join(install_home(root), "state", COMMIT_FILE)   # where install.sh recorded it, for this copy
    rec = (read_text(rec_path) or "").strip()
    if not head:
        problems.append("the installed commit can't be read (.git is missing)")
    elif rec and rec != head:
        problems.append(f"the installed commit is {head[:12]}, but install.sh recorded {rec[:12]}")
    elif not rec and not problems:
        os.makedirs(os.path.dirname(rec_path), exist_ok=True)
        with open(rec_path, "w") as f:
            f.write(head + "\n")
    return problems


# ---------------------------------------------------------------- main
def main(argv=None):
    """Never show a stack trace to the Bot or the user: one plain line, the detail saved for `isr.py doctor`."""
    try:
        return main_inner(argv)
    except SystemExit:
        raise
    except BrokenPipeError:
        return 0
    except Exception as e:   # noqa: BLE001
        detail = traceback.format_exc()
        try:
            with open(state_path("last_error.txt"), "w") as f:
                f.write(f"{now()} isr.py {' '.join((argv or sys.argv[1:])[:3])} (v{VERSION})\n{detail}")
            where = " The detail is saved; `isr.py doctor --save` makes a file you can send to the author."
        except OSError:
            where = ""
        kind = "ISR Bot can't write to its folder " + home() if isinstance(e, OSError) and not where else f"ISR Bot hit a problem it didn't expect ({type(e).__name__})"
        print(f"ERROR {kind}. Nothing was changed.{where}", file=sys.stderr)
        return 3
    finally:
        try:
            if os.path.isdir(os.path.join(home(), "state")):   # after an uninstall, don't recreate the folder just to look for a lock
                cur = load_json(state_path("run.lock"), None)
                if cur and cur.get("pid") == os.getpid():
                    os.remove(state_path("run.lock"))
        except OSError:
            pass


_PROBLEM_NAMED = re.compile(r"(?s)(.*?)( is missing or not a plain file| changed since install| is not in the release)")


def shown_problem(p):
    """A self-check problem as SELF-CHECK FAILED shows it. Claude review 2 (review 1, item 9): whoever plants a file chooses
    its name, so a name is shown only when it is plain (letters, digits, . _ / -, at most 80 characters); the ledger keeps it."""
    m = _PROBLEM_NAMED.fullmatch(p)
    if m and not re.fullmatch(r"[A-Za-z0-9._/-]{1,80}", m.group(1)):
        return "a file with an unusual name (named in ISR Bot's ledger)" + m.group(2)
    return p


def self_check_gate(count_only=False):
    """4 (after one plain SELF-CHECK FAILED line) when this installed copy doesn't match its release, else None. With
    count_only (`--version`, which setup reads to decide on a reinstall) the line gives only how many problems there are:
    Claude review 1 (9), a file planted as "0.7.1" or named like an instruction put its name into that very output. The
    ledger keeps the names."""
    problems = self_check()
    if problems:
        ledger({"event": "self-check-failed", "problems": problems[:20]})
        what = (f"{len(problems)} problem{'s' if len(problems) != 1 else ''} (listed in ISR Bot's ledger)" if count_only else
                "; ".join(map(shown_problem, problems[:5])) + (f" (and {len(problems) - 5} more)" if len(problems) > 5 else ""))
        print("SELF-CHECK FAILED - ISR Bot stopped before doing anything. Its own files don't match the release it installed: "
              + what + ". Tell the owner now. Don't run ISR Bot again until they reinstall it from the release (setup skill, section 1).")
        return 4
    return None


class VersionAction(argparse.Action):
    """Hardening batch 3 (R12): `--version` answered before the self-check, so a changed copy still printed its version and
    setup skipped the reinstall. It now checks itself first, during parsing, and exits 4 without the version when that fails."""

    def __init__(self, option_strings, dest=argparse.SUPPRESS, default=argparse.SUPPRESS, help="print the version (after the self-check)"):
        super().__init__(option_strings=option_strings, dest=dest, default=default, nargs=0, help=help)

    def __call__(self, parser, namespace, values, option_string=None):
        code = self_check_gate(count_only=True)
        if code:
            parser.exit(code)
        print(VERSION)
        parser.exit(0)


def build_parser():
    ap = argparse.ArgumentParser(prog="isr.py", description="ISR Bot security watch for Grok Bot")
    ap.add_argument("--version", action=VersionAction)
    sub = ap.add_subparsers(dest="cmd", required=True)
    v = sub.add_parser("vet"); v.add_argument("path"); v.add_argument("--json", action="store_true"); v.add_argument("--deep", action="store_true"); v.add_argument("--page-only", action="store_true", help="the text was copied from a marketplace page; skill bodies were not visible")
    for name in ("audit", "daily", "baseline"):
        p = sub.add_parser(name)
        p.add_argument("--roots", nargs="*")
        p.add_argument("--exports")
        p.add_argument("--budget", type=int, help="seconds of scanner time for this run (default 420, at most 3600); a full audit runs long enough to use it; unfinished skills resume next run")
        sc = p.add_mutually_exclusive_group()
        sc.add_argument("--everything", action="store_true", help="also check skills in archives, clones and other projects (remembered)")
        sc.add_argument("--live-only", action="store_true", help="back to the default: only what the platform loads (remembered)")
        if name == "baseline":
            p.add_argument("--owner-said-yes", action="store_true", help="the owner said yes to approving every skill as it is now (the first baseline on a computer needs no yes)")
    sub.add_parser("status")
    sub.add_parser("report")
    sub.add_parser("breakdown")
    dm = sub.add_parser("dismiss", help="drop a Worth-a-look finding shown to be a false alarm (logged)"); dm.add_argument("key", nargs="?"); dm.add_argument("--reason", default="")
    dm.add_argument("--list", action="store_true", help="what was dismissed (rule, where, reason); last 24 hours unless --since"); dm.add_argument("--since")
    sh = sub.add_parser("show"); sh.add_argument("rule"); sh.add_argument("--limit", type=int, default=15)
    c = sub.add_parser("canary"); c.add_argument("action", choices=["plant", "status", "remove"]); c.add_argument("--token-file")
    c.add_argument("--owner-said-yes", action="store_true", help="with remove: the owner said yes to removing the decoys in this conversation")
    aa = sub.add_parser("auto-allow", help="list Allow-automatically lines on consequential actions, or keep exact ones after the owner's yes")
    aa.add_argument("action", nargs="?", choices=["list", "keep"], default="list"); aa.add_argument("ids", nargs="?", help="with keep: line ids, comma-separated")
    aa.add_argument("--owner-said-yes", action="store_true", help="with keep: the owner said yes to keeping these exact lines in this conversation"); aa.add_argument("--reason")
    fx = sub.add_parser("fix"); fx.add_argument("--apply", action="store_true"); fx.add_argument("--roots", nargs="*")
    fx.add_argument("--upgrade", action="store_true", help="upgrade the Python packages in the preview (not the owner's projects)"); fx.add_argument("--accept"); fx.add_argument("--reason")
    fx.add_argument("--upgrade-projects", action="store_true", help="run npm's lockfile fix in the owner's own projects: needs its own yes, never part of the one-yes fix")
    fx.add_argument("--keep-open", help="names or paths to leave open even though their rule is in --accept (comma-separated)")
    fx.add_argument("--revet", action="store_true", help="re-scan changed skills with every engine and re-approve the clean ones")
    fx.add_argument("--only", help="with --revet: re-approve only these skills (names, comma-separated); works on skills the daily check or audit already reported as changed (a fresh fix preview is not required); every other changed skill stays open")
    fx.add_argument("--exception", help="skill name(s) the owner confirmed as security tools (30 days)")
    fx.add_argument("--quarantine", help="the owner's own skill(s) to move out of use and into ISR Bot's quarantine folder (comma-separated)")
    fx.add_argument("--rename-reviewed", metavar="SKILLS", help="approve these skills' name-only changes (the product's former name now ISR Bot, nothing else), comma-separated; needs --owner-said-yes")
    fx.add_argument("--owner-said-yes", action="store_true", help="with --apply: the owner said yes to the cleanup list in the last preview; with --rename-reviewed: to the name-only diff")
    fx.add_argument("--approve-platform", metavar="CODE", help="refused: platform files are never scored, so there is nothing to approve (kept so older instructions get a plain answer)")
    fx.add_argument("--platform-from", metavar="CURSOR", help="refused, like --approve-platform")
    fx.add_argument("--skip", help="with --apply: cleanup items (ids or paths, comma-separated) the owner said to leave alone")
    qq = sub.add_parser("quarantine"); qq.add_argument("names", nargs="?"); qq.add_argument("--restore"); qq.add_argument("--reason")
    un = sub.add_parser("uninstall"); un.add_argument("--apply", action="store_true"); un.add_argument("--remove-folder", action="store_true")
    df = sub.add_parser("diff"); df.add_argument("skill"); df.add_argument("--lines", type=int, default=120)
    dr = sub.add_parser("doctor"); dr.add_argument("--save", action="store_true")
    xc = sub.add_parser("exception"); xc.add_argument("action", choices=["add", "list", "remove"]); xc.add_argument("name", nargs="?"); xc.add_argument("--reason")
    ac = sub.add_parser("accept"); ac.add_argument("rule", nargs="?"); ac.add_argument("where", nargs="?")
    ac.add_argument("--reason"); ac.add_argument("--days", type=int, default=90); ac.add_argument("--list", action="store_true"); ac.add_argument("--remove", action="store_true"); ac.add_argument("--all-current", action="store_true")
    ac.add_argument("--owner-said-yes", action="store_true", help="the owner said yes to accepting this one finding two checks agree on")
    ev = sub.add_parser("events"); ev.add_argument("action", choices=["list", "clear"]); ev.add_argument("--rule"); ev.add_argument("--owner-said-yes", action="store_true")
    r = sub.add_parser("rollcall"); r.add_argument("--dir"); r.add_argument("--owner-said-yes", action="store_true", help="the owner said yes to this roll-call in this conversation")
    r.add_argument("--question", action="store_true", help="print the one fixed roll-call question to send, unchanged")
    r.add_argument("--save", metavar="BOT", help="save one Bot's reply (read from stdin) as a 0600 file in the private roll-call folder")
    pp = sub.add_parser("prepublish"); pp.add_argument("path"); pp.add_argument("--json", action="store_true")
    ic = sub.add_parser("incident"); ic.add_argument("--note")
    cs = sub.add_parser("codescan"); cs.add_argument("path")
    br = sub.add_parser("brief"); br.add_argument("--summary"); br.add_argument("--notes"); br.add_argument("--offline")
    ax = sub.add_parser("access", help="what every Bot on this computer can reach, and what each Bot said in the roll-call")
    ax.add_argument("--json", action="store_true", help="the same, as JSON for the Bot (at most 4 KB)")
    return ap


def main_inner(argv=None):
    a = build_parser().parse_args(argv)
    _ACCESS_RUN.clear()   # PR B, Codex round 1 (2): each command shows a map it built itself (load_access_map)
    if a.cmd not in SELF_CHECK_SKIP:
        code = self_check_gate()
        if code:
            return code
    if a.cmd not in SELF_CHECK_SKIP:
        migrate_rollcall_state()
    return {"vet": cmd_vet, "audit": cmd_audit, "daily": cmd_daily, "baseline": cmd_baseline, "report": cmd_report, "breakdown": cmd_breakdown, "show": cmd_show, "dismiss": cmd_dismiss,
            "canary": cmd_canary, "rollcall": cmd_rollcall, "prepublish": cmd_prepublish, "incident": cmd_incident,
            "codescan": cmd_codescan, "brief": cmd_brief, "events": cmd_events, "fix": cmd_fix, "accept": cmd_accept, "status": cmd_status,
            "diff": cmd_diff, "exception": cmd_exception, "doctor": cmd_doctor, "quarantine": cmd_quarantine, "uninstall": cmd_uninstall,
            "auto-allow": cmd_auto_allow, "access": cmd_access}[a.cmd](a)


if __name__ == "__main__":
    sys.exit(main())
