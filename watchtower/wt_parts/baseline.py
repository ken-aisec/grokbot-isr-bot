# Part of wt.py: runs inside wt.py's namespace (loaded by _wt_part); not a module on its own.
BASELINE_META = "baseline_meta.json"
RESET_WHY = {"missing": "is missing", "empty": "is empty", "unreadable": "can't be read"}


def ledger_events(kinds):
    """The ledger's events of these kinds, read line by line (never through a link or a FIFO); a line that isn't one is skipped."""
    try:
        fd = os.open(state_path("ledger.jsonl"), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        return
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return
        with os.fdopen(fd, "rb") as f:
            fd = None
            for line in f:
                if b'"event"' not in line:
                    continue
                try:
                    e_ = json.loads(line)
                except ValueError:
                    continue
                if isinstance(e_, dict) and e_.get("event") in kinds:
                    yield e_
    except OSError:
        return
    finally:
        if fd is not None:
            os.close(fd)


def ran_before():
    """True once Watchtower has run on this box: the baseline's meta file exists, or the ledger has an audit, daily or baseline.
    The ledger is read line by line (never through a link or a FIFO), so a long-lived box never looks new because it is big."""
    if os.path.lexists(state_path(BASELINE_META)):
        return True
    for _ in ledger_events(("audit", "daily", "baseline")):
        return True
    return False


def load_baseline():
    """(baseline, status, why). status "ok": a baseline to compare with. "first": nothing approved yet (the first run ever, or a
    box whose meta file says the baseline held nothing): take one. "reset" (R4, Oct 16): Watchtower ran here before and its
    baseline is now missing, empty or unreadable: an alarm (WT-I010), never a quiet fresh start. An empty baseline counts as
    "nothing approved" only on a record a past run wrote, never on what the current scan sees: `daily --roots /nonexistent`
    finds nothing, and once that empty scan is saved as the baseline the next audit approves everything (Codex, round 1)."""
    path = state_path("baseline.json")
    base = load_json_regular(path, None)
    if isinstance(base, dict) and base:
        return base, "ok", ""
    try:
        st = os.lstat(path)
        why = "empty" if isinstance(base, dict) or (stat.S_ISREG(st.st_mode) and st.st_size == 0) else "unreadable"
    except OSError:
        why = "missing"
    if not ran_before():
        return {}, "first", why
    if why != "unreadable":
        m = load_json_regular(state_path(BASELINE_META), None)
        if isinstance(m, dict) and m.get("files") == 0 and not isinstance(m.get("files"), bool):
            return {}, "first", why   # it held nothing: as today, the first file to fingerprint starts it
    return {}, "reset", why         # an install from before the meta file has no record that it held nothing


def save_baseline_meta(files):
    m = load_json_regular(state_path(BASELINE_META), None)
    first_at = m.get("first_at") if isinstance(m, dict) and isinstance(m.get("first_at"), str) else now()
    save_json_keep_mode(state_path(BASELINE_META), {"first_at": first_at, "at": now(), "files": files})


def save_baseline(base):
    """The only way the baseline is written: atomically, never through a link, with a note of when and how many files."""
    save_json_keep_mode(state_path("baseline.json"), base)
    save_baseline_meta(len(base))


def save_first_baseline(manifest):
    """The first baseline on a box (R10: it needs no yes). Codex, item 8 review 2 (high 3): it approved every platform file it
    found, with or without provenance. Decision, Oct 18: a first baseline, on a new box or a wiped one, vouches for no
    platform file. Returns the platform files it left out. b8i4 (decision, Oct 22): a clean changed one at a release-list path
    raised nothing on this first run and rolls in on a later full audit (the middle path). Fix round 1 (Codex 1): a new skill
    folder, or a new file in one, is a counted high on a first run and on every run after (platform_held_before), like the rest,
    until a Watchtower release lists it."""
    held = platform_unproven(manifest)
    save_baseline({p: h for p, h in manifest.items() if p not in held})
    return held


def baseline_reset_finding(why):
    m = load_json_regular(state_path(BASELINE_META), None)
    held = (f" (it held {m['files']} files on {m['at'][:10]})" if isinstance(m, dict) and isinstance(m.get("files"), int)
            and isinstance(m.get("at"), str) else "")
    return finding("WT-I010", "Chief Worry Bot's memory was reset", "high", ["AST07"], "state/baseline.json",
                   f"baseline.json {RESET_WHY.get(why, why)}{held}",
                   "Something emptied, damaged or deleted the file where Chief Worry Bot remembers the skills you approved, so it can't tell "
                   "whether any of them changed. It has not approved anything on its own. `wt.py diff <skill>` still compares a skill with "
                   "the copy you approved. When you've looked, say yes and Chief Worry Bot starts a new baseline (`wt.py baseline --owner-said-yes`).",
                   ident="baseline-reset")


MIDDLE_PATH_STAGES = ("SkillSpector and husk", "gitleaks (keys in files)")   # b8i4 fix round 1: a failed one holds a middle-path roll


def roll_builtin(fs, meta, notes):
    """Built-in files the platform added, updated or removed are accepted on their own when nothing flags them, so they
    don't pile up as hundreds of lines for the user to approve."""
    base, status, _ = load_baseline()
    if status != "ok":
        return fs
    cache = load_json(state_path("engine_cache.json"), {}) or {}
    installed = [n for n, t in (("SkillSpector", "skillspector"), ("husk", "husk")) if tool(t)]
    if engines_blocked():   # batch 3 (R7): an engine that's swapped, not listed or gone never lets a change roll in on rules alone
        return fs
    flagged, flagged_votes = set(), set()
    for f in fs:
        if f["rule"].startswith("WT-I") or f["severity"] not in ("critical", "high", "medium"):
            continue
        w = f["where"].split(":")[0]
        # b8i4: a wording-only vote on a platform skill (DQ-042) doesn't hold back a middle-path update: settle_platform_updates
        # already let it through. A listed update still waits for it, as before.
        (flagged_votes if f["rule"] == "WT-X003" and unconfirmed_platform_vote(f, fs) else flagged).update({w, skill_root(w) or w})
        # fix round 2 (Codex 4): a grouped finding (gitleaks's WT-S002 on a folder) holds every file it stands for
        for q in f.get("affected_files") or []:
            if isinstance(q, str):
                flagged.update({q, skill_root(q) or q})
    # b8i4 fix round 1 (Codex 5): a middle-path update rolls only after every check of it finished: a secret-scanning stage that
    # failed this run (its last results are only carried) holds it, and so does a scanner that ran out of time on its folder
    blocked = [s for s in MIDDLE_PATH_STAGES if s in STAGE_FAILED]

    def passes(q, mid):
        root = skill_root(q)
        e_ = (cache.get(root) or {}) if root else {}
        checked = (not root) or (not installed) or (entry_current(e_, skill_dir_hash(root), installed) and not (mid and e_.get("stuck")))
        held = flagged if mid else flagged | flagged_votes
        return q not in held and (root or q) not in held and checked

    keep, rolled, moved = [], 0, []
    for f in fs:
        w = f["where"].split(":")[0]
        mid = bool(f.get("platform_update"))
        # fix round 1 (Codex 6): each place a merged managed-skills finding names (also_at) is checked on its own, and the
        # finding rolls only when every one of them passes, so a held copy keeps the bytes the baseline had for it
        places = [w] + list(f.get("also_at") or [])
        # fix round 2 (Codex 2): and each still leads where it led when it was chosen, inside a platform folder. Fix round 3 (Codex
        # 1): checked here, before the gate, as the last check before the baseline is written; one that fails is a counted high
        # (hold_moved_updates), never kept as a quiet update the Platform refresh line names
        if mid and not all(platform_still_bound(q) for q in places):
            moved.append(f)
            continue
        # item 8 (R3): a platform change the vendor release list doesn't include waits for a release that lists it, never rolls
        if f["rule"] in ("WT-I001", "WT-I002", "WT-I003") and builtin(f) and not f.get("unverified_platform"):
            if not (mid and blocked) and all(passes(q, mid) for q in places):
                for q in places:
                    if f["rule"] == "WT-I003":
                        base.pop(q, None)
                    elif q in meta["manifest"]:
                        base[q] = meta["manifest"][q]
                rolled += 1
                if mid:   # fix round 1 (Codex 7): accepted, and still the one Platform refresh line naming it (summarize_refresh)
                    f["platform_accepted"] = True
                    keep.append(f)
                continue
        keep.append(f)
    if rolled:
        save_baseline(base)
        notes.append(f"{rolled} built-in plugin or skill files were added, updated or removed by the platform. Nothing flagged them, so they were accepted automatically.")
        ledger({"event": "builtin-roll", "files": rolled})
    return hold_moved_updates(keep + moved, moved, meta["manifest"])


def is_accepted(f, sup, today):
    if f.get("unverified_platform"):
        return False   # Codex, item 8 review 1: before every branch, key matches included; only a release that lists it clears one
    if f.get("rule") == "WT-A002" and f.get("accepted_exact"):
        return True   # exact owner-accepted line (state/accepted_auto_allow.json); severity untouched
    names = refused = None
    for s_ in sup:
        if s_.get("expires", "9999") < today:
            continue
        if s_.get("kind") == EXC_KIND:        # named skill only, and only while its files are exactly what the owner confirmed
            if f["rule"] == "WT-X003" and os.path.normpath(f["where"]) == s_.get("where") and skill_dir_hash(f["where"]) == s_.get("hash"):
                return s_
            continue
        if s_.get("key") and s_["key"] in (f["key"], f.get("key0")):
            return True
        # rule + whole name survives rescans that change a finding's evidence (and so its key). R2/R10 (Oct 16): never a part of a
        # name, and never a finding `accept` refuses, so an entry an earlier version stored (`accept WT-K001 /`) no longer applies.
        if s_.get("rule") == f["rule"] and s_.get("match") and isinstance(s_["match"], str):
            if refused is None:
                refused = bool(accept_refused(f))
            if refused:
                continue
            if names is None:
                names = accept_names(f)
            if s_["match"] in names:
                return True
    return False


DISMISSED_BACK = "You dismissed this before; it is back because {why}. "


def set_aside_dismissed(findings):
    """Batch 6 fix round 1 (Codex 7): (kept, dismissed), each finding judged on its own before findings are grouped, so a
    dismissed line that would have led a group never takes another file's finding with it; the audit groups the kept ones. An
    accepted risk is left for active() (it shows under accepted risks, not as dismissed).
    Fix round 2 (Codex 6, 7; the owner's rule): a dismissal sets aside only a Worth-a-look finding, as at 5dcd0a2. state/dismissed.jsonl
    can be written by a Bot, and a Bot can compute any digest, so no record holds a finding something backs up: one dismissed
    before and backed up now (most often by a change to its file, WT-I001/I002) counts again, and its fix says so (DQ-045, a
    dismissal that survives an unrelated edit, needs a dismissal authority a Bot can't write: not done, see KNOWN-LIMITS)."""
    sup = load_json(state_path("suppressions.json"), [])
    today = dt.date.today().isoformat()
    gone = dismissed_records()
    drift = [(_place(g), g["rule"]) for g in findings if g.get("rule") in DRIFT_RULES] if gone else []
    kept, out = [], []
    for f in findings:
        rec = gone.get(f.get("key"))
        if rec is None or f.get("unverified_platform") or is_accepted(f, sup, today):
            kept.append(f)
        elif f.get("class") == "pattern":   # the disprove step; never evidence
            f["dismissed"] = rec.get("reason", "")
            out.append(f)
        else:
            fix = f.get("fix") or ""
            if f.get("class") == "corroborated" and not fix.startswith(DISMISSED_BACK[:30]):   # a line a daily carries keeps one
                here = _place(f)
                changed = next((r for p, r in drift if _covers(p, here)), None)
                f["fix"] = DISMISSED_BACK.format(why=f"the file changed (see {changed})" if changed else "something else now backs it up") + fix
            kept.append(f)
    return kept, out


def active(findings):
    """(open, set aside): accepted risks and the owner's dismissals (Worth-a-look findings only) set aside. The audit judges
    dismissals before grouping (set_aside_dismissed); the fix's re-approval reads the findings as they are."""
    sup = load_json(state_path("suppressions.json"), [])
    today = dt.date.today().isoformat()
    flags = [is_accepted(f, sup, today) for f in findings]   # per finding, never by shared key
    gone = dismissed_keys()
    for i, f in enumerate(findings):
        if not flags[i] and f.get("class") == "pattern" and f.get("key") in gone and not f.get("unverified_platform"):   # the disprove step; never evidence
            f["dismissed"], flags[i] = gone[f["key"]], True
    for f, a in zip(findings, flags):
        if isinstance(a, dict):
            f["exception"] = {"kind": "security tool", "until": a.get("expires"), "reason": a.get("reason", "")}
    return [f for f, a in zip(findings, flags) if not a], [f for f, a in zip(findings, flags) if a]


def canonical_rule(s):
    """A rule id as Watchtower writes it, whatever its case: WT- and the letters upper, a suffix after the number lower
    (WT-T006k, WT-T001r, WT-WA07s). Uppercasing it all stored WT-T006K, which matches nothing (Codex, round 1)."""
    s = str(s or "").strip()
    m = re.fullmatch(r"(?i)wt-([a-z]+)(\d*)([a-z]*)", s)
    if not m:
        return s.upper()
    return f"WT-{m.group(1).upper()}{m.group(2)}{m.group(3).lower()}"


def cmd_accept(args):
    """Accept a risk on purpose: it stops counting against the score and shows under 'accepted risks' until it expires."""
    if args.rule:
        args.rule = ",".join(canonical_rule(r) for r in args.rule.split(","))
    sup = load_json(state_path("suppressions.json"), [])
    today = dt.date.today().isoformat()
    if args.list or not args.rule:
        ignored = 0
        for s_ in sup:
            state = "expired" if s_.get("expires", "9999") < today else "active"
            if s_.get("kind") != EXC_KIND and s_.get("match") and accept_rule_refused(str(s_.get("rule", ""))):
                state, ignored = "ignored", ignored + 1
            what = (s_.get("where") or "") + " [SECURITY-TOOL EXCEPTION]" if s_.get("kind") == EXC_KIND else (s_.get("match") or s_.get("key", "")[:12])
            print(f"{state:8} {s_.get('rule', '-'):9} {what:40} until {s_.get('expires')}  {s_.get('reason', '')}")
        if not sup:
            print("No accepted risks.")
        if ignored:
            print("\"ignored\": an earlier version accepted these, but a decoy alarm, or something Chief Worry Bot saw happen, can't be "
                  "marked as fine. They count again.")
        return 0
    if args.all_current:
        n, skipped, exp = accept_current([r.strip() for r in args.rule.split(",")], args.reason or "reviewed by owner", args.days)
        print(f"Accepted {n} finding(s) until {exp}." + (f" Left open: {'; '.join(sorted(set(skipped))[:6])}." if skipped else ""))
        return 0
    if args.remove:
        keep = [s_ for s_ in sup if not (canonical_rule(s_.get("rule")) == args.rule and s_.get("match") == args.where)]
        save_json(state_path("suppressions.json"), keep)
        print(f"Removed {len(sup) - len(keep)} accepted risk(s).")
        return 0
    if not args.where or not args.reason:
        print("ERROR give a rule, the name or path it applies to, and --reason in your own words", file=sys.stderr)
        return 2
    rule = args.rule
    snap = load_json(state_path("last_findings.json"), {}) or {}
    hits = [f for f in (snap.get("findings") or []) + (snap.get("suppressed") or [])
            if isinstance(f, dict) and f.get("rule") == rule and args.where in accept_names(f)]
    why = accept_rule_refused(rule) or next((w for w in map(accept_refused, hits) if w), None)
    if why:
        print(f"NOT ACCEPTED: {why}")
        return 1
    days = max(1, min(args.days, 365))
    exp = (dt.date.today() + dt.timedelta(days=days)).isoformat()
    sup = [s_ for s_ in sup if not (s_.get("rule") == rule and s_.get("match") == args.where)]
    sup.append({"rule": rule, "match": args.where, "reason": args.reason[:200], "expires": exp, "added": now()})
    save_json(state_path("suppressions.json"), sup)
    ledger({"event": "accept", "rule": rule, "match": args.where, "expires": exp})
    n_open = sum(1 for f in hits if f in (snap.get("findings") or []))
    print(f"Accepted {rule} for “{args.where}” until {exp}. It will show under accepted risks, then come back for a re-check. " +
          (f"It covers {n_open} open finding(s) now." if n_open else
           f"Nothing open matches “{args.where}” exactly right now; it applies only to a finding at exactly that place, skill or package."))
    return 0


def ledger(event):
    event["at"] = now()
    with open(state_path("ledger.jsonl"), "a") as f:
        f.write(json.dumps(event) + "\n")


LOCK_STALE = 45 * 60


class Busy(Exception):
    pass


def take_lock(wait=0):
    """One Watchtower run at a time: two at once fight over the same files and slow each other's scanners."""
    path, t0 = state_path("run.lock"), time.monotonic()
    while True:
        try:
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            os.write(fd, json.dumps({"pid": os.getpid(), "at": time.time()}).encode())
            os.close(fd)
            return path
        except FileExistsError:
            cur = load_json(path, {}) or {}
            dead = False
            try:
                os.kill(int(cur.get("pid", 0)), 0)
            except (OSError, ValueError, TypeError):
                dead = True
            if dead or time.time() - cur.get("at", 0) > LOCK_STALE:
                try:
                    os.remove(path)
                except OSError:
                    pass
                continue
            if time.monotonic() - t0 >= wait:
                raise Busy()
            time.sleep(2)


def note_run_window(t_start):
    runs = [list(r) for r in run_windows() if r[1] > time.time() - 3 * 86400][-60:]
    runs.append([t_start, time.time()])
    save_json(state_path("run_windows.json"), runs)


def run_audit(args, quick):
    global SCAN_EVERYTHING
    lock, t_start = take_lock(wait=0 if quick else 900), time.time()
    try:
        return run_audit_locked(args, quick)
    finally:
        SCAN_EVERYTHING = False   # the scope lives in state/scope.json; nothing outside a run inherits it
        note_run_window(t_start)
        try:
            os.remove(lock)
        except OSError:
            pass


def run_audit_locked(args, quick):
    global ENGINE_BUDGET, SCAN_EVERYTHING
    SCAN_EVERYTHING = scope_everything(args)
    roots = args.roots or [os.path.expanduser("~"), "/workspace"]
    exports = args.exports or os.path.join(home(), "exports")
    start = dt.datetime.now()
    global DEADLINE
    saved = ENGINE_BUDGET
    del STAGE_FAILED[:]
    try:
        limit = DAILY_LIMIT if quick else RUN_LIMIT
        if getattr(args, "budget", None) is not None:
            ENGINE_BUDGET = max(0, min(args.budget, MAX_BUDGET))
            if not quick:   # DQ-010: an owner who asks for more scanner time gets it; the run limit used to cap it at about 8 minutes
                limit = max(limit, ENGINE_BUDGET + 120)   # the other stages take about two minutes
        DEADLINE = time.monotonic() + limit
        fs, meta = audit(roots, exports, quick=quick)
    finally:
        ENGINE_BUDGET, DEADLINE = saved, None
    if quick:  # the daily run skips the slow engines; keep their last results instead of calling them fixed
        prev_snap = load_json(state_path("last_findings.json"), {"findings": []})
        have = keys_of(fs)
        rescanned = {f["where"] for f in fs if f["rule"].startswith("WT-X")} | ENGINE_CURRENT   # these have an up-to-date answer, flagged or clean
        for f in prev_snap.get("findings", []):
            if f["rule"] in SLOW_RULES and not known(f, have) and f["where"] not in rescanned:
                fs.append(kept_line(f))
        fs = sort_findings(merge_managed_mirrors(hold_on_kept_votes(fs, meta["manifest"]), meta["manifest"]))   # b8i4
    # b8i4 fix round 3 (Codex 1): every quiet platform update still leads where it led when it was chosen, or it is a counted high
    # (never the Platform refresh line, never rolled), whether or not this run rolls anything
    fs = sort_findings(hold_unbound_updates(fs, meta["manifest"]))
    if not quick and "SkillSpector and husk" not in STAGE_FAILED:
        fs = roll_builtin(fs, meta, meta["notes"])
    fs = split_facts(platform_owned(fs))
    for f in fs:
        # batch 6 (B2), fix round 1 (Codex 2, 3): whether a gitleaks hit in a metadata file is a platform note is decided where it
        # is asked (metadata_hit_note), from the release list and the file's bytes then; 6cd1ab4's stored flag means nothing.
        f.pop("verified_metadata", None)
        if f.get("unverified_platform"):   # item 8 (R3): the owner's to decide, so no platform or built-in scope
            continue
        if platform_file(f):
            f["scope"] = "platform"
        elif builtin(f):
            f["scope"] = "builtin"
        elif in_pending_plugin(f["where"]) and f["rule"] in ("WT-X001", "WT-X002", "WT-T006k") and f["severity"] == "low":
            f["severity"] = "medium"   # one scanner flagging a skill in a plugin nobody has reviewed yet is worth a look
    # Label before platform-refresh summary so a built-in that turns Confirmed critical/high alerts (Claude v0.7.1 F4).
    fs = label_findings(fs, ask_first_covered(fs))
    # batch 6 fix round 1 (Codex 7): each finding's dismissal is judged on its own, then only the kept ones are grouped
    fs, gone = set_aside_dismissed(mark_platform(summarize_refresh(mark_reviewed(fs, meta.get("manifest")))))
    fs = sort_findings(group_changed_skills(group_root_causes(fs)))
    live, suppressed = active(fs)
    suppressed = sort_findings(gone + suppressed)
    prev = load_json(state_path("last_findings.json"), {"findings": []})
    note_earlier_auto_allow(prev, live)
    prev_keys, cur_keys = keys_of(prev.get("findings", [])), keys_of(live)
    new = [f for f in live if not known(f, prev_keys) and (f["severity"] != "info" or f.get("class") == "pattern")]
    fixed = [f for f in prev.get("findings", []) if not known(f, cur_keys) and f["rule"] != REFRESH_RULE   # a summary going away fixes nothing
             and not f.get("guarded")]                                                                # nor does a warning-text record
    s, g = score(scored(live))
    if meta["baseline_status"] == "first":
        held = save_first_baseline(meta["manifest"])
        save_approved_all(meta.get("skill_dirs", []), held, load_baseline()[0])
    elif meta["baseline_status"] == "ok":
        if not os.path.lexists(state_path(BASELINE_META)):   # an install from before the meta file: remember it ran
            save_baseline_meta(len(load_baseline()[0]))
        if not quick:   # skills approved before copies were kept: keep one now, but only while they still match what was approved
            drifted = {skill_root(f["where"].split(":")[0]) for f in expand_groups(fs) if f["rule"] in ("WT-I001", "WT-I002", "WT-I003")}
            save_approved_all([d for d in meta.get("skill_dirs", []) if os.path.normpath(d) not in drifted and not os.path.exists(approved_path(d))])
    # "reset": nothing is saved or approved; WT-I010 stays open every run until the owner's yes (`wt.py baseline --owner-said-yes`)
    snapshot = {"at": now(), "version": VERSION, "status": status_of(scored(live)), "score": s, "grade": g, "previous_score": prev.get("score"), "findings": live, "suppressed": suppressed,
                "scanners_missing": meta.get("scanners_missing", []), "stages_skipped": list(STAGE_FAILED),
                "inventory": meta["inventory"], "notes": meta["notes"]}
    if meta.get("plugin_version_changes"):   # DQ-047 fix round 1: cmd_daily says them; only when there are any
        snapshot["plugin_version_changes"] = meta["plugin_version_changes"]
    # PR A, Codex round 2 (6): critical or high findings a daily run had no room to name stay owed while they are open, whatever
    # run comes next (cmd_daily names them and clears them)
    owed = prev.get("undelivered") if isinstance(prev.get("undelivered"), list) else []
    if owed:
        snapshot["undelivered"] = sorted({k for k in owed if isinstance(k, str) and k in cur_keys})
    mask_stored(live), mask_stored(suppressed)   # batch 4 (R11): an older version's unmasked evidence (kept engine lines) is cleaned here
    fixed = mask_stored([dict(f) for f in fixed])   # Codex, round 3: resolved ones come from the last snapshot, maybe an older version's
    snapshot["notes"] = [mask_secrets(n) if isinstance(n, str) else n for n in snapshot["notes"]]   # round 2: a scanner's error line too
    mask_approved_copies()                       # and its approved skill copies (Codex, round 1)
    save_json(state_path("last_findings.json"), snapshot)
    save_platform_held(live + suppressed, meta.get("platform_held_before"))   # b8i4 fix round 2 (Codex 1)
    refresh_access_map(snapshot, meta)           # batch 5 (a): state/access_map.json, from what this run collected
    with open(state_path("score_history.csv"), "a") as f:
        f.write(f"{snapshot['at']},{s},{len(live)},{'daily' if quick else 'full'},{score_fingerprint()}\n")
    resolved = load_json(state_path("resolved.json"), {})
    for f in fixed:
        if f["severity"] in ("critical", "high", "medium") and f["key"] not in resolved:
            resolved[f["key"]] = now()
    cutoff = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=60)).isoformat()
    save_json(state_path("resolved.json"), {k: v for k, v in resolved.items() if v >= cutoff})
    elapsed = round((dt.datetime.now() - start).total_seconds(), 1)
    ledger({"event": "daily" if quick else "audit", "score": s, "findings": len(live), "new": len(new), "fixed": len(fixed), "seconds": elapsed})
    return snapshot, new, fixed


def score_fingerprint():
    """What was measuring: formula era, Watchtower version, and which scanners ran. When it changes between two
    audits, a score change may be Watchtower looking at more (or differently), not your setup changing."""
    used = (load_json(state_path("engines_used.json"), {}) or {}).get("engines", [])
    return f"{SCORE_ERA}:{VERSION}|" + "+".join(sorted(used))


def load_history():
    """Full audits in the current scoring era. Each row: (time, score, findings, changed, fingerprint) where
    changed means Watchtower itself differed from the previous audit. Older rows used other formulas and are hidden."""
    rows, prev = [], None
    try:
        with open(state_path("score_history.csv")) as f:
            lines = f.read().splitlines()
    except OSError:
        return rows
    for line in lines:
        parts = line.strip().split(",", 4)
        if len(parts) < 5 or parts[3] != "full" or not parts[4].startswith(SCORE_ERA + ":"):
            continue
        try:
            a, sc, n = parts[0], int(parts[1]), int(parts[2])
        except ValueError:
            continue
        rows.append((a, sc, n, prev is not None and parts[4] != prev, parts[4]))
        prev = parts[4]
    return rows


SLOW_RULES = ("WT-X001", "WT-X002", "WT-X003", "WT-S002", "WT-D001", "WT-D002")


def compact(f):
    out = dict({k: f[k] for k in ("rule", "severity", "title", "where", "evidence", "fix", "owasp")}, label=label_of(f))
    if f.get("also_count"):   # v0.7.1 item 5: one line per root cause
        rules = sorted({a["rule"] for a in f.get("also_flagged_by", [])})
        out["also_flagged_by"] = f"{f['also_count']} more in this skill about the same kind of risk ({', '.join(rules)})"
    return out
