# Part of wt.py: runs inside wt.py's namespace (loaded by _wt_part); not a module on its own.
# ---------------------------------------------------------------- audit
def audit(roots, exports, quick=False):
    rules = load_rules()
    fs, notes = [], []
    version_changes = []   # DQ-047 fix round 1: the pending plugins' version-folder notes, said in daily too
    INCOMPLETE_SKILLS.clear()
    _RUNS_CODE.clear()
    VERIFIED_METADATA.clear()   # batch 6 (B1): filled by platform_verified below
    _METADATA_PROOF.clear()   # fix round 1: metadata_proof decides again from the disk
    reset_scanner_checks()
    walk_errors = []   # batch 5 PR B, Codex round 2 (3): a folder the scan couldn't list leaves the access map incomplete
    walk_skipped = []   # round 3 (1): so does one it left out (a link, too deep, a folder it never scans)
    inv = collect_inventory(roots, errors=walk_errors, skipped=walk_skipped)
    manifest = {}
    # DQ-022/023, v0.7.1 item 1: SKILL.md outside loadable locations — one "Not scanned" line (a Tip), never scored as installed
    if inv.get("non_live_skills"):
        places = not_scanned_places(inv["non_live_skills"], roots)
        shown = ", ".join(places[:6]) + (f", +{len(places) - 6} more" if len(places) > 6 else "")
        hint = "" if SCAN_EVERYTHING else "; say 'scan everything' to include them"
        fs.append(finding("WT-I007", f"Not scanned: {len(places)} folder{'' if len(places) == 1 else 's'} ({shown}){hint}",
                          "info", ["AST09"], "not-scanned",
                          f"{len(inv['non_live_skills'])} SKILL.md file(s) outside the places Grok Bot loads skills from "
                          "(archives, clones, other projects, tests, fixtures, quarantine). Keys are still checked there.",
                          "No action. Only skills the platform loads are checked." +
                          ("" if SCAN_EVERYTHING else " Say 'scan everything' to include them (`wt.py audit --everything`)."),
                          ident="not-scanned"))

    # 1. skills, plugins, MCP configs on disk
    # PR A, Codex round 1 (8): each file is read once; what is scanned and its fingerprint are the same bytes, and each finding
    # from them carries that fingerprint (_snap) until mark_reviewed, which only applies an entry to it.
    def scanned_from(batch, h):
        for f in batch:
            f["_snap"] = h
        return batch

    for skill in inv["skills"]:
        for p in skill_dir_files(skill):
            if os.path.splitext(p)[1].lower() in TEXT_EXT:
                t, manifest[p] = read_scanned(p)
                if t is not None:
                    kind = "vendor" if is_vendor(p) else ("skill" if os.path.basename(p) == "SKILL.md" else "reference")
                    batch = scan_text(t, p, rules, kind=kind)
                    if is_vendor_template_file(p):   # DQ-024: story text in a built-in deck template is not a hidden-action hit
                        for f in batch:
                            if f["rule"] in ("WT-T008", "WT-T016"):   # story wording only; never exfil/pipe/override (R2)
                                f["severity"] = "info"
                                f["title"] = f["title"] + " (example text in a built-in template)"
                    fs += scanned_from(batch, manifest[p])
            else:
                manifest[p] = sha256_file(p)
    for p in inv["plugin_files"] + inv["mcp_configs"]:
        t, h = read_scanned(p)
        if t is not None:
            fs += scanned_from(scan_text(t, p, rules, kind="reference"), h)
            manifest[p] = h
            for ln, ev in mcp_unpinned(t):   # batch 6 (B8): every launcher alike, read from the server's command and args
                fs.append(finding("WT-M001", "MCP server launched unpinned", "medium", ["AST02", "ASI04"],
                                  f"{p}:{ln}", ev, "Pin an exact version (pkg@1.2.3) so an update can't change what runs."))
    if inv["platform_aliases"]:   # item 8 review 1: a platform name of a file already scanned is fingerprinted, never dropped
        scanned = {os.path.realpath(p) for p in manifest}
        for a in inv["platform_aliases"]:
            for p in (skill_dir_files(a) if os.path.basename(a) == "SKILL.md" else [a]):
                rp = os.path.realpath(p)
                if rp not in scanned and os.path.splitext(p)[1].lower() in TEXT_EXT:
                    scanned.add(rp)
                    t, manifest[p] = read_scanned(p)
                    if t is not None:
                        fs += scanned_from(scan_text(t, p, rules, kind="vendor" if is_vendor(p) else ("skill" if os.path.basename(p) == "SKILL.md" else "reference")),
                                           manifest[p])
                else:
                    manifest[p] = sha256_file(p)
    # item 8 review 2 (high 1): every file name in the platform folders, found by their own walk, is fingerprinted
    plat_files, plat_short = platform_inventory(roots)
    for p in plat_files:
        if p not in manifest:
            manifest[p] = sha256_file(p)
    fs += [platform_coverage_finding(d, why) for d, why in plat_short]

    # 2. integrity drift (AST07)
    base, base_status, base_why = load_baseline()
    # item 8 (R3): no vendor provenance, a counted high. Checked before any exemption (Codex, item 8 review 1: Watchtower's own
    # watchtower-fix/SKILL.md copied into .grok/bundled/skills passed as its own release, with no line for that path). Review 2
    # (high 3): a matching baseline.json line is not provenance. Decision, Oct 18: only the release list is, on every run; a
    # first run (a new box, or one whose state was wiped) vouches for nothing. Decision, Oct 22 (b8i4): the middle path. A
    # candidate (platform_update_candidates) goes through the drift loop like a listed update and is decided after the engines
    # (settle_platform_updates); every other unproven file is a counted high here. Fix round 1 (Codex 1): new skill folders and
    # new files in one only in an update run, and never one the last run held outside the middle path.
    unproven = platform_unproven(manifest)
    held_before = platform_held_before()   # fix round 2 (Codex 1): kept by save_platform_held, after any run or `wt.py baseline`
    cands = platform_update_candidates(unproven, manifest, base, plat_short, established=base_status == "ok",
                                       held_before=held_before)
    for p in sorted(unproven - set(cands)):
        fs.append(unverified_platform_finding(p, manifest[p], base.get(p)))
    if base_status == "reset":   # R4: never a fresh start; nothing is re-approved until the owner says yes
        fs.append(baseline_reset_finding(base_why))
    elif base:
        # Item 8 (Codex high 2): a file is moved only when an approved file with the same name and bytes is gone from disk, one
        # for one, within one trust boundary, and never in or out of a platform folder (match_moves).
        moved_from, moved_to = match_moves(base, manifest)
        versions = plugin_versions(inv["plugin_files"])
        for p, h in manifest.items():
            if p in unproven and p not in cands:
                continue
            if p not in cands and own_release_file(p, h):   # b8i4: a platform file is never exempted as Watchtower's own
                continue   # Watchtower's own skill, identical to the checksummed release it was installed from
            if p in moved_to:
                continue   # the same file under a new folder name (plugins are reinstalled under new folders after a restart)
            if p in base and base[p] != h and is_vendor(p):
                fs.append(finding("WT-I001", "Built-in skill or plugin updated", "low", ["AST07"], p, f"sha256 {base[p][:12]}→{h[:12]}",
                                  "Usually the platform or a plugin update. The scanners re-check the new version; the fix re-approves it if clean."))
                fs[-1]["refresh"] = platform_file(p)
            elif p in base and base[p] != h:
                fs.append(finding("WT-I001", "Reviewed skill or plugin changed", "high", ["AST07"], p,
                                  f"sha256 {base[p][:12]}→{h[:12]}",
                                  "Tell Chief Worry Bot \"fix it\": it re-scans the skill with every engine and re-approves it if clean. `wt.py diff <skill>` shows what changed."))
            elif p not in base:
                fs.append(finding("WT-I002", "New skill or plugin file", "low", ["AST09"], p, h[:12],
                                  "Vet it (`wt vet`), then run `wt baseline` to accept it."))
                fs[-1]["refresh"] = platform_file(p)
                ck = plugin_file_key("WT-I002", p, h, versions)   # DQ-047: same bytes, same plugin version, new catalog folder
                if ck:
                    fs[-1]["key0"] = ck
        for p in base:
            if any(x in p for x in SKIP_PATH_PARTS):
                continue
            if p in moved_from:
                continue   # moved, not removed
            if platform_churn_file(p):
                continue   # sync bookkeeping an older baseline listed (PLATFORM_CHURN): still there, just no longer fingerprinted
            if p not in manifest and not p.startswith("persist:") and out_of_scope_but_present(p):
                continue
            if p not in manifest and not p.startswith("persist:") and not os.path.exists(p) and not is_live_skill_path(p):
                continue   # item 8 dry run (Oct 13): gone from a place nothing loads (skill-hunt candidates, clones): not a live removal   # v0.7.1 item 1: still on disk, just outside the live scan (archive, clone, scope back to live-only)
            if p not in manifest and not p.startswith("persist:"):
                fs.append(finding("WT-I003", "Skill or plugin file removed", "info", ["AST09"], p, "missing", "Confirm you removed it."))
                fs[-1]["refresh"] = platform_file(p)
    else:
        notes.append("No baseline yet: integrity drift starts next run.")
    if platform_lock_problem():
        notes.append(f"The platform release list ({PLATFORM_LOCK_REL}) can't be used: {platform_lock_problem()}. So no file in a platform "
                     "folder is verified by it: every new or changed one is a high alert until a Chief Worry Bot release lists it.")
    for rel, problem in ((PLATFORM_REVIEWED_REL, platform_reviewed_problem()), (PLATFORM_NORMALIZE_REL, platform_normalize_problem()),
                         (ACCESS_VOCAB_REL, access_vocab_problem()), (ASK_FIRST_VOCAB_REL, ask_first_vocab_problem())):
        if problem:   # batch 5 (d2, d3b): ignored whole, so nothing in a platform file is checked or normalized by it (b: no story is matched)
            notes.append(f"Chief Worry Bot's {rel} can't be used: {problem}. It is ignored, so nothing it lists applies this run.")
    if os.path.lexists(state_path(OLD_PLATFORM_APPROVALS)):
        notes.append(f"state/{OLD_PLATFORM_APPROVALS} is left from an earlier Chief Worry Bot and is no longer read: platform files it listed are "
                     "alerts again unless the release list includes them. You can delete it.")
    for d, (n_done, n_all) in sorted(INCOMPLETE_SKILLS.items()):
        fs.append(finding("WT-I006", "Skill too large to check completely", "info", ["AST07"], d, f"{n_done} of {n_all} files fingerprinted and scanned",
                          "Files past the limit are NOT checked for changes; Chief Worry Bot can't re-approve this skill automatically. Trim it, or review changes by hand."))
    new_plugins = note_plugins(inv)
    synced = catalog_sync(new_plugins)
    for market, commit, names in synced:
        fs.append(finding("WT-I005", "Platform catalog sync added plugins", "info", ["AST09"], f"plugins/cache/{market}",
                          f"{len(names)} at catalog commit {commit[:12]}: {', '.join(names)}"[:200],
                          "The platform updated its public plugin catalog; nobody installed these. None of them adds hooks, scripts or a "
                          "program that runs on this computer. Their skills are still scanned like any other.", ident=f"{market}@{commit}"))
        for n in names:
            new_plugins.pop(n, None)
    for f in fs:   # F1: a change is a platform refresh only once the plugin list says whose plugin it is
        if "refresh" in f and f["rule"] in ("WT-I001", "WT-I002", "WT-I003"):
            f["refresh"] = platform_file(f["where"])
    for name, proots in sorted(new_plugins.items()):
        inside = lambda p: any(p == r or p.startswith(r + "/") for r in proots)
        n_files = sum(1 for p in manifest if inside(p))
        n_skills = sum(1 for p in inv["skills"] if inside(p))
        fs = [f for f in fs if not (f["rule"] in ("WT-I001", "WT-I002") and inside(f["where"].split(":")[0]) and not f.get("unverified_platform"))]
        fs.append(finding("WT-I004", "New plugin installed", "medium", ["AST02", "AST09"], proots[0], f"{name}: {n_files} files, {n_skills} skills",
                          "A plugin's skills can't be vetted before it is installed, so they are checked now. Anything the scanners flag in it is "
                          "listed and counts until you decide. Tell Chief Worry Bot \"fix it\" to keep it with one yes, or remove it in the app (Marketplace → Your plugins)."))
        rel = [sorted(os.path.relpath(p, r) for p in manifest if p == r or p.startswith(r + "/")) for r in proots]
        was = PLUGIN_MOVES.get(name)
        if not was or (len(was[0]) == len(was[1]) and not any(os.path.lexists(r) for r in was[0])):
            fs[-1]["key0"] = plugin_place_key(name, proots, rel)   # DQ-047: the same files in a new version folder, the old one gone
        if was:
            line = (f"Plugin {name} changed version folder ({', '.join(os.path.basename(r) for r in was[0])} → "
                    f"{', '.join(os.path.basename(r) for r in was[1])}); it is still waiting for your decision (WT-I004).")
            notes.append(line)
            version_changes.append(line)

    # 3. persistence (ASI10)
    CRONTAB_SEEN.clear()   # batch 5 PR B, Codex round 2 (3): unless this look says otherwise, the crontab couldn't be read
    PERSIST_UNKNOWN.clear()   # batch 6 (KL5): what this look couldn't see (a stand-in snapshot sees everything it returns)
    snap = persistence_snapshot()
    old = load_json(state_path("persistence.json"), None)
    if old is not None:
        for k, v in snap.items():
            if persistence_changed(old, k, v):
                fs.append(finding("WT-P001", "Persistence point changed", "medium", ["ASI10", "ASI05"], k,
                                  str(v)[:120], "Check who added this cron entry, unit, or shell rc change; remove it if no Bot of yours needs it.",
                                  shown=str(v)))
    save_json(state_path("persistence.json"), persistence_stored(snap))

    # 4. secrets in files (known CLI credential files reported separately)
    cli_unknown = []   # batch 6 (KL5): a credential file Watchtower couldn't look at leaves the access map's sign-ins incomplete
    fs += cli_credentials(cli_unknown)
    # batch 6 PR3, Codex round 1 (11): the platform's sign-in and secret-store places under the roots are looked up too, as
    # access_map_now does (a stat, never opened or read): one Watchtower couldn't look at (a folder it may not search) leaves
    # the sign-ins unknown, never "none found"
    cli_unknown += [p for p in sorted(secret_store_places()) if any(_under(p, {os.path.normpath(os.path.expanduser(r))}, strict=True)
                                                                    for r in roots) and _look(p) is None]
    known ={os.path.join(os.path.expanduser("~"), k) for k in KNOWN_CRED_FILES}
    fs += browser_sessions(roots)
    jar = {}
    sign_ins = new_sign_ins(jar)   # kept open EVENT_DAYS with the other one-time events below
    decoys = canary_paths()
    for p in walk(roots, max_depth=6):
        if p in known or p in decoys or os.path.basename(p) in SESSION_FILES:
            continue
        if is_platform_secret_store(p):   # Decision, Oct 13: the platform's masked-secret store; never read, only noted
            fs.append(platform_secret_store_note(p))
            continue
        # v0.7.0 review R1: no sample-folder or quarantine skip here. A key is a key wherever it sits, and the
        # decoy-copy check must see docs/, tests/, examples/, references/ and fixtures/ folders too.
        if os.path.splitext(p)[1].lower() not in TEXT_EXT:
            continue
        t = read_text(p, limit=300_000)
        if not t:
            continue
        if decoys:
            cp = canary_copies(t, p)
            if cp:
                fs.append(cp)
        rule = next(r for r in rules["rules"] if r["id"] == SECRET_RULE)
        # batch 6 (B5): the shared content check (secret_at). Fix round 3 (Codex 1, 2): every hit counts, an example-looking one
        # as any other; the finding names a real-looking one first, and gets the example note only when every hit looks like one
        hits = [(m, secret_at(t, m)[1]) for m in rule["rx"].finditer(t)]
        if hits:
            m, why = next((h for h in hits if not h[1]), hits[0])
            f = finding("WT-S001", "Secret stored in a file on the shared computer", secret_severity(p, False), ["ASI03", "LLM02"],
                        f"{p}:{line_of(t, m.start())}", f"{mask(m.group(0))} ({len(hits)} in file)",
                        "Every Bot can read this file. Revoke the key, delete the file, and use the secure secret request instead.", path=p)
            fs.append(annotate_example(f, why) if why else f)

    export_rules = ""
    # 5. exports the user pastes in (routines, descriptions, Auto Review rules, settings)
    if exports and os.path.isdir(exports):
        for fn in sorted(os.listdir(exports)):
            p = os.path.join(exports, fn)
            t = read_text(p)
            if t is None:
                continue
            low = fn.lower()
            if low.startswith("routine"):
                fs += scan_text(t, f"export:{fn}", rules, kind="routine")
            elif low.startswith(("bot", "description", "skill", "template")):
                fs += scan_text(t, f"export:{fn}", rules, kind="description")
            elif low.startswith("auto-review") or low.startswith("autoreview"):
                export_rules += "\n" + t
                fs += lint_auto_review(t, f"export:{fn}", check_missing=False)
            elif low.startswith("settings") and low.endswith(".json"):
                fs += lint_settings(load_json(p, {}), f"export:{fn}")
    else:
        notes.append("No exports folder: routine text not checked (Auto Review rules come from settings.json).")

    nat, entries = native_settings(entries=True), []
    if nat:
        entries, settings, p = nat
        if entries:
            fs += lint_auto_review(entries, p, check_missing=False)
        fs += lint_settings(settings, p)
    else:
        notes.append("Grok Bot settings.json not found: Auto Review rules and local execution checked from exports only.")

    # batch 6 (B4): read in every language rules/ask_first_vocab.json has. Fix round 1 (Codex 5): coverage nobody can show is the
    # counted medium whatever the rules say ("." and "every shell command" too); rules none of whose words Watchtower reads also
    # get a Tip about the language, beside the medium, never instead of it
    seen, gaps = ask_first_state(entries, export_rules)
    if gaps:
        fs.append(finding("WT-A003", {"absent": "Ask-first rules not found", "unread": "Ask-first rules don't say what they cover"}.get(
                              seen, "Ask-first rules don't cover everything"), "medium", ["ASI09"], "Auto-review rules", ", ".join(gaps),
                          "Rules saved only in the app can't be seen from the computer. Tell the Bot to add them and save a copy to "
                          "/workspace/watchtower/exports/auto-review.txt."))
    if seen == "unread":
        fs.append(finding("WT-A003", "If your Ask-first rules are in a language Chief Worry Bot doesn't read, it can't check them", "info",
                          ["ASI09"], "Auto-review rules", ASK_UNREAD_EVIDENCE,
                          "Chief Worry Bot reads Ask-first rules in English, Spanish, French, German, Portuguese, Italian, Russian, Chinese, "
                          "Japanese, Korean, Arabic, Greek and Hindi, and found none of their words in yours. The alert above stays "
                          "until your rules name sending, publishing, payments, deleting and permission changes in one of those."))
        fs[-1]["ask_first_unread"] = True   # a Tip (ask_first_unread: this evidence only, so it never matches the medium)

    # 5b. tripwires and shell history (zero tokens)
    fs += soft("hooks", ("WT-C005",), notes, [], hook_findings, roots, inv)
    USED_PATHS.clear()
    USED_PATHS.update(soft("project users", (), notes, set(), project_users, roots, inv, exports) or set())
    soft("decoys", (), notes, None, tend_canaries, notes)
    soft("saved first-run skill", (), notes, None, saved_skill_notes, notes)
    fs += remember_events(canary_findings() + history_findings(rules) + sign_ins)
    if not load_json(state_path("canaries.json"), {}):
        notes.append("No canaries planted: run `wt.py canary plant` for zero-cost tripwires.")
    rc = load_json(state_path("rollcall_findings.json"), None)
    if rc and rc.get("at", "") >= (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=ROLLCALL_MAX_DAYS)).isoformat():
        rc, gone = prune_removed_bots(rc)
        if gone:
            notes.append(f"Roll-call findings for {len(gone)} Bots no longer on the roster were dropped.")
        hint = roster_hint(rc)
        if hint:
            notes.append(hint)
        fs += rc.get("findings", [])
    else:
        notes.append("Roll-call is off (opt-in): other Bots' memories and routines are not checked. Ask for a roll-call to run one with your yes.")

    # 6. second and third engines on the user's skills plus anything new or changed; secrets; packages
    changed = {skill_root(f["where"].split(":")[0]) or os.path.dirname(f["where"].split(":")[0]) for f in fs if f["rule"] in ("WT-I001", "WT-I002")}
    user_dirs = [os.path.dirname(x) for x in inv["skills"] if skill_tier(x) == "user"]
    user_roots = sorted({x.split("/workflows/")[0] + "/workflows" for x in user_dirs if "/workflows/" in x})
    if not quick:
        # The quick scanners go first and the slow skill scanners last, each with only the time that is left.
        fs += soft("gitleaks (keys in files)", ("WT-S002",), notes, [], gitleaks_findings, roots, notes)
        fs += soft("pip-audit (installed Python packages)", ("WT-D001",), notes, [], package_findings, notes)
        fs += soft("OSV-Scanner (project dependencies)", ("WT-D002",), notes, [], osv_findings, roots, notes)
        fs += soft("Chief Worry Bot's own tools", ("WT-W001",), notes, [], self_findings, notes)
        secret_paths = [f["where"].split(":")[0] for f in fs if f["rule"] in ("WT-S001", "WT-S002")]
        ks = soft("TruffleHog (which keys still work)", (), notes, None, trufflehog_status, secret_paths, notes)
        if ks is None or "TruffleHog (which keys still work)" in STAGE_FAILED:
            old = load_json(state_path("key_status.json"), {}) or {}
            fs = apply_key_status(fs, old.get("files", {}), ran=bool(old.get("ran")))
        else:
            fs = apply_key_status(fs, ks, ran=bool(tool("trufflehog")))
        other_dirs = sorted(os.path.dirname(x) for x in inv["skills"] if skill_tier(x) != "user")
        fs += soft("SkillSpector and husk", ("WT-X001", "WT-X002", "WT-X003", "WT-X004"), notes, [], engine_findings,
                   user_dirs + sorted(changed) + other_dirs, fs, notes, user_roots, budget=max(0, min(ENGINE_BUDGET, time_left() - 20)))
        set_progress("finishing", 0, 0)
        rearm_canaries(within=roots)  # Watchtower's own scanners just read the files under roots; reset only those (batch 2, R2)
    else:
        # The daily check re-scans what changed and then works through anything still waiting, two minutes at most.
        rest = [d for d in user_dirs + sorted(os.path.dirname(x) for x in inv["skills"] if skill_tier(x) != "user") if d not in changed]
        fs += soft("SkillSpector and husk", (), notes, [], engine_findings, sorted(changed) + rest, fs, notes, user_roots,
                   budget=max(0, min(ENGINE_BUDGET, 120, time_left() - 10)))
    if quick:
        ks = load_json(state_path("key_status.json"), {}) or {}
        fs = apply_key_status(fs, ks.get("files", {}), ran=bool(ks.get("ran")))
    prev_used = load_json(state_path("engines_used.json"), {}) or {}
    prev_used = prev_used if isinstance(prev_used, dict) else {}
    # Codex, batch 3 round 1: `expected` was only last run's expectation while one scanner was missing, so a scanner that first
    # ran during that time was forgotten the second run after it went missing, and its findings read as fixed. Expected is now
    # every scanner expected before plus every one that ran, until all of them are back.
    before = list(dict.fromkeys(n for k in ("expected", "engines") for n in (prev_used.get(k) if isinstance(prev_used.get(k), list) else [])
                                if isinstance(n, str)))
    used_now = ["Watchtower rules"] + [n for n, t in (
        ("SkillSpector", "skillspector"), ("husk", "husk"), ("gitleaks", "gitleaks"), ("TruffleHog", "trufflehog"),
        ("pip-audit", "pip-audit"), ("OSV-Scanner", "osv-scanner")) if scanner_used(t)]   # Claude review 2 (3)
    gone = [n for n in before if n not in used_now]
    save_json(state_path("engines_used.json"), {"at": now(), "engines": used_now, **({"expected": list(dict.fromkeys(before + used_now))} if gone else {})})
    if gone:
        notes.insert(0, f"SCANNERS MISSING: {', '.join(gone)} ran last time and didn't run now (not installed, or not the copy Chief Worry Bot installed), "
                        "so this is a partial scan and their last results are kept. Run `bash /workspace/watchtower/app/scripts/install.sh --scanners`, then audit again.")
    fs += scanner_x005()   # batch 3 (R7): every scanner was looked at just above, in audit and daily alike
    fs = merge_managed_mirrors(settle_platform_updates(fs, cands, manifest, base, rules), manifest)   # b8i4
    fs = sort_findings(dedupe(fs))
    meta = {"inventory": {k: len(v) for k, v in inv.items() if k not in ("non_live_skills", "platform_aliases")}, "notes": notes, "plugin_version_changes": version_changes, "manifest": manifest, "persistence": snap, "scanners_missing": gone,
            "skill_dirs": [os.path.dirname(x) for x in inv["skills"]], "baseline_status": base_status, "platform_held_before": sorted(held_before),
            "access_sources": {"roots": list(roots), "mcp": list(inv["mcp_configs"]), "plugin_files": list(inv["plugin_files"]),
                               "browser": jar.get("hosts"),   # batch 5 (a); PR B, Codex round 1 (2): this run's own look at the jar
                               # round 2 (1, 3): the jar and the cookie seed looked at whole (or said not to be), the crontab's
                               # answer, the folders the scan couldn't list
                               "jar": _ax_jar_now(), "seed": _ax_seed_now(roots), "crontab": CRONTAB_SEEN.get("crontab", "failed"),
                               "walk_errors": len(walk_errors), "walk_skipped": len(walk_skipped),   # round 3 (1): and those it left out
                               # batch 6 (KL5): the sign-in files and scheduled-job folders it couldn't look at
                               "cli_unknown": len(cli_unknown), "persist_unknown": sorted(PERSIST_UNKNOWN)}}
    return fs, meta
