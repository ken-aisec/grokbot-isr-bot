# Part of wt.py: runs inside wt.py's namespace (loaded by _wt_part); not a module on its own.
ENGINE_BUDGET = int(os.environ.get("WT_ENGINE_BUDGET", "420"))   # seconds of engine time per run; the rest resumes next run
ENGINE_CHUNK = 20                                                # skills per launch: small enough that a slow computer still saves progress every batch
ENGINE_MAX_FILES, ENGINE_MAX_BYTES = 400, 2_000_000
ENGINE_LAUNCH_BASE = int(os.environ.get("WT_ENGINE_LAUNCH_BASE", "30"))   # seconds one engine launch may take, plus time per skill.
ENGINE_LAUNCH_PER_SKILL = 4                                               # measured on a real box: 3s to launch on one small skill, up to 3.3s per skill when busy.
#                                                                           v0.6.3 allowed 300s per batch, so one skill that hung a scanner used the whole run.
ENGINE_SOLO_LIMIT = int(os.environ.get("WT_ENGINE_SOLO_LIMIT", "120"))    # seconds for one skill scanned on its own. v0.6.4 to v0.6.6 gave 34, and on
#                                                                           a real box healthy skills with Office files took 37 to 61 and were marked stuck.
ENGINE_MAX_TARGETS = 5000
ENGINE_CURRENT = set()                                                    # skills whose scanner answer is up to date after this run
ENGINE_HEAVY_BYTES, ENGINE_HEAVY_FILES = 400_000, 120                     # bigger skills are scanned on their own so they can't jam a batch
STUCK_RETRY_DAYS = 7
TIMED_OUT = "ran out of time"


STAGE_FAILED = []        # stages that did not finish in the current run


def carry(rules):
    """Last run's findings for rules whose stage didn't finish this time: unknown is not the same as fixed."""
    prev = load_json(state_path("last_findings.json"), {}) or {}
    return [kept_line(f) for f in (prev.get("findings") or []) + (prev.get("suppressed") or []) if f.get("rule") in rules]


def kept_line(f):
    """A scanner line kept from the last run wasn't refreshed by this one. A WT-X003 kept that way may lack a kind (one written
    before DQ-042 read only four summaries), so it is never filed under Platform until a scan refreshes it (Codex, DQ-042 round 3)."""
    if f.get("rule") == "WT-X003":
        f["kinds_incomplete"] = True
    return f


STAGE_FAILS = []   # R16: explicit failure markers set by the stages themselves, not read back out of note wording


def fail_note(notes, text):
    """A stage didn't finish (or part of it didn't): say so, and mark it failed so its previous results are kept. Masked first:
    a scanner's error line is shown and stored (Codex, batch 4 round 3)."""
    text = mask_secrets(text)
    notes.append(text)
    STAGE_FAILS.append(text)


def soft(stage, rules, notes, default, fn, *a, **k):
    """Fail-soft: a stage either finishes, or it is skipped with one line saying so and its previous results are kept.
    It can never stop the audit or change the score by failing."""
    before, fails_before = len(notes), len(STAGE_FAILS)
    try:
        if time_left() <= 3:
            raise TimeoutError("the run's time limit was reached before this stage started")
        res = timed(stage, fn, *a, **k)
        failed = len(STAGE_FAILS) > fails_before or any(re.search(r"(?i)\bfailed\b", n) for n in notes[before:])
    except Exception as e:   # noqa: BLE001 - nothing a scanner or a strange file does may break the audit
        res, failed = default, True
        notes.append(f"{stage} FAILED ({type(e).__name__}: {mask_secrets(str(e)[:MASK_WINDOW])[:100]}): skipped, NOT checked this run; "
                     "the last results are kept.")
    if failed:
        STAGE_FAILED.append(stage)
        if isinstance(res, list):
            res = res + carry(rules)
    return res


def timed(stage, fn, *a, **k):
    """Run one audit stage, remember what's running and how long it took, so a slow one is easy to spot with `wt.py status`."""
    set_progress(stage, 0, 0)
    t0 = time.monotonic()
    try:
        return fn(*a, **k)
    finally:
        times = load_json(state_path("stage_times.json"), {}) or {}
        times[stage] = round(time.monotonic() - t0, 1)
        save_json(state_path("stage_times.json"), times)


def set_progress(stage, done, total, started=None):
    save_json(state_path("progress.json"), {"stage": stage, "done": done, "total": total, "at": now(),
                                            "seconds": round(time.monotonic() - started) if started else None})


def skill_files(d):
    out = []
    for dirpath, dirnames, filenames in os.walk(d):
        dirnames[:] = sorted(x for x in dirnames if x not in SKIP_DIRS)
        for fn in sorted(filenames):
            p = os.path.join(dirpath, fn)
            try:
                if os.path.isfile(p) and not os.path.islink(p) and os.path.getsize(p) <= ENGINE_MAX_BYTES:
                    out.append(p)
            except OSError:
                pass
            if len(out) >= ENGINE_MAX_FILES:
                return out
    return out


def entry_engines(e_):
    """Which engines produced a remembered result. Older entries didn't record it: they were scanned if SkillSpector left a summary."""
    if "engines" in e_:
        return set(e_["engines"])
    return {"SkillSpector", "husk"} if e_.get("ss") is not None else set()


def ss_kinds_complete(ss):
    """False for a SkillSpector "do not install" from before DQ-042: no kinds kept, and its four summaries may have lost a fifth."""
    return not (isinstance(ss, dict) and ss.get("recommendation") == "DO_NOT_INSTALL" and "kinds" not in ss and len(ss.get("top") or ()) >= 4)


def hk_words_missing(hk):
    """True when husk flagged a skill but none of its messages say anything: "flagged", "flagged (5 issues)", or empty. That is
    what husk_batch writes when the words don't come back; a cache from before hk_partial kept it with no mark (Codex, DQ-042)."""
    return bool(hk) and isinstance(hk, list) and not any(re.search(r"[^\W\d_]", re.sub(r"(?i)\b(flagged|issues?)\b", "", str(m)))
                                                         for m in hk)


def entry_current(e_, h, installed):
    """A remembered result is good when the skill hasn't changed and every scanner installed now has looked at it.
    A SkillSpector "do not install" from before DQ-042 kept no kinds; with four summaries it may have lost a fifth, so it is
    scanned again. So is one where husk flagged the skill but its words never came back (hk_partial, Codex DQ-042 round 3),
    including one cached before hk_partial existed, whose husk answer is only a placeholder (Codex, DQ-042 final review)."""
    if not ss_kinds_complete(e_.get("ss") if isinstance(e_, dict) else None):
        return False
    if isinstance(e_, dict) and (e_.get("hk_partial") or hk_words_missing(e_.get("hk"))) and not e_.get("stuck"):
        return False
    return bool(e_) and e_.get("hash") == h and (bool(e_.get("stuck")) or set(installed) <= entry_engines(e_))


def has_binary(d):
    return any(os.path.splitext(p)[1].lower() not in TEXT_EXT and os.path.getsize(p) > 20_000 for p in skill_files(d))


def skill_weight(d):
    sizes = [os.path.getsize(p) for p in skill_files(d)]
    return sum(sizes), len(sizes)


def skill_dir_hash(d):
    h = hashlib.sha256()
    for p in skill_files(d):
        h.update(os.path.relpath(p, d).encode())
        h.update(sha256_file(p).encode())
    return h.hexdigest()[:20]


def stage_skills(dirs, root):
    """Copy skills into one folder so each engine is launched once for the whole batch instead of once per skill.
    (Symlinks aren't followed by SkillSpector; copies are small because only text-sized files are taken.)"""
    mapping = {}
    for i, d in enumerate(dirs):
        name = f"{i:04d}-{re.sub(r'[^A-Za-z0-9_.-]+', '_', os.path.basename(d.rstrip('/')))[:40]}"
        for p in skill_files(d):
            dst = os.path.join(root, name, os.path.relpath(p, d))
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            shutil.copyfile(p, dst)
        os.makedirs(os.path.join(root, name), exist_ok=True)
        mapping[name] = d
    return mapping


SCAN_OK_EXITS = (0, 1)   # 1 = "found something" for both engines; anything else is a failed run


def skillspector_batch(exe, stage, mapping, timeout=600):
    """One SkillSpector run over a staged folder. Returns ({original_dir: summary}, error or None)."""
    tmp = os.path.join(stage, "..", f"ss-{os.path.basename(stage)}.json")
    code, _, err = run([exe, "scan", stage, "--recursive", "--no-llm", "--format", "json", "--output", tmp], timeout)
    if code == 124:
        try:
            os.remove(tmp)
        except OSError:
            pass
        return {}, TIMED_OUT
    data = load_json(tmp, None)
    try:
        os.remove(tmp)
    except OSError:
        pass
    if not isinstance(data, dict) or code not in SCAN_OK_EXITS or not (isinstance(data.get("skills"), list) or (len(mapping) == 1 and "risk_assessment" in data)):
        return {}, f"no valid result (exit {code}: {(err.strip().splitlines() or ['timed out, crashed or unreadable output'])[-1][:100]})"
    res = {}
    for sk in data.get("skills") or ([dict(data, path=".")] if len(mapping) == 1 else []):
        name = os.path.basename(os.path.normpath(sk.get("path") or "."))
        orig = mapping.get(name) or (next(iter(mapping.values())) if len(mapping) == 1 else None)
        if not orig:
            continue
        ra = sk.get("risk_assessment") or {}
        issues = [i for i in sk.get("issues") or [] if isinstance(i, dict)]
        top = sorted({f"{i.get('category')}: {i.get('pattern')}" for i in issues if i.get("severity") in ("CRITICAL", "HIGH")})
        # DQ-042 (Codex): the kinds come from every critical/high issue, before the summary is cut to four. Four Memory Poisoning
        # lines sorted ahead of "Privilege Escalation: Credential Access" used to drop the credential kind with the fifth line.
        res[orig] = {"score": ra.get("score", sk.get("risk_score")), "recommendation": ra.get("recommendation", ""), "issues": len(issues),
                     "top": top[:4], "kinds": sorted(engine_kinds(top))}
    if len(res) < len(set(mapping.values())):      # R03: every skill sent must come back, or the batch didn't finish
        return {}, f"incomplete result ({len(res)} of {len(set(mapping.values()))} skills)"
    return res, None


def husk_batch(exe, stage, mapping, timeout=600, partial=None):
    """Husk's own bulk mode flags names in one run; only flagged skills are re-run for their messages.
    The detail runs stop when the time is up: a flagged skill is still flagged, just with a shorter message.
    A flagged skill whose words didn't come back (no time left, a timeout, an error exit, no SARIF, no message) is added to
    `partial`: "flagged" names no kind, so it must never read as wording only (Codex, DQ-042 round 3)."""
    partial = set() if partial is None else partial
    cache = os.path.join(stage, "..", "husk-cache.json")
    t0 = time.monotonic()
    code, out_s, err = run([exe, "registry", "--cache", cache, "--json", stage], timeout)
    if code == 124:
        return {}, TIMED_OUT
    try:
        data = json.loads(out_s)
        flagged = data.get("flagged") if isinstance(data, dict) else None
    except ValueError:
        flagged = None
    if code not in SCAN_OK_EXITS or not isinstance(flagged, dict):   # R03: an error exit or "{}" is not a clean scan
        return {}, f"no valid result (exit {code})"
    res = {}
    for n, name in enumerate(list(flagged)):
        orig = mapping.get(name)
        if not orig:
            continue
        left = timeout - (time.monotonic() - t0)
        if n >= 25 or left < 1:
            res[orig] = [f"flagged ({flagged[name]} issues)"]
            partial.add(orig)
            continue
        sarif = os.path.join(stage, "..", f"hk-{name}.sarif")
        code, _, _ = run([exe, "package", os.path.join(stage, name), "--output", sarif], min(60, left))
        data = load_json(sarif, None) or {}
        msgs = [r.get("message", {}).get("text", "") for run_ in data.get("runs", []) for r in run_.get("results", [])]
        if code not in SCAN_OK_EXITS or not any(str(m).strip() for m in msgs):
            partial.add(orig)
        res[orig] = msgs or ["flagged"]
        try:
            os.remove(sarif)
        except OSError:
            pass
    return res, None


X003_PAIRS = (("SkillSpector", "husk"), ("SkillSpector", "Watchtower"), ("husk", "Watchtower"))


def engine_evidence(rule, s_, hk, engines=()):
    """The evidence an engine finding (X001, X002, X003) is made with: one place, so its stored key can be made the same way."""
    detail = "; ".join(s_.get("top", [])[:2])
    if rule == "WT-X003":
        return (" + ".join(engines) + (f"; {detail}" if detail else ""))[:150]
    if rule == "WT-X001":
        return f"risk {s_.get('score')}; {detail}"[:150]
    return str(hk[0])[:150] if hk else ""


def engine_entry_masked(d, e):
    """Codex, batch 4 round 2 (R11): a cache entry as engine_cache.json keeps it, every Bot being able to read that file. The
    scanners' words (SkillSpector's summaries, husk's messages) are masked; what they mean is read from the raw words first and
    kept beside them when masking changed anything: which husk messages count (hk_keep), the kinds they name (hk_kinds,
    top_kinds) and the keys the folder's X001, X002 and X003 findings get (keys, for folder `d`), so those keys stay the ones
    857ab38 gave. An entry already masked by this version is returned as it is; one masked by an older version is masked again
    (its words were raw wherever that masking changed nothing, so their meaning is read then)."""
    if not isinstance(e, dict) or e.get("masked") == MASK_VERSION:
        return e
    e = dict(e)
    ss = dict(e["ss"]) if isinstance(e.get("ss"), dict) else None
    hk = list(e["hk"]) if isinstance(e.get("hk"), list) else None
    meta = {}
    if "keys" not in e:
        s_ = ss or {}
        kept = [i for i, m in enumerate(hk or ()) if husk_messages_that_count(d, [m])]
        hk_kept = [hk[i] for i in kept]
        keys = {"for": d, "WT-X001": finding_key("WT-X001", d, engine_evidence("WT-X001", s_, None)),
                "WT-X002": finding_key("WT-X002", d, engine_evidence("WT-X002", s_, hk_kept))}
        keys.update((" + ".join(p), finding_key("WT-X003", d, engine_evidence("WT-X003", s_, None, p))) for p in X003_PAIRS)
        meta = {"keys": keys, "hk_keep": kept, "hk_kinds": sorted(engine_kinds(hk_kept))}
        if ss is not None and "kinds" not in ss:
            meta["top_kinds"] = sorted(engine_kinds(ss.get("top", [])))
    changed = False
    if ss is not None and isinstance(ss.get("top"), list):
        top = [mask_secrets(t) if isinstance(t, str) else t for t in ss["top"]]
        changed, ss["top"] = top != ss["top"], top
        e["ss"] = ss
    if hk is not None:
        msgs = [mask_secrets(m) if isinstance(m, str) else m for m in hk]
        changed, e["hk"] = changed or msgs != hk, msgs
    if changed:
        e.update(meta)
    e["masked"] = MASK_VERSION
    return e


def engine_findings(skill_dirs, wt_findings, notes, user_root_dirs=(), budget=None):
    """Second and third opinions on skills. Each engine starts once per batch of 40 skills; a skill is only re-scanned when
    its files change; work stops at the time budget and resumes next run. A skill is 'corroborated' only when two engines flag it."""
    out, started = [], time.monotonic()
    budget = ENGINE_BUDGET if budget is None else budget
    ENGINE_CURRENT.clear()
    ss_exe, hk_exe = tool("skillspector"), tool("husk")
    blocked = engines_blocked()
    if blocked:   # batch 3 (R7): not checked is not clean. The stage is marked failed, so last run's scanner lines are kept whole
        fail_note(notes, blocked + " SkillSpector and husk were not run this time.")
        ENGINE_CURRENT.clear()
        return []
    if not ss_exe:
        scanner_absent(notes, "skillspector", "SkillSpector not installed: run install.sh --scanners for a second engine.")
    if not hk_exe:
        scanner_absent(notes, "husk", "husk not installed: run install.sh --scanners for an obfuscation-focused engine.")
    targets = []
    for d in skill_dirs:
        d = os.path.normpath(d)
        if d not in targets and os.path.isdir(d) and os.path.isfile(os.path.join(d, "SKILL.md")):
            targets.append(d)
    if len(targets) > ENGINE_MAX_TARGETS:
        notes.append(f"This computer has {len(targets)} skills; SkillSpector and husk cover the first {ENGINE_MAX_TARGETS} (yours first). "
                     f"The other {len(targets) - ENGINE_MAX_TARGETS} were checked by Chief Worry Bot's own rules only.")
        targets = targets[:ENGINE_MAX_TARGETS]
    cache = load_json(state_path("engine_cache.json"), {}) or {}
    stale = [k for k, v in cache.items() if isinstance(v, dict) and v.get("masked") != MASK_VERSION]
    for k in stale:   # Codex, batch 4 round 2: entries an older version kept with the scanners' raw words
        cache[k] = engine_entry_masked(k, cache[k])
    if stale:
        save_json(state_path("engine_cache.json"), cache)
    hashes = {d: skill_dir_hash(d) for d in targets}
    retry_before = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=STUCK_RETRY_DAYS)).isoformat()
    installed = [n for n, x in (("SkillSpector", ss_exe), ("husk", hk_exe)) if x]
    by_hash = {}
    for k, v in cache.items():
        if isinstance(v, dict) and v.get("hash") and (v.get("stuck") or entry_engines(v)):
            by_hash.setdefault(v["hash"], v)
    for d in targets:
        if not entry_current(cache.get(d) or {}, hashes[d], installed) and entry_current(by_hash.get(hashes[d]) or {}, hashes[d], installed):
            cache[d] = dict(by_hash[hashes[d]])
    alive = set(targets)
    for k in [k for k, v in cache.items() if k not in alive and not os.path.isdir(k)]:   # folders that no longer exist
        if sum(1 for v in cache.values() if v.get("hash") == cache[k].get("hash")) > 1:
            del cache[k]
    todo = [d for d in targets if not entry_current(cache.get(d) or {}, hashes[d], installed)
            or (cache[d].get("stuck") and (cache[d].get("at", "") < retry_before or cache[d].get("limit", 0) < ENGINE_SOLO_LIMIT))] if installed else []
    scanned, stuck_now = 0, []
    # Copies of one skill (the same files in several clones of a repo) are scanned once; every copy gets that answer.
    # Up to v0.6.7 each copy was queued and scanned on its own, so eight clones of one big skill cost eight solo scans.
    twins, first = {}, {}
    for d in todo:
        if hashes[d] in first:
            twins.setdefault(first[hashes[d]], []).append(d)
        else:
            first[hashes[d]] = d
    run = [d for d in todo if first[hashes[d]] == d]

    def remember(d, entry):   # kept masked; the raw words' meaning and keys are worked out for each copy's own folder
        cache[d] = engine_entry_masked(d, entry)
        for t in twins.get(d, []):
            cache[t] = engine_entry_masked(t, dict(entry))
        return 1 + len(twins.get(d, []))
    tune = load_json(state_path("engine_tune.json"), {}) or {}
    size = max(1, min(ENGINE_CHUNK, int(tune.get("chunk", ENGINE_CHUNK))))
    left_s = lambda: budget - (time.monotonic() - started)
    weight = {d: skill_weight(d) for d in run}
    # Big skills, and skills carrying files that aren't text (slide decks, images, archives), are the ones that hang a scanner.
    # Each runs on its own, after the quick ones, so a hang costs one short launch instead of a whole batch.
    # DQ-013: skills a scanner already gave up on are retried last, alone, and only with time to spare, so new or changed skills
    # are never stuck behind them. v0.6.8 retried them first-come, inside the normal batches, and each one jammed a batch.
    retry = [d for d in run if (cache.get(d) or {}).get("stuck") and (cache[d].get("hash") == hashes[d])]
    fresh = [d for d in run if d not in retry]
    heavy = [d for d in fresh if weight[d][0] > ENGINE_HEAVY_BYTES or weight[d][1] > ENGINE_HEAVY_FILES or has_binary(d)]
    light = [d for d in fresh if d not in heavy]
    queue = [light[i:i + size] for i in range(0, len(light), size)] + [[d] for d in heavy]   # big skills alone, after the quick ones
    retry_q = [[d] for d in retry]
    while queue or retry_q:
        if left_s() <= 0:
            break
        chunk = queue.pop(0) if queue else retry_q.pop(0)
        cap = ENGINE_LAUNCH_BASE + ENGINE_LAUNCH_PER_SKILL * len(chunk)   # a launch that takes longer than this is stuck, not busy
        if len(chunk) == 1:
            cap = max(cap, ENGINE_SOLO_LIMIT)                            # alone, a slow skill only costs its own time
        stage = tempfile.mkdtemp(prefix="stage-", dir=state_path())
        ss, hk, ss_err, hk_err, hk_part = {}, {}, None, None, set()
        try:
            mapping = stage_skills(chunk, stage)
            set_progress("SkillSpector and husk", scanned, len(todo), started)
            # the budget is checked inside the batch too: each engine only gets the time that is left
            # both engines at once (DQ-013): a batch costs the slower engine's time, not the sum
            lim = min(cap, left_s())
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                f_ss = pool.submit(skillspector_batch, ss_exe, stage, mapping, lim) if ss_exe and lim > 0 else None
                f_hk = pool.submit(husk_batch, hk_exe, stage, mapping, lim, hk_part) if hk_exe and lim > 0 else None
                if ss_exe:
                    ss, ss_err = f_ss.result() if f_ss else ({}, TIMED_OUT)
                if hk_exe:
                    hk, hk_err = f_hk.result() if f_hk else ({}, TIMED_OUT)
            if ss_err and not (ss_err == TIMED_OUT and len(chunk) == 1):   # a lone skill SkillSpector can't finish still gets husk
                hk, hk_err = {}, hk_err
        finally:
            shutil.rmtree(stage, ignore_errors=True)
        if TIMED_OUT in (ss_err, hk_err):
            if left_s() <= 0:                  # the budget ran out mid-batch: stop, keep what's done, try a smaller batch next time
                if len(chunk) > 1:
                    save_json(state_path("engine_tune.json"), {"chunk": max(1, len(chunk) // 2), "at": now()})
                break
            who = "SkillSpector" if ss_err == TIMED_OUT else "husk"
            if len(chunk) > 1:                 # one skill in here is jamming the scanner: run them one at a time, smallest first,
                queue += [[d] for d in sorted(chunk, key=lambda d: weight[d])]   # after the batches still waiting (DQ-013)
                continue
            d = chunk[0]                       # found it: remember, report it, and stop spending every run on it
            entry = {"hash": hashes[d], "stuck": who, "at": now(), "limit": cap}
            if who == "SkillSpector" and hk_exe and not hk_err:
                entry["hk"] = hk.get(d)           # husk's answer still counts
            stuck_now += [d] + twins.get(d, [])
            scanned += remember(d, entry)
            save_json(state_path("engine_cache.json"), cache)
            continue
        for err_, who in ((ss_err, "SkillSpector"), (hk_err, "husk")):
            if err_:
                fail_note(notes, f"{who} failed on a batch of {len(chunk)} skills ({err_}); they'll be retried next run.")
        if ss_err or hk_err:
            continue   # don't remember a batch that didn't finish
        for d in chunk:   # husk's words missing (hk_partial): not current, so they are asked for again next run (DQ-042 round 3)
            scanned += remember(d, {"hash": hashes[d], "ss": ss.get(d), "hk": hk.get(d), "engines": installed, "at": now(),
                                    **({"hk_partial": True} if d in hk_part else {})})
        save_json(state_path("engine_cache.json"), cache)   # progress survives an interrupted run
        if size < ENGINE_CHUNK and len(chunk) == size:      # a smaller batch fit: go back to the normal size next run
            size = ENGINE_CHUNK
            save_json(state_path("engine_tune.json"), {"chunk": size, "at": now()})
    left = len(todo) - scanned
    if left > 0 and not any("failed on a batch" in n for n in notes):
        notes.append(f"SkillSpector and husk checked {scanned} of {len(todo)} new or changed skills in the time budget; "
                     f"the other {left} are picked up by the next runs, daily checks included (results are remembered)"
                     + (". To check them all now, run `wt.py audit --budget 1800` (up to 30 minutes)." if 300 <= budget < 1800 else "."))
    set_progress("done", scanned, len(todo), started)

    wt_hits = {}   # v0.7.1 item 2: wording never votes (one word used to give one critical plus one high)
    for f in wt_findings:
        if f["severity"] in ("critical", "high") and f["rule"] in BEHAVIOR_RULES:
            wt_hits.setdefault(os.path.dirname(f["where"].split(":")[0]), []).append(f["rule"])
    for d in targets:
        e_ = cache.get(d) or {}
        if e_.get("hash") != hashes[d] or not (e_.get("stuck") or entry_engines(e_)):
            continue
        if e_.get("stuck"):
            out.append(finding("WT-X004", "A scanner couldn't finish this skill", "low", ["AST08"], d,
                               f"{e_['stuck']} gave no answer in time", "Chief Worry Bot's own rules still checked it. Chief Worry Bot tries the scanner again in a week, or sooner if the skill changes. "
                               "Big or unusual files are the usual cause.", source="engines"))
            if not e_.get("hk"):
                continue
        # Codex, batch 4 round 2: the words are masked; where masking changed them, their meaning was read before (hk_keep, …)
        s_, hk = e_.get("ss") or {}, ([e_["hk"][i] for i in e_["hk_keep"] if i < len(e_["hk"])] if "hk_keep" in e_ and isinstance(e_.get("hk"), list)
                                      else husk_messages_that_count(d, e_.get("hk")))
        raw_keys = e_["keys"] if isinstance(e_.get("keys"), dict) and e_["keys"].get("for") == d else {}
        ss_flag = s_.get("recommendation") == "DO_NOT_INSTALL"
        hk_flag = bool(hk)
        wt_k = {RISK_KIND[r] for k, rs in wt_hits.items() if k == d or k.startswith(d + "/") for r in rs}
        ss_k = set(s_["kinds"] if "kinds" in s_ else e_.get("top_kinds", engine_kinds(s_.get("top", [])))) if ss_flag else set()
        hk_k = set(e_.get("hk_kinds", engine_kinds(hk))) if hk_flag else set()
        tier = skill_tier(d + "/")
        # SkillSpector and husk both saying the folder is bad still agree (neither reports which file); Watchtower's own vote
        # joins only when it names the same kind of risk as the engine it pairs with.
        if ss_flag and hk_flag:
            agree = [("SkillSpector", ss_k), ("husk", hk_k)]
        else:
            agree = [(n, k) for n, flag, k in (("SkillSpector", ss_flag, ss_k), ("husk", hk_flag, hk_k)) if flag and wt_k & k]
            agree += [("Watchtower", wt_k & (ss_k | hk_k))] if agree else []
        engines = [n for n, _ in agree]
        if len(engines) >= 2:
            x = finding("WT-X003", "Corroborated by multiple engines", "critical" if tier == "user" else "high",
                        ["AST01", "AST08"], d, engine_evidence("WT-X003", s_, hk, engines),
                        "Two independent engines agree. Disable this skill until you've read the flagged lines.", source="engines")
            x["key"] = raw_keys.get(" + ".join(engines), x["key"])
            x["kinds"] = sorted(agree[-1][1] if engines[-1] == "Watchtower" else ss_k | hk_k)
            if not entry_current(e_, hashes[d], installed):   # Codex, DQ-042 rounds 2-3: an old answer not yet scanned again (the budget
                x["kinds_incomplete"] = True                  # ran out), or husk's words missing, may lack a kind: never filed under Platform
            out.append(x)
        elif ss_flag:
            x = finding("WT-X001", "SkillSpector: do not install", "high" if tier == "user" else "low", ["AST01", "AST08"], d,
                        engine_evidence("WT-X001", s_, hk),
                        "Run `skillspector scan <folder>` for the exact lines; one engine alone can be wrong.", source="skillspector")
            x["key"] = raw_keys.get("WT-X001", x["key"])
            x["kinds"] = sorted(ss_k)
            out.append(x)
        elif hk_flag:
            x = finding("WT-X002", "husk flagged this skill", "medium" if tier == "user" else "low", ["AST01", "AST05"], d,
                        engine_evidence("WT-X002", s_, hk), "Run `husk package <folder>` for details; one engine alone can be wrong.", source="husk")
            x["key"] = raw_keys.get("WT-X002", x["key"])
            x["kinds"] = sorted(hk_k)
            out.append(x)
    if installed:
        ENGINE_CURRENT.update(d for d in targets if entry_current(cache.get(d) or {}, hashes[d], installed))
    save_json(state_path("engines.json"), {"at": now(), "targets": len(targets), "scanned_this_run": scanned, "cached": len(targets) - len(todo),
                                           "waiting": max(0, left),
                                           "seconds": round(time.monotonic() - started, 1)})
    return out


def cmd_status(args):
    p = load_json(state_path("progress.json"), None)
    e_ = load_json(state_path("engines.json"), None)
    st = load_json(state_path("stage_times.json"), None)
    print(json.dumps({"progress": p, "last_engine_run": e_, "seconds_per_stage": st}, indent=1))
    return 0
