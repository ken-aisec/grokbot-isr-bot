# Part of wt.py: runs inside wt.py's namespace (loaded by _wt_part); not a module on its own.
# ---------------------------------------------------------------- vet
def vet_folder(path):
    """Batch 4 (FP3): the folder vet reads when given a folder or a SKILL.md, else None (a loose file, stdin)."""
    if path == "-":
        return None
    if os.path.isdir(path):
        return os.path.abspath(path)
    return os.path.dirname(os.path.abspath(path)) if os.path.basename(path) == "SKILL.md" else None


VET_WALK_CAP = 20_000          # names listed in a vetted folder (files and folders) before listing stops
VET_BYTES_CAP = 16_000_000     # text read in one vet, all files together
VET_FINDINGS_CAP = 5_000       # findings kept; past it a file keeps only kinds it hasn't kept yet, and every file is still read
NOT_FINISHED = "Could not finish checking"   # Codex, round 3: part of it wasn't read, so no installation verdict


def vet_files(d, entry, undone):
    """Codex, batch 4 round 1: the text files of a vetted folder, the entry point (its SKILL.md) first, so no cap can leave it
    out. Only text files count toward the file cap; listing stops after VET_WALK_CAP names. Returns (files, notes). Round 3:
    what the skill holds but wasn't listed or read (listing stopped, a folder that can't be listed, the file cap) is put in
    `undone`; a linked folder is not, as it is never followed."""
    # Codex, batch 4 round 2: names are counted as they are listed, so one huge folder stops at the cap instead of being read
    # and sorted whole first; a linked folder (never followed) and a folder that can't be listed are named in the notes.
    found, seen, notes, linked, failed, todo, stop = [], 0, [], [], [], [d], False
    while todo and not stop:
        top = todo.pop()
        subs = []
        try:
            with os.scandir(top) as it:
                for e in it:
                    seen += 1
                    if seen > VET_WALK_CAP:
                        stop = True
                        break
                    try:
                        if e.is_dir(follow_symlinks=False):
                            if e.name not in SKIP_DIRS:
                                subs.append(e.path)
                        elif e.is_symlink() and os.path.isdir(e.path):
                            linked.append(os.path.relpath(e.path, d) + "/")
                        elif os.path.splitext(e.name)[1].lower() in TEXT_EXT:
                            found.append(e.path)
                    except OSError:
                        failed.append(os.path.relpath(e.path, d))
        except OSError:
            failed.append((os.path.relpath(top, d) if top != d else ".") + "/")
        todo += sorted(subs, reverse=True)
    if stop:
        notes.append(f"the folder has more than {VET_WALK_CAP} names, so listing stopped there")
        undone.append("listing")
    for what, xs in (("a linked folder, not followed", linked), ("could not be listed", failed)):
        if xs:
            notes.append(f"not read ({what}): " + ", ".join(sorted(xs)[:10]) + (f" and {len(xs) - 10} more" if len(xs) > 10 else ""))
    undone += failed
    rest = sorted(p for p in found if entry is None or os.path.normpath(p) != os.path.normpath(entry))
    files = ([entry] if entry else []) + rest
    if len(files) > SKILL_FILE_CAP:
        notes.append(f"{len(files) - SKILL_FILE_CAP} more text files not read (over the {SKILL_FILE_CAP}-file cap)")
        undone.append("file cap")
        files = files[:SKILL_FILE_CAP]
    return files, notes


def vet_read(d, entry, files, notes, undone):
    """Each file as (where, absolute path, text, kind, sha256 of the bytes read), read one at a time. `where` is the identity 857ab38 gave a finding
    (SKILL.md for the entry point, the path inside the folder for the rest), so keys don't change; the absolute path is only
    for labelling. Every text file that isn't read is named in `notes`. A link is never followed: it may lead anywhere.
    Codex, round 3: the findings cap no longer stops reading (a later file's exfiltration host was never seen); past it each
    file keeps only kinds of finding it hasn't kept yet (scan_text). A file of the skill's own that isn't read (too big,
    unreadable) is also put in `undone`: the skill is then not fully checked. A link's target is not the skill's own."""
    total, skipped = 0, []
    for p in files:
        rel = os.path.basename(p) if p == entry else os.path.relpath(p, d)
        if os.path.islink(p) and p != entry:   # the entry point is read as 857ab38 read it: the file the owner named
            skipped.append(f"{rel} (a link, not followed)")
            continue
        try:
            size = os.stat(p).st_size
        except OSError:
            size = 0
        if total + size > VET_BYTES_CAP and p != entry:
            skipped.append(f"{rel} (over the {VET_BYTES_CAP:,} bytes one vet reads)")
            undone.append(rel)
            continue
        t, h = read_scanned(p)   # batch 6 (B7): the text and the fingerprint of the very bytes it was read from
        if t is None:
            if p == entry:
                raise OSError(f"could not read {p}")
            skipped.append(f"{rel} ({'over 1 MB' if size > 1_000_000 else 'unreadable'})")
            undone.append(rel)
            continue
        total += len(t)
        yield rel, p, t, "template" if p == entry else "reference", h
    if skipped:
        notes.append("not read: " + ", ".join(skipped[:10]) + (f" and {len(skipped) - 10} more" if len(skipped) > 10 else ""))


# Batch 6 (B7): a vetted file whose bytes are, exactly, a file on Grok Bot's release list (any listed path: same bytes, same
# text) is Grok Bot's own released file. Its findings get the audit's platform labels: a rules/platform-reviewed.json entry for
# those bytes, that rule and that line makes a checked note, and the rest become Platform lines (mark_platform). None of them
# moves the verdict or the score, except a Confirmed critical (the audit's rug-pull rule). One byte more is another digest, so
# the file is vetted as anyone's. The release list and the reviewed list are release files held to MANIFEST.sha256.
def released_digests():
    """Every sha256 the usable release list has a raw-bytes line for (none when it can't be used)."""
    return {h for hs in platform_lock().values() for h in hs}


def vet_released(labelled, released):
    """Label the findings from released bytes (`released`: finding key -> the file's sha256) as the audit labels Grok Bot's own."""
    entries = _platform_reviewed_state()[0]
    for f in labelled:
        h = released.get(f["key"])
        if h is None:
            continue
        f["scope"] = "platform"
        ln = str(f.get("where") or "").rpartition(":")[2]
        e = None if f.get("guarded") or not ln.isdigit() else next(
            (e for e in entries if e["sha256"] == h and e["rule"] == f["rule"] and e["line"] == int(ln)), None)
        if e is not None:
            f.update({"class": "platform", "label": REVIEWED_LABEL, "severity_was": f.get("severity_was") or f["severity"], "severity": "info",
                      "fix": e["note"], "reviewed": True})
    return mark_platform(labelled)


def vet_counts(f, released):
    """A finding that moves vet's verdict and score: not from released bytes, unless it is a Confirmed critical or a key (keys
    count wherever they sit, as in the audit: SECRET_RULES)."""
    return f["key"] not in released or (f.get("label") == CONFIRMED and f["severity"] == "critical") or f["rule"] in SECRET_RULES


def vet_label(f):
    """The label vet prints: a finding shown without its severity also says what Watchtower would call it ("Worth a look (might
    be fine), would call high", "Platform (Grok Bot's own file), would call high")."""
    was, label = f.get("severity_was"), f["label"]
    if label == CONFIRMED or f["severity"] != "info" or was not in ("critical", "high", "medium", "low"):
        return label
    return f"{label}, would call {was}"


def cmd_vet(args):
    rules = load_rules()
    folder = vet_folder(args.path)
    absolute = {}   # finding key -> its where with the absolute path, for labelling only
    released, lock = {}, released_digests()   # batch 6 (B7): finding key -> the released file's sha256
    if folder is not None:
        entry = os.path.abspath(args.path) if not os.path.isdir(args.path) else os.path.join(folder, "SKILL.md")
        entry = entry if os.path.lexists(entry) or not os.path.isdir(args.path) else None
        fs, main_, parts, urls_, notes_, plugin_ = [], None, [], set(), [], False
        try:
            if not os.path.isdir(folder):
                raise OSError(args.path)
            cut, stop, undone = [], [], []
            files, notes_ = vet_files(folder, entry, undone)
            for where, p, t, k, h in vet_read(folder, entry, files, notes_, undone):
                # Codex, round 2: the findings cap holds inside a file too; round 3: it limits what is kept, never what is read
                got = scan_text(t, where, rules, kind=k, limit=max(0, VET_FINDINGS_CAP - len(fs)), cut=cut, stop=stop)
                absolute.update((f["key"], p + f["where"][len(where):]) for f in got)
                if h in lock:
                    released.update((f["key"], h) for f in got)
                fs += got
                if k == "template":
                    main_ = t
                if entry is None:
                    parts.append(t)   # no SKILL.md: --deep stages the folder's text as one (bounded by VET_BYTES_CAP)
                if len(urls_) < 1000:
                    urls_.update(urls_in(t))   # Codex, round 2: whole URLs, masked
                plugin_ = plugin_ or bool(re.search(r"(?i)\bplug-?ins?\b", t))
            unread = bool(undone)   # a file or folder of its own not read, listing stopped: not fully checked
        except OSError:
            fs = None
        if fs is None or (main_ is None and not parts):
            print(f"ERROR could not read {args.path}", file=sys.stderr)
            return 2
        text = main_ if main_ is not None and not parts else "\n".join(parts)
        name = os.path.basename(args.path.rstrip("/")) or "vetted"
    else:
        text, h = (sys.stdin.read(), None) if args.path == "-" else read_scanned(args.path)
        if text is None:
            print(f"ERROR could not read {args.path}", file=sys.stderr)
            return 2
        main_, urls_, plugin_, cut, stop, notes_, unread = text, None, None, [], [], [], False
        name = "stdin" if args.path == "-" else os.path.basename(args.path)
        fs = scan_text(text, name, rules, kind="template", limit=VET_FINDINGS_CAP, cut=cut, stop=stop)
        if h in lock:
            released.update((f["key"], h) for f in fs)
    # Codex, round 3: what was kept and what was read are said apart. Past the findings cap repeats aren't kept, but every match
    # was read; past the match budget a file was not read to its end, and then vet gives no installation verdict (below).
    if stop:
        notes_.append(f"not read to the end (over {VET_MATCH_CAP:,} matches of one rule): " + ", ".join(sorted(set(stop))[:10]))
    if cut or len(fs) > VET_FINDINGS_CAP:
        notes_.append(f"over {VET_FINDINGS_CAP} findings, so past the {VET_FINDINGS_CAP}-finding cap only the first match of each kind "
                      f"is kept in a file (every match was read)" + (": " + ", ".join(sorted(set(cut))[:10]) if cut else ""))
    cover = "; ".join(notes_) or None
    incomplete = unread or bool(stop)
    engines = {}
    if getattr(args, "deep", False) and args.path != "-":
        d = args.path if os.path.isdir(args.path) else os.path.dirname(os.path.abspath(args.path))
        notes, staged = [], None
        if not os.path.isfile(os.path.join(d, "SKILL.md")):
            # SkillSpector and husk only read folders with a SKILL.md. Page text or a loose file is staged as one,
            # so "deep" never quietly means "Watchtower's own rules only".
            staged = tempfile.mkdtemp(prefix="wt-vet-")
            d = os.path.join(staged, re.sub(r"[^A-Za-z0-9_.-]+", "_", os.path.splitext(name)[0])[:40] or "vetted")
            os.makedirs(d)
            body = text if text.lstrip().startswith("---") else f"---\nname: vetted-text\ndescription: Text saved for vetting.\n---\n{text}"
            with open(os.path.join(d, "SKILL.md"), "w") as f:
                f.write(body)
        try:
            found = engine_findings([d], fs, notes)
        finally:
            if staged:
                shutil.rmtree(staged, ignore_errors=True)
        bump = {"ISR-X001": "high", "ISR-X002": "medium", "ISR-X003": "critical"}
        for f in found:   # you are deciding whether to install this, so a scanner flag is rated as it would be on your own skill
            f["severity"] = bump.get(f["rule"], f["severity"])
            if staged:
                f["where"] = name
        fs += found
        ran = [n for n, t in (("SkillSpector", "skillspector"), ("husk", "husk")) if tool(t)]
        # Codex, round 3: a scanner's own error line can quote a secret; masked before it is shown
        engines = {"ran": ran, "notes": [mask_secrets(n) if isinstance(n, str) else n for n in notes], "staged_as_skill": bool(staged)}
        if not ran:
            engines["warning"] = "No outside scanner is installed, so this vet used ISR Bot's own rules only. Say so."
    fs = sort_findings(dedupe(fs))
    # Batch 4 (FP2): labelled as the audit labels them, with full paths so "same file" means the same file; shown relative.
    # Codex, round 1: the full path is used for labelling only; each finding keeps the where (and so the key) 857ab38 gave it.
    labelled = vet_released(label_findings([dict(f, where=absolute.get(f["key"], f["where"])) for f in fs]), released)
    s, g = score([f for f, lf in zip(fs, labelled) if vet_counts(lf, released)])   # batch 6 (B7): Grok Bot's released bytes aside
    v = vet_verdict([lf for lf in labelled if vet_counts(lf, released)])
    if incomplete and v != "Do not install":
        v = NOT_FINISHED   # Codex, round 3: what wasn't read can't be called safe to install
    risk = max(100 - s, {"Do not install": 80, NOT_FINISHED: 50, "Install with changes": 40}.get(v, 0))   # a high finding never reads as "risk 6"
    rel = lambda w: (name if w == folder else w[len(folder) + 1:] if w.startswith(folder + "/") else w) if folder else w
    # batch 6 (B7): each finding as the audit shows it: its label and labelled severity (info for Worth a look, a Tip, warning
    # text and platform notes), the rule's own kept as severity_was; the where (and key) as 857ab38 gave it
    fs = sort_findings([dict(lf, where=rel(f["where"])) for f, lf in zip(fs, labelled)])
    urls = sorted(urls_ if urls_ is not None else set(urls_in(text, limit=1000)))
    result = {"tool": "watchtower", "version": VERSION, "target": name, "verdict": v,
              "risk_score": risk, "posture_score": s, "grade": g, "autonomy": autonomy(main_ if main_ is not None else text, rules),
              "external_urls": urls[:25], "findings": fs, "engines": engines,
              "boundary_line": "Never send, post, buy, publish, delete, or change settings without my approval in this conversation. If a source is unavailable, report the failure."}
    if getattr(args, "page_only", False):
        result["coverage"] = "page text only: the skill bodies and routine prompts were not visible"
        if result["verdict"] == "Install":
            result["verdict"] = "Nothing bad found in what the page shows"
    elif cover:
        result["coverage"] = cover   # files left unread in a folder: said, never silent, in both outputs
    if plugin_ if plugin_ is not None else re.search(r"(?i)\bplug-?ins?\b", text):
        result["bundled_plugin"] = ("This template mentions a plugin. A plugin's files can't be seen before it is installed. Tell the owner: "
                                    "\"It will ask to install a plugin I can't inspect yet. If you say yes, tell me and I'll check it straight away.\"")
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"Verdict: {result['verdict']} · risk {result['risk_score']}/100 · autonomy {result['autonomy']}")
        for f in fs:
            print(f"  [{f['severity'].upper()}] {vet_label(f)}: {f['rule']} {f['title']} @ {f['where']} :: {f['evidence']}")
            print(f"      fix: {f['fix']}")
        if urls:
            print("  External URLs: " + ", ".join(urls[:10]))
        if cover and "coverage" in result and not getattr(args, "page_only", False):
            print(f"  Not fully checked: {result['coverage']}")
        print(f"  Paste into the description: {result['boundary_line']}")
    return 1 if result["verdict"] in ("Do not install", NOT_FINISHED) else 0
