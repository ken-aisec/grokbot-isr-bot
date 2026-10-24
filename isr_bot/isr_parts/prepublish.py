# Part of isr.py: runs inside isr.py's namespace (loaded by _isr_part); not a module on its own.
# ---------------------------------------------------------------- pre-publish check (before Share → Create template)
PREPUB_RULES = [
    ("ISR-PP01", "Email address", "medium", r"[\w.+-]+@[\w-]+\.[\w.-]+"),
    ("ISR-PP02", "Phone number", "medium", r"(?<!\d)(\+?1[\s.-]?)?\(?\d{3}\)?[\s.-]\d{3}[\s.-]\d{4}(?!\d)"),
    ("ISR-PP03", "Private network address or internal host", "high",
     r"\b(10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|[\w-]+\.(internal|local|corp|lan))\b"),
    ("ISR-PP04", "Link to a private doc, drive or workspace", "high",
     r"(docs\.google\.com/\S+|drive\.google\.com/\S+|notion\.so/\S+|[\w-]+\.slack\.com/\S+|airtable\.com/\S+|app\.hubspot\.com/\S+|1[\w-]{30,}\b)"),
    ("ISR-PP05", "Path that only exists on your computer", "medium", r"(/home/box/\S+|/workspace/\S+|/Users/\w+/\S+)"),
    ("ISR-PP06", "Depends on something templates don't carry", "medium",
     r"(?i)\b(mcp server|custom mcp|run (the|this|my) script|\.py\b|\.sh\b|my local|localhost:\d+)"),
]


NAMES_FILE = ("exports", "names.txt")


def known_names(shared):
    """Personal names that must not ship: the owner's name and other names in exports/names.txt (one per line, written at
    setup), plus every Bot or person on the saved roll-call roster. The Bot being shared may name itself."""
    names = [l.strip() for l in (read_text(os.path.join(home(), *NAMES_FILE)) or "").splitlines() if l.strip() and not l.startswith("#")]
    roster = load_json(os.path.join(home(), *ROSTER_FILE), None)
    items = roster.get("entries", roster.get("roster", [])) if isinstance(roster, dict) else roster
    for e in items if isinstance(items, list) else []:
        if isinstance(e, dict) and isinstance(e.get("name"), str) and str(e.get("kind", "")).lower() in BOT_KINDS:
            names.append(e["name"].strip())
    skip = {"watchtower", (shared or "").lower()}
    return sorted({n for n in names if len(n) >= 3 and n.lower() not in skip})


OWN_TEMPLATE_REL = re.compile(r"(bot|routines)/[^/]+|skills/[^/]+/SKILL\.md")


def own_release_digests():
    """v0.7.4 fix round 1 (Codex MED3): this release's own template files (bot/*, routines/*, skills/*/SKILL.md) name the Bot
    ISR Bot by design, so that roster name is no leak in an unchanged copy of one; anywhere else it is. Fix round 2 (Codex
    MED3): an unchanged copy is told only by the sha256 of its raw bytes, one the MANIFEST.sha256 this process checked itself
    against (release_manifest: self_check's, read once) lists for one of those files. Never a folder listing or a text compare
    (a CRLF copy or a file put there after the self-check matched); no manifest, no exemption. The owner's decision (Oct 23):
    exempt only those exact files, and only for the name ISR Bot."""
    return {h for rel, h in release_manifest().items() if OWN_TEMPLATE_REL.fullmatch(rel) and re.fullmatch(r"[0-9a-f]{64}", h)}


def read_once(path, limit=1_000_000):
    """(the text read_text gives, the sha256 of the raw bytes it was decoded from), from one read; (None, "") as read_text."""
    try:
        st = os.stat(path)
        if not stat.S_ISREG(st.st_mode) or st.st_size > limit:
            return None, ""
        with open(path, "rb") as f:
            data = f.read()
    except (OSError, ValueError):
        return None, ""
    return data.decode("utf-8", errors="replace").replace("\r\n", "\n").replace("\r", "\n"), hashlib.sha256(data).hexdigest()


def _body(t):
    t = t or ""
    if t.startswith("---"):
        end = t.find("\n---", 3)
        t = t[end + 4:] if end != -1 else t
    return re.sub(r"\s+", " ", t.replace("\u2019", "'")).strip()


def prepublish_extra(where, t, names):
    out = []
    for n in names:   # DQ-015
        for m in re.finditer(r"(?<![\w-])" + re.escape(n) + r"(?![\w-])", t):
            out.append(finding("ISR-PP08", "Owner or Bot name", "high", ["AST04", "LLM02"], f"{where}:{line_of(t, m.start())}", n,
                               "Replace the name with 'the owner' or 'another Bot': a template ships to strangers."))
    old = {os.path.basename(x) for x in OLD_CANARY_PATHS + PUBLISHED_CANARY_PATHS} | set(OLD_CANARY_PATHS + PUBLISHED_CANARY_PATHS)
    for x in sorted(old):   # DQ-016: never print the location itself
        i = t.find(x)
        if i != -1:
            out.append(finding("ISR-PP10", "Names a decoy location from an older release", "high", ["AST04"], f"{where}:{line_of(t, i)}",
                               "an old fixed decoy location (not shown)", "Refresh this text from the current release; decoys now have random names."))
            break
    if "getting-started" in os.path.basename(where):
        cur = read_text(os.path.join(SELF_ROOT, "bot", "getting-started.md"))
        if cur is not None and _body(t) != _body(cur):
            out.append(finding("ISR-PP09", "Getting-started is older than this ISR Bot", "high", ["AST04"], where, "differs from app/bot/getting-started.md",
                               "Replace the saved getting-started skill's body with /workspace/isr-bot/app/bot/getting-started.md, then run prepublish again."))
    return out


def cmd_prepublish(args):
    rules = load_rules()
    names = known_names(os.path.basename(os.path.normpath(args.path)) if args.path != "-" else "")
    paths = []
    if args.path == "-":
        texts = [("stdin", sys.stdin.read(), "")]
    else:
        for root, _, files in (os.walk(args.path) if os.path.isdir(args.path) else [(os.path.dirname(args.path), [], [os.path.basename(args.path)])]):
            for fn in files:
                paths.append(os.path.join(root, fn))
        texts = [(p, t or "", h) for p, (t, h) in ((p, read_once(p)) for p in paths)]
    fs, own = [], own_release_digests()
    for where, t, digest in texts:
        fs += [f for f in scan_text(t, where, rules, kind="template")   # batch 6 fix round 3: ISR-T011x is ISR-T011 (an example-looking one)
               if f["rule"] in ("ISR-T011", "ISR-T011x", "ISR-T013", "ISR-T007", "ISR-T008", "ISR-T005", "ISR-T006", "ISR-T018")]
        for rid, title, sev, rx in PREPUB_RULES:
            for m in re.finditer(rx, t):
                ev = m.group(0)
                if rid == "ISR-PP01" and re.search(r"(?i)(example\.(com|org)|noreply|no-reply)", ev):
                    continue
                if rid == "ISR-PP05" and "/workspace/isr-bot" in ev:
                    continue
                if rid == "ISR-PP06":   # Watchtower's own script is installed by its setup skill from a pinned release, so it does travel
                    line = t[t.rfind("\n", 0, m.start()) + 1:(t.find("\n", m.end()) if t.find("\n", m.end()) != -1 else len(t))]
                    if re.search(r"(isr\.py|/workspace/isr-bot/|install\.sh)", line):
                        continue
                fs.append(finding(rid, title, sev, ["AST04", "LLM02"], f"{where}:{line_of(t, m.start())}", mask(ev) if rid in ("ISR-PP01", "ISR-PP02") else ev[:120],
                                  "Remove or generalize it before you create the template: anything in a description, skill or routine ships to every installer.",
                                  shown=None if rid in ("ISR-PP01", "ISR-PP02") else ev))
        fs += prepublish_extra(where, t, [n for n in names if not (n.lower() == "isr bot" and digest in own)])
        if not has_approval(t, rules) and rules["write_verbs"].search(t):
            fs.append(finding("ISR-PP07", "No approval boundary", "high", ["ASI02"], where, "no approval line",
                              "Add: never send, post, buy, publish, delete, or change settings without my approval."))
    fs = sort_findings(dedupe(fs))
    blocking = [f for f in fs if f["severity"] in ("critical", "high")]
    result = {"verdict": "FAIL" if blocking else "PASS", "blocking": len(blocking), "findings": [compact(f) for f in fs][:40]}
    print(fit(result) if args.json else
          f"Pre-publish: {result['verdict']} ({len(blocking)} blocking, {len(fs)} total)\n" +
          "\n".join(f"  [{f['severity'].upper()}] {f['title']} @ {f['where']} :: {f['evidence']}" for f in fs[:40]))
    return 1 if blocking else 0


# ---------------------------------------------------------------- incident mode (evidence first, containment with approval)
CONTAINMENT = [
    "Pause every routine on the affected Bot (and any Bot that shares its connectors).",
    "In the Grok Bot browser, sign out of sensitive sites; then log out all sessions from each site's security settings.",
    "Disconnect connectors the affected Bot uses (Marketplace → Your plugins) and revoke them in the source service.",
    "Rotate CLI credentials on the computer (GitHub CLI, cloud CLIs) and any key found in the evidence.",
    "Disable or delete the skill, plugin or template that triggered this; keep a copy in /workspace/isr-bot/incidents for review.",
    "If you can't explain what ran, reset the cloud computer (Settings → Computer) after saving what you need.",
]


def cmd_incident(args):
    rules = load_rules()
    ts = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%MZ")
    idir = os.path.join(home(), "incidents")
    os.makedirs(idir, exist_ok=True)
    snap = load_json(state_path("last_findings.json"), {"findings": []})
    secret = next(r["rx"] for r in rules["rules"] if r["id"] == SECRET_RULE)
    # batch 4 (R11): tokens and passwords too. Codex, round 1: masked before the T011 pass, so a private key's header is still
    # there to find its body by, and over the whole text, so a body on the lines after its header is found as well
    clean = lambda t: secret.sub(lambda m: mask(m.group(0)), mask_secrets(t or ""))
    _, ps, _ = run(["ps", "-eo", "pid,ppid,user,etime,cmd", "--sort=-etime"], 20)
    _, net, _ = run(["ss", "-tunp"], 20)
    _, cron, _ = run(["crontab", "-l"], 10)
    _, timers, _ = run(["systemctl", "--user", "list-timers", "--all", "--no-pager"], 10)
    recent = []
    for r in [os.path.expanduser("~"), "/workspace"]:
        for p in walk([r], max_depth=6):
            try:
                if os.path.getmtime(p) > dt.datetime.now().timestamp() - 86400 and p not in canary_paths():
                    recent.append(p)
            except OSError:
                pass
    tails = []
    for hf in HISTORY_FILES:
        p = os.path.expanduser(hf)
        if os.path.isfile(p):
            with open(p, errors="replace") as f:
                tails += [f"{hf}: {l.rstrip()[:200]}" for l in clean(f.read()[-262144:]).splitlines()[-40:]]
    # Codex, round 1: the snapshot may still be an older version's, written before evidence was masked
    hot = mask_stored([dict(f) for f in snap.get("findings", []) if isinstance(f, dict) and f.get("severity") in ("critical", "high")])
    ledger_tail = []
    try:
        with open(state_path("ledger.jsonl")) as f:
            ledger_tail = f.readlines()[-20:]
    except OSError:
        pass
    md = [f"# ISR Bot incident {ts}", "", f"Reported: {args.note or '(no description given)'}", "",
          "## Containment checklist (each step needs your yes)", ""] + [f"{i}. [ ] {c}" for i, c in enumerate(CONTAINMENT, 1)] + [
          "", "## Open critical and high findings", ""] + [f"- {f['severity']} {f['rule']} {f['title']} at `{f['where']}` ({f['evidence']})" for f in hot[:40]] + [
          "", "## Canaries", "", "\n".join(f"- {f['title']} at `{f['where']}`" for f in canary_findings(record=False)) or "- quiet",
          "", "## Files changed in the last 24 hours", ""] + [f"- `{p}`" for p in sorted(recent)[:150]] + [
          "", "## Shell history (last 40 lines per file, secrets masked)", "", "```"] + tails + ["```",
          "", "## Processes", "", "```", clean(ps)[:8000], "```", "", "## Network connections", "", "```", clean(net)[:6000], "```",
          "", "## Scheduled jobs", "", "```", clean(cron)[:2000], clean(timers)[:2000], "```",
          "", "## ISR Bot ledger (last 20 runs)", "", "```"] + [l.rstrip() for l in ledger_tail] + ["```", ""]
    path = os.path.join(idir, f"incident-{ts}.md")
    with open(path, "w") as f:
        f.write("\n".join(md))
    ledger({"event": "incident", "file": path, "hot": len(hot)})
    print(fit({"evidence_pack": path, "open_critical_high": len(hot), "changed_24h": len(recent),
               "top": [compact(f) for f in hot[:5]], "containment": CONTAINMENT}))
    return 0
