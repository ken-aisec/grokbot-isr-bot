# Part of wt.py: runs inside wt.py's namespace (loaded by _wt_part); not a module on its own.
# ---------------------------------------------------------------- one-time events (history, canaries) stay open
EVENT_DAYS = 14


def remember_events(new):
    """History lines and canary trips happen once. Keep them open for EVENT_DAYS so the next run
    doesn't report them as fixed; suppress one (wt.py show + suppressions.json) to close it sooner."""
    store = mask_stored(load_json(state_path("events.json"), []))   # batch 4 (R11): evidence an older version stored unmasked
    known = {e["key"] for e in store}
    for f in new:
        if f["key"] in BULK_KEYS:
            old = [e for e in store if e["key"] == f["key"]]
            n = sum(e.get("times", 1) for e in old) + 1
            store = [e for e in store if e["key"] != f["key"]]
            ev = f["evidence"] + (f"; {n} times in the last {EVENT_DAYS} days" if n > 1 else "")
            store.append(dict(f, evidence=ev[:220], times=n, first_seen=now()))
        elif f["key"] not in known:
            store.append(dict(f, first_seen=now()))
    cutoff = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=EVENT_DAYS)).isoformat()
    store = mask_stored([e for e in store if e.get("first_seen", "") >= cutoff])
    save_json(state_path("events.json"), store)
    return [{k: v for k, v in e.items() if k not in ("first_seen", "times")} for e in store]


# ---------------------------------------------------------------- shell history (closest thing to Action Recording)
HISTORY_FILES = ("~/.bash_history", "~/.zsh_history", "~/.local/share/fish/fish_history", "~/.python_history")
HISTORY_RULES = [
    ("ISR-H001", "Script piped into a shell from an unknown host", "high", ["ASI05", "AST02"],
     r"(curl|wget)[^\n|]{0,200}\|\s*(sudo\s+)?(ba|z)?sh\b"),
    ("ISR-H002", "Decoded payload executed", "critical", ["ASI05"], r"base64\s+(-d|--decode)[^\n]{0,80}\|\s*(ba|z)?sh|python3?\s+-c\s+['\"].{0,40}(exec|b64decode)"),
    ("ISR-H003", "Reverse shell pattern", "critical", ["ASI05", "ASI10"],
     r"(bash\s+-i\s*>&\s*/dev/tcp/|nc(at)?\s+[^\n]{0,40}-e\s|mkfifo\s+/tmp/[^\n]{0,60}\bnc\b|socat\s+[^\n]{0,60}exec:)"),
    ("ISR-H004", "Credential store read", "high", ["ASI03"],
     r"(cat|less|head|tail|cp|scp|base64)\s+[^\n]{0,40}(\.ssh/id_|\.aws/credentials|\.git-credentials|\.netrc|credentials\.json|cookie)"),
    ("ISR-H005", "File uploaded with curl", "high", ["ASI04"], r"curl\s[^\n]{0,200}(-d\s*@|--data(-binary)?\s*@|-F\s*\S*=@|-T\s)"),
    ("ISR-H006", "History tampering", "high", ["ASI10"], r"(history\s+-c|unset\s+HISTFILE|HISTFILE=/dev/null|>\s*~?/?\.?bash_history|shred\s+[^\n]*history)"),
    ("ISR-H007", "World-writable permissions", "medium", ["ASI03"], r"chmod\s+(-R\s+)?(0?777|a\+rwx|o\+w)\b"),
    ("ISR-H008", "New persistence added", "medium", ["ASI10"], r"(crontab\s+(-\s*$|-r|[^\s-])|>>\s*~?/?\.(bashrc|profile|zshrc)|systemctl\s+(--user\s+)?enable)"),
    ("ISR-H009", "Environment dumped to a file or the network", "high", ["ASI03"], r"\b(env|printenv|set)\s*(>|\|\s*(curl|nc|tee))"),
]


def history_findings(rules):
    out, offsets = [], load_json(state_path("history_offsets.json"), {})
    compiled = [(i, t, s, o, re.compile(rx, re.I | re.M)) for i, t, s, o, rx in HISTORY_RULES]
    secret = next(r["rx"] for r in rules["rules"] if r["id"] == SECRET_RULE)
    for hf in HISTORY_FILES:
        p = os.path.expanduser(hf)
        if not os.path.isfile(p):
            continue
        size = os.path.getsize(p)
        start = offsets.get(p, 0)
        if start > size:  # truncated or rotated
            start = 0
            out.append(finding("ISR-H006", HISTORY_SHRANK, "medium", ["ASI10"], p,
                               f"{offsets.get(p)} → {size} bytes", "Something cleared or rotated the history. Confirm it was you."))
        with open(p, "r", encoding="utf-8", errors="replace") as f:
            f.seek(start)
            chunk = f.read()
        offsets[p] = size
        masked = None
        for n, line in enumerate(chunk.splitlines(), 1):
            line = re.sub(r"^: \d+:\d+;", "", line)  # zsh extended history prefix
            for rid, title, sev, owasp, rx in compiled:
                if rx.search(line):
                    if rid == "ISR-H001" and known_installer(line):
                        continue
                    legacy = secret.sub(lambda m: mask(m.group(0)), line)   # the key, as before (finding() cuts it to 160)
                    # Codex, batch 4 round 1: what is stored is masked from the raw line, so a private key's body is hidden before
                    # the T011 pass shortens its header. Round 2: masked from the whole chunk, line for line, so a quote opened
                    # on an earlier line (a token over two lines) is still hidden on this one.
                    if masked is None:
                        masked = mask_lines(chunk)
                    out.append(finding(rid, title, sev, owasp, f"{p}:+{n}", legacy,
                                       "Find which Bot or session ran this (Agent Computer view, routine runs). If none of yours meant to, tell ISR Bot \"incident check\".",
                                       shown=secret.sub(lambda m: mask(m.group(0)), re.sub(r"^: \d+:\d+;", "", masked[n - 1]))))
                    break
    save_json(state_path("history_offsets.json"), offsets)
    return out
