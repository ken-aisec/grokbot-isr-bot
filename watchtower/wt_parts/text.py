# Part of wt.py: runs inside wt.py's namespace (loaded by _wt_part); not a module on its own.
# ---------------------------------------------------------------- text analysis
KNOWN_INSTALLERS = re.compile(r"(?i)https?://(bun\.sh|deno\.land|sh\.rustup\.rs|astral\.sh|get\.docker\.com|brew\.sh|"
                              r"raw\.githubusercontent\.com/(nvm-sh|Homebrew)|install\.python-poetry\.org|cli\.github\.com|"
                              r"claude\.ai/install|get\.pnpm\.io|fnm\.vercel\.app|supabase\.com|vercel\.com|fly\.io/install|"
                              r"ollama\.com/install|sdk\.cloud\.google\.com|awscli\.amazonaws\.com|x\.ai/cli|tailscale\.com/install|"
                              r"downloads\.slack-edge\.com|cursor\.com/install|opencode\.ai/install|get\.helm\.sh|"
                              r"install\.determinate\.systems|starship\.rs|deb\.nodesource\.com|cli\.doppler\.com|"
                              r"railway\.app/install|github\.com/cli/cli)")


def known_installer(text):
    """True only when every link in the line is a known installer (a decoy link next to a real one doesn't pass)."""
    urls = re.findall(r"(?i)https?://[^\s'\"`)|;]+", text)
    return bool(urls) and all(_known_url(u) for u in urls)


def _known_url(u):
    """R13: the exact host. A bare-host entry must be followed by a separator (bun.sh.evil.io is not bun.sh); an entry that
    already names a path (tailscale.com/install) may go on (install.sh)."""
    m = KNOWN_INSTALLERS.match(u)
    if not m:
        return False
    rest = u[m.end():]
    return rest == "" or rest[0] in ("/:?#." if "/" in m.group(1) else "/:?#")   # nvm-sh-evil is a different account
PLACEHOLDER = re.compile(r"(?i)(example|sample|placeholder|your[_-]?|dummy|fake|test|xxxx|0000|1234|abcd|\.\.\.|<|>|\*{3})")


FILE_MAGIC = (b"PK\x03\x04", b"%PDF", b"\x89PNG", b"\xff\xd8\xff", b"GIF8", b"<!DOCTYPE", b"<!doctype", b"<html", b"<svg", b"<?xml", b"RIFF", b"\x1f\x8b")


def is_document_blob(b64):
    """Base64 that decodes to an ordinary file (Office, PDF, image, HTML) is data being uploaded, not a payload."""
    import base64, binascii
    chunk = b64[:64]
    try:
        head = base64.b64decode(chunk + "=" * (-len(chunk) % 4))
    except (binascii.Error, ValueError):
        return False
    return head.lstrip().startswith(FILE_MAGIC)


def looks_real_secret(s):
    """Drop documentation placeholders: example words, repeated characters, or low character variety."""
    if PLACEHOLDER.search(s):
        return False
    body = re.sub(r"^(sk-(proj|ant|svcacct|admin)-|sk-|ghp_|github_pat_|xox[baprs]-|xai-|AKIA|AIza)", "", s)
    if len(set(body)) < 10 or re.search(r"(.)\1{5,}", body):
        return False
    return True


# Hardening batch 2 (review R1; guard redesign after fix round 3): a guarded match is kept as a "Warning or example text" record,
# never dropped. For the dangerous rules below (credential path, exfiltration host, pipe-to-shell, upload) a guard can only lower
# the match to medium, and vet never says Install over it. Only prose outside the command vouches for it: text in a code span or
# a command's arguments is never read, and any doubt (a cap, an unclosed backtick, shell text in the prose) means no guard.
GUARD_CODE_RULES = frozenset(("WT-T004", "WT-T005", "WT-T006", "WT-T017", "WT-T018"))
GUARD_FUNCTION = frozenset("a an the any your my its this that it them to from into as of or nor ever just blindly".split())
CLAUSE_END = re.compile(r"\.\s|\n|[:;!?](?=\s|$)|\s[-–—]{1,2}\s")
GUARD_TOKEN = re.compile(r",|[^\s,]+")
REPORTED = re.compile(r"(?i)\b(if|when)\s+((a|an|the|any|some)\s+)?[\w-]+\s+(says?|tells?|asks?|instructs?)\s+((you|the\s+bot|it)\s+)?"
                      r"(to\s+)?(?P<rest>(\S+\s+){0,2})$")
UNTRUSTED_AFTER = re.compile(r"(?i)^\s*(inside|in|within|found\s+in|from|embedded\s+in)\s+((a|an|the|any|this|that|its|your|their|each|every)\s+)?"
                             r"(web\s+)?(pages?|sites?|websites?|emails?|messages?|documents?|files?|transcripts?|comments?|issues?|"
                             r"tool\s+outputs?|search\s+results?)\b")
DESCRIBED_AFTER = re.compile(r"(?i)\btreat\s+(it|this|them|that|these|those)\s+as\s+(untrusted\s+)?data\b|\b(is|are)\s+(an?\s+)?(attack|injection|"
                             r"prompt[- ]injection)\b|\b(don'?t|do\s+not|never)\s+(follow|obey)\s+(it|this|them|that|these|those)\b")


def _clause_before(text, start):
    """The clause before a match: the partial token glued to it (https://, ~/, an opening backtick, the "an" of "another") is
    dropped, then the text is cut at a sentence end, a colon, semicolon, ! or ?, or a spaced dash."""
    before = text[max(0, start - 200):start].replace("’", "'")
    before = re.sub(r"\S+$", "", before)
    before = re.sub(r"(?i)\b(e)\.(g)\.|\b(i)\.(e)\.", lambda x: "".join(g for g in x.groups() if g), before)   # e.g. is not a sentence end
    return CLAUSE_END.split(before)[-1]


def _guard_token(t):
    return t if t == "," else t.strip("*_`\"'“”‘()[]<>").lower()


def _negated(clause, rules):
    """The nearest governing word (a negation, an example word, a describer) governs the verb: reached walking back through at
    most 3 filler words (run, read, send, data, keys, a masked code span...); function words (the, to, ever...) are free. A comma
    ends the clause unless it follows the governing word ("Never, ever run") or a filler verb ("never read, send or upload")."""
    toks = [t for t in (_guard_token(x) for x in GUARD_TOKEN.findall(clause)) if t]
    gov, verbs, nouns = rules["context_guard"], rules["guard_filler"]["verbs"], rules["guard_filler"]["nouns"]
    n = 0
    for i in range(len(toks) - 1, -1, -1):
        t = toks[i]
        if t == ",":
            prev = toks[i - 1] if i else ""
            if not (gov.match(prev) or verbs.match(prev)):
                return False
        elif gov.match(t):
            return True
        elif t in GUARD_FUNCTION:
            continue
        elif verbs.match(t) or nouns.match(t) or t == CODE:
            n += 1
            if n > 3:
                return False
        else:
            return False
    return False


LINE_CAP, SPAN_CAP, ARGS_CAP, CLAUSE_CAP, AFTER_CAP, TOKEN_CAP, NEST_CAP, LIST_CAP = 4000, 300, 300, 300, 200, 200, 3, 200
CODE = "\x01"                                    # a masked code span: one filler noun in the prose around it
SENTENCE_END = re.compile(r"[.!?](?=\s|$)")      # quote-unaware: a quote never hides a sentence end (the 5" of 5"-wide)
COMMAND = re.compile(r"(?i)\b(curl|wget)\b")
SHELLY = re.compile(r"\||&&|(?:^|\s)&(?:\s|$)|\$[({]|[<>]\(|`|(?:^|\s)#|(?:^|\s)-{1,2}[A-Za-z0-9]|=@|(?:^|\s)@\S|\\\s*$|;(?=\S)"
                    r"|(?i:\b(?:curl|wget)\b)")
SHELL_WORD = re.compile(r"(?i)(?:^|\s)(?:-c|eval|exec|sh|bash|zsh|dash|sudo|xargs|env|nohup|time|then|do|run|runs|execute|executes)\s*$")
LONG_TOKEN = re.compile(r"\S{%d,}" % (TOKEN_CAP + 1))
HEADING = re.compile(r"^ {0,3}#{1,6}[ \t]+")      # a Markdown heading marker at the line start: never a shell comment
AFTER_SEP = re.compile(r"(?i)(?:[ \t]*[;:]|[ \t]+[-–—]{1,2})[ \t]+(?P<phrase>(?:don'?t|do\s+not|never)\s+(?:follow|obey)\s+"
                       r"(?:it|this|them|that|these|those)|treat\s+(?:it|this|them|that|these|those)\s+as\s+(?:untrusted\s+)?data|"
                       r"(?:it|this|that)\s+is\s+(?:an?\s+)?(?:attack|injection|prompt[- ]injection))[ \t]*(?:[.!](?=\s|$)|$)")


def _spans(line):
    """The closed inline code spans on a line as (start, end, backtick run length); None when a backtick run never closes."""
    out, op = [], None
    for r in re.finditer(r"`+", line):
        if op is None:
            op = r
        elif len(r.group()) == len(op.group()):
            out.append((op.start(), r.end(), len(op.group())))
            op = None
    return None if op is not None else out


def _span_ok(s):
    """A code span that is one well-formed command: strict shell quoting in one pass with an explicit stack, no separator, no
    comment, no nested backtick, nesting at most NEST_CAP deep."""
    if len(s) > SPAN_CAP:
        return False
    st, i = [], 0
    while i < len(s):
        c, top = s[i], (st[-1] if st else "")
        if c == "\\":
            i += 2
            continue
        if top == '"':
            if c == '"':
                st.pop()
            elif s.startswith("$(", i):
                st.append("(")
                i += 1
            elif c == "`":
                return False
        elif c == "'":
            j = s.find("'", i + 1)
            if j == -1:
                return False
            i = j + 1
            continue
        elif c in '"(':
            st.append(c)
        elif c == ")":
            if top != "(":
                return False
            st.pop()
        elif c in ";`" or s.startswith(("||", "&&"), i):
            return False
        elif c == "&" and not (i and s[i - 1] in "<>") and not s.startswith("&>", i):
            return False
        elif c == "#" and (i == 0 or s[i - 1].isspace()):
            return False
        if len(st) > NEST_CAP:
            return False
        i += 1
    return not st


def _args_ok(s, word, n):
    """The bare arguments `s` between curl/wget and the match: no separator, substitution, comment or prose punctuation. A quote
    opens only at a word start or right after a closing quote, so it's and users' are literal. A quote still open at the match
    is fine only when its argument is one word ('key=@~/.ssh/id_rsa') with no escape or substitution and the quote closes after
    the match: `word` is the match's word from the match on, `n` the match's length."""
    if len(s) > ARGS_CAP or CODE in s:
        return False
    q, qs, closed, i = "", 0, -1, 0
    while i < len(s):
        c = s[i]
        if q:
            if c == q:
                q, closed = "", i + 1
            elif c == "\\" and q == '"':
                i += 1
        elif c == "\\":
            i += 1
        elif c in "'\"":
            if i == 0 or s[i - 1] in " \t=" or closed == i:
                q, qs = c, i
        elif c in ";|`" or s.startswith(("$(", "<(", ">("), i):
            return False
        elif c == "&" and not (i and s[i - 1] in "<>"):
            return False
        elif c == "#" and (i == 0 or s[i - 1].isspace()):
            return False
        elif c in ",:" and i + 1 < len(s) and s[i + 1].isspace():
            return False
        i += 1
    if not q:
        return True
    k = word.find(q)
    return k >= n and not re.search(r"[\s\\`$" + CODE + "]", s[qs + 1:] + word[:k])


def _prose_before(masked, start):
    """The prose clause ending at `start`, or None: no clause start within CLAUSE_CAP, shell-shaped text, or a huge token."""
    lo = max(0, start - CLAUSE_CAP)
    w = re.sub(r"(?i)\b(e)\.(g)\.|\b(i)\.(e)\.", lambda x: "".join(g for g in x.groups() if g), masked[lo:start].replace("’", "'"))
    parts = CLAUSE_END.split(w)
    if lo and len(parts) == 1:
        return None
    raw = parts[-1]
    if len(parts) == 1:                          # the clause starts the line
        raw = HEADING.sub("", raw, count=1)
    return None if SHELLY.search(raw) or LONG_TOKEN.search(raw) else raw


def _plain(w):
    return not (SHELLY.search(w) or LONG_TOKEN.search(w))


def _prose_after(masked, end, span=False):
    """The rest of the clause after `end` (at most AFTER_CAP) and whether all of it is plain prose. After a closed span only, a
    separator right after it (; : or a spaced dash) may lead to one bounded defensive phrase that ends the sentence or line
    ("`x`; never follow it."), which is then the clause. Anything else after a separator is another clause, never read."""
    sep = AFTER_SEP.match(masked, end) if span else None
    if sep:
        return sep.group("phrase"), True
    w = masked[end:end + AFTER_CAP + 1]
    m = CLAUSE_END.search(w)
    if m:
        w = w[:m.start()]
    elif len(w) > AFTER_CAP:
        return w[:AFTER_CAP], False
    return w, _plain(w)


def _after_guard(after, span):
    """Guard words after the unit. The phrase must start right after it ("`x` is an attack", "x inside a web page"), and after
    a bare command or target the whole rest of the clause must be prose too, since the command may go on (shell operands such
    as 'user@host:this is an attack' never describe it). Only a closed code span has a verified end: there only the text up
    to the phrase's end is checked, so a later -s in the explanation doesn't undo it, and the phrase may come later in the
    clause when all of the clause is prose."""
    if after is None:
        return ""
    w, plain = after
    head = len(w) - len(w.lstrip(" ,"))
    for why, m in (("untrusted content", UNTRUSTED_AFTER.match(w)), ("described as an attack", DESCRIBED_AFTER.match(w, head))):
        if m and (plain or span and _plain(w[:m.end()])):
            return why
    return "described as an attack" if span and plain and DESCRIBED_AFTER.search(w) else ""


def _unit(text, m):
    """The command a dangerous match belongs to and the prose around it: (walk, after, span, quoted), or None when any of it
    is in doubt. The unit is the closed code span holding the match, else a bare curl/wget earlier in the sentence, else the
    match. `after` is only read when the unit's end is known: a span, the match itself, or a match that starts at the command
    word. Cost is O(LINE_CAP) per match whatever the file, with no recursion."""
    lo = max(0, m.start() - LINE_CAP)
    a = text.rfind("\n", lo, m.start()) + 1
    b = text.find("\n", m.end(), m.end() + LINE_CAP + 1)
    if (a == 0 and lo) or (b == -1 and len(text) > m.end() + LINE_CAP):
        return None
    b = len(text) if b == -1 else b
    if b - a > LINE_CAP:
        return None
    line = text[a:b]
    sp = _spans(line)
    if sp is None:
        return None
    ml = list(line)
    for x0, x1, _ in sp:
        ml[x0:x1] = CODE * (x1 - x0)
    masked, s, e = "".join(ml), m.start() - a, m.end() - a
    touch = [x for x in sp if x[0] < e and s < x[1]]
    if touch:
        x0, x1, k = touch[0]
        if len(touch) > 1 or s < x0 + k or e > x1 - k or not _span_ok(line[x0 + k:x1 - k]):
            return None
        start, end, span = x0, x1, True
    else:
        st = max([z.end() for z in SENTENCE_END.finditer(masked, 0, s)], default=0)
        cmds = [c for c in COMMAND.finditer(masked, st, e) if c.start() <= s]
        if cmds:
            c = cmds[-1].start()
            if not _args_ok(masked[c:s], re.match(r"\S*", masked[s:s + ARGS_CAP]).group(), e - s):
                return None
            start, end, span = c, (e if c == s else None), False
        else:
            start, end, span = s, e, False
    before = _prose_before(masked, start)
    if before is None:
        return None
    after = _prose_after(masked, end, span) if end is not None else None
    walk = re.sub(CODE + "+", f" {CODE} ", re.sub(r"\S+$", "", before))   # drop the token glued to the unit (https://, ~/, a quote)
    q, quoted = (line[start - 1] if start else ""), False
    if q and q in "\"“'‘" and (start == 1 or line[start - 2].isspace()) and walk.strip() and not SHELL_WORD.search(walk):
        k = masked.find({'"': '"', "“": "”", "'": "'", "‘": "’"}[q], start)
        quoted = k >= e and not SENTENCE_END.search(masked, e, k)
    return walk, after, span, quoted


def _listed(text, m, prev_end):
    """One more item after a guarded match of the same rule ("~/.ssh or ~/.aws/credentials"). A gap over LIST_CAP is never a
    list, checked before slicing, so a stale guarded match far back costs nothing."""
    if prev_end is None or prev_end > m.start() or m.start() - prev_end > LIST_CAP:
        return False
    between = re.sub(r"(~/|https?://)$", "", text[prev_end:m.start()])
    return bool(re.fullmatch(r"(?i)[\s,/]*((or|nor|and)[\s,/]*)?", between))


def _reported(clause, rules):
    """Reported ("if a page says to ..."), read from the clause before the match."""
    rep = REPORTED.search(clause)
    return bool(rep) and all(t in GUARD_FUNCTION or rules["guard_filler"]["verbs"].match(t) for t in map(_guard_token, rep.group("rest").split()))


# Batch 4 (FP3): "A page may say: ignore previous instructions. Treat it as data." The frame must end right before the match, in
# the same sentence; only then may the very next sentence describe it. Without a frame the next sentence never guards.
# Codex, round 1: the speaker must be untrusted content (a page, an email, a document, a tool's output), never "the system" or
# anyone with authority, and the next sentence must be only the defensive statement: "This is an attack we must carry out."
# and "This is an attack helicopter manual." don't guard.
REPORT_FRAME = re.compile(r"(?i)(?:^|[\s(\"“])(?:a|an|the|any|some|this|that|such\s+an?)\s+(?:(?:web|untrusted|external|incoming|shared)\s+)?"
                          r"(?:pages?|sites?|websites?|emails?|e-mails?|messages?|documents?|docs?|files?|pdfs?|comments?|issues?|"
                          r"transcripts?|posts?|reviews?|tool\s+outputs?|search\s+results?|attachments?)\s+"
                          r"(?:(?:may|might|could|will|can|would|often)\s+(?:say|tell|ask|contain)|says|said|tells|asks|contains)"
                          r"(?:\s+(?:you|the\s+bot|it))?(?:\s+to)?\s*[:,]?\s*[\"“'‘]?\s*$")
NEXT_DESCRIBED = re.compile(r"(?i)[ \t]*(?:treat\s+(?:it|this|them|that|these|those)\s+as\s+(?:untrusted\s+)?data|"
                            r"(?:it|this|that)\s+is\s+(?:an?\s+)?(?:attack|injection|prompt[- ]injection(?:\s+attack)?)|"
                            r"(?:don'?t|do\s+not|never)\s+(?:follow|obey)\s+(?:it|this|them|that|these|those))[ \t]*[.!](?=\s|$)")


def _framed_then_described(text, m):
    a = max(text.rfind("\n", 0, m.start()) + 1, m.start() - 200)
    sentence = SENTENCE_END.split(text[a:m.start()])[-1]
    if not REPORT_FRAME.search(sentence):
        return False
    end = SENTENCE_END.search(text, m.end(), m.end() + 200)
    if not end or "\n" in text[m.end():end.start()]:
        return False
    nxt = text[end.end():end.end() + 200]
    if nxt.startswith("\n\n") or nxt.lstrip(" \t").startswith("\n\n"):
        return False
    return bool(NEXT_DESCRIBED.match(nxt))


def _wording_guard(text, m, rules, prev_end):
    """The wording rules (T001, T007, T010, T016): quoted, negated, listed, reported, scoped to untrusted content, described as
    an attack, or detector code. No shell handling: a backtick or a leading | is a quotation here."""
    wide = text[max(0, m.start() - 90):m.start()]
    if wide.rstrip().endswith(("\"", "“", "'", "(", "[", "`", "|")):
        return "quoted"
    clause = _clause_before(text, m.start())
    if _negated(clause, rules):
        return "negated"
    if _listed(text, m, prev_end):
        return "list"
    if _reported(clause, rules):
        return "reported"
    if UNTRUSTED_AFTER.match(text[m.end():m.end() + 80]):
        return "untrusted content"
    if DESCRIBED_AFTER.search(re.split(r"[.!?](?=\s|$)|\n", text[m.end():m.end() + 200])[0]):
        return "described as an attack"
    if _framed_then_described(text, m):
        return "described as an attack"
    if re.search(r"(r\"|r'|\\s[+*]|\(\?i\))", wide + text[m.end():m.end() + 40]):
        return "detector code"
    return ""


# Batch 6 PR3 added guards here for false alarms vet showed; Codex rounds 1 and 2 showed each also exempted real attacks, so all
# are removed: an override that names a config file or a reviewer's output (T001), an env file copied into another (T004), and
# (round 2, H2) "Do not debug with `env`, `printenv` …", whose negation a trailing "unless …" makes conditional. Those false
# alarms are open (docs/KNOWN-LIMITS.md, B7).


def in_warning(text, m, rules, rule_id, prev_end=None):
    """Why the match reads as defensive prose, or "" when it doesn't: quoted, negated, one more item in a guarded list, reported
    ("if a page says to ..."), scoped to untrusted content, described as an attack, or detector code. `prev_end`: where the
    previous guarded match of the same rule ended. A dangerous rule's guard words come only from the prose around its unit."""
    if rule_id not in GUARD_CODE_RULES:
        return _wording_guard(text, m, rules, prev_end)
    u = _unit(text, m)
    if u is None:
        return ""                                                 # any doubt: no guard
    walk, after, span, quoted = u
    if quoted:
        return "quoted"
    if _negated(walk, rules):
        return "negated"
    if _listed(text, m, prev_end):
        return "list"
    if _reported(walk, rules):
        return "reported"
    return _after_guard(after, span)


GUARD_FIX = ("No action if this line warns against the step or quotes it as an example. If it tells the Bot to do it, treat it as the "
             "full finding.")
GUARDED_LABEL = "Warning or example text"


def guard_record(f, reason, danger=False):
    """A guarded match is kept as a record: listed in breakdown, vet and the dashboard, never scored, never new, never a vote.
    A wording match has no severity; a dangerous one (`danger`, GUARD_CODE_RULES) is only lowered, to medium at most, so vet
    still shows it. Its key differs from the full finding's, so deleting the "never" later shows as new."""
    sev = f["severity"]
    low = (sev if SEV_ORDER.index(sev) >= SEV_ORDER.index("medium") else "medium") if danger else "info"
    g = dict(f, severity=low, severity_was=sev, guarded=reason, title=f["title"] + " (reads as a warning or example)", fix=GUARD_FIX)
    g["key"] = hashlib.sha1((f["key"] + "|guarded").encode()).hexdigest()[:16]
    g.pop("key0", None)
    return g


def sends_data(ev):
    """WT-T017: the curl/wget segment itself (up to a pipe, ;, && or ||) carries a data flag.
    -G/--get is harmless only when the data is not a file (@) or a command substitution. Batch 6 PR3 exempted a command whose
    data, headers, method and URL were all literal; Codex round 2 (H1) removed it: curl and wget read a config file the
    command never names (~/.curlrc, .wgetrc: a credential header, an upload), so no visible command proves what is sent. The
    false alarm is open (docs/KNOWN-LIMITS.md, B7)."""
    m = re.search(r"(?i)\b(curl|wget)\b", ev)
    if not m:
        return True   # the prose form; its object words are checked by the rule
    seg = re.split(r"\|\|?|;|&&", ev[m.start():])[0].split("\n", 1)[0]  # one shell line; ignore fence backticks below
    data = re.search(
        r"(?i)(-X\s*POST\b|--data(-binary|-raw|-urlencode)?\b|-d[\"'\s@$]|"
        r"-F[\"'\s]|--upload-file\b|\s-T\s|--post-(data|file)\b|--json\b|"
        r"--body-file\b|--method=POST\b)", seg)
    if not data:
        return False
    if re.search(r"(?i)(\s-G\b|\s--get\b)", seg):
        return bool(re.search(r"(?i)(@\S|\$\(|`[^`\n]+`)", seg))
    return True


# Codex, batch 4 round 1: a chat webhook is WT-T018 only when the URL's own host is exactly the chat service's, with its webhook
# path. evil-discord.com/api/webhooks/…, https://collector.example/discord.com/api/webhooks/…, a user@ or a port in front of the
# host: not the service, so Slack and Discord lookalikes stay the critical WT-T005 they were on 857ab38.
CHAT_HOOKS = ((re.compile(r"hooks\.slack\.com"), re.compile(r"/(services|workflows|triggers)/")),
              (re.compile(r"discord(app)?\.com"), re.compile(r"/api/webhooks/")),
              (re.compile(r"[a-z0-9-]+\.webhook\.office\.com"), re.compile(r"/")),
              (re.compile(r"outlook\.office\.com"), re.compile(r"/webhook/")),
              (re.compile(r"chat\.googleapis\.com"), re.compile(r"/v1/spaces/[^/]+/messages")),
              (re.compile(r"api\.telegram\.org"), re.compile(r"/bot")))
CHAT_IN_T005 = re.compile(r"(?i)discord(app)?\.com/api/webhooks|hooks\.slack\.com/services")
URL_CLOSE = {"(": ")", "<": ">", "[": "]", "{": "}"}
_URL_END = re.compile(r"[\s\"'`<>|;&\\)]")
_URL_PLAIN = re.compile(r"(?i)https?://[^\s)\"'>]*")


def url_arg(text, s):
    """Codex, batch 4 round 2: where the URL that starts at `s` ends, read as one whole argument. Its line is read with the
    shell's quoting up to `s`: `s` must start a word, or follow an opening quote or bracket that itself starts one (url='…',
    post('…'), "url": "…", [x](…), <…>). A quoted URL ends at its own closing quote, never at punctuation inside it. None when
    `s` is the middle of something bigger (…/path;https://…, ?u='https://…, "$BASE"'https://…, x'https://…') or in doubt."""
    ls = text.rfind("\n", 0, s) + 1
    if s - ls > 4096:
        return None
    q, qs, ws, i = None, -1, ls, ls
    while i < s:
        c = text[i]
        if q is None:
            if c in " \t`":
                ws = i + 1
            elif c == "\\":
                i += 1
            elif c in "'\"" and not (c == "'" and i > ls and text[i - 1].isalnum() and text[i + 1:i + 2].isalpha()):   # don't, it's
                q, qs = c, i
        elif c == q:
            q = None
        elif c == "\\" and q == '"':
            i += 1
        i += 1
    if i != s:
        return None
    if q is None:
        o = text[s - 1] if s > ws else ""
        if not (s == ws or (o in URL_CLOSE and (s - 1 == ws or text[s - 2] in "]([{"))):
            return None
        m = _URL_END.search(text, s)
        end = m.start() if m else len(text)
        if o in URL_CLOSE:
            c = text.find(URL_CLOSE[o], s, end)
            end = c if c != -1 else end
        return end
    if qs != s - 1:
        return None
    before = text[qs - 1] if qs > ws else ""
    if before == "=":
        k = qs - 1
        while k > ws and (text[k - 1].isalnum() or text[k - 1] in "_-"):
            k -= 1
        if k == qs - 1 or not (k == ws or text[k - 1] in "([{,"):
            return None   # url='…' or --url='…' starts an argument; ?u='… is inside another URL
    elif before == ":":
        if text[qs - 2:qs - 1] not in ("'", '"'):
            return None   # "url":"…" (JSON)
    elif before and before not in "([{,":
        return None
    end = s
    while True:
        end = text.find(q, end)
        if end == -1 or "\n" in text[s:end]:
            return None
        if q == '"' and text[end - 1] == "\\":
            end += 1
            continue
        break
    if text[end + 1:end + 2] not in ("", " ", "\t", "\r", "\n", ")", ",", ";", "]", "}", ">", "|", "&", "`"):
        return None   # glued to more text: 'https://discord.com'.evil.example/… is another host
    return end


def urls_in(text, limit=200):
    """The http(s) URLs in `text`, each read whole (url_arg; one inside another is part of it) and masked (Codex, round 2)."""
    out, end = [], 0
    for m in re.finditer(r"(?i)\bhttps?://", text):
        if m.start() < end:
            continue
        e = url_arg(text, m.start())
        end = e if e is not None else _URL_PLAIN.match(text, m.start()).end()
        out.append(mask_secrets(text[m.start():end]))
        if len(out) >= limit:
            break
    return out


# Codex, batch 4 round 3: a literal is one piece of a bigger string when something can be put in front of it in the same
# expression: another literal next to it (Python joins 'a' 'b', also across lines), a + or %, or a join/format/urljoin call
# whose arguments it is among; or something follows it (+, %, another literal, a .method). A destination can then come first.
_JOIN_CALL = r"\b(?:join|format|format_map|concat\w*|reduce|sum|urljoin|Template|reversed|sorted)\b"
_JOIN_BEFORE = re.compile(rf"(?:{_JOIN_CALL}|%)\s*[(\[{{\s]*$")
_JOIN_NEAR = re.compile(rf"{_JOIN_CALL}\s*\(|%\s*[(\[{{]")
_SKIP = " \t\r\n\\"


# Batch 5 (Codex review 4, c1): the expression around a quoted URL is read, not one character on each side. A shell line (in an
# sh/bash/shell/console block, or a logical line or `inline code` starting with curl, wget, http, https or xh, after an optional
# $ prompt, sudo and VAR=value words) is read as shell words: the URL is the whole value when its word is exactly the quoted URL,
# so 'Content-Type: application/json' 'URL' are two arguments, and 'a''URL' or "$B"'URL' one glued word. Anything else is read as
# code (the stricter reading): a small tokenizer (string literals with Python/JS quotes, triple quotes and template backticks,
# # and // and /* */ comments, brackets) climbs from the literal through redundant ( ) groups, wrapper calls and the
# collections it is an element of, up to a sender call (post, request, fetch, axios, urlopen, Request, get, put, send), an
# assignment, a keyword argument, a dict value at the top, a markdown link or the statement start. A +, % or * next to it, a
# literal next to it (comments in between included), a join/format/urljoin/concat call, an f-string, or an index or attribute
# after it at any level: not the whole value. Unbalanced brackets, an unterminated string or comment, or anything else in
# doubt: not the whole value, so the URL stays WT-T005.
_SHELL_FENCES = frozenset(("sh", "bash", "shell", "console"))
_SHELL_TOOL = re.compile(r"[ \t]*(?:\$[ \t]+)?(?:sudo[ \t]+)?(?:[A-Za-z_][A-Za-z0-9_]*=\S*[ \t]+)*(?:curl|wget|https?|xh)[ \t]")
_FENCE_LINE = re.compile(r"^[ \t]{0,3}(`{3,}|~{3,})[ \t]*([^\s`]*)[^\n]*", re.M)
_SENDERS = frozenset(("post", "request", "fetch", "urlopen", "Request", "get", "put", "send"))
_JOINERS = frozenset(("join", "format", "format_map", "reduce", "sum", "urljoin", "Template", "reversed", "sorted"))
_URL_KEYS = frozenset(("url", "uri", "endpoint"))   # PR A, Codex round 1 (1): the keyword or dict key a sender's destination is under
# PR A, Codex round 2 (1, 7): calls that look something up. What they return is the value found under the key, or the default
# when nothing is there: a URL as the key is never where it goes; a URL as the default is, when the key is a plain name.
_LOOKUPS = frozenset(("getattr", "getenv", "setdefault", "pop", "getOrDefault", "get_or", "getdefault"))
_LOOKUP_DEFAULTS = frozenset(("default", "fallback"))
_BOOL_OPS = frozenset(("or", "and", "if", "else", "not", "||", "&&", "?"))
# PR A, Codex round 3 (5): the receivers `get` is an HTTP GET on (requests.get, httpx.get, https.get, axios.get, $.get, …); on any
# other receiver it is a lookup (round 3 (1)). Batch 6 (KL2): a session or client only when the code binds it to one
# (_CLIENT_MAKERS, http_client), never by its name
_CONFIG_PARSER = re.compile(r"(?i)configparser")
_ANY_URL = re.compile(r"(?i)\b[a-z][a-z0-9+.\-]*://[^\s'\"`<>()\[\]{}|\\,]*|(?<=['\"`])//[^\s'\"`<>()\[\]{}|\\,]+")


def _other_urls(text):
    """PR A, Codex round 3 (1): where each URL of `text` that isn't a chat webhook (CHAT_HOOKS) starts, read once per text."""
    import urllib.parse
    memo = _memo(text)
    if "other_urls" not in memo:
        out = []
        for m in _ANY_URL.finditer(text):
            try:
                u = urllib.parse.urlsplit(m.group(0) if "://" in m.group(0) else "https:" + m.group(0))
                host, port = (u.hostname or "").lower(), u.port
            except ValueError:
                host, port = "", None
            if not (port is None and host and u.netloc.lower() == host and any(h.fullmatch(host) and p.match(u.path) for h, p in CHAT_HOOKS)):
                out.append(m.start())
        memo["other_urls"] = out
    return memo["other_urls"]
_CRED_WORD = re.compile(r"(?i)token|secret|passw(?:or)?d|api_?key|private_?key|credential|cookie|(?<![\w$])\.(?:ssh|aws|netrc|env)\b"
                        r"|\bid_(?:rsa|ed25519)\b")
_STR_RX = (r"[rRbBuUfF]{0,2}(?:'''[\s\S]*?(?:'''|\Z)|\"\"\"[\s\S]*?(?:\"\"\"|\Z)|'(?:[^'\\\n]|\\.)*'|\"(?:[^\"\\\n]|\\.)*\"%s)")
_TOK_TAIL = (r"|(?P<name>[A-Za-z_$][\w$]*(?:'[A-Za-z]+)*)|(?P<num>\d[\w.]*)|(?P<open>[(\[{])|(?P<close>[)\]}])"
             r"|(?P<op>\*\*|&&|\|\||==|!=|<=|>=|[-+*/%=<>!&|^~?:;,.@])|(?P<bad>[\s\S])")
_CODE_TOK = re.compile(r"(?P<nl>\n)|(?P<ws>[ \t\r\f\v]+|\\\r?\n)|(?P<com>(?<![^\s])#[^\n]*|(?<![:/])//[^\n]*|/\*[\s\S]*?\*/)"
                       r"|(?P<ucom>/\*)|(?P<str>" + _STR_RX % r"|`(?:[^`\\]|\\[\s\S])*(?:`|\Z)" + r")" + _TOK_TAIL)
_PROSE_TOK = re.compile(r"(?P<nl>\n)|(?P<ws>[ \t\r\f\v`]+|\\\r?\n)|(?P<str>" + _STR_RX % "" + r")" + _TOK_TAIL)   # markdown: ` is inline code
_REGION_MEMO = []   # [text, {(start, end, prose): parsed region}]: every match of one text shares one reading


def _fences(text):
    """[(body start, body end, tag)] of the fenced code blocks of `text`, read once per text."""
    if _REGION_MEMO and _REGION_MEMO[0] is text and "fences" in _REGION_MEMO[1]:
        return _REGION_MEMO[1]["fences"]
    out, open_ = [], None
    for m in _FENCE_LINE.finditer(text):
        if open_ is None:
            open_ = (min(len(text), m.end() + 1), m.group(2).lower(), m.group(1)[0], len(m.group(1)))
        elif m.group(1)[0] == open_[2] and len(m.group(1)) >= open_[3] and m.group(0).strip() == m.group(1):
            out.append((open_[0], m.start(), open_[1]))
            open_ = None
    if open_:
        out.append((open_[0], len(text), open_[1]))
    memo = _memo(text)
    memo["fences"], memo["fence_starts"] = out, [f[0] for f in out]
    return out


def _memo(text):
    if not (_REGION_MEMO and _REGION_MEMO[0] is text):
        _REGION_MEMO[:] = [text, {}]
    return _REGION_MEMO[1]


def _region(text, start, end, prose):
    """The tokens of text[start:end]: kinds, starts, ends, `nl` (a line break before the token), the bracket each token is in
    (`parent`) and each bracket's partner (`match`), and where the reading broke (an unterminated string or comment), if it did."""
    key = (start, end, prose)
    memo = _memo(text)
    if key in memo:
        return memo[key]
    kinds, starts, ends, nl, comments, broke, pending = [], [], [], [], [], None, False
    for m in (_PROSE_TOK if prose else _CODE_TOK).finditer(text, start, end):
        k = m.lastgroup
        if k == "nl" or (k == "com" and "\n" in m.group(0)):
            pending = True
        if k in ("nl", "ws"):
            continue
        if k == "com":
            comments.append((m.start(), m.end()))
            continue
        body = m.group(0).lstrip("rRbBuUfF") if k == "str" else ""
        if k == "ucom" or (m.end() == end and (body[:3] in ("'''", '"""') and (len(body) < 6 or not body.endswith(body[:3]))
                                               or body[:1] == "`" and (len(body) < 2 or not body.endswith("`")))):
            broke = m.start()   # a string or comment that never ends
            break
        kinds.append(k)
        starts.append(m.start())
        ends.append(m.end())
        nl.append(pending)
        pending = False
    n, match, parent, stack = len(kinds), {}, [None] * len(kinds), []
    for i in range(n):
        parent[i] = stack[-1] if stack else None
        if kinds[i] == "open":
            stack.append(i)
        elif kinds[i] == "close":
            if stack and text[starts[stack[-1]]] + text[starts[i]] in ("()", "[]", "{}"):
                j = stack.pop()
                match[j], match[i], parent[i] = i, j, parent[j]
    memo[key] = r = {"kinds": kinds, "starts": starts, "ends": ends, "nl": nl, "parent": parent, "match": match, "broke": broke,
                     "comments": comments}
    return r


# Batch 6 (KL1, KL2): what a region binds. A name's identity (an HTTP client, an empty map) comes only from how the region binds
# it, never from the name itself (cfg_client is not a client); a name bound twice is whatever the second binding made it.
_BIND_OPS = frozenset(("+", "-", "*", "/", "%", "|", "&", "^", ":"))
_SELF_WRITES = frozenset(("globals", "locals", "vars", "exec", "eval", "setattr", "__dict__", "__setitem__"))


def _region_names(text, start, end, prose):
    """{"binds": {name or a.b chain: [(first token, kind, token after "=")]}, "uses": {plain name: [token]}, "self_writes": bool}
    for the region's tokens, read once per region (one pass). kind: "=" (also +=, :=), "as", "for" or "other" (global, del)."""
    memo = _memo(text)
    k = ("names", start, end, prose)
    if k in memo:
        return memo[k]
    r = _region(text, start, end, prose)
    kinds, starts, ends, parent = r["kinds"], r["starts"], r["ends"], r["parent"]
    n = len(kinds)
    tok = lambda i: text[starts[i]:ends[i]] if 0 <= i < n else None
    binds, uses, writes = {}, {}, False
    for i in range(n):
        if kinds[i] != "name":
            continue
        t = tok(i)
        writes = writes or t in _SELF_WRITES
        if tok(i - 1) != ".":
            uses.setdefault(t, []).append(i)
        nx = tok(i + 1)
        if nx == "." or (i + 1 < n and kinds[i + 1] == "open"):
            continue   # not the end of a chain, or a call or an index
        c = i
        while c >= 2 and tok(c - 1) == "." and kinds[c - 2] == "name":
            c -= 2
        if parent[c] is not None and text[starts[parent[c]]] == "(":
            continue   # a keyword argument or a parameter's default
        chain = ".".join(tok(j) for j in range(c, i + 1, 2))
        prev = tok(c - 1)
        if nx == "=" or (nx in _BIND_OPS and tok(i + 2) == "=" and ends[i + 1] == starts[i + 2]):
            binds.setdefault(chain, []).append((c, "=", i + 2 if nx == "=" else i + 3))
        elif prev in ("as", "for"):
            binds.setdefault(chain, []).append((c, prev, None))
        elif prev in ("global", "nonlocal", "del"):
            binds.setdefault(chain, []).append((c, "other", None))
    memo[k] = out = {"binds": binds, "uses": uses, "self_writes": writes}
    return out


# The modules whose own get is an HTTP GET, and the calls that make an HTTP client (KL2)
_CLIENT_MODULES = frozenset(("requests", "httpx", "aiohttp", "urllib3", "http", "https", "axios", "got", "ky", "needle", "superagent",
                             "$", "jquery", "$http"))
_CLIENT_MAKERS = frozenset(("requests.Session", "requests.session", "httpx.Client", "httpx.AsyncClient", "aiohttp.ClientSession",
                            "urllib3.PoolManager", "axios.create"))
_CHOICE_BEFORE = frozenset(("or", "and", "else", "||", "&&", "?"))   # one side of a choice made at run time (KL1)
_CHOICE_AFTER = frozenset(("or", "and", "if", "||", "&&", "?"))
_USES_FOLLOWED = 50   # a destination name used more often than this is in doubt: never a chat webhook


# Codex round 2 (H4-H6): code that writes names, modules or builtins at run time, so no name in the document is certain
_REBINDS_ANY = re.compile(r"\b(?:exec|eval|globals|locals|vars|setattr|delattr|builtins|__builtins__|__import__|importlib|__dict__|"
                          r"__setattr__|__main__|__class__|__globals__|f_globals|f_locals|monkeypatch|globalThis|Reflect|defineProperty|"
                          r"__proto__|prototype)\b|\bimport\s*\*|\bsys\s*\.\s*modules\b")
_GLOBAL_INDEX = re.compile(r"\b(?:window|global|globalThis|self|this)\s*\[")   # window['config'], a map written under a string
_DEFINERS = frozenset(("def", "class", "function"))
_MAP_INTERVENES = frozenset(("import", "from", "await", "yield", "del", "exec", "with", "global", "nonlocal", "lambda", "def", "class",
                        "function", "new", "async", "raise", "assert", "return", "require"))   # between a map's binding and its lookup
_FROM_MODULES = frozenset(("requests", "httpx", "aiohttp", "urllib3", "urllib.request"))   # from M import post: M's own
_SHELL_SHADOW = re.compile(r"(?m)\bfunction\s+(?:curl|wget|https?|xh)\b|(?<![\w-])(?:curl|wget|https?|xh)\s*\(\s*\)|\balias\s+(?:curl|wget|https?|xh)="
                           r"|\bPATH\s*\+?=|\bhash\s+-p\b|\bsys\s*\.\s*path\b|\b(?:PYTHONPATH|NODE_PATH|NODE_OPTIONS)\b")   # another curl, requests
# What a comment may hide: the reader takes // for a comment, and Python for floor division (x = 1 // 1; send = evil); # starts
# a JS private field (#send = …). Its names are counted, and these are loose.
_COMMENT_BINDS = re.compile(r"(?<![\w$])([A-Za-z_$][\w$]*)\s*(?:[-+*/%|&^:]?=)(?!=)"
                            r"|\b(?:def|function|class|import|as|for|global)\s+([A-Za-z_$][\w$]*)")
_COMMENT_WORD = re.compile(r"[A-Za-z_$][\w$]*")


def _builtin_name(text, name):
    """Batch 6 PR3, Codex round 1 (10): `name` (dict, str) is certainly the builtin in this document: it appears exactly once in
    the whole text (the call itself: nothing anywhere binds, imports or shadows it), and nothing in it writes names or builtins
    at run time (exec, globals, setattr, builtins, `import *`). Round 2 (H6): and no identifier in its code is anything but
    ASCII (Python reads ｄｉｃｔ as dict). Read once per text and name."""
    memo = _memo(text)
    k = ("builtin", name)
    if k not in memo:
        memo[k] = (len(re.findall(r"(?<![\w$.])" + name + r"(?![\w$])", text)) == 1 and not _REBINDS_ANY.search(text)
                   and not _code_facts(text)["unsure"])
    return memo[k]


def _code_blocks(text):
    """[(start, end)] of the text's code: its fenced blocks, or the whole text when it has none (a .py or .js file, a bare
    snippet). Prose outside fences is not code (Codex #15 medium 5)."""
    fences = _fences(text)
    return [(f[0], f[1]) for f in fences] if fences else [(0, len(text))]


def _code_facts(text):
    """Batch 6 PR3, Codex round 2 (H4-H6): what every code block of the document (_code_blocks, read as code) says about names,
    read once per text (one pass over each block's tokens):
    "unsure": no destination in the document can be proven: an identifier (or anything outside a string or comment) that isn't
      ASCII (Python reads ｄｉｃｔ as dict, ｓｅｎｄ as send), a block whose reading broke before non-ASCII text, code that writes
      names, modules or builtins at run time (_REBINDS_ANY), or a shell function or alias named curl, wget, http or xh;
    "loose": {name: how often it appears other than as a call or the head of an a.b chain}: bound, defined, assigned, passed,
      imported (`import requests` at a statement's start, `from requests import post`, `const axios = require('axios')` and
      `import axios from 'axios'` for an HTTP module of its own name are the module's own, not loose);
    "count": {name: how often it appears at all}; "call_blocks": the start of each block that calls anything;
    "index": a block writes under a string key of window, global, self or this."""
    memo = _memo(text)
    if "code_facts" in memo:
        return memo["code_facts"]
    unsure, loose, count, call_blocks, index = False, {}, {}, [], False
    for s, e in _code_blocks(text):
        r = _region(text, s, e, False)
        kinds, starts, ends, nl, match = r["kinds"], r["starts"], r["ends"], r["nl"], r["match"]
        n = len(kinds)
        tok = lambda i: text[starts[i]:ends[i]] if 0 <= i < n else None
        stmt = lambda i: i == 0 or nl[i] or tok(i - 1) == ";"   # token i starts a statement
        if r["broke"] is not None and not text[r["broke"]:e].isascii():
            unsure = True
        if _REBINDS_ANY.search(text, s, e) or _SHELL_SHADOW.search(text, s, e):
            unsure = True
        index = index or bool(_GLOBAL_INDEX.search(text, s, e))
        own, calls = set(), False   # the names of an import of the module's own
        for cs, ce in r["comments"]:   # what may not be a comment (_COMMENT_BINDS): its words count, its bindings are loose
            body = text[cs:ce]
            if not body.startswith("#") and not body.isascii():
                unsure = True   # a // or /* */ "comment" may be Python code with a name that isn't ASCII
            for w in _COMMENT_WORD.findall(body):
                count[w] = count.get(w, 0) + 1
            for x in _COMMENT_BINDS.finditer(body):
                w = x.group(1) or x.group(2)
                loose[w] = loose.get(w, 0) + 1
            calls = calls or bool(re.search(r"[\w$)\]]\s*\(", body))
        for i in range(n):
            t = tok(i)
            if kinds[i] != "str" and not t.isascii():
                unsure = True
            if kinds[i] != "name":
                continue
            count[t] = count.get(t, 0) + 1
            pv, nx = tok(i - 1), tok(i + 1)
            if t in ("from", "import") and stmt(i):   # the module's own names: import a.b, from a.b import c, d
                j, mod = i + 1, []
                while j < n and not nl[j] and (kinds[j] == "name" if len(mod) % 2 == 0 else tok(j) == "."):
                    mod.append(j)
                    j += 1
                if mod and kinds[mod[-1]] == "name" and tok(mod[-1]) != "import":
                    if t == "import" and tok(j) != "from":
                        own.update(mod)   # import requests, import urllib.request (then as x, or the line's end)
                    elif t == "from" and tok(j) == "import":
                        own.update(mod)   # from M: binds nothing itself
                        if "".join(tok(x) for x in mod) in _FROM_MODULES:
                            j += 1
                            while j < n and kinds[j] == "name" and not nl[j] and tok(j + 1) != "as":
                                own.add(j)   # from requests import post, get: requests' own
                                if tok(j + 1) != "," or (j + 2 < n and nl[j + 2]):
                                    break
                                j += 2
            if i in own:
                continue
            if (t in _CLIENT_MODULES and ((pv == "import" and stmt(i - 1) and nx == "from" and tok(i + 2) is not None
                                          and tok(i + 2)[1:-1] == t and kinds[i + 2] == "str")
                                         or (pv in ("const", "let", "var") and nx == "=" and tok(i + 2) == "require"
                                             and tok(i + 3) == "(" and tok(i + 4) is not None and tok(i + 4)[1:-1] == t
                                             and tok(i + 5) == ")"))):
                continue   # import axios from 'axios', const axios = require('axios')
            if nx == "(" and i + 1 < n and kinds[i + 1] == "open":
                calls = True
            if (pv not in _DEFINERS and i + 1 < n and nx in ("(", ".") and kinds[i + 1] in ("open", "op")
                    and not (nx == "(" and tok(match.get(i + 1, n) + 1) == "{")):
                continue   # a call, or the head (or a link) of an a.b chain; not a JS method's definition (post(url) { … })
            loose[t] = loose.get(t, 0) + 1
        if calls:
            call_blocks.append(s)
    memo["code_facts"] = out = {"unsure": unsure, "loose": loose, "count": count, "call_blocks": call_blocks, "index": index}
    return out


def _code_standalone(text, a, b, start, end, prose, natural=True):
    """The code reading (see above) of the literal text[a:b] in the region text[start:end]."""
    import bisect
    r = _region(text, start, end, prose)
    kinds, starts, ends, nl, parent, match = r["kinds"], r["starts"], r["ends"], r["nl"], r["parent"], r["match"]
    if r["broke"] is not None and r["broke"] < b:
        return False   # an unterminated string or comment before the end of the URL: nothing is certain
    facts = _code_facts(text)
    if facts["unsure"]:
        return False   # Codex round 2 (H6): a name that isn't ASCII, or code that rewrites names at run time: no name is certain
    c = bisect.bisect_right(r["comments"], (a, len(text))) - 1
    if c >= 0 and r["comments"][c][1] > a:   # in a comment: nothing there runs, but its words are read as prose
        ca, cb = r["comments"][c]
        return cb >= b and _code_standalone(text, a, b, ca + (1 if text[ca] == "#" else 2), cb - (2 if text.startswith("/*", ca) else 0), True)
    li = bisect.bisect_right(starts, a) - 1
    if li < 0 or ends[li] <= a:
        return False
    if kinds[li] != "str" or ends[li] != b or not re.fullmatch(r"[rRbBuU]{0,2}", text[starts[li]:a]):
        return False   # the URL is inside another token (an f-string, a comment the tokenizer saw, a longer literal)
    n = len(kinds)
    tok = lambda i: text[starts[i]:ends[i]] if 0 <= i < n else None
    first = lambda i: nl[i] or (i == 0 and natural)

    def edge_line(i, step):
        """Prose: the nearest non-blank line before (step -1) or after (+1) the region continues an expression with the URL."""
        if not prose:
            return False
        if step < 0:
            j = text.rfind("\n", 0, start)
            while j > 0:
                k = text.rfind("\n", 0, j)
                line = text[k + 1:j].strip()
                if line:
                    return line[-1] in "'\"`+%([{,=\\*"
                j = k
            return False
        j = text.find("\n", end)
        while j != -1:
            k = text.find("\n", j + 1)
            line = text[j + 1:k if k != -1 else len(text)].strip()
            if line:
                return line[0] in "'\"`+%.[(*"
            j = k
        return False
    def destination(o, p, pt, bt, keys):
        """PR A, Codex round 1 (1): the operand ending at p + 1 is where the call opened at o sends: its first argument, a url=
        keyword, or request's second after an HTTP method; reached through dict values only under a url key."""
        if any(k.strip("'\"`") not in _URL_KEYS for k in keys):
            return False
        if p == o:
            return True
        if pt == "=" and p - 1 > o and kinds[p - 1] == "name" and tok(p - 1) in _URL_KEYS and (p - 2 == o or tok(p - 2) == ","):
            return True
        return (bt == "request" and p == o + 2 and pt == "," and kinds[o + 1] == "str"
                and re.fullmatch(r"[rRbBuU]{0,2}(['\"`])(?i:get|post|put|patch|delete|head|options)\1", tok(o + 1) or "") is not None)

    def args(o):
        """The arguments of the call opened at o: [(first token, last token, keyword or None)]."""
        out, s, i = [], o + 1, o + 1
        while i < match[o]:
            if kinds[i] == "op" and tok(i) == ",":
                out.append((s, i - 1))
                s = i + 1
            elif kinds[i] == "open" and i in match:
                i = match[i]
            i += 1
        if s < match[o]:
            out.append((s, match[o] - 1))
        return [(s, e, tok(s) if e > s and kinds[s] == "name" and tok(s + 1) == "=" else None) for s, e in out]

    def calls_out(c):
        """The call whose name starts at c is an argument of a call that sends."""
        o = parent[c]
        if o is None or text[starts[o]] != "(" or o < 1 or kinds[o - 1] != "name":
            return False
        b = o - 1
        while b >= 2 and tok(b - 1) == "." and kinds[b - 2] == "name":
            b -= 2
        return tok(o - 1) in _SENDERS or tok(b) == "axios"

    names = lambda: _region_names(text, start, end, prose)

    def maker(i):
        """The a.b chain starting at token i is a call that makes an HTTP client (_CLIENT_MAKERS)."""
        j = i
        while j + 2 < n and tok(j + 1) == "." and kinds[j + 2] == "name":
            j += 2
        return (kinds[i] == "name" and j + 1 < n and kinds[j + 1] == "open" and text[starts[j + 1]] == "("
                and ".".join(tok(x) for x in range(i, j + 1, 2)) in _CLIENT_MAKERS)

    def http_client(c, o):
        """Batch 6 (KL2): the receiver of the call opened at o (tokens c..o-3, before .get) is an HTTP client: a module whose get
        is a GET (requests, httpx, https, axios, …), or a name (self.x too) the region binds exactly once, to a call that makes
        one (x = requests.Session(), with httpx.Client() as x). Never from the name: cfg_client and session are anything."""
        chain = ".".join(tok(x) for x in range(c, o - 2, 2))
        if o - 3 == c and chain.lower() in _CLIENT_MODULES:
            return True
        b = names()["binds"].get(chain, [])
        if len(b) != 1:
            return False
        first, kind, v = b[0]
        if kind == "=":
            return v is not None and v < n and maker(v)
        if kind == "as" and first >= 2 and kinds[first - 2] == "close" and first - 2 in match:
            m = match[first - 2]
            s = m - 1
            while s >= 2 and tok(s - 1) == "." and kinds[s - 2] == "name":
                s -= 2
            return s >= 0 and maker(s)
        return False

    def resolved(c, e):
        """Batch 6 PR3, Codex round 2 (H4): the sender call's name, tokens c..e (send, requests.post, s.post), is what it says. Its
        method or function name is never loose anywhere in the document's code (a def send(url), a post = …, a JS post(u) { … }
        or an import of it from anywhere but the HTTP module itself makes it a helper); its receiver is a module never loose
        (requests, `import requests` aside) or a name the region binds once to an HTTP client (http_client) and nothing else
        binds; each other link of the chain is never loose either."""
        lo_ = facts["loose"]
        if lo_.get(tok(e), 0):
            return False
        if e == c:
            return True
        if e - 2 == c and tok(c).lower() in _CLIENT_MODULES:
            return not lo_.get(tok(c), 0)   # requests.post, axios.post (const axios = require('axios') is its own)
        chain = ".".join(tok(x) for x in range(c, e - 1, 2))
        b = names()["binds"].get(chain, [])
        if len(b) == 1 and http_client(c, e + 1):
            return lo_.get(tok(e - 2), 0) == 1   # x = requests.Session(): its one binding, and no other
        return all(not lo_.get(tok(x), 0) for x in range(c, e - 1, 2))

    def empty_map(o, c, lo):
        """Batch 6 (KL1): the call opened at o is NAME.get(key, default) with the URL as that default, and NAME is proven an empty
        map: the region binds it exactly once, before this, to {} or dict() as a whole statement, never uses it anywhere else (no
        write, no alias, not passed to anything), and nothing in the region writes names at run time (exec, globals, setattr).
        Only then is the default certainly what the lookup returns. Codex round 2 (H5): nor does any other code block mention
        NAME (its two uses are the whole document's) or call anything (a helper defined there runs here), nothing writes under a
        string key of window, global, self or this, and nothing runs between the binding and the lookup (no call that completes
        there, no import, no operator: only names, literals, commas and the calls the lookup is an argument of)."""
        if o - 3 != c or tok(o - 1) != "get" or kinds[c] != "name":
            return False
        al = args(o)
        if len(al) != 2 or any(x[2] for x in al) or not al[1][0] <= lo <= al[1][1]:
            return False
        nm = names()
        b = nm["binds"].get(tok(c), [])
        if nm["self_writes"] or len(b) != 1 or len(nm["uses"].get(tok(c), [])) != 2:
            return False
        if facts["count"].get(tok(c), 0) != 2 or facts["index"]:
            return False
        if any(s != start for s in facts["call_blocks"]):
            return False   # another block (or, for a line of prose, any block) calls something
        first, kind, v = b[0]
        if kind != "=" or first >= c or v is None or v >= n or tok(first + 1) != "=":
            return False
        if tok(v) == "{" and match.get(v) == v + 1:
            last = v + 1
        elif tok(v) == "dict" and tok(v + 1) == "(" and match.get(v + 1) == v + 2 and _builtin_name(text, "dict"):
            last = v + 2   # PR3, Codex round 1 (10): only the builtin dict (`dict = lambda: json.load(…)` makes it anything)
        else:
            return False
        k = bisect.bisect_left(r["comments"], (ends[last], 0))
        if k < len(r["comments"]) and r["comments"][k][0] < starts[c]:
            return False   # a comment between them (x = 1 // 1; configure() is Python code)
        for j in range(last + 1, c):
            if kinds[j] == "open" and match.get(j, -1) > c:
                continue   # a call or bracket the lookup is inside
            if kinds[j] in ("str", "num") or tok(j) in (".", ",", "=", ";"):
                continue
            if kinds[j] == "name" and tok(j) not in _MAP_INTERVENES:
                continue
            return False   # something that runs between the binding and the lookup (configure(), import x, a + b)
        return ((first == 0 or nl[first] or tok(first - 1) in (";", "const", "let", "var"))
                and (last + 1 >= n or nl[last + 1] or tok(last + 1) == ";"))

    def settled(a, lo):
        """Batch 6 (KL1): when the statement starting at token a assigns the URL to a name, that name is bound only there, and
        no use of it is one side of a choice (or, ||, a conditional) or a lookup's argument (os.environ.get('HOOK', WEBHOOK)):
        each would let something else be chosen at run time."""
        k = a + 1 if tok(a) in ("const", "let", "var") else a
        e = k
        while e + 2 < n and tok(e + 1) == "." and kinds[e + 2] == "name":
            e += 2
        if kinds[k] != "name" or tok(e + 1) != "=" or e + 1 >= lo:
            return True   # not an assignment of the URL to a name
        chain = ".".join(tok(x) for x in range(k, e + 1, 2))
        nm = names()
        if len(nm["binds"].get(chain, [])) > 1:
            return False
        uses = [u for u in nm["uses"].get(tok(k), []) if u != k] if e == k else []
        if len(uses) > _USES_FOLLOWED:
            return False
        for u in uses:
            if tok(u - 1) in _CHOICE_BEFORE or tok(u + 1) in _CHOICE_AFTER:
                return False
            o2 = parent[u]
            if o2 is not None and o2 >= 1 and text[starts[o2]] == "(" and kinds[o2 - 1] == "name" and o2 in match:
                c2 = o2 - 1
                while c2 >= 2 and tok(c2 - 1) == "." and kinds[c2 - 2] == "name":
                    c2 -= 2
                role = lookup(o2, c2, tok(o2 - 1), u)
                if role and not (role == "default" and empty_map(o2, c2, u)):
                    return False
        return True

    def lookup(o, c, bt, lo):
        """PR A, Codex round 2 (1, 7): None when the call at o (its name starting at c) sends or wraps; else the role of the
        argument at lo in the lookup: "default" (a default= or fallback= keyword, or the last positional argument after the key)
        or "key". `get` is both a lookup and an HTTP GET: an HTTP GET on an HTTP client (_HTTP_CLIENT) or bare with the URL
        first, unless another sender sends to what it returns (round 3; it was read from its arguments before)."""
        al = args(o)
        pos = [a for a in al if a[2] is None]
        mine = next((a for a in al if a[0] <= lo <= a[1]), None)
        if mine is None:
            return None
        if bt == "get":
            # PR A, Codex round 3 (1, 5): `get` is an HTTP GET only on an HTTP client (requests.get, session.get, https.get,
            # self.client.get, …, whatever its other arguments: params, a named callback) or as a bare get(url, …) with the URL
            # first; on anything else (config.get, os.environ.get, cfg.get) it is a lookup, its arguments keys and a default.
            # Batch 6 (KL2): a client is a module's own (requests.get) or a name the region binds once to one (http_client)
            http = http_client(c, o) if o - 3 >= c else bool(pos) and mine is pos[0]
            if http and not calls_out(c):
                return None
        elif bt not in _LOOKUPS:
            return None
        if mine[2] in _LOOKUP_DEFAULTS:
            return "default"
        first = 1 if bt == "getattr" else 0   # getattr(object, name, default)
        if mine[2] is None and pos.index(mine) > first and mine is pos[-1]:
            return "default"
        return "key"

    def statement(lo, hi):
        """The tokens of the statement the operand lo..hi is in: (first, last)."""
        a = lo
        while parent[a] is not None:
            a = parent[a]
        b = match.get(a, a) if kinds[a] == "open" else a
        b = max(b, hi)
        cont = lambda j: (kinds[j] == "op" and tok(j) != ";") or (kinds[j - 1] == "op" and tok(j - 1) != ";")
        while a > 0 and tok(a - 1) != ";" and not (nl[a] and not cont(a)):
            a -= 1
            if kinds[a] == "close" and a in match:
                a = match[a]
        while b + 1 < n and tok(b + 1) != ";" and not (nl[b + 1] and not cont(b + 1)):
            b += 1
            if kinds[b] == "open" and b in match:
                b = match[b]
        return a, b

    def quiet():
        """PR A, Codex round 2 (1): a destination that is only maybe the chat webhook (a lookup's default, a helper's argument
        until batch 6 PR3 round 1, one side of an or, an element of a dict or list) can't be a way to send something somewhere else. Round 3 (1): what
        overrides it may be anywhere in the code (config = {'hook': 'https://collector…'} two lines up), so nothing in the region
        is another URL (_other_urls), and no string or name in it is a credential's. Batch 6 (#15 medium 5): the region of the
        send (its code block, or the whole file when it has none), not the whole text: a docs link in the prose around a code
        block is not where the code sends. PR3, Codex round 1 (9): but every code block is (one block may define what another
        calls), so the URLs counted are those of the region and of every code block in the text (_code_blocks)."""
        memo = _memo(text)
        ck = ("cred", start, end, prose)
        if ck not in memo:
            memo[ck] = [i for i in range(n) if kinds[i] in ("str", "name") and _CRED_WORD.search(tok(i))]
        if "code_urls" not in memo:
            import bisect
            blocks = _code_blocks(text)
            bs = [x[0] for x in blocks]
            memo["code_urls"] = [s for s in _other_urls(text) if (lambda k: k >= 0 and s < blocks[k][1])(bisect.bisect_right(bs, s) - 1)]
        return (all(i == li for i in memo[ck]) and all(a <= s < b for s in _other_urls(text) if start <= s < end)
                and all(a <= s < b for s in memo["code_urls"]))

    def sent(lo, hi):
        """The call text[lo..hi] sends to the URL: true when nothing makes its result one piece of something else, up to the
        statement (its result used, .json() or [0], is fine; an operator or a literal beside it, a join, or another sender that
        sends somewhere else, isn't)."""
        used = False
        for _ in range(n + 1):
            while True:   # its result used: .name, a call, an index
                q = hi + 1
                if q + 1 < n and tok(q) == "." and kinds[q + 1] == "name":
                    hi, used = q + 1, True
                elif q < n and kinds[q] == "open" and text[starts[q]] in "([" and q in match:
                    hi, used = match[q], True
                else:
                    break
            p, q = lo - 1, hi + 1
            pk, pt = (kinds[p], tok(p)) if p >= 0 else (None, None)
            qk, qt = (kinds[q], tok(q)) if q < n else (None, None)
            if pk in ("str", "bad") or (pt in ("+", "%") or (pt == "*" and not first(p))):
                return False
            if qk in ("str", "bad") or qt in ("+", "%", "*"):
                return False
            if pk is None and edge_line(lo, -1) or qk is None and edge_line(hi, 1):
                return False
            o = parent[lo]
            if o is None:
                return not (qk == "close" or (qk is None and r["broke"] is not None))
            if o not in match:
                return False
            ob, bb = text[starts[o]], o - 1
            bk, bt = (kinds[bb], tok(bb)) if bb >= 0 else (None, None)
            if ob == "(" and (bk == "name" or bt in (")", "]")):
                if bk != "name":
                    return False
                c = bb
                while c >= 2 and tok(c - 1) == "." and kinds[c - 2] == "name":
                    c -= 2
                if bt in _JOINERS or bt.startswith("concat"):
                    return False
                if (bt in _SENDERS or tok(c) == "axios") and (used or not destination(o, p, pt, bt, ())):
                    return False   # inside another call that sends: urlopen(Request(url)) only
                lo, hi = c, match[o]
                continue
            if ob == "[" and (bk in ("name", "str") or bt in (")", "]", "}")):
                return False
            lo, hi = o, match[o]
        return False

    lo = hi = li
    keys = []   # the dict keys it is the value of, on the way up
    maybe = False   # PR A, Codex round 2 (1): only maybe where it goes (a lookup's default, one of a call's arguments, round 3: a collection's element)
    for _ in range(n + 1):
        p, q = lo - 1, hi + 1
        pk, pt = (kinds[p], tok(p)) if p >= 0 else (None, None)
        qk, qt = (kinds[q], tok(q)) if q < n else (None, None)
        if pk in ("str", "bad") or (pt in ("+", "%") or (pt == "*" and not first(p))):
            return False   # a literal or an operator in front of it: one piece of a bigger string
        if qk in ("str", "bad") or qt in ("+", "%", "*", ".", "[", "("):
            return False   # a literal, an operator, an index, an attribute or a call after it
        if pk is None and edge_line(lo, -1) or qk is None and edge_line(hi, 1):
            return False
        o = parent[lo]
        if o is None:   # at the top of the region
            if qk == "close" or (qk is None and r["broke"] is not None):
                return False   # it closes a bracket opened before the region, or the reading broke after it
            if not prose:   # code: one side of an or, an and or a conditional (prose reads these words as English)
                a, b = statement(lo, hi)
                if any(parent[i] is None and tok(i) in _BOOL_OPS for i in range(a, b + 1)):
                    return False   # batch 6 (KL1): another value may be chosen at run time (os.environ.get('HOOK') or URL)
                if not settled(a, lo):
                    return False   # batch 6 (KL1): the name it is kept under is bound again, or chosen between at run time
            if pk is None:
                return natural and (not maybe or quiet())
            return not (pt == "," or pk == "close" or pt == ".") and (not maybe or quiet())
        if o not in match:
            return False   # a bracket that never closes
        if not (p == o or pt in (",", ":", "=")) or not (qt == "," or q == match[o]):
            return False   # more than this operand in its argument
        ob, bb = text[starts[o]], o - 1
        bk, bt = (kinds[bb], tok(bb)) if bb >= 0 else (None, None)
        if pt == ":":
            if ob != "{":
                return False   # a slice, a lambda or an annotation
            keys.append(tok(p - 1) or "")
            maybe = True   # PR A, Codex round 3 (1): a dict's value; the code may use another one ({'hook': …, 'api': 'https://…'})
            lo, hi = o, match[o]   # a dict value: the dict is the operand now
            continue
        if pt == "=" and not (ob == "(" and p - 1 > o and kinds[p - 1] == "name" and (p - 2 == o or tok(p - 2) == ",")):
            return False
        if ob == "(" and (bk == "name" or bt in (")", "]")):
            if bk != "name":
                return False   # a call on the result of an expression
            c = bb
            while c >= 2 and tok(c - 1) == "." and kinds[c - 2] == "name":
                c -= 2
            if bt in _JOINERS or bt.startswith("concat"):
                return False
            role = lookup(o, c, bt, lo)
            if role == "key" or (role and keys):
                return False   # PR A, Codex round 2 (1): a lookup's key: what is found under it is where it goes, not this URL
            memo = _memo(text)
            if role and "configparser" not in memo:   # batch 6: once per text (it was a search of the whole text per lookup)
                memo["configparser"] = bool(_CONFIG_PARSER.search(text))
            if role and memo["configparser"]:
                return False   # PR A, Codex round 3 (1): a ConfigParser reads its options from a file (cfg.get(section, option))
            if role and not empty_map(o, c, lo):
                return False   # batch 6 (KL1): the environment, a file, getattr, setdefault, pop or an unknown map may hold the key
            if role:
                # PR A, Codex round 2 (7): a lookup's default is what it returns when the key isn't there, followed outward to the
                # sender like any operand. Round 3 (1): only maybe (the key may be there: config = {'hook': …} above), whatever
                # the key is. Batch 6 (KL1): only from a map proven empty (empty_map), and still only maybe
                maybe = True
                lo, hi = c, match[o]
                continue
            if bt in _SENDERS or tok(c) == "axios":
                # PR A, Codex round 1 (1): a call named like a sender sends to one argument (config.get('hook', URL) is a lookup's
                # default); the URL must be that argument, and the call itself must be the whole statement's sending. Codex
                # round 2 (H4): and its names are what they say (resolved): a send() defined here is a helper
                return resolved(c, bb) and destination(o, p, pt, bt, keys) and sent(c, match[o]) and (not maybe or quiet())
            if not (bt == "str" and c == bb and len(args(o)) == 1 and _builtin_name(text, "str")):
                # PR A, Codex round 2 (1) read a helper's argument as maybe the destination. Batch 6 PR3, Codex round 1 (9): a
                # helper (defined in another block, imported, not defined at all, or even defined here: its body may read the
                # environment) may send to or return any destination, so it never proves one
                return False
            lo, hi = c, match[o]   # the builtin str() of a string is that string: the call is the operand now
            continue
        if ob == "[" and (bk in ("name", "str") or bt in (")", "]", "}")):
            return False   # a subscript, not a list
        # PR A, Codex round 3 (1): one element of a list, a set or a tuple is only maybe where the code sends; ( URL ) is the URL
        maybe = maybe or ob in "[{" or pt == "," or qt == ","
        lo, hi = o, match[o]   # a group, a tuple, a list or a set: the whole is the operand now
    return False


def _standalone(text, a, b, quoted):
    """True when text[a:b], a URL literal (with its quotes) or a whole URL argument, is the complete value: nothing can come
    before it or after it in the same string expression. Any doubt is False. Batch 5 (c1): read as shell words on a shell line,
    else (quoted) as code; an unquoted URL off a shell line keeps the neighbour test below."""
    import bisect
    fences = _fences(text)
    k = bisect.bisect_right(_memo(text)["fence_starts"], a) - 1
    fence = fences[k] if k >= 0 and fences[k][0] <= a < fences[k][1] else None
    floor = max(0, a - 4096, fence[0] if fence else 0)
    ls = text.rfind("\n", 0, a) + 1
    while ls > floor and ls >= 2 and _JOINED_LINE.search(text, text.rfind("\n", 0, ls - 1) + 1, ls - 1):
        ls = text.rfind("\n", 0, ls - 1) + 1   # the line before ends in a join: the logical line starts there
    tick = text.rfind("`", ls, a)
    cs = tick + 1 if tick != -1 and not (fence and fence[2] in _SHELL_FENCES) else ls
    if (fence and fence[2] in _SHELL_FENCES) or _SHELL_TOOL.match(text, cs) or _SHELL_TOOL.match(text, ls):
        if _code_facts(text)["unsure"]:
            return False   # PR3, Codex round 2 (H4, H6): a curl function or alias, a name that isn't ASCII: nothing is certain
        inline = cs != ls and _SHELL_TOOL.match(text, cs)
        for wa, wb, _ in _logical_words(text, cs if inline else ls):
            if wb > a:   # `inline code` ends at its closing backtick
                return wa == a and (wb == b or (inline and wb == b + 1 and text[b] == "`"))
        return False
    if not quoted:
        return _standalone_plain(text, a, b, quoted)
    if fence:
        return _code_standalone(text, a, b, fence[0], fence[1], False)
    if not fences:
        return _code_standalone(text, a, b, 0, len(text), False)
    le = text.find("\n", a)
    return _code_standalone(text, a, b, text.rfind("\n", 0, a) + 1, len(text) if le == -1 else le, True)   # markdown prose: its line


def _standalone_plain(text, a, b, quoted):
    """Before batch 5 (and still for an unquoted URL off a shell line): one character on each side, past spaces, line breaks and
    backslashes. Any doubt is False."""
    j, stop = a - 1, max(0, a - 4096)
    while j >= stop and text[j] in _SKIP:
        j -= 1
    p = text[j] if j >= stop else " "
    if p in "+%" or (quoted and p in "'\""):
        return False
    if p in "([{" and _JOIN_BEFORE.search(text, max(0, j - 200), j + 1):
        return False
    if p in ",:":   # one item among others: is it inside a join, a format or a % ?
        w = text[max(0, j - 512):j]
        w = w[max(w.rfind("\n\n"), w.rfind("```")) + 1:]
        if _JOIN_NEAR.search(w):
            return False
    k, n = b, len(text)
    while k < min(n, b + 4096) and text[k] in _SKIP:
        k += 1
    nx = text[k] if k < n else " "
    if nx in "+%" or (quoted and (nx in "'\"" or re.match(r"\.\s*[A-Za-z_]", text[k:k + 64]))):
        return False
    return True


def chat_webhook(text, m):
    """True when the match is the host and path of a real chat webhook URL (see CHAT_HOOKS): the host right after the scheme
    of a URL that is a whole argument (url_arg) and the whole value, not one piece of a string expression (_standalone).
    Any doubt is False."""
    import urllib.parse
    st = m.start()
    sch = re.search(r"(?i)\bhttps?://$", text[max(0, st - 9):st])
    s = st - len(sch.group(0)) if sch else st   # no scheme: the match must start the word (xhooks.slack.com is someone else's)
    end = url_arg(text, s)
    if end is None:
        return False
    o = text[s - 1] if s else " "
    quoted = o in "'\"" and text[end:end + 1] == o
    a = s - 1 if quoted or o in "([{<`" else s
    b = end + 1 if quoted or (end < len(text) and text[end] in ")]}>`") else end
    if not _standalone(text, a, b, quoted):
        return False
    url = text[s:end] if sch else "https://" + text[s:end]
    try:
        u = urllib.parse.urlsplit(url)
        port = u.port
    except ValueError:
        return False
    host = (u.hostname or "").lower()
    if port is not None or u.netloc.lower() != host:   # a user@, a password or a port in front of the host
        return False
    return any(h.fullmatch(host) and p.match(u.path) for h, p in CHAT_HOOKS)


REF_RULES = ("WT-T001", "WT-T002", "WT-T004", "WT-T005", "WT-T006", "WT-T007", "WT-T008", "WT-T018")
REF_WORDS = re.compile(r"(?i)((prompt[- ]injection|injection|attack|dangerous[- ]code)\s+(patterns?|examples?|signatures?|detection|techniques?)"
                       r"|\bevil\.com\b|\battacker\b|detection\s+rules?|red[- ]team)")


def attack_reference(text, rules, where=""):
    """A supporting file (never a SKILL.md, the file a Bot follows) that describes itself as documenting
    or detecting attacks. Its matches stay visible but drop to low: downgraded, never hidden."""
    if os.path.basename(re.sub(r"(:\d+)+$", "", where)) == "SKILL.md" or where in ("stdin",):   # a colon in a folder name stays
        return False
    hits = sum(len(r["rx"].findall(text)) for r in rules["rules"] if r["id"] in REF_RULES)
    return hits >= 1 and bool(REF_WORDS.search(text))


def ref_line(text, m):
    """Batch 2 (R1): in a reference file a credential read, an exfiltration host or a pipe-to-shell is lowered only when its own
    line describes an attack or is a table row. One "attacker" elsewhere in the file no longer lowers a real command."""
    a = text.rfind("\n", 0, m.start()) + 1
    b = text.find("\n", m.end())
    line = text[a:b if b != -1 else len(text)]
    return bool(REF_WORDS.search(line)) or line.lstrip().startswith("|")


def sentence_of(text, m):
    a = max(text.rfind(c, 0, m.start()) for c in ".!?\n") + 1
    ends = [i for i in (text.find(c, m.end()) for c in ".!?\n") if i != -1]
    return text[a:min(ends) if ends else len(text)]


VET_MATCH_CAP = 200_000   # matches of one rule in one file that vet looks at; past it the file is not fully checked


def scan_text(text, where, rules, kind="skill", limit=None, cut=None, stop=None):
    """Apply text rules plus document-level logic. kind: skill|reference|template|routine|description.
    Codex, batch 4 round 3 (vet): `limit` bounds the findings one file keeps, never what is looked at. Every match is still
    read; past the limit a match is kept only when it is a kind this file hasn't kept yet (rule, severity, warning or not), so
    a dangerous match after thousands of harmless ones is never lost, and labels come out as they would with all of them.
    `cut` (a list) is told when a repeat was left out. Detection has its own budget: past VET_MATCH_CAP matches of one rule
    the file is not fully read, and `stop` (a list) is told, so vet says it couldn't finish instead of giving a verdict."""
    out, kinds = [], set()
    guarded = set(rules.get("guarded_rules", []))
    is_ref = attack_reference(text, rules, where)
    if is_ref:
        out.append(finding("WT-T001r", "Describes injection patterns (reference or detector)", "info", ["AST05"], where,
                           "pattern list", "No action. Listed so you know this file contains attack examples."))
    for rule in rules["rules"]:
        # Vendor/platform: critical rules, hidden Unicode, and high/critical behavior (credential read, send-out, pipe).
        # High wording and medium behavior (e.g. eval) stay off so fiction and noise in shipped plugins do not pile up;
        # a built-in that turns malicious still trips T004/T017 (Claude v0.7.1 F4).
        # Codex, batch 4 round 2: WT-T018 too. A real chat webhook is no longer the critical WT-T005, so it must not vanish here.
        if kind == "vendor" and rule["severity"] != "critical" and rule["id"] not in ("WT-T002", "WT-T018"):
            if not (rule["id"] in BEHAVIOR_RULES and rule["severity"] in ("critical", "high")):
                continue
        prev_end, seen = None, 0
        for m in rule["rx"].finditer(text):
            if limit is not None:
                seen += 1
                if seen > VET_MATCH_CAP:
                    if stop is not None:
                        stop.append(where)
                    break
            if rule["id"] == "WT-T018" and not chat_webhook(text, m):
                continue   # a lookalike or nested host: not a chat service's webhook (a Slack or Discord one stays T005)
            if rule["id"] == "WT-T005" and CHAT_IN_T005.fullmatch(m.group(0)) and chat_webhook(text, m):
                continue   # the owner's own chat webhook is WT-T018, not an exfiltration host
            if is_ref and rule["id"] in REF_RULES and (rule["id"] not in GUARD_CODE_RULES or ref_line(text, m)):
                if limit is not None and len(out) >= limit and (rule["id"], "ref") in kinds:
                    if cut is not None:
                        cut.append(where)
                    continue
                kinds.add((rule["id"], "ref"))
                out.append(finding(rule["id"], rule["title"] + " (in an attack-pattern reference)", "low", rule["owasp"],
                                   f"{where}:{line_of(text, m.start())}", f"U+{ord(m.group(0)):04X}" if rule["id"] == "WT-T002" else m.group(0)[:140],
                                   "Documentation or detector text. Confirm the file is what it claims to be.",
                                   shown=None if rule["id"] == "WT-T002" else mask(m.group(0)) if rule["id"] == SECRET_RULE else m.group(0)))
                if rule["id"] == "WT-T002":
                    break
                continue
            if rule["id"] == "WT-T017" and not sends_data(text[m.start():m.start() + 400]):
                continue   # look past the short regex match so -G with @ or $(...) still counts; later | tr -d stays out
            if rule["id"] == "WT-T016" and not rules["write_verbs"].search(sentence_of(text, m)):
                continue   # "failed silently", "quietly refresh the cache": quiet wording only matters next to an outward action
            if rule["id"] == SECRET_RULE and not looks_real_secret(m.group(0)):
                continue
            if rule["id"] == "WT-T003" and is_document_blob(m.group(0)):
                continue
            ev = m.group(0)
            installer = rule["id"] == "WT-T006" and known_installer(ev)
            reason = in_warning(text, m, rules, rule["id"], prev_end) if rule["id"] in guarded else ""
            if reason:
                prev_end = m.end()
            sig = ("WT-T006k" if installer else rule["id"], bool(reason))   # severity follows from these two
            if limit is not None and len(out) >= limit and sig in kinds:
                if cut is not None:
                    cut.append(where)   # a repeat of a kind already kept: read, not stored
                continue
            kinds.add(sig)
            if installer:
                f = finding("WT-T006k", "Known installer piped to shell", "medium" if kind != "vendor" else "low",
                            ["ASI05", "AST02"], f"{where}:{line_of(text, m.start())}", ev[:140],
                            "A well-known installer, but still unpinned. Prefer a package manager or a pinned, checksummed download.", shown=ev)
            else:
                if rule["id"] == SECRET_RULE:
                    ev = mask(ev)
                elif rule["id"] == "WT-T002":
                    ev = f"U+{ord(ev):04X}"
                elif rule["id"] == "WT-T003":
                    ev = ev[:24] + f"… ({len(m.group(0))} chars)"
                f = finding(rule["id"], rule["title"], rule["severity"], rule["owasp"], f"{where}:{line_of(text, m.start())}", ev, rule["fix"])
            if reason:   # batch 2 (R1): downgraded to a record, never dropped
                f = guard_record(f, reason, danger=rule["id"] in GUARD_CODE_RULES)
            out.append(f)
            if rule["id"] in ("WT-T002",):
                break  # one per file is enough for invisible chars
    writes = first_action(text, rules["write_verbs"])
    approved = has_approval(text, rules)
    if writes and not approved and kind not in ("reference", "vendor"):
        strong = first_action(text, STRONG_VERBS)
        sev = ("medium" if strong else "low") if kind == "skill" else ("high" if strong else "medium")
        writes = strong or writes
        out.append(finding("WT-T013", "External action with no approval line", sev, ["ASI02", "AST03", "LLM06"],
                           f"{where}:{line_of(text, writes.start())}", writes.group(0),
                           "Add to the description or routine: never send, post, buy, publish or delete without my approval."))
    if kind in ("routine", "template"):
        if rules["schedule_terms"].search(text) and not rules["nodata_terms"].search(text):
            out.append(finding("WT-R002", "Routine has no failure or no-data rule", "medium", ["ASI08"], where,
                               "no 'if the source is unavailable' clause",
                               "Add: if a source is unavailable, report the failure instead of using old data; if nothing changed, send nothing."))
        hf = rules["high_freq"].search(text)
        if hf:
            out.append(finding("WT-R003", "High-frequency schedule", "low", ["ASI08"], where, hf.group(0),
                               "Hourly routines burn the weekly allowance; prefer daily or an event trigger."))
    return dedupe(out)


# Batch 6 PR3 exempted a T013 action whose only recipient was the user, the owner, me or this chat ("send updates to the user").
# Codex round 2 (H3) removed it: a recipient wrapped onto the next line ("to the user⏎at partners@…") and an object read as the
# recipient ("Send user data to Mallory") passed, and no word list proves the owner is the only one told. The false alarm is
# open (docs/KNOWN-LIMITS.md, B7); PR3's other T007 exemption, "without asking the user which…", went in round 1 (7).


STRONG_VERBS = re.compile(r"(?i)\b(send|sends|sending|publish|publishes|purchase|purchases|buy|buys|pay|pays|transfer|transfers|submit|submits|deploy|deploys|invite|invites|tweet|tweets)\b")
NEGATION = re.compile(r"(?i)(don'?t|do\s+not|never|no\s+need\s+to|without|\bno)\s+$")


NEGATED_VERB = re.compile(r"(?i)\b((never|not|\w+n't|cannot|without|no\s+longer|nor)\s+(\w+\s+){0,2}|no\s+(\w+\s+)?)$")   # "No sends", "no outbound sends"
NEGATED_LIST = re.compile(r"(?i)\b(never|not|\w+n't|cannot|without|nor)\s+\w+(\s*,\s*\w+){0,6}\s*,?\s*(or|and|nor)?\s+$")
# "X posts", "the top posts", "3 invites": the thing, not the act.
NOUN_BEFORE = re.compile(r"(?i)\b(x|twitter|linkedin|blog|social|forum|reddit|outreach|draft|drafts|drafted|of|the|a|an|each|every|this|that|"
                         r"these|those|their|your|my|new|top|recent|latest|all|any|\d+)\s+$")
# "drafts Sam sends himself", "for Sam to send", "for the user to review and publish": the owner acts, not the Bot.
OWNER_AFTER = re.compile(r"(?i)^\s+(\w+\s+){0,2}(himself|herself|myself|themselves|themself)\b")
OWNER_BEFORE = re.compile(r"(?i)\bfor\s+(?!(?:the\s+)?(?:bot|agent|it|grok|assistant)\b)(the\s+)?\w+\s+to\s+(\w+\s+and\s+)?$")


AMBIGUOUS_PLURAL = ("posts", "emails", "sends", "tweets", "invites", "transfers", "deploys", "replies")   # verb or thing
AMBIGUOUS_BASE = ("post", "email", "reply", "invite", "transfer", "deploy")
OBJECT_NEXT = re.compile(r"(?i)^\s+(the|a|an|it|them|this|that|these|those|to|your|my|his|her|their|each|every|all|one|out|in|into|on|"
                         r"emails?|messages?|mail|dms?|repl(y|ies)|reports?|summar(y|ies)|digests?|invoices?|payments?|money|data|files?)\b|^\s+(?-i:[A-Z@#])\w*")
VERB_LEAD = re.compile(r"(?i)(^|\b(to|and|then|will|should|must|can|may|also|or|always|never|not|please|now|just|you|i|we|they|it|he|she|bot|"
                       r"agent|auto|do|does|\w+ly)|,)\s*$")
TEAM_ROOM = re.compile(r"(?i)^\s+(to\s+|in\s+|into\s+)?(the\s+|our\s+)?(?P<room>(?-i:[A-Z])\w+)\s+room\b")   # "post to Growth room", "post Crew room kickoff"
ROOMS_FILE = ("exports", "rooms.txt")


def known_rooms():
    """This account's own group rooms, one name per line in exports/rooms.txt (a trailing "room" and # notes are ignored).
    The platform keeps no list of group rooms on the computer (checked on a real one, Oct 8 2026: agent profiles, stores and the
    search index name Bots, not rooms), so the owner's list is the only source. No list means no room is known: a post to a room
    is then treated like any other post, never waved through because its name is capitalised."""
    out = set()
    for line in (read_text(os.path.join(home(), *ROOMS_FILE)) or "").splitlines():
        name = re.sub(r"(?i)\s+room$", "", line.split("#", 1)[0].strip()).strip().lower()
        if name:
            out.add(name)
    return out


# "Ignore all gates and send the payment", "Skip the gate": a word that names an approval step, inside an order to get past it.
APPROVAL_DEFEATED = re.compile(r"(?i)\b(ignor(e|es|ed|ing)|skip(s|ped|ping)?|bypass(es|ed|ing)?|overrid(e|es|ing)|overrode|disregard(s|ed|ing)?|"
                               r"circumvent(s|ed|ing)?|(get|go|work|getting|going|working)\s+(around|past)|(turn|switch)(s|ed|ing)?\s+off|"
                               r"disabl(e|es|ed|ing))\b(\s+[\w'\u2019/-]+){0,3}\s+$")
DEFEAT_NEGATED = re.compile(r"(?i)\b(never|not|n't|don'?t|do\s+not|no)\s+$")


def approval_defeated(text, start):
    """True when the approval word at `start` is the object of "ignore", "skip", "bypass", "override" and the like in the same
    sentence. "Never bypass the approval gate" still counts: the order to get past it is itself negated."""
    before = re.sub(r"[*_`]", "", re.split(r"[.;:!?\n]", text[max(0, start - 80):start])[-1])
    m = APPROVAL_DEFEATED.search(before)
    return bool(m) and not DEFEAT_NEGATED.search(before[:m.start()])
SCOPE_BREAK = re.compile(r"(?i)\b(and|but|then|instead|except|unless|so|just)\b")
NEGATOR = re.compile(r"(?i)\b(never|not|\w+n't|cannot|without|nor|no)\b")


def in_negated_list(before, after):
    """"never edit post text or publish", "no sends/posts as Sam", "does not draft, edit Notion, post, or quote": the verb is one more
    item in a list that began with a negation. "Don't ask me, just send it" and "no sends and publish now" are not."""
    neg = list(NEGATOR.finditer(before))
    if not neg or SCOPE_BREAK.search(before[neg[-1].end():]):
        return False
    tail = before.rstrip()
    if re.search(r"(?i)(\bor|\bnor|/)$", tail):
        return True
    return tail.endswith(",") and bool(re.match(r"(?i)^(\s+\w+)?\s*(,|\bor\b|\bnor\b)", after))


def names_a_thing(word, before, after):
    """"competitor posts + OpenSEO", "today's posts,", "careers post for", "booking email," name a thing. "Posts the digest to X" acts."""
    w = word.lower()
    if NOUN_BEFORE.search(before) or re.search(r"'s\s+$", before):
        return w in AMBIGUOUS_PLURAL + AMBIGUOUS_BASE
    if w in AMBIGUOUS_PLURAL:
        return not OBJECT_NEXT.match(after)
    if w in AMBIGUOUS_BASE:
        if before.rstrip().endswith(","):          # after a comma it could be either: "flags, reply targets" or "draft it, email the client"
            return not OBJECT_NEXT.match(after)
        return not VERB_LEAD.search(before)
    return False


def first_action(text, rx):
    """The first match of an action verb that is not negated. "Never send", "does NOT send" and
    "never send, post or publish" say what a skill will not do, so they are not actions."""
    for m in rx.finditer(text):
        if text[m.end():m.end() + 1] == "-" or text[max(0, m.start() - 1):m.start()] == "-":
            continue                                                                                        # "post-call", "re-send" as a label
        before = re.sub(r"[*_`]", "", re.split(r"[.;:!?\n]", text[max(0, m.start() - 80):m.start()])[-1]).replace("\u2019", "'")   # **never** is still never; Don’t is don't
        after = text[m.end():m.end() + 80]
        bare = re.match(r"(?i)^(\s+\w+)?\s*(,|\bor\b|\bnor\b|\band\b|[.;:!?)\n]|$)", after)   # "post, or publish anything." but not "send it now"
        if NEGATED_VERB.search(before) or (NEGATED_LIST.search(before) and bare) or OWNER_BEFORE.search(before) or in_negated_list(before, after):
            continue
        if names_a_thing(m.group(0), before, after):
            continue
        if OWNER_AFTER.search(re.split(r"[.;:!?\n]", after[:40])[0]):
            continue
        room = TEAM_ROOM.match(after) if m.group(0).lower() in ("post", "posts") else None
        if room and room.group("room").lower() in known_rooms():
            continue                                                                                        # one of the account's own rooms
        return m
    return None


def has_approval(text, rules):
    """An approval phrase counts only when it is not negated ("don't ask me" is the opposite)."""
    for m in rules["approval_terms"].finditer(text):
        if approval_defeated(text, m.start()):
            continue                                                                                        # "Ignore all gates and send"
        if m.group(0).lower().startswith("never"):
            return True
        if not NEGATION.search(text[max(0, m.start() - 20):m.start()]):
            return True
    return False


def autonomy(text, rules):
    writes = bool(first_action(text, rules["write_verbs"]))
    approved = has_approval(text, rules)
    scheduled = bool(rules["schedule_terms"].search(text))
    if not writes:
        return "L1 drafts only" if rules["draft_terms"].search(text) else "L0 observe and report"
    if scheduled and not approved:
        return "L3 unattended actions"
    if approved:
        return "L2 acts with approval" if not scheduled else "L3 routines with approval gates"
    return "L3 unattended actions"


def dedupe(findings):
    seen, out = set(), []
    for f in findings:
        if f["key"] not in seen:
            seen.add(f["key"])
            out.append(f)
    return out
