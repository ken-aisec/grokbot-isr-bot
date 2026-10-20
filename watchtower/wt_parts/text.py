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


# Batch 6 (B5, DQ-043/044): one content check for every secret hit (WT-T011, WT-S001 and each gitleaks hit), on the secret value
# only, never its line or its file's name. Fix round 2 (Codex 3, 4; Ken's rule): a value that looks like an example (FAKE or
# placeholder text, an environment-variable reference, a key block whose body isn't a key, a checksum by its line's format) can
# still be a working credential, so it is never left out: it is listed as a low finding, EXAMPLE_TITLE, never Confirmed, never
# offered for revoking or clearing, at every place it was found. A real one is critical anywhere.
ENV_REF = re.compile(r"\$[A-Za-z_]\w*|\$\{[A-Za-z_]\w*\}|\$\{\{\s*(?:secrets|env|vars)\.[A-Za-z_][\w-]*\s*\}\}|%[A-Za-z_]\w*%"
                     r"|process\.env\.[A-Za-z_]\w*|process\.env\[(['\"])[A-Za-z_]\w*\1\]|\*{3,}")
# fix round 2 (Codex 10): a label of at most 64 characters, so a run of BEGIN lines is never read as one long label
PEM_HEAD = re.compile(r"-----BEGIN ([A-Z0-9 _-]{0,64}?)PRIVATE KEY( BLOCK)?-----")
PEM_END = re.compile(r"-----END [A-Z0-9 _-]{0,64}?PRIVATE KEY(?: BLOCK)?-----")
PEM_CAP = 16384
EXAMPLE_WHY = {"placeholder": "FAKE or placeholder text", "env": "an environment variable name", "pem": "a key block that isn't a real key",
               "digest": "a file's checksum"}
EXAMPLE_TITLE = "Looks like an example or checksum value - check it"
EXAMPLE_T011 = "WT-T011x"   # WT-T011's example-looking hits: listed beside it, as WT-T006k beside WT-T006; WT-T011 stays for real ones
EXAMPLE_FIX = ("Watchtower read this as {why}, not a working key, but can't be sure: anyone can write a real key that way. "
               "Check it; if it is a real key, turn it off at its provider.")


def example_finding(f, why):
    """Fix round 2: finding f (a secret hit) as an example-looking value: low, EXAMPLE_TITLE, its why kept (`example`)."""
    return dict(f, title=EXAMPLE_TITLE, severity="low", fix=EXAMPLE_FIX.format(why=why), example=why)


# Batch 6 fix round 1 (Codex 2): a placeholder is a whole value of one of these forms, never a word inside a value (a real key
# can have "test" or "abcd" in it) and never a guess from how varied its characters are. After an optional provider prefix:
# FAKE or EXAMPLE right at the start (the convention this project's fake keys follow: ghp_FAKE…, sk_live_FAKE…, AKIAFAKE…), only
# placeholder words (your-api-key-here, YOUR_TOKEN, xxxx), or one unit of 1 to 4 characters repeated (aaaa…, a1B2a1B2…). Also
# <…> as the whole value. Fix round 2 (Codex 9): read by is_placeholder, left to right, never by a regular expression whose
# repetitions overlap (x{3,} inside repeated words backtracked exponentially).
KEY_PREFIXES = tuple(re.compile(p) for p in (r"sk-(?:proj|ant|svcacct|admin)-", r"sk-ant-[a-z]{2,6}\d\d-", r"sk-", r"[sr]k_(?:live|test)_",
                                             r"gh[pousr]_", r"github_pat_", r"glpat-", r"xox[baprs]-", r"xai-", r"AKIA", r"ASIA", r"AIza",
                                             r"npm_", r"pypi-"))
PH_WORDS = ("your", "my", "the", "api", "access", "secret", "private", "key", "token", "password", "passwd", "pass", "here", "goes",
            "insert", "replace", "put", "example", "sample", "placeholder", "dummy", "fake", "redacted", "changeme", "change", "me", "value")


def _placeholder_words(s):
    """True when s is placeholder words only (PH_WORDS, any case, or a run of 3 or more x or *), each joined to the next by at
    most one of - _ . or a space. One pass left to right over where a word may start: no word starts with x or *, so a run of
    them is taken whole."""
    low, n = s.lower(), len(s)
    run = [0] * (n + 1)
    for i in range(n - 1, -1, -1):
        run[i] = run[i + 1] + 1 if low[i] in "x*" and (i + 1 == n or low[i + 1] == low[i]) else (1 if low[i] in "x*" else 0)
    start = [False] * (n + 1)
    start[0] = n > 0
    for i in range(n):
        if not start[i]:
            continue
        ends = [i + len(w) for w in PH_WORDS if low.startswith(w, i)] + ([i + run[i]] if run[i] >= 3 else [])
        for e in ends:
            if e == n:
                return True
            start[e] = True
            if low[e] in "-_. " and e + 1 < n:
                start[e + 1] = True
    return False


def _repeated_unit(s):
    """True when s is one unit of 1 to 4 characters (no space) repeated at least 4 times."""
    n = len(s)
    return not any(c.isspace() for c in s) and any(n % k == 0 and n // k >= 4 and s == s[:k] * (n // k) for k in (1, 2, 3, 4))


def is_placeholder(u):
    """True when u, a whole value, is a placeholder: <…> (1 to 80 characters, no <, > or line break inside), or after no prefix or
    one of KEY_PREFIXES: FAKE or EXAMPLE then no space, placeholder words only, or a repeated unit. Linear in len(u)."""
    if len(u) >= 3 and u[0] == "<" and u[-1] == ">" and len(u) <= 82 and not any(c in "<>\n" for c in u[1:-1]):
        return True
    for k in {0} | {m.end() for m in (p.match(u) for p in KEY_PREFIXES) if m}:
        rest = u[k:]
        if rest and ((rest.startswith(("FAKE", "EXAMPLE")) and not any(c.isspace() for c in rest))
                     or _placeholder_words(rest) or _repeated_unit(rest)):
            return True
    return False
# Batch 6 fix round 1 (Codex 3): a hex value is a checksum only when its own line says so; its name never does.
DIGEST_LEN = {"md5": 32, "sha1": 40, "sha224": 56, "sha256": 64, "sha384": 96, "sha512": 128}
_SUM_LINE = re.compile(r" [ *]\S+")                                              # sha256sum: <hex>  <path> or <hex> *<path>
_BSD_SUM = re.compile(r"\\?(SHA1|SHA224|SHA256|SHA384|SHA512|MD5) \(.+\) = ")   # sha256sum --tag, BSD sha256: SHA256 (path) = <hex>
_TYPED_SUM = re.compile(r"(?:^|[\s\"'\[,=])(sha1|sha224|sha256|sha384|sha512):$")  # pip --hash=sha256:, Pipfile/poetry "sha256:…"
_SRI_SUM = re.compile(r"(?:\"integrity\"\s*:\s*\"|^\s*integrity\s+\"?)(sha256|sha384|sha512)-$")   # package-lock / yarn.lock


def checksum_provenance(line, s, e):
    """True when line[s:e] is a checksum by the format of its own line (`line`: the whole source line, no line break): a
    sha256sum-style `<hex>  <path>` line, a `SHA256 (path) = <hex>` line, a typed `sha256:<hex>` (pip --hash, Pipfile.lock,
    poetry.lock), Cargo.lock's `checksum = "<hex>"`, or a package-lock/yarn.lock `integrity` sha256/384/512 value. The value's
    length must be its algorithm's. A name (a file name, a dot, a slash) never makes a value a checksum."""
    import base64, binascii
    if not (0 <= s < e <= len(line)):
        return False
    v, pre, post = line[s:e], line[:s], line[e:]
    if re.fullmatch(r"[0-9a-fA-F]+", v):
        if pre in ("", "\\") and len(v) in DIGEST_LEN.values() and _SUM_LINE.fullmatch(post):
            return True
        m = _BSD_SUM.fullmatch(pre)
        if m and post == "" and DIGEST_LEN[m.group(1).lower()] == len(v):
            return True
        m = _TYPED_SUM.search(pre)
        if m and DIGEST_LEN[m.group(1)] == len(v) and (post == "" or post[0] in " \t\"',]\\"):
            return True
        return re.fullmatch(r'\s*checksum = "', pre) is not None and post == '"' and len(v) == 64
    m = re.match(r"(sha256|sha384|sha512)-", v)
    if m:   # the secret may hold the algorithm too
        pre, v = pre + m.group(0), v[m.end():]
    m = _SRI_SUM.search(pre)
    if not m or not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", v) or not (post == "" or post[0] in "\",\t "):
        return False
    try:
        return len(base64.b64decode(v, validate=True)) * 2 == DIGEST_LEN[m.group(1)]
    except (binascii.Error, ValueError):
        return False


def _der_seq(b):
    """True when b starts with a DER SEQUENCE of at least 32 bytes whose length fits in b and whose first element is an INTEGER
    (PKCS#1, PKCS#8, SEC1) or a SEQUENCE (encrypted PKCS#8). Bytes after it don't matter: a key with more after it is a key."""
    if len(b) < 4 or b[0] != 0x30 or b[1] == 0x80:
        return False
    if b[1] < 0x80:
        n, h = b[1], 2
    else:
        k = b[1] & 0x7F
        if k > 4 or len(b) < 2 + k:
            return False
        n, h = int.from_bytes(b[2:2 + k], "big"), 2 + k
    return 32 <= n and h + n <= len(b) and b[h:h + 1] in (b"\x02", b"\x30")


_ESCAPED_BREAK = re.compile(r"\\+[nrt]")
_ARMOR_HEADER = re.compile(r"(?:Version|Comment|Hash|Charset|MessageID):(?: |$)")   # a PGP armor's own headers


def _code_literals(s, opened):
    """Fix round 2 (Codex 5): `s` (what is between a key block's BEGIN and END lines) read as string literals in code, or None
    unless it is exactly that: literals ('…' or "…", no line break inside, a backslash only before n, r or t), with only
    whitespace, +, comma and semicolon between them. `opened`: the quote already open where s starts (the BEGIN line's own
    literal), or None. Each literal's content is one line; one still open at the end is the END line's. One pass."""
    out, i, n, q = [], 0, len(s), opened
    while i < n:
        if q is None:
            if s[i] in " \t\r\n+,;":
                i += 1
            elif s[i] in "\"'":
                q, i = s[i], i + 1
            else:
                return None
            continue
        j = i
        while j < n and s[j] != q:
            if s[j] in "\r\n" or (s[j] == "\\" and s[j + 1:j + 2] not in ("n", "r", "t", "\\")):
                return None
            j += 2 if s[j] == "\\" else 1
        out.append(s[i:j])
        q, i = (None, j + 1) if j < n else (q, n)
    return out


def _pem_body(lines):
    """A key block's body lines (escaped line breaks already split) judged: "real", "example", or None when a line isn't read
    plainly. A Proc-Type or DEK-Info header (an old encrypted key, ciphertext) is real; a PGP armor's own headers before the body
    and its checksum line after it are its syntax. Every other line must be base64, nothing in it left out."""
    import base64, binascii
    body = []
    for ln in lines:
        s = ln.strip()
        if not body and re.match(r"(?i)(proc-type|dek-info):", s):
            return "real"
        if not body and _ARMOR_HEADER.match(s):
            continue
        if s:
            body.append(s)
    if body and re.fullmatch(r"=[A-Za-z0-9+/]{4}", body[-1]):
        body.pop()
    if not body or not all(re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", s) for s in body):
        return None
    try:
        raw = base64.b64decode("".join(body), validate=True)
    except (binascii.Error, ValueError):
        return None
    if not raw:
        return None
    b = raw[0]
    if b & 0x80 and ((b & 0x3F) if b & 0x40 else ((b & 0x3C) >> 2)) in (5, 7):
        return "real"   # a PGP secret-key packet
    # fix round 2: a DER or OpenSSH key where any line starts (on a whole base64 group) is a key, so lines of other bytes put
    # before a real key never make it an example
    at = 0
    for s in body:
        if at % 4 == 0 and at // 4 * 3 < len(raw):
            rest = raw[at // 4 * 3:]
            if _der_seq(rest) or rest.startswith(b"openssh-key-v1\x00"):
                return "real"
        at += len(s)
    return "example"


def pem_kind(label, tail):
    """A private key block's kind from its decoded body alone, never its BEGIN label (fix round 1, Codex 4: a PKCS#8 key framed
    as OPENSSH or ENCRYPTED is still a key): "real" or "example". `tail` is the text after the BEGIN line, read to its END line
    (at most PEM_CAP characters). Real: any body that is a private key structure (a DER SEQUENCE starting with an INTEGER or a
    SEQUENCE: PKCS#1, PKCS#8, SEC1, encrypted PKCS#8; openssh-key-v1; a PGP secret-key packet), and any block whose framing
    isn't plainly read (no END, another BEGIN before it, a Proc-Type/DEK-Info encrypted body, a line that isn't base64,
    base64 that doesn't decode). Example only when the whole text between BEGIN and END holds too few base64 characters for
    any key (under 64, 48 bytes), or one reading of it decodes cleanly to bytes that are none of those structures and none does
    to a key. Fix round 2 (Codex 5): nothing on a line is ever left out. The readings are the text as it is (its lines, \\n
    escapes as line breaks: a .pem, YAML, a JSON string) and, only when the whole of it is exactly string literals in code
    ("MIIE…\\n" + "…"), their contents; `<base64> # ""` is neither, so it is real. A FAKE word decides nothing; `label` is not
    read."""
    end = PEM_END.search(tail, 0, PEM_CAP)
    if not end or PEM_HEAD.search(tail, 0, end.start()):
        return "real"
    region = tail[:end.start()]
    if len(re.findall(r"[A-Za-z0-9+/]", _ESCAPED_BREAK.sub("", region))) < 64:
        return "example"   # too few characters anywhere in it for the smallest private key (48 bytes)
    readings = [_ESCAPED_BREAK.sub("\n", region).split("\n")]
    for q in (None, '"', "'"):
        lits = _code_literals(region, q)
        if lits is not None:
            readings.append([x for lit in lits for x in _ESCAPED_BREAK.sub("\n", lit).split("\n")])
    verdicts = {_pem_body(r) for r in readings}
    return "example" if verdicts == {"example"} or verdicts == {"example", None} else "real"


def secret_kind(value, tail="", line=None, at=None):
    """("real" | "example", why) for one secret value. Example: a key block whose decoded body isn't a key (pem_kind; its
    label and a FAKE word in it are ignored), a whole environment-variable reference ($X, ${X}, ${{ secrets.X }}, %X%,
    process.env.X, ***), a whole placeholder (is_placeholder), or (when `line`, the value's whole source line, and `at`, its
    start there, are given) a checksum by its line's format (checksum_provenance). Everything else is real. `tail`: the text
    after the value, for a key block's body (none: only the value itself is read). Fix round 2: "example" lowers a hit to a
    listed low finding (example_finding), never more; nothing is left out on it."""
    v = (value or "").strip()
    h = PEM_HEAD.match(v)
    if h:
        return ("real", "") if pem_kind(h.group(1), tail or v[h.end():]) == "real" else ("example", EXAMPLE_WHY["pem"])
    u = v.strip("\"'`")
    if ENV_REF.fullmatch(u):
        return "example", EXAMPLE_WHY["env"]
    if line is not None and at is not None and checksum_provenance(line, at, at + len(value or "")):
        return "example", EXAMPLE_WHY["digest"]
    if is_placeholder(u):
        return "example", EXAMPLE_WHY["placeholder"]
    return "real", ""


def secret_at(text, m):
    """secret_kind of the T011 match m in text (with the text after it, for a key block's body)."""
    return secret_kind(m.group(0), tail=text[m.end():m.end() + PEM_CAP])


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
    -G/--get is harmless only when the data is not a file (@) or a command substitution."""
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
# PR A, Codex round 3 (5): the receivers `get` is an HTTP GET on (requests.get, httpx.get, session.get, self.client.get, https.get,
# axios.get, $.get, …); on any other receiver it is a lookup (round 3 (1))
_HTTP_CLIENT = re.compile(r"(?i)requests|httpx|aiohttp|urllib3|https?|axios|got|ky|needle|superagent|\$|jquery|\$http|[\w$]*(?:session|client)")
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


def _code_standalone(text, a, b, start, end, prose, natural=True):
    """The code reading (see above) of the literal text[a:b] in the region text[start:end]."""
    import bisect
    r = _region(text, start, end, prose)
    kinds, starts, ends, nl, parent, match = r["kinds"], r["starts"], r["ends"], r["nl"], r["parent"], r["match"]
    if r["broke"] is not None and r["broke"] < b:
        return False   # an unterminated string or comment before the end of the URL: nothing is certain
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
            # first; on anything else (config.get, os.environ.get, cfg.get) it is a lookup, its arguments keys and a default
            recv = tok(o - 3) if o - 3 >= c else None
            http = _HTTP_CLIENT.fullmatch(recv) is not None if recv is not None else bool(pos) and mine is pos[0]
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
        """PR A, Codex round 2 (1): a destination that is only maybe the chat webhook (a lookup's default, a helper's argument,
        one side of an or, an element of a dict or list) can't be a way to send something somewhere else. Round 3 (1): what
        overrides it may be anywhere (config = {'hook': 'https://collector…'} two lines up), so nothing in the whole text is
        another URL (_other_urls), and no string or name in the whole region is a credential's."""
        memo = _memo(text)
        ck = ("cred", start, end, prose)
        if ck not in memo:
            memo[ck] = [i for i in range(n) if kinds[i] in ("str", "name") and _CRED_WORD.search(tok(i))]
        return all(i == li for i in memo[ck]) and all(a <= s < b for s in _other_urls(text))

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
                maybe = maybe or any(parent[i] is None and tok(i) in _BOOL_OPS for i in range(a, b + 1))
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
            if role and _CONFIG_PARSER.search(text):
                return False   # PR A, Codex round 3 (1): a ConfigParser reads its options from a file (cfg.get(section, option))
            if role:
                # PR A, Codex round 2 (7): a lookup's default is what it returns when the key isn't there, followed outward to the
                # sender like any operand. Round 3 (1): only maybe (the key may be there: config = {'hook': …} above), whatever
                # the key is
                maybe = True
                lo, hi = c, match[o]
                continue
            if bt in _SENDERS or tok(c) == "axios":
                # PR A, Codex round 1 (1): a call named like a sender sends to one argument (config.get('hook', URL) is a lookup's
                # default); the URL must be that argument, and the call itself must be the whole statement's sending
                return destination(o, p, pt, bt, keys) and sent(c, match[o]) and (not maybe or quiet())
            maybe = maybe or len(args(o)) > 1   # PR A, Codex round 2 (1): a helper's argument: it may send to another one
            lo, hi = c, match[o]   # a wrapper call: the call is the operand now
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
            # batch 6 (B5): the value judged on itself, never the line or the file name; fix round 2: an example-looking one is
            # listed low (example_finding), never left out
            example = secret_at(text, m)[1] if rule["id"] == SECRET_RULE else ""
            if rule["id"] == "WT-T003" and is_document_blob(m.group(0)):
                continue
            ev = m.group(0)
            installer = rule["id"] == "WT-T006" and known_installer(ev)
            reason = in_warning(text, m, rules, rule["id"], prev_end) if rule["id"] in guarded else ""
            if reason:
                prev_end = m.end()
            sig = ("WT-T006k" if installer else rule["id"], bool(reason), bool(example))   # severity follows from these
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
                f = finding(EXAMPLE_T011 if example else rule["id"], rule["title"], rule["severity"], rule["owasp"],
                            f"{where}:{line_of(text, m.start())}", ev, rule["fix"])
                if example:
                    f = example_finding(f, example)
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
