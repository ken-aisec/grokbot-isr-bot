# Part of wt.py: runs inside wt.py's namespace (loaded by _wt_part); not a module on its own.
def mask(s):
    if len(s) <= 12:
        return s[:2] + "…"
    return s[:6] + "…" + s[-4:]


# Hardening batch 4 (R11): every Bot can read Watchtower's state files, so stored evidence never holds a secret. Key shapes keep
# their first 6 characters (mask); a password, token or cookie value next to a name that says so becomes [hidden]. A bare $VAR
# or ${VAR} reference is never touched, nor is anything already masked. Lengths are loose so a key cut at 160 is still caught.
# Codex, batch 4 round 2: each reader below (private keys, key shapes, URLs, JSON/YAML fields, shell words) only marks spans of
# the original text, and one pass writes them out, so no reader sees another's output, a hidden value keeps its line breaks
# (history and `show` stay line for line) and the whole is linear. MASK_VERSION goes up whenever masking learns a new shape:
# copies stored masked by an older version (approved skills, the engine cache) are then masked again.
MASK_VERSION = 5   # batch 5: whole logical shell words for credentials, quoted YAML keys, webhook URLs over joins and \u escapes
# (4); PR A, Codex round 1 (5): attached -u/-U/-p and the other line-reader forms in whole words, YAML quoted values over lines,
# an escaped or joined scheme separator
MASK_WINDOW = 8192   # finding() stores 160 characters: it masks this much of the text they are cut from, never less
HIDDEN = "[hidden]"
KEY_SHAPE = re.compile(   # the lookahead names every shape's first letter, so most of a text is skipped at C speed
    r"(?=[AsxgEre])(AKIA[0-9A-Z]{12,}|ASIA[0-9A-Z]{12,}|\bsk-(proj|ant|svcacct|admin)-[A-Za-z0-9_-]{8,}|\bsk-[A-Za-z0-9]{20,}|\bxai-[A-Za-z0-9]{8,}"
    r"|\bgh[pousr]_[A-Za-z0-9]{8,}|\bgithub_pat_[A-Za-z0-9_]{8,}|\bxox[baprs]-[A-Za-z0-9-]{8,}|\bglpat-[A-Za-z0-9_-]{8,}"
    r"|\bsq0(atp|csp)-[0-9A-Za-z_-]{8,}|\bEAAA[A-Za-z0-9_+=-]{20,}|\b[rs]k_live_[0-9A-Za-z]{8,}|AIza[0-9A-Za-z_-]{8,}"
    r"|\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{4,}(\.[A-Za-z0-9_-]*)?)")
# A private key's body; "-----B…----" is the header as an older version stored it (mask() of the T011 match), so a body kept
# after it is hidden too. The body may run over several lines, or be serialized with literal \n (a JSON key file, Codex round 2).
_PEM_GAP = r"(?:[ \t\r\n]|\\[nrt])"
_B64 = r"(?:[A-Za-z0-9+]|\\?/)"
PEM_BODY = re.compile(rf"(?:-----BEGIN [A-Z ]*PRIVATE KEY-----|-----B…----){_PEM_GAP}*(?P<body>(?:{_B64}|=){{8,}}"
                      rf"(?:{_PEM_GAP}+(?:{_B64}{{16,}}={{0,2}}|{_B64}{{1,15}}={{1,2}}))*)")
# Codex, batch 4 round 1: one tokenizer instead of regex special cases. A shell word keeps its quotes ('…', "…", $'…') and
# backslash escapes whole; one left open (evidence cut short) runs to the end of the line, so all of it is hidden. Separators
# (| || && ; & and a line break) end a command. Round 2: text with line breaks is read twice, once with quotes kept to their
# line and once as the shell reads it, where a closed quote may cross lines (up to 4096 characters), and both readings' spans
# are hidden: a token split over two lines is hidden on both, and a stray apostrophe in prose can't pair quotes wrongly.
_Q_LINE = r"\$'(?:[^'\\\n]|\\.)*'?|'[^'\n]*'?|\"(?:[^\"\\\n]|\\.)*\"?"
_Q_MULTI = r"\$'(?:[^'\\]|\\[\s\S]){0,4096}'|'[^']{0,4096}'|\"(?:[^\"\\]|\\[\s\S]){0,4096}\"|" + _Q_LINE


def _shell_rx(quoted, escape, nl=r"\n"):
    return re.compile(rf"(?P<sep>\|\||&&|[|;&]|{nl})|(?P<word>(?:{quoted}|{escape}|\$|[^\s'\"\\|;&$]+)+)")


# Round 3: in the shell's reading a backslash before a line break joins the lines. Inside a word (API_TOKEN=\ then FAKE) it is
# part of the word; before spaces (--token \ then FAKE) it is only a space, and that line break never ends the command.
_SHELL, _SHELL_ML = _shell_rx(_Q_LINE, r"\\."), _shell_rx(_Q_MULTI, r"\\(?:\r?\n(?![ \t\r\n])|(?!\r?\n)[\s\S])", r"(?<!\\)(?<!\\\r)\n")
_QUOTED, _QUOTED_ML = re.compile(_Q_LINE), re.compile(_Q_MULTI)
SECRET_WORDS = ("token", "secret", "passwd", "pass", "api_key", "apikey", "api-key", "access_key", "private_key", "auth",
                "credential", "session", "cookie")
NOT_SECRET_NAMES = frozenset(("author", "authors", "authored", "authority", "auth_url", "auth_uri", "token_url", "token_uri",
                              "tokenizer", "passive", "compass", "bypass"))
SECRET_FLAGS = frozenset(("--password", "--passwd", "--pass", "--token", "--api-key", "--apikey", "--secret", "--auth-token",
                          "--access-token"))
USER_FLAGS = frozenset(("-u", "--user", "--proxy-user", "-U"))   # curl and friends: user:password
USER_EQ = ("--user=", "--proxy-user=")   # Codex, round 3: the long options' attached form
SECRET_HEADER = re.compile(r"(?i)^[ \t]*(?:--?[A-Za-z][\w-]*=)?(?:(?P<auth>(?:proxy-)?authorization|x-api-key|x-auth-token)|(?P<jar>(?:set-)?cookie))[ \t]*:[ \t]*"
                           r"(?:(?(auth)(?:bearer|basic|token|bot|digest|apikey|negotiate|ntlm)[ \t]+))?")
MYSQL_TOOLS = frozenset(("mysql", "mysqldump", "mysqladmin", "mariadb", "mariadb-dump", "mysqlimport", "mysqlcheck", "mysqlshow"))
# Codex, round 2: only a bare reference is kept. ${TOKEN:-FAKEfallback}, ${X/a/FAKE} and the like carry a literal: hidden.
BARE_VAR = re.compile(r"\$[A-Za-z_][A-Za-z0-9_]*|\$\{[A-Za-z_][A-Za-z0-9_]*\}")
_NAME_CH = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-")
_LEAD = re.compile(r"[-'\"$]*")
# A value inside a word ends at the next & , ; bracket or space; a quoted part ("FAKE", 'a b') is read whole (Codex, round 2).
_VALUE = re.compile(r"(?:'[^']*'?|\"(?:[^\"\\]|\\[\s\S])*\"?|[^&,;\"'`}) \t\r\n])*")


def _kept(v):
    """A value that is not a secret: a bare $VAR or ${VAR} reference (quoted or not), or already [hidden]. Nothing else (a
    leading - or $, an ellipsis, an expansion with a default) is waved through."""
    u = v.replace("'", "").replace('"', "").strip()
    return u in ("", HIDDEN) or bool(BARE_VAR.fullmatch(u))


def _secret_name(name):
    n = name.lower()
    return n not in NOT_SECRET_NAMES and any(w in n for w in SECRET_WORDS)


def _unquote(raw):
    return re.sub(r"\\(.)", r"\1", raw.replace("$'", "'").replace("'", "").replace('"', ""))


def _unquote_map(raw):
    """The shell's reading of one word (quotes removed, escapes resolved) and, for each character of it, where it is in `raw`."""
    out, idx, i, n, q = [], [], 0, len(raw), None
    while i < n:
        c = raw[i]
        if q is None and c in "'\"":
            q, i = c, i + 1
            continue
        if q is None and c == "$" and raw[i + 1:i + 2] == "'":
            q, i = "$", i + 2
            continue
        if q is not None and c == ("'" if q in "'$" else '"'):
            q, i = None, i + 1
            continue
        if c == "\\" and q != "'" and i + 1 < n:
            i += 1
        out.append(raw[i])
        idx.append(i)
        i += 1
    return "".join(out), idx


def _assignments(raw, at, spans):
    """NAME=value (export, env, --token=…, a query string, JSON-ish text). Each = is read once and its name is found by walking
    back over name characters, so repeated name fragments cost nothing extra. At the start of a word (after dashes or an opening
    quote) the value is the rest of the word; inside one it is _VALUE. Round 2: where a word starts is found once, never by
    copying the text before each = (that was quadratic)."""
    lead, n = _LEAD.match(raw).end(), len(raw)
    i = raw.find("=")
    while i != -1:
        j = i
        while j > 0 and raw[j - 1] in _NAME_CH:
            j -= 1
        if j < i and _secret_name(raw[j:i]):
            end = n if j <= lead else _VALUE.match(raw, i + 1).end()
            if end > i + 1 and not _kept(raw[i + 1:end]):
                spans.append((at + i + 1, at + end))
                i = end - 1   # nothing inside a hidden value is read again: TOKEN=TOKEN=… stays linear
        i = raw.find("=", i + 1)


AUTH_SCHEME = re.compile(r"(?i)bearer|basic|token|bot|digest|apikey|negotiate|ntlm")

# Codex, round 2: URLs are read where they are, not as shell words. A password in the authority, a secret-named query value and
# a chat webhook's credential path are hidden; the scheme, host and the rest of the path stay readable.
_AUTH_END = re.compile(r"[/?#\s\"'`<>|\\]")
_PATH_END = re.compile(r"[?#\s\"'`<>|\\]")
_QUERY_END = re.compile(r"[#\s\"'`<>|\\]")
_QPARAM = re.compile(r"(?P<name>[^=&;#\s\"'`<>|\\]*)(?:=(?P<val>(?:'[^'\n]*'?|\"(?:[^\"\\\n]|\\.)*\"?|[^&;#\s\"'`<>|\\])*))?")
URL_SECRET_PARAMS = frozenset(("key", "sig", "signature", "code", "pwd", "x-amz-signature", "x-amz-credential",
                               "x-amz-security-token", "x-goog-signature", "x-goog-credential"))
WEBHOOK_PATHS = ((re.compile(r"hooks\.slack\.com"), re.compile(r"/(?:services|workflows|triggers)/(?P<s>.+)")),
                 (re.compile(r"discord(?:app)?\.com"), re.compile(r"/api/webhooks/(?P<s>.+)")),
                 (re.compile(r"[a-z0-9-]+\.webhook\.office\.com"), re.compile(r"/[^/]*/(?P<s>.+)")),
                 (re.compile(r"outlook\.office\.com"), re.compile(r"/webhook/(?P<s>.+)")),
                 (re.compile(r"api\.telegram\.org"), re.compile(r"/(?:file/)?bot(?P<s>[^/]+)")))
ANY_WEBHOOK_PATH = re.compile(r"/api/webhooks/(?P<s>.+)")   # a Discord-style webhook on any host


def _urls(s, spans):
    """Each scheme:// is read once, up to the next one, so URLs inside URLs stay linear."""
    i = s.find("://")
    while i != -1:
        nxt = s.find("://", i + 3)
        lim = len(s) if nxt == -1 else nxt
        a = i + 3
        m = _AUTH_END.search(s, a, lim)
        b = m.start() if m else lim
        auth = s[a:b]
        k = auth.rfind("@")
        c = auth.find(":", 0, k) if k != -1 else -1
        if c != -1 and not _kept(auth[c + 1:k]):
            spans.append((a + c + 1, a + k))
        host = auth[k + 1:].split(":")[0].lower()
        m = _PATH_END.search(s, b, lim)
        pe = m.start() if m else lim
        path = s[b:pe]
        pm = next((rx.match(path) for h, rx in WEBHOOK_PATHS if h.fullmatch(host)), None) or ANY_WEBHOOK_PATH.search(path)
        if pm and not _kept(pm.group("s")):
            spans.append((b + pm.start("s"), b + pm.end("s")))
        pos = pe + 1
        while pe < lim and s[pe] == "?" and pos < lim:
            q = _QPARAM.match(s, pos, lim)
            if q.group("val") and (q.group("name").lower() in URL_SECRET_PARAMS or _secret_name(q.group("name"))) \
                    and not _kept(q.group("val")):
                spans.append((q.start("val"), q.end("val")))
            pos = q.end()
            if pos >= lim or s[pos] not in "&;":
                break
            pos += 1
        i = nxt


# ://, and JSON's :\/\/, :\\\/\\\/ or //. PR A, Codex round 1 (4): the colon written : too, and line joins
# (backslash, line break) and quotes anywhere between the three, so the URL's word is read before it is searched (https:\ then
# //…, 'https:/'\ then '/…').
_URLISH = re.compile(r"(?::|\\u003[aA])(?:['\"]|\\\r?\n)*(?:\\*/|\\u002[fF])(?:['\"]|\\\r?\n)*(?:\\*/|\\u002[fF])")


_JOINED_LINE = re.compile(r"(?<!\\)(?:\\\\)*\\\r?$")


def _word_urls(s, spans):
    """Codex, round 3: a URL is also read as the shell reads its word, with JSON's escaped slashes as slashes, so a webhook
    credential glued on after a quote ('https://hooks.slack.com/services/T0/B0/'FAKE) or written https:\\/\\/… is found. What
    _urls finds in that reading is mapped back to the original characters.
    Batch 5 (Codex review 4, c4): the word is the shell's logical word (_logical_words): a backslash at the end of a line joins
    the next one into it (…/B0/\\ then FAKE on the next line, or the host on one line and the path on the next), and JSON's
    \\uXXXX escapes are read too (_json_unescape). A quoted value closed before } ] ) > or , ends there, so a JSON "…FAKE"} keeps
    its "}. The text is read from the start of each URL's logical line, never twice: reading resumes after the last word read."""
    pos = done = 0
    while True:
        m = _URLISH.search(s, pos)
        if not m:
            return
        a = s.rfind("\n", 0, m.start()) + 1
        while a > done and a >= 2 and _JOINED_LINE.search(s, s.rfind("\n", 0, a - 1) + 1, a - 1):
            a = s.rfind("\n", 0, a - 1) + 1   # the line before ends in a join: the logical line starts there
        start, pos = max(a, done), m.end()
        for wa, wb, _ in _logical_words(s, start):
            done = pos = wb
            raw = s[wa:wb]
            if wb > m.start() and _URLISH.search(raw) and ("'" in raw or '"' in raw or "\\" in raw):   # else the plain reading saw it
                plain, lo, hi = _shell_plain(raw, stop_at_close=True)
                plain, lo, hi = _json_unescape(plain, lo, hi)
                found = []
                _urls(plain, found)
                spans += [(wa + lo[x], wa + hi[y - 1]) for x, y in found if y > x]
            if wb >= m.end():
                break
        else:
            done = pos = max(pos, len(s))


# Codex, round 2: "password": "…", 'api_key': '…', \"token\":\"…\" (JSON inside a string) and YAML's `password: …` (a single
# value on its own line). A field whose name is not a secret is skipped past its name only, so a field nested in its value is
# still read.
# Round 3: serialized JSON (\"password\":\"…\") is read escape by escape: \\\" is a quote inside the value, not its end. A YAML
# value is read whole by _yaml_value: words with spaces, and a `|` or `>` block or any line indented under the key.
_FIELD = re.compile(
    r"(?P<q>\\?[\"'])(?P<n1>[A-Za-z_][\w.-]{0,63})(?P=q)[ \t]*[:=][ \t]*"
    r"(?P<v1>\\\"(?:\\\\(?:\\[^\n]|[^\\\n])|\\[^\\\"\n]|[^\\\"\n])*(?:\\\")?|\"(?:[^\"\\\n]|\\.)*\"?|'(?:[^'\\\n]|\\.)*'?"
    r"|[^\s,;{}\[\]()\"'][^\s,;}\])\"']*)"
    r"|^(?P<ind>[ \t]*(?:-[ \t]+)?)(?P<n2>[A-Za-z_][\w.-]{0,63})[ \t]*:(?=[ \t]|$)", re.M)
_YAML_COMMENT = re.compile(r"[ \t]#")


def _yaml_value(s, m):
    """Where a YAML key's value is: the rest of its line (up to a ` #` comment, unless quoted) and every line after it that is
    blank or indented deeper than the key. (start, end); start == end when there is none. Each line is read once."""
    col, n = len(m.group("ind").expandtabs()), len(s)
    a = m.end()
    while a < n and s[a] in " \t":
        a += 1
    eol = s.find("\n", a)
    eol = n if eol == -1 else eol
    end = eol
    if a < eol and s[a] not in "'\"":
        c = _YAML_COMMENT.search(s, a, eol) if s[a] != "#" else None
        end = a if s[a] == "#" else (c.start() if c else eol)
    if a < eol and s[a] in "|>" and re.fullmatch(r"[|>][-+0-9]*", s[a:end].rstrip()):
        a = end = eol   # a block: only the lines under it
    while end > a and s[end - 1] in " \t\r":
        end -= 1
    p = eol
    while p < n:
        q = s.find("\n", p + 1)
        q = n if q == -1 else q
        line = s[p + 1:q]
        body = line.lstrip(" \t")
        if body.strip():
            if len(line[:len(line) - len(body)].expandtabs()) <= col:
                break
            end = q - (1 if line.endswith("\r") else 0)
            if a == eol:
                a = p + 1
        p = q
    return a, max(a, end)


# Batch 5 (Codex review 4, c3): a quoted YAML key ("password": or 'token': at the start of a line, after its indentation and an
# optional "- ", then a space or the line's end) has a YAML value: read whole by _yaml_value, like an unquoted key's.
_YAML_QKEY = re.compile(r"^(?P<ind>[ \t]*(?:-[ \t]+)?)(?P<q>[\"'])(?P<n2>[A-Za-z_][\w.-]{0,63})(?P=q)[ \t]*:(?=[ \t]|\r?$)", re.M)


def _yaml_quoted_keys(s, spans):
    """A quoted YAML key's whole value: a | or > block, words up to a ` #` comment, or lines indented under it. A quoted value
    ("password": "x") and a JSON or flow value ({…}, […]) keep _FIELD's reading, and so does a single word alone on its line
    (`"token": 5,` in JSON): that reading already hides all of it. Each match is read once; the search goes on after the value."""
    pos = 0
    while True:
        m = _YAML_QKEY.search(s, pos)
        if not m:
            return
        pos = m.end()
        if not _secret_name(m.group("n2")):
            continue
        eol = s.find("\n", m.end())
        rest = s[m.end():eol if eol != -1 else len(s)].strip(" \t\r")
        if rest[:1] in ("'", '"', "{", "["):
            continue
        a, b = _yaml_value(s, m)
        one_word = (eol == -1 or b <= eol) and rest and not re.search(r"[ \t]", rest) and rest[0] not in "|>"
        if b > a and not one_word and not _kept(s[a:b]):
            spans.append((a, b))
        pos = max(pos, b)


def _quoted_scalar_end(s, a):
    """PR A, Codex round 1 (3): where the YAML quoted scalar opened at s[a] ends (after its closing quote; the text's end when it
    never closes). It may run over lines: in "…" a backslash escapes the next character (a line break too), in '…' '' is a quote."""
    q, i, n = s[a], a + 1, len(s)
    while i < n:
        c = s[i]
        if c == "\\" and q == '"':
            i += 2
            continue
        if c == q:
            if q == "'" and s[i + 1:i + 2] == "'":
                i += 2
                continue
            return i + 1
        i += 1
    return n


def _multiline_scalar(s, a):
    """The end of the quoted value opened at s[a] when it runs past its line (_quoted_scalar_end), else None: a value closed on
    its own line keeps the line readers' reading."""
    if a >= len(s) or s[a] not in "'\"":
        return None
    e = _quoted_scalar_end(s, a)
    eol = s.find("\n", a)
    return e if eol != -1 and e > eol else None


def _fields(s, spans):
    _yaml_quoted_keys(s, spans)
    pos = 0
    while True:
        m = _FIELD.search(s, pos)
        if not m:
            return
        if m.group("n1") is not None:
            if _secret_name(m.group("n1")) and not _kept(m.group("v1")):
                e = _multiline_scalar(s, m.start("v1")) or m.end("v1")   # round 1 (3): "password": "FAKEa\n  FAKEz"
                spans.append((m.start("v1"), e))
                pos = m.end()   # never past e: a key on the next line of text that isn't YAML is still read
            else:
                pos = max(m.start("v1"), m.start() + 1)
        elif _secret_name(m.group("n2")):
            a, b = _yaml_value(s, m)
            e = max(b, _multiline_scalar(s, a) or b)   # password: 'FAKEa\nFAKEz', its next line not indented
            if e > a and not _kept(s[a:e]):
                spans.append((a, e))
            pos = max(b, m.end())
        else:
            pos = m.end()


def _mask_words(s, at, spans, depth, ml=False):
    """Mark the secret spans of shell text `s` (starting at offset `at`). Quoted words are read again inside (depth 2).
    `ml`: the reading where a closed quote may cross lines."""
    words = []   # a separator as its text; a word as (start, end, raw, plain)
    for m in (_SHELL_ML if ml else _SHELL).finditer(s):
        raw = m.group("word")
        if raw is None:
            words.append(m.group("sep"))
        else:
            quoted = "'" in raw or '"' in raw or "\\" in raw
            words.append((at + m.start(), at + m.end(), raw, _unquote(raw) if quoted else raw, quoted))
    word = lambda j: words[j] if 0 <= j < len(words) and not isinstance(words[j], str) else None
    tool, skip = None, 0
    for k, w in enumerate(words):
        if k < skip:
            continue   # already hidden as a header's value
        if isinstance(w, str):
            tool = None
            continue
        a, b, raw, plain, quoted = w
        nxt, prev, low = word(k + 1), word(k - 1), plain.lower()
        if "=" in raw:
            _assignments(raw, a, spans)
        if nxt is not None:
            if (low in SECRET_FLAGS or (low == "=" and prev and _secret_name(prev[3]))
                    or (len(low) > 1 and (low[-1] == "=" or (low[-1] == ":" and ("_" in low or "-" in low))) and _secret_name(low[:-1]))
                    or plain in ("Bearer", "BEARER") or (low == "bearer" and len(nxt[3]) >= 8)):   # "the bearer token" in prose stays
                if not _kept(nxt[2]):
                    spans.append((nxt[0], nxt[1]))
            elif low in USER_FLAGS and ":" in nxt[2]:   # curl -u user:password: the password
                c = nxt[2].find(":")
                if not _kept(nxt[2][c + 1:]):
                    spans.append((nxt[0] + c + 1, nxt[1]))
            elif nxt[3][:1] == "=" and len(nxt[3]) > 1 and _secret_name(plain) and not _kept(nxt[2][1:]):
                spans.append((nxt[0] + 1, nxt[1]))
        if low[:2] == "-u" and len(low) > 2 and ":" in raw and low[:3] != "-u=":   # curl -uuser:password
            if not _kept(raw[raw.find(":") + 1:]):
                spans.append((a + raw.find(":") + 1, b))
        if low.startswith(USER_EQ) and ":" in plain:   # --user=user:password, --proxy-user='user:password'
            exact, idx = _unquote_map(raw) if quoted else (plain, range(len(plain)))
            c = exact.find(":", exact.find("="))
            if c != -1 and c + 1 < len(exact) and not _kept(exact[c + 1:]):
                spans.append((a + idx[c + 1], a + idx[-1] + 1))
        h = SECRET_HEADER.match(plain) if ":" in plain else None
        if h:   # Codex, round 2: the header is the whole shell word, however it is quoted or glued ('Cookie: a=1;'sid='x')
            exact, idx = _unquote_map(raw) if quoted else (plain, range(len(plain)))
            h = SECRET_HEADER.match(exact)
        if h:
            if h.end() < len(exact) and not _kept(exact[h.end():]):
                spans.append((a + idx[h.end()], a + idx[-1] + 1))
            j = k + 1
            if h.end() == len(exact) or not quoted:
                # unquoted (or a value still to come): it runs to the end of the command; a cookie's own ; doesn't end it
                if h.end() == len(exact) and h.group("auth") and word(j) and AUTH_SCHEME.fullmatch(word(j)[3]):
                    j += 1
                while j < len(words) and (word(j) or (h.group("jar") and words[j] == ";")):
                    if word(j) and not _kept(words[j][2]):
                        spans.append((words[j][0], words[j][1]))
                    j += 1
            skip = j
            continue
        if tool == "sshpass":
            if plain == "-p" and nxt is not None:
                spans.append((nxt[0], nxt[1]))
            elif plain.startswith("-p") and len(plain) > 2:
                spans.append((a + 2, b))
            elif not plain.startswith("-") and not (prev and prev[3] == "-p"):
                tool = "done"   # sshpass's own options end at the command it runs (ssh -p 2222 stays)
        elif tool == "mysql" and plain.startswith("-p") and len(plain) > 2 and not _kept(raw[2:]):
            spans.append((a + 2, b))   # every -p<password>, not only the first
        base = plain.rpartition("/")[2]
        if base == "sshpass" and tool is None:
            tool = "sshpass"
        elif base in MYSQL_TOOLS:
            tool = "mysql"
        if depth < 2 and quoted and _TRIGGER.search(raw):
            for q in (_QUOTED_ML if ml else _QUOTED).finditer(raw):
                o = 2 if q.group(0).startswith("$'") else 1
                inner = q.group(0)[o:]
                if inner.endswith(q.group(0)[o - 1]) and len(q.group(0)) > o:
                    inner = inner[:-1]
                if _SEVERAL.search(inner) and _TRIGGER.search(inner):   # one word inside is the word itself, already read
                    _mask_words(inner, a + q.start() + o, spans, depth + 1, ml)


_BREAKS = re.compile(r"\r\n|[\n\r\x0b\x0c\x1c\x1d\x1e\x85  ]")


# Every shell-word rule needs one of these in the same line (a secret-named variable, flag or header, -p, -u, Bearer, sshpass or
# a MySQL tool), so the tokenizer only reads lines that have one, and a quoted part without one is not read again inside.
_TRIGGER = re.compile(r"(?i)(?=[tspacbm-])(?:token|secret|pass|api[_-]?key|access_key|private_key|auth|credential|session|cookie"
                      r"|bearer|-[pu]|sshpass|mysql|mariadb)")
# A closed quote that crosses a line (the shell's reading); one closed on its own line is skipped whole.
_SEVERAL = re.compile(r"[\s|;&]")   # quoted text with more than one shell word in it
_CROSSING = re.compile(r"'[^'\n]*'|\"(?:[^\"\\\n]|\\.)*\"|(?P<x>'[^']{0,4096}'|\"(?:[^\"\\]|\\[\s\S]){0,4096}\")")


def _blocks(s, matches):
    """Whole lines around each match, runs of neighbouring lines joined: [(start, end)], in order, each line once."""
    out = []
    for a, b in matches:
        a, b = s.rfind("\n", 0, a) + 1, s.find("\n", b)
        b = len(s) if b == -1 else b
        if out and a <= out[-1][1] + 1:
            out[-1] = (out[-1][0], max(out[-1][1], b))
        else:
            out.append((a, b))
    return out


def _trigger_lines(s):
    pos = 0
    while True:
        m = _TRIGGER.search(s, pos)
        if not m:
            return
        end = s.find("\n", m.end())
        yield m.start(), m.end()
        if end == -1:
            return
        pos = end + 1


# Codex, round 3: a backslash at the end of a line joins the next line to the command (API_TOKEN=\ then FAKE on the next line).
_CONTINUED = re.compile(r"(?<!\\)(?:\\\\)*\\\r?\n")
_OPEN_VALUE = re.compile(r"(?<![\w.])(?P<n>[A-Za-z_][\w.-]{0,63})=(?P<q>\$'|'|\")")


def _quoted_values(s, spans):
    """Codex, round 3: NAME='…', NAME="…" and NAME=$'…' for a secret NAME are read to their closing quote however far away it
    is, as the shell reads them, so a value longer than the 4096 characters a crossing quote is read for, or over many lines,
    is hidden whole; one never closed runs to the end of the text. Each value is read once and the search goes on after it."""
    pos, n = 0, len(s)
    while True:
        m = _OPEN_VALUE.search(s, pos)
        if not m:
            return
        pos = m.end()
        if not _secret_name(m.group("n")):
            continue
        a, q, e = m.end(), m.group("q")[-1], m.end()
        while True:
            e = s.find(q, e)
            if e == -1 or m.group("q") == "'":
                break
            k = e
            while k > a and s[k - 1] == "\\":
                k -= 1
            if (e - k) % 2 == 0:
                break
            e += 1
        e = n if e == -1 else e
        if e > a and not _kept(s[a:e]):
            spans.append((a, e))
        pos = max(pos, e + 1)


# Batch 5 (Codex review 4, c2 and c4): the shell's own words over the whole text, read once and with no length cap. A word keeps
# its quotes ('…', "…", $'…', one left open running to the end of the text), escapes and glued segments whole; a backslash before a
# line break joins the lines (inside a word it is part of it, between words only space). | || && ; & and a line break end a
# command. Every alternative eats at least one character and none can fail after it started, so finditer is linear.
_LW = re.compile(r"(?P<sep>\|\||&&|[|;&]|\n)|(?P<word>(?:'[^']*'?|\$'(?:[^'\\]|\\[\s\S])*'?|\"(?:[^\"\\]|\\[\s\S])*\"?"
                 r"|\\\r?\n|\\[\s\S]?|[^\s'\"\\|;&$]+|\$)+)")
_JOINS = re.compile(r"(?:\\\r?\n)*")
_DQ_RUN, _SQ_RUN, _UQ_RUN = re.compile(r"[^\"\\]+"), re.compile(r"[^'\\]+"), re.compile(r"[^'\"\\$]+")


def _logical_words(s, pos=0):
    """(start, end, first) for each shell word of s from `pos` (a word boundary), `first` when no word of the same command came
    before it. Line joins in front of a word are not part of it; a word that is only joins is none."""
    first = True
    for m in _LW.finditer(s, pos):
        if m.group("sep") is not None:
            first = True
            continue
        a, b = _JOINS.match(s, m.start(), m.end()).end(), m.end()
        if a < b:
            yield a, b, first
            first = False


def _shell_plain(raw, stop_at_close=False):
    """The shell's reading of one word: (text, lo, hi), where text[k] came from raw[lo[k]:hi[k]] (an escape keeps its backslash
    in its range). Line joins are dropped; inside "…" only \\$ \\` \\" \\\\ escape, inside $'…' only \\' and \\\\ (the rest are kept
    as written). `stop_at_close`: the reading ends at a closing quote followed by } ] ) > or , (a JSON value's end, not more URL)."""
    out, lo, hi, i, n = [], [], [], 0, len(raw)

    def put(c, a, b):
        out.append(c)
        lo.append(a)
        hi.append(b)
    while i < n:
        c = raw[i]
        if c == "'" or c == '"' or (c == "$" and raw[i + 1:i + 2] == "'"):
            q, i = ("'", i + 2) if c == "$" else (c, i + 1)
            ansi = c == "$"
            run = _SQ_RUN if ansi else _DQ_RUN
            while i < n and raw[i] != q:
                if c == "'":   # '…': nothing escapes
                    e = raw.find("'", i)
                    e = n if e == -1 else e
                    out.append(raw[i:e])
                    lo += range(i, e)
                    hi += range(i + 1, e + 1)
                    i = e
                    break
                m = run.match(raw, i)
                if m:
                    out.append(m.group(0))
                    lo += range(i, m.end())
                    hi += range(i + 1, m.end() + 1)
                    i = m.end()
                    continue
                if raw[i] == "\\" and i + 1 < n:   # a backslash
                    nx = raw[i + 1]
                    if not ansi and nx == "\n":
                        i += 2
                        continue
                    if not ansi and raw[i + 1:i + 3] == "\r\n":
                        i += 3
                        continue
                    if nx in ("'\\" if ansi else "$`\"\\"):
                        put(nx, i, i + 2)
                        i += 2
                        continue
                put(raw[i], i, i + 1)
                i += 1
            i += 1
            if stop_at_close and i < n and raw[i] in "}])>,":
                break
            continue
        if c == "\\":
            if raw[i + 1:i + 2] == "\n":
                i += 2
                continue
            if raw[i + 1:i + 3] == "\r\n":
                i += 3
                continue
            if i + 1 < n:
                put(raw[i + 1], i, i + 2)
                i += 2
                continue
        m = _UQ_RUN.match(raw, i)
        e = m.end() if m else i + 1
        out.append(raw[i:e])
        lo += range(i, e)
        hi += range(i + 1, e + 1)
        i = e
    return "".join(out), lo, hi


_JSON_ESC = re.compile(r"\\+/|\\u([0-9a-fA-F]{4})")


def _json_unescape(text, lo, hi):
    """`text` with JSON's escaped slashes (\\/, once or twice serialized) and \\uXXXX escapes (a surrogate pair is one character)
    read as the characters they stand for; lo and hi carried along, so each covers every escape character it came from."""
    if "\\" not in text:
        return text, lo, hi
    out, nlo, nhi, pos = [], [], [], 0
    for m in _JSON_ESC.finditer(text):
        a, b = m.start(), m.end()
        if a < pos:
            continue
        out.append(text[pos:a])
        nlo += lo[pos:a]
        nhi += hi[pos:a]
        if m.group(1) is None:
            ch = "/"
        else:
            cp = int(m.group(1), 16)
            pair = re.match(r"\\u([dD][c-fC-F][0-9a-fA-F]{2})", text[b:b + 6]) if 0xD800 <= cp < 0xDC00 else None
            if pair:
                cp, b = 0x10000 + ((cp - 0xD800) << 10) + (int(pair.group(1), 16) - 0xDC00), b + 6
            ch = chr(cp) if not 0xD800 <= cp < 0xE000 else "\ufffd"
        out.append(ch)
        nlo.append(lo[a])
        nhi.append(hi[b - 1])
        pos = b
    out.append(text[pos:])
    return "".join(out), nlo + lo[pos:], nhi + hi[pos:]


def _credential_word_spans(s, spans):
    """Batch 5 (c2): a credential's whole shell word, however many lines and glued segments it has. Only words that cross a line
    (or run past the 4096 characters the older readers read a crossing quote for) are read here: on one line those readers already
    see the whole word. NAME=… with a secret NAME (export "NAME=…", 'NAME'='…', --token=… too) hides from after the = to the word's
    end; --user=/--proxy-user= and -u/--user/--proxy-user's next word hide from after the first :; a secret flag (--token, …)
    hides the whole next word; a credential header's word (after -H or not) hides from after its name and scheme; a -d/--data*
    word hides from a secret name's = to its end. Bare $VAR references stay.
    PR A, Codex round 1 (2): every form the line readers (_mask_words) know is read here too: an attached -uuser:… or -Uuser:…
    (from after the first :), a MySQL tool's -p… and sshpass's -p… (after the -p) or the word after sshpass's -p, the word after
    Bearer, after a secret name= or name: word (or a lone = after a secret name), and =… right after a secret name."""
    prev = prev2 = tool = None   # the shell's reading, lowered, of the two words before (short ones), and the command's tool
    for a, b, first in _logical_words(s):
        raw = s[a:b]
        if first:
            prev = prev2 = tool = None
        flag, flag2 = prev, prev2
        short = b - a <= 32 and "\n" not in raw
        prev2, prev = prev, (_unquote(raw).lower() if short else None)
        was = tool
        if prev is not None:   # _mask_words' tool reading: sshpass's own options end at the command it runs
            if tool == "sshpass" and not prev.startswith("-") and flag != "-p":
                tool = "done"
            base = prev.rpartition("/")[2]
            if base == "sshpass" and tool is None:
                tool = "sshpass"
            elif base in MYSQL_TOOLS:
                tool = "mysql"
        if "\n" not in raw and b - a <= 4096:
            continue
        head, _, _ = _shell_plain(raw[:200])
        hl = head.lower()
        if (flag in SECRET_FLAGS or (was == "sshpass" and flag == "-p") or flag in ("bearer",)
                or (flag == "=" and flag2 is not None and _secret_name(flag2))
                or (flag is not None and len(flag) > 1 and (flag[-1] == "=" or (flag[-1] == ":" and ("_" in flag or "-" in flag)))
                    and _secret_name(flag[:-1]))):
            if not _kept(raw):
                spans.append((a, b))
            continue
        plain, lo, hi = _shell_plain(raw)
        hit = None
        if was in ("mysql", "sshpass") and head.startswith("-p") and len(plain) > 2:
            hit = 2   # mysql -p'…', sshpass -p'…'
        elif hl[:2] == "-u" and len(hl) > 2 and hl[:3] != "-u=" and ":" in plain:
            hit = plain.find(":") + 1   # curl -uuser:'…', -Uuser:"…"
        elif flag is not None and plain[:1] == "=" and len(plain) > 1 and _secret_name(flag):
            hit = 1   # TOKEN ='…'
        elif flag in USER_FLAGS or hl.startswith(USER_EQ):
            c = plain.find(":", plain.find("=") + 1 if hl.startswith(USER_EQ) else 0)
            hit = c + 1 if c != -1 else None
        elif flag in ("-d", "--data", "--data-raw", "--data-binary", "--data-urlencode", "--data-ascii"):
            i = plain.find("=")
            while i != -1:
                j = i
                while j > 0 and plain[j - 1] in _NAME_CH:
                    j -= 1
                if j < i and _secret_name(plain[j:i]):
                    hit = i + 1
                    break
                i = plain.find("=", i + 1)
        if hit is None:
            h = SECRET_HEADER.match(head) if ":" in head else None
            if h:
                hit = h.end()
            else:
                nm = re.match(r"-*([A-Za-z_][\w.-]{0,63})=", head)
                if nm and _secret_name(nm.group(1)):
                    hit = nm.end()
        if hit is not None and hit < len(plain) and not _kept(plain[hit:]):
            spans.append((a + lo[hit], b))


def mask_spans(s):
    """What masking replaces in `s`, merged and in order: (start, end, replacement), None meaning [hidden]. Overlapping spans
    (a word and the same value read inside its quotes, a key shape inside a hidden value) are one [hidden]."""
    spans = [(m.start("body"), m.end("body"), None) for m in PEM_BODY.finditer(s)]
    spans += [(m.start(), m.end(), mask(m.group(0))) for m in KEY_SHAPE.finditer(s)]
    words = []
    _urls(s, words)
    _word_urls(s, words)
    _fields(s, words)
    _quoted_values(s, words)
    if "\n" in s or len(s) > 4096:
        _credential_word_spans(s, words)   # batch 5 (c2): only words that cross a line or are longer than a crossing quote is read
    for a, b in _blocks(s, _trigger_lines(s)):
        _mask_words(s[a:b], a, words, 0)
    if "\n" in s:
        # the shell's reading: quotes that cross lines, and lines joined by a trailing backslash (Codex, round 3)
        crossing = ((m.start(), m.end()) for m in _CROSSING.finditer(s) if m.group("x") and "\n" in m.group("x"))
        joined = ((m.start(), m.end()) for m in _CONTINUED.finditer(s))
        for a, b in _blocks(s, heapq.merge(crossing, joined)):
            if _TRIGGER.search(s, a, b):
                _mask_words(s[a:b], a, words, 0, ml=True)
    spans += [(a, b, None) for a, b in words if b > a]
    spans.sort(key=lambda t: (t[0], -t[1]))
    out = []
    for a, b, rep in spans:
        if out and (a < out[-1][1] or (a == out[-1][1] and rep is None and out[-1][2] is None)):
            pa, pb, prep = out[-1]
            out[-1] = (pa, max(pb, b), prep if (a, b, rep) == (pa, pb, prep) else None)
        else:
            out.append((a, b, rep))
    return out


def mask_secrets(s):
    """Text with its secrets masked: a private key's body, key shapes (KEY_SHAPE, first 6 characters kept), passwords and
    tokens in URLs, chat webhook credentials, secret JSON/YAML fields, then every value the tokenizer finds next to a name, flag,
    header or tool that says it is a secret. A hidden value keeps its line breaks. Idempotent; rule, title and where are never
    passed here."""
    if not s:
        return s or ""
    spans = mask_spans(s)
    out, pos = [], 0
    for a, b, rep in spans:
        out += [s[pos:a], rep if rep is not None else HIDDEN + "".join(_BREAKS.findall(s, a, b))]
        pos = b
    return "".join(out) + s[pos:]


def mask_lines(s):
    """s.splitlines(), masked from one reading of the whole text (Codex, round 2): a quote or key that runs over several lines
    is hidden on each of them, and line N is still line N."""
    spans, out, k, pos = mask_spans(s or ""), [], 0, 0
    for ln in (s or "").splitlines(True):
        lo = pos
        hi = lo + len((ln.splitlines() or [""])[0])
        pos += len(ln)
        while k < len(spans) and spans[k][1] <= lo:
            k += 1
        parts, p, j = [], lo, k
        while j < len(spans) and spans[j][0] < hi:
            a, b, rep = spans[j]
            ca, cb = max(a, lo), min(b, hi)
            if cb > ca:
                parts += [s[p:ca], rep if rep is not None and (ca, cb) == (a, b) else HIDDEN]
                p = cb
            j += 1
        out.append("".join(parts) + s[p:hi])
    return out


def mask_stored(findings):
    """Batch 4 (R11): evidence written by an older version is masked in place once; `key` and `key0` never change."""
    for f in findings or ():
        if isinstance(f, dict) and isinstance(f.get("evidence"), str):
            f["evidence"] = mask_secrets(f["evidence"])
    return findings
