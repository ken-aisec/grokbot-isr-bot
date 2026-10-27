# Part of isr.py: runs inside isr.py's namespace (loaded by _isr_part); not a module on its own.
GITLEAKS_CONFIG = r"""[extend]
useDefault = true

[[rules]]
id = "anthropic-oauth-token"
description = "A Claude sign-in token (CLAUDE_CODE_OAUTH_TOKEN): gitleaks' own rules know only Anthropic API and admin keys"
regex = '''\b(sk-ant-oat\d{2}-[A-Za-z0-9_-]{40,})'''
secretGroup = 1
entropy = 3.5
keywords = ["sk-ant-oat"]

[[allowlists]]
description = "ISR Bot: package caches, lockfiles, headers and its own state"
paths = [
  '''(^|/)(go/pkg|pkg/mod|\.local/go|node_modules|\.cache|\.npm|\.venv|site-packages|dist-packages)/''',
  '''(^|/)\.config/(google-chrome[^/]*|chromium[^/]*|BraveSoftware)/''',
  '''(^|/)scoped_dir[^/]*/''',
  '''(^|/)chrome-profile/''',
  '''(^|/)(\.codex/auth\.json|\.claude/\.credentials\.json|\.config/gh/hosts\.yml|\.aws/credentials|\.git-credentials|\.netrc|\.docker/config\.json|\.npmrc)$''',
  '''(^|/)isr-bot/(state|reports|app|\.venv|scanners|bin)/''',
  '''chrome-cookie-seed\.json$''',
  '''\.h$''',
  '''(^|/)(package-lock\.json|pnpm-lock\.yaml|yarn\.lock|go\.sum|Cargo\.lock|marketplace\.json)$''',
]
regexTarget = "line"
regexes = [
  '''(?i)x-amz-(credential|signature|security-token)=''',
  '''(?i)[?&](AWSAccessKeyId|Signature|Expires)=''',
]

[[allowlists]]
description = "A bare 40-character hex string is a git commit, not a Sourcegraph token"
targetRules = ["sourcegraph-access-token"]
regexTarget = "secret"
regexes = ['''^[a-fA-F0-9]{40}$''']

[[allowlists]]
description = "A code name made of short lowercase words and version numbers (eapi-grok-4-3-internal, self.eapi_4_3_x_algo) is not a key"
targetRules = ["generic-api-key"]
regexTarget = "secret"
regexes = ['''^((([a-z]{1,12}|[0-9]{1,4})[._-])*[0-9]{1,4}([._-]([a-z]{1,12}|[0-9]{1,4}))+|(([a-z]{1,12}|[0-9]{1,4})[._-])+[0-9]{1,4})$''']

[[allowlists]]
description = "A paging cursor (next_token, nextPageToken, prev_cursor...) in an API result is not a key. Matched on the found text, not the line"
targetRules = ["generic-api-key"]
regexTarget = "match"
regexes = ['''(?i)^["']?(next|prev|previous|page|pagination|continuation)_?(page_?)?(token|cursor)\b''']
"""


# Batch 6 (B5, DQ-043/044): no name-based skips. The tests/, fixtures/ and *.test.* path skips and the line rule that hid a whole
# line next to "token" and a $VAR, <...> or xxxx (so token=$X api_key=<a real key> was hidden) are gone; each hit's own secret is
# judged by its content instead (gitleaks_example), the same check as ISR Bot's own rule (secret_kind). Fix round 3: an
# example-looking hit is scored as any other and only noted (annotate_example), never lowered or left out.
GITLEAKS_READ_LIMIT = 5_000_000   # gitleaks reads files up to --max-target-megabytes 5
GITLEAKS_FRAGMENT = 100_000       # gitleaks reads a file 100,000 bytes at a time (sources/file.go); a later piece's columns start over
GITLEAKS_REPORT_LIMIT = 256 * 1024 * 1024


class PrivateDir:
    """Batch 6 fix round 2 (Codex 2): a new folder of this run's own (mkdtemp: 0700, a random name) held open by a descriptor
    checked to be it, owned by this user and 0700. Files in it are made and read through that descriptor, never through a link,
    so nothing in state/ (which a Bot can write) is ever read as gitleaks' answer or given to it as its config."""
    def __init__(self, prefix):
        self.path = tempfile.mkdtemp(prefix=prefix)
        try:
            self.fd = os.open(self.path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        except OSError:
            shutil.rmtree(self.path, ignore_errors=True)
            raise
        st = os.fstat(self.fd)
        if not self.same() or st.st_uid != os.getuid() or stat.S_IMODE(st.st_mode) != 0o700:
            self.close()
            raise OSError("the private folder is not the one made")

    def same(self):
        """True while the folder's path still names the folder the descriptor holds."""
        try:
            a, b = os.fstat(self.fd), os.lstat(self.path)
        except OSError:
            return False
        return stat.S_ISDIR(b.st_mode) and (a.st_ino, a.st_dev) == (b.st_ino, b.st_dev)

    def write(self, name, data, dir_fd=None):
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o400,
                     dir_fd=self.fd if dir_fd is None else dir_fd)
        try:
            view = memoryview(data)
            while view:
                view = view[os.write(fd, view):]
        finally:
            os.close(fd)
        return os.path.join(self.path, name)

    def read(self, name, limit):
        """The bytes of `name` in the folder: a plain file of this user's with one link, opened without following a link, at
        most `limit`; None otherwise."""
        try:
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=self.fd)
        except OSError:
            return None
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid() or st.st_nlink != 1 or st.st_size > limit:
                return None
            data = b""
            while len(data) <= limit:
                chunk = os.read(fd, limit + 1 - len(data))
                if not chunk:
                    break
                data += chunk
            return data if len(data) <= limit else None
        except OSError:
            return None
        finally:
            os.close(fd)

    def changed_since(self):
        """The folder's change time now (nanoseconds): any file changed after this has a later or equal one."""
        return os.fstat(self.fd).st_ctime_ns

    def close(self):
        try:
            os.close(self.fd)
        except OSError:
            pass
        shutil.rmtree(self.path, ignore_errors=True)


def gitleaks_private(exe, source, priv, timeout=180):
    """gitleaks run on `source` with ISR Bot's config written into `priv` (a PrivateDir) and its report written there and read
    from there (PrivateDir.read): (the report's list of hits or None, gitleaks' error text)."""
    cfg = priv.write("gitleaks.toml", GITLEAKS_CONFIG.encode())
    code, _, err = run([exe, "detect", "--source", source, "--no-git", "--redact", "--config", cfg, "--report-format", "json",
                        "--report-path", os.path.join(priv.path, "report.json"), "--exit-code", "0", "--max-target-megabytes", "5"], timeout)
    if code != 0 or not priv.same():
        return None, err
    data = priv.read("report.json", GITLEAKS_REPORT_LIMIT)
    try:
        leaks = json.loads(data) if data is not None else None
    except ValueError:
        leaks = None
    return (leaks if isinstance(leaks, list) else None), err


def _read_unchanged(p, limit, since_ns):
    """The bytes of p (a plain file, opened without following a link, at most `limit`) when its change time, which only the
    kernel sets, is before `since_ns` and stays the same while it is read; None otherwise. Fix round 2 (Codex 2): so the bytes
    an example verdict is made on are the ones gitleaks read, with no second scan to compare (equal-entropy swaps fooled it)."""
    try:
        fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError:
        return None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_ctime_ns >= since_ns or st.st_size > limit:
            return None
        data = b""
        while len(data) <= limit:
            chunk = os.read(fd, limit + 1 - len(data))
            if not chunk:
                break
            data += chunk
        end = os.fstat(fd)
        same = (end.st_ctime_ns, end.st_mtime_ns, end.st_size) == (st.st_ctime_ns, st.st_mtime_ns, st.st_size) == (st.st_ctime_ns, st.st_mtime_ns, len(data))
        return data if same else None
    except OSError:
        return None
    finally:
        os.close(fd)


def _int_field(leak, k):
    v = leak.get(k)
    return v if isinstance(v, int) and not isinstance(v, bool) else None


def _leak_order(leak):
    """One order for gitleaks hits, whatever order the folder was listed or gitleaks reported them in: the file's path, then
    the line as a number (then column and rule, so hits on one line keep one order too)."""
    return (str(leak.get("File") or ""), _int_field(leak, "StartLine") or 0, _int_field(leak, "StartColumn") or 0, str(leak.get("RuleID") or ""))


def _fill(match, text):
    """The secret when `text` is gitleaks' Match with each REDACTED put back as one same secret; None otherwise. Both ends of
    text are fixed, so the secret's length, and the secret, follow from the length alone."""
    parts = match.split("REDACTED")
    k, rest = len(parts) - 1, len(text) - sum(len(p) for p in parts)
    if k < 1 or rest <= 0 or rest % k:
        return None
    s = text[len(parts[0]):len(parts[0]) + rest // k]
    return s if s.join(parts) == text else None


class FileBytes:
    """Fix round 3 (Codex 7): one file's bytes as read once, with where each of its lines starts found once (on first use, and
    before the GITLEAKS_FRAGMENT test) and each line decoded once, however many gitleaks hits it has; the whole text is decoded
    once too, for a key block's body. The bytes never change: a FileBytes is made from bytes already read."""
    def __init__(self, data):
        self.data, self._starts, self._lines, self._text = data, None, {}, None

    def starts(self):
        if self._starts is None:
            self._starts = [0] + [m.end() for m in re.finditer(b"\n", self.data)]
        return self._starts

    def line_index(self, i):
        """The line (from 0) byte i is on; a line break is on the line it ends."""
        return bisect.bisect_right(self.starts(), i) - 1

    def line(self, k):
        """Line k (from 0) as UTF-8 without its line break or a CR before it, and, when it isn't ASCII, where each of its
        characters starts in bytes from the line's start (one more for its end); None when it isn't UTF-8."""
        if k not in self._lines:
            st, data = self.starts(), self.data
            raw = data[st[k]:st[k + 1] - 1 if k + 1 < len(st) else len(data)]
            try:
                text = raw.decode("utf-8")
            except UnicodeDecodeError:
                self._lines[k] = None
            else:
                cols = None
                if not raw.isascii():
                    cols, at = [], 0
                    for c in text:
                        cols.append(at)
                        at += len(c.encode("utf-8"))
                    cols.append(at)
                self._lines[k] = (text.rstrip("\r"), cols)
        return self._lines[k]

    def text(self):
        """(the whole file as text, bytes that aren't UTF-8 replaced, and where each line starts in it); made once."""
        if self._text is None:
            t = self.data.decode("utf-8", "replace")
            self._text = (t, [0] + [m.end() for m in re.finditer("\n", t)])
        return self._text


def gitleaks_secret(leak, data):
    """(secret, its line, where it starts there) for one gitleaks hit (gitleaks_hit), `data` the file's bytes or a FileBytes."""
    got = gitleaks_hit(leak, data)
    return got[:3] if got else None


def gitleaks_hit(leak, data):
    """Fix round 1 (Codex 1): (secret, its whole source line, where it starts in that line, (its line from 0, where it starts
    there)) for one gitleaks hit, read from `data` (the file's bytes as ISR Bot read them once, as bytes or a FileBytes) at
    exactly the place gitleaks reported: StartLine/StartColumn to
    EndLine/EndColumn, in bytes. gitleaks counts a column from 1 on the first line of what it read at once and from 2 on the
    lines after (it counts the line break before), and trims line breaks from the ends of its Match. The bytes there must be
    gitleaks' Match exactly (it runs with --redact: each REDACTED is the same secret, so the secret follows from the length)
    and the secret must have gitleaks' Entropy. None, and the hit is kept as it is, unless exactly one place fits: no field, no
    Entropy, another text there, bytes that aren't UTF-8. No other text on the line is ever picked.
    Fix round 2 (Codex 1): gitleaks reads a file GITLEAKS_FRAGMENT bytes at a time (and on to a blank line, up to 25,000 more),
    and a later piece counts columns from where it starts, which can be the middle of a long line, at a place ISR Bot can't
    know. Its first piece starts at byte 0 and holds at least the first GITLEAKS_FRAGMENT bytes, so a hit is read only when the
    whole file fits in that, or its first line ends there (a hit from a later piece is on that piece's first line or after);
    any other hit keeps the severity gitleaks' rule gives it.
    Fix round 3 (Codex 7): the file's line starts are found once per file (FileBytes), never once per hit, and each line is
    decoded once. A secret over several lines (a key block) has no line or start of its own (None, None): only a one-line value
    can be a checksum by its line's format."""
    match = leak.get("Match")
    sl, el, sc, ec = (_int_field(leak, k) for k in ("StartLine", "EndLine", "StartColumn", "EndColumn"))
    want = leak.get("Entropy")
    buf = data if isinstance(data, FileBytes) else FileBytes(data) if isinstance(data, bytes) else None
    if (not isinstance(match, str) or "REDACTED" not in match or buf is None or None in (sl, el, sc, ec)
            or not isinstance(want, (int, float)) or isinstance(want, bool) or want < 0):
        return None
    data, starts = buf.data, buf.starts()
    if not (1 <= sl <= el <= len(starts)):
        return None
    nl = starts[sl] - 1 if sl < len(starts) else -1   # the line break that ends line sl
    if len(data) > GITLEAKS_FRAGMENT and not 0 <= nl < GITLEAKS_FRAGMENT:
        return None   # maybe a later piece's columns: never read as the first's
    # (start, end) count: line 1 is the first line of the first piece; a later line counts the line break before it
    counts = [(1, 0 if sl == el else 1)] if sl == 1 else [(2, 1)]
    found = set()
    for ds, de in counts:
        a, b = starts[sl - 1] + sc - ds, starts[el - 1] + ec - de
        if not (0 <= a < b <= len(data)):
            continue
        raw = data[a:b]
        lead = len(raw) - len(raw.lstrip(b"\n"))
        try:
            text = raw.strip(b"\n").decode("utf-8")
        except UnicodeDecodeError:
            continue
        secret = _fill(match, text)
        if secret is None or abs(shannon_entropy(secret) - float(want)) > 1e-5:   # gitleaks writes Entropy as a float32
            continue
        at = a + lead + len(match.split("REDACTED")[0].encode("utf-8"))
        found.add((at, at + len(secret.encode("utf-8"))))
    if len(found) != 1:
        return None
    s, e = found.pop()
    ks, ke = buf.line_index(s), buf.line_index(e)
    got = buf.line(ks)
    if got is None:
        return None
    line, cols = got
    off = s - starts[ks]
    if cols is not None:
        j = bisect.bisect_left(cols, off)
        if j == len(cols) or cols[j] != off:
            return None
        off = j
    try:
        secret = data[s:e].decode("utf-8")
    except UnicodeDecodeError:
        return None
    return (secret, line, off, (ks, off)) if ks == ke else (secret, None, None, (ks, off))


def shannon_entropy(s):
    """Shannon entropy of s per byte of UTF-8, as gitleaks computes its Entropy."""
    import math
    if not s:
        return 0.0
    counts, n = {}, len(s.encode("utf-8"))
    for c in s:
        counts[c] = counts.get(c, 0) + 1
    return -sum(k / n * math.log2(k / n) for k in counts.values())


def gitleaks_example(leak, datas, since_ns):
    """Why a gitleaks hit's own secret, read at gitleaks' place in the file's bytes (gitleaks_secret), looks like an example
    value (secret_kind: a whole placeholder or environment-variable reference, a key block whose body isn't a key, a checksum
    by its line's format), or "". The file's bytes are read once per run (`datas`): a plain file, never through a link, at most
    GITLEAKS_READ_LIMIT, and (fix round 2, Codex 2) unchanged since before gitleaks started (`since_ns`, _read_unchanged), so
    they are the bytes gitleaks read. Anything that can't be read that way keeps the hit as gitleaks gave it. Fix round 3
    (Codex 1, 2, 7): it only adds a note (annotate_example), never lowers or leaves out a hit; the file is held as a FileBytes,
    so its lines are found once for all its hits, and a key block is judged in the whole file's text, as masking reads it."""
    return _example_why(_gitleaks_found(leak, datas, since_ns))


def _gitleaks_found(leak, datas, since_ns):
    """v0.8.2 (item 1): (gitleaks_hit's answer, the file's FileBytes) for one hit, its bytes read as gitleaks_example says
    (once per file per run, into `datas`); None when it can't be read that way."""
    p = leak.get("File")
    if not isinstance(p, str) or not p:
        return None
    if p not in datas:
        data = _read_unchanged(p, GITLEAKS_READ_LIMIT, since_ns)
        datas[p] = FileBytes(data) if data is not None else None
    buf = datas[p]
    found = gitleaks_hit(leak, buf) if buf is not None else None
    return (found, buf) if found else None


def _example_why(got):
    """gitleaks_example's answer for _gitleaks_found's `got`."""
    if not got:
        return ""
    (secret, line, at, (k, col)), buf = got
    block = None
    if PEM_HEAD.match(secret.strip()):
        text, lines = buf.text()
        block = (text, lines[k] + col + (len(secret) - len(secret.lstrip())), True)
    return secret_kind(secret, line=line, at=at, block=block)[1]


OWN_TOKEN = {}   # v0.8.2 (item 2): "on" while an audit runs; "fp": the fingerprint of this computer's own gh token, once looked up


def own_gh_token():
    """The token gh signs in with on this computer (`gh auth token` reads gh's own config or GH_TOKEN; it calls no API), or None.
    Only its fingerprint is kept (own_token_of); the value is never printed, logged, stored or passed anywhere else."""
    exe = shutil.which("gh")
    if not exe:
        return None
    code, out_s, _ = run([exe, "auth", "token"], 10)
    lines = out_s.strip().splitlines()
    return lines[0].strip() if code == 0 and len(lines) == 1 and lines[0].strip() else None


def own_token_of(fp):
    """"gh" when fingerprint `fp` is this computer's own gh token, else None. Looked up only while an audit runs, and then once,
    when the first secret is found (so a run that finds none never asks gh)."""
    if not fp or "on" not in OWN_TOKEN:
        return None
    if "fp" not in OWN_TOKEN:
        OWN_TOKEN["fp"] = secret_fp(own_gh_token())
    return "gh" if fp == OWN_TOKEN["fp"] else None


def fp_marks(fp):
    """What a found secret's record keeps: its fingerprint (this run only, drop_fingerprints) and, when it is this computer's
    own gh token, own_token "gh" (kept: a later run never compares fingerprints made in another). {} without a fingerprint."""
    if not fp:
        return {}
    own = own_token_of(fp)
    return {"fp": fp, **({"own_token": own} if own else {})}


def drop_fingerprints(fs):
    """D1 (v0.8.2): fingerprints are for this run's counts and owner split only, never stored. A finding keeps its counts (in its
    evidence) and its own_token mark; its member hits lose "fp", ISR-S001's per-hit list (secret_hits) goes."""
    for f in fs:
        if not isinstance(f, dict):
            continue
        f.pop("secret_hits", None)
        if isinstance(f.get("member_hits"), list):
            f["member_hits"] = [{k: v for k, v in m.items() if k != "fp"} if isinstance(m, dict) else m for m in f["member_hits"]]
    return fs


# v0.8.2 (item 5): a tool's output spill file that holds a whole environment dump (set -x, env, a shell-state dump) with a key in
# it. Cursor's layout: ~/.cursor/projects/<p>/agent-tools, .../terminals and /workspace/agent-tools
SPILL_PLACES = ("agent-tools", "terminals")
SPILL_READ_LIMIT = 20_000_000   # the fix plan's read limit; ISR-S001 reads files up to 300,000 bytes
SPILL_MIN_NAMES, SPILL_MIN_SHELL = 15, 3
SPILL_SHELL = frozenset(("PATH", "HOME", "SHELL", "USER", "LOGNAME", "PWD", "HOSTNAME", "LANG", "TERM", "SHLVL"))
SPILL_SECRET_NAME = re.compile(r"TOKEN|SECRET|PASSWORD|PASSWD|API_KEY|PRIVATE_KEY|CREDENTIAL")
SPILL_ASSIGN = re.compile(r"^[ \t]*(?:\++[ \t]+)?(?:export[ \t]+|declare[ \t]+-x[ \t]+)?([A-Za-z_][A-Za-z0-9_]*)=([^\n]*)", re.M)


def spill_place(p):
    """v0.8.2 (item 5): a tool's output spill file: a .txt directly in a folder named agent-tools or terminals."""
    return p.endswith(".txt") and os.path.basename(os.path.dirname(p)) in SPILL_PLACES


def spill_dump(text):
    """v0.8.2 (item 5): [(line, variable name or None, fingerprint)] for each real secret in `text` when it holds a whole
    environment dump, else []. A dump: NAME=value lines (`export `, `declare -x ` or xtrace's `+ ` in front allowed) with at least
    15 different names, 3 of them the shell's own (SPILL_SHELL). A secret: a value SCRUB's key shapes match, anywhere in the file,
    or else the value of a variable whose name says TOKEN, SECRET, PASSWORD... (16 characters or more, not a path); either only
    when secret_kind calls it real, so a placeholder (xxxx) or a $VAR reference never counts. Fingerprints only, never a value."""
    assigns = list(SPILL_ASSIGN.finditer(text))
    names = {a.group(1) for a in assigns}
    if len(names) < SPILL_MIN_NAMES or len(names & SPILL_SHELL) < SPILL_MIN_SHELL:
        return []
    lines, n, at = [], 1, 0
    for a in assigns:
        n += text.count("\n", at, a.start()); at = a.start()
        lines.append(n)
    out, shaped, i, n, at = [], set(), 0, 1, 0
    for m in SCRUB.finditer(text):
        while i < len(assigns) and assigns[i].end(2) <= m.start():
            i += 1
        a = i if i < len(assigns) and assigns[i].start(2) <= m.start() else None
        if a is not None:
            shaped.add(a)   # a key shape in its value: the name rule isn't asked
        if secret_kind(m.group(0), block=(text, m.start(), True))[0] != "real":
            continue
        n += text.count("\n", at, m.start()); at = m.start()
        out.append((n, assigns[a].group(1) if a is not None else None, secret_fp(m.group(0))))
    for k, a in enumerate(assigns):
        if k in shaped or not SPILL_SECRET_NAME.search(a.group(1).upper()):
            continue
        v = a.group(2).strip()
        if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
            v = v[1:-1]
        if len(v) >= 16 and not v.startswith(("/", "~/", "./")) and secret_kind(v)[0] == "real":
            out.append((lines[k], a.group(1), secret_fp(v)))
    return out


def spill_findings(spills):
    """v0.8.2 (item 5): one ISR-S006 per folder for {folder: {spill file: spill_dump's list}}. Its evidence names each secret by
    its variable and says which is this computer's own gh token (own_token_of); counts by fingerprint, no value, no fingerprint
    kept. Its key is made from its folder (ident): files and copies coming and going never make a new/fixed pair."""
    out = []
    count = lambda k, one, many: f"{k} {one if k == 1 else many}"
    for d, files in sorted(spills.items()):
        hits = [(p, ln, name, fp) for p, got in files.items() for ln, name, fp in got]
        named = {}
        for _, _, name, fp in hits:
            if name and fp not in named:
                named[fp] = name
        own = {fp for fp in {h[3] for h in hits} if own_token_of(fp)}
        labels = sorted({named[fp] + (SPILL_OWN_NOTE if fp in own else "") for fp in named})
        bare = len({h[3] for h in hits} - set(named))
        what = ", ".join(labels + ([f"{bare} with no name"] if bare else []))
        f = finding("ISR-S006", SPILL_TITLE, "high", ["ASI03", "LLM02"], d,
                    f"{count(len(files), 'file', 'files')}, {count(len({h[3] for h in hits}), 'secret', 'secrets')} ({what}), "
                    f"{count(len({(p, ln, fp) for p, ln, _, fp in hits}), 'copy', 'copies')}",
                    SPILL_FIX + (" " + SPILL_OWN_FIX if own else ""), ident="spill-dump")
        f["affected_files"] = sorted(files)
        if own:
            f["own_token"] = "gh"
        out.append(f)
    return out


GROUPED_DIRS = ("/agent-transcripts", "/agent-tools", "/.cursor/projects")
TOOL_CACHE_DIRS = ("/agent-tools",)


VENDOR_CODE = ("/plugins/", "/plugin-cache/", "/managed-skills/", "/skills-library/", "/.agents/skills/", "/.codex/skills/", "/.grok/bundled/")


def secret_severity(path, generic):
    """Documentation-style hits in shipped plugin code are medium; real token types in tool caches are high
    (usually someone else's token inside an API response); anywhere else a real token type is critical."""
    if generic or vendor_root_path(path):   # item 8 (R3): a real vendor folder, never a name in the path
        return "medium"
    if any(x in path for x in TOOL_CACHE_DIRS):
        return "high"
    return "critical"


def group_dir(fpath):
    """Folders that fill up with machine output are grouped at their top, not per subfolder."""
    fpath = fpath or ""
    for g in GROUPED_DIRS:
        i = fpath.find(g + "/")
        if i >= 0:
            return fpath[:i + len(g)]
    return os.path.dirname(fpath)


def group_why(d):
    """The fix line of a grouped ISR-S002 on the folder `d`."""
    return ("Tool-overflow cache: oversized API results (Notion pages, GitHub payloads) land here and any Bot can read them. "
            "Hits are often third-party tokens inside those payloads. Check for any of yours, then clear the folder; it refills on its own."
            if any(x in d for x in TOOL_CACHE_DIRS) else "Check which of these tokens are still live and revoke them, then clear the folder or move it off "
            "the shared computer. Transcripts and tool output often capture tokens by accident.")


def gitleaks_findings(roots, notes):
    exe = tool("gitleaks")
    if not exe:
        scanner_absent(notes, "gitleaks", "gitleaks not installed: secrets checked with ISR Bot's rules only.")
        return []
    out = []
    # the owner's copy of the config gitleaks is given; fix round 2 (Codex 2): gitleaks reads its own, in a private folder
    with open(state_path("gitleaks.toml"), "w") as f:
        f.write(GITLEAKS_CONFIG)
    for r in roots:
        r = os.path.expanduser(r)
        if not os.path.isdir(r):
            continue
        try:
            priv = PrivateDir("isr-bot-gitleaks-")
        except OSError as e:
            fail_note(notes, f"gitleaks FAILED on {r} (no private folder for its report: {e.strerror or e}): secrets there were NOT checked by gitleaks.")
            continue
        try:
            since = priv.changed_since()   # every file changed after this is read as gitleaks may not have
            got, err = gitleaks_private(exe, r, priv)
        finally:
            priv.close()
        if got is None:
            reason = next((l for l in re.sub(r"\x1b\[[0-9;]*m", "", err).splitlines() if "FTL" in l or "error" in l.lower()), err.strip()[:160] or "no report written")
            fail_note(notes, f"gitleaks FAILED on {r} ({reason.strip()[-160:]}): secrets there were NOT checked by gitleaks.")
            continue
        per_file, decoys, skipped_tool, examples, datas, marks = {}, canary_paths(), 0, {}, {}, {}
        for leak in got:
            if not isinstance(leak, dict):
                continue
            if os.path.abspath(str(leak.get("File") or "")) in decoys:
                continue
            if is_platform_secret_store(str(leak.get("File") or "")):
                continue                                  # Decision, Oct 13: the platform's masked-secret store is one Platform note (ISR-I009)
            if in_toolchain_tree(str(leak.get("File") or "")):
                skipped_tool += 1
                continue                                  # item 8 dry run: test vectors in a language toolchain or package store                                  # ISR Bot's own decoys (their names are this install's, not in this config)
            per_file.setdefault(leak.get("File"), []).append(leak)
            # batch 6 (B5); fix round 3 (Codex 1, 2): an example-looking hit is grouped, counted and scored as any other; its why
            # only adds a note to a finding all of whose hits look like that (_note_examples)
            got_ = _gitleaks_found(leak, datas, since)
            why = _example_why(got_)
            if why:
                examples[id(leak)] = why
            # v0.8.2 (items 1, 2): each hit's secret by its fingerprint, so copies of one count once (the value is not kept)
            marks[id(leak)] = fp_marks(secret_fp(got_[0][0])) if got_ else {}
        datas.clear()
        member = lambda l, d: dict({"file": os.path.abspath(str(l.get("File") or d)), "line": l.get("StartLine"),
                                 "rule_id": l.get("RuleID", "secret"), "example": examples.get(id(l))}, **marks.get(id(l), {}))
        by_dir = {}
        for fpath in per_file:
            by_dir.setdefault(group_dir(fpath), []).append(fpath)
        for d, files in by_dir.items():
            if len(files) >= 4 or any(x in d for x in GROUPED_DIRS):  # transcripts, tool output: one finding per folder
                leaks = sorted((l for fp in files for l in per_file.pop(fp)), key=_leak_order)   # named in one order, not gitleaks' listing
                kinds = sorted({l.get("RuleID", "secret") for l in leaks})
                generic = all(k.startswith("generic") for k in kinds)
                sev = secret_severity(d + "/", generic)
                why = group_why(d)
                # name the files and lines: the folder alone sent the owner re-running gitleaks to find the hit. The files in
                # these folders come and go, so the finding keeps one name (ident) while its evidence changes
                locs = [f"{os.path.relpath(l.get('File') or d, d)}:{l.get('StartLine')}" for l in leaks]
                at = ", ".join(locs[:3]) + (f" and {len(locs) - 3} more" if len(locs) > 3 else "")
                out.append(_note_examples(finding("ISR-S002", f"gitleaks: secrets in {len(files)} {'file' if len(files) == 1 else 'files'} under {os.path.basename(d)}", sev,
                                                  ["ASI03", "LLM02"], d, f"{len(leaks)} hit(s): {', '.join(kinds)[:60]} at {at}", why, source="gitleaks",
                                                  ident="gitleaks:" + ",".join(kinds)), leaks, examples))
                # b8i4 fix round 2 (Codex 4): every file it stands for, by path (its `where` is their folder), so a change to one
                # of them is held and never rolled in
                out[-1]["affected_files"] = sorted(os.path.abspath(str(fp)) for fp in files if fp)
                # v0.8.1 (§3.4): each hit's file, line and kind (no secret text), so the gate can split a group by owner
                out[-1]["member_hits"] = [member(l, d) for l in leaks]
                mark_own(out[-1], out[-1]["member_hits"])
        for fpath, leaks in per_file.items():
            kinds = sorted({l.get("RuleID", "secret") for l in leaks})
            generic = all(k.startswith("generic") for k in kinds)
            out.append(_note_examples(finding("ISR-S002", "gitleaks: secrets in file", secret_severity(fpath or "", generic), ["ASI03", "LLM02"],
                                              f"{fpath}:{leaks[0].get('StartLine')}", f"{len(leaks)} hit(s): {', '.join(kinds)[:100]}",
                                              "Check whether these are live credentials. Revoke live ones, then delete or scrub the file.", source="gitleaks",
                                              path=fpath if isinstance(fpath, str) and fpath.startswith("/") else None), leaks, examples))
            # v0.8.2 (item 1): its hits too, so its copies are counted (one file: the gate gives the same answer as for its path)
            if isinstance(fpath, str) and fpath.startswith("/"):
                out[-1]["member_hits"] = [member(l, fpath) for l in leaks]
                mark_own(out[-1], out[-1]["member_hits"])
        if examples:
            notes.append(f"gitleaks: {len(examples)} hit(s) look like example or checksum values; each is scored as any other hit "
                         "and noted, to check (anyone can write a real key that way).")
        if skipped_tool:
            notes.append(f"gitleaks: {skipped_tool} hit(s) in language toolchains and package stores (Go, pnpm, ...) not listed: "
                         "those are the tools' own test keys. A key TruffleHog proves live is still reported wherever it is.")
    return out


def _note_examples(f, leaks, examples):
    """Fix round 3 (Codex 1, 2): finding f (for gitleaks hits `leaks`) with the example note (annotate_example) when every one
    of its hits looks like an example or checksum value (`examples`: id(hit) -> why); f as it is otherwise."""
    whys = [examples.get(id(l)) for l in leaks]
    return annotate_example(f, whys[0]) if whys and all(whys) else f


def regroup_s002(f, kept, status, ran):
    """v0.8.1 (§3.4): a grouped ISR-S002 made again from only its `kept` member hits (the owner's), as gitleaks_findings makes
    one: files, title, evidence, kinds, generic-or-real severity, example note, and the key from its kinds (ident). TruffleHog's
    answers (`status`, applied when `ran`) are those for the kept files only, so another file's live key never makes it live."""
    d = f["where"]
    kept = sorted(kept, key=lambda m: (str(m.get("file")), str(m.get("line"))))
    files = sorted({m["file"] for m in kept})
    kinds = sorted({m.get("rule_id") or "secret" for m in kept})
    locs = [f"{os.path.relpath(m['file'], d)}:{m.get('line')}" for m in kept]
    at = ", ".join(locs[:3]) + (f" and {len(locs) - 3} more" if len(locs) > 3 else "")
    g = finding("ISR-S002", f"gitleaks: secrets in {len(files)} {'file' if len(files) == 1 else 'files'} under {os.path.basename(d)}",
                secret_severity(d + "/", all(k.startswith("generic") for k in kinds)), f.get("owasp") or ["ASI03", "LLM02"], d,
                f"{len(kept)} hit(s): {', '.join(kinds)[:60]} at {at}", group_why(d), source="gitleaks", ident="gitleaks:" + ",".join(kinds))
    g.update(affected_files=files, member_hits=kept)
    whys = [m.get("example") for m in kept]
    g = mark_own(annotate_example(g, whys[0]) if all(whys) else g, kept)
    return key_status_severity([g], {p: ks for p, ks in status.items() if p in files}, ran)[0]


_LEAK_FIELDS = ("RuleID", "StartLine", "EndLine", "StartColumn", "EndColumn", "Match", "Secret", "Entropy")


def _leak_marks(leaks):
    """What gitleaks reported for each hit in one file, but the file's name, in an order two scans can be compared in."""
    return sorted(json.dumps([l.get(k) for k in _LEAK_FIELDS], sort_keys=True, default=str) for l in leaks)


def metadata_bound(exe, per_file):
    """Batch 6 fix round 1 (Codex 2): {file: sha256} for the files among `per_file` (gitleaks' hits by file, from the scan of
    the folders) that this run verified by content (VERIFIED_METADATA holds the bytes it verified) and on whose verified bytes
    gitleaks gives exactly the same hits. Verification happens before gitleaks reads the folders, so the file it scanned may
    not be the one verified; the hits are bound to the verified bytes only when a private copy of them, written from memory
    (a new 0700 folder, each file 0400, never through a link), gives the same ones and is unchanged after the scan (inode,
    change time, size, bytes). metadata_hit_note then also needs the file itself to have those bytes still. Anything else binds
    nothing, and the hit counts."""
    files = [(fp, VERIFIED_METADATA[os.path.normpath(fp)]) for fp in per_file
             if isinstance(fp, str) and fp.startswith("/") and os.path.normpath(fp) in VERIFIED_METADATA]
    if not files:
        return {}
    leaks = scan_copies(exe, [(os.path.basename(fp), data) for fp, data in files])
    if leaks is None:
        return {}
    return {fp: hashlib.sha256(data).hexdigest() for (fp, data), mine in zip(files, leaks)
            if mine and _leak_marks(mine) == _leak_marks(per_file[fp])}


def scan_copies(exe, named):
    """gitleaks' hits on private copies of some bytes, one list per (name, bytes) in `named`, in order; None when anything
    is off. The copies are written from memory (in a PrivateDir, each file 0400 in its own 0700 folder under its name, made
    through the folders' descriptors, never through a link) and must be unchanged after the scan (inode, change time, size,
    bytes). Fix round 2 (Codex 2): gitleaks' config and report are in a second private folder, the report read from there
    (PrivateDir.read), never from state/. (metadata_bound's private scan.)"""
    src = priv = None
    try:
        src = PrivateDir("isr-bot-metadata-")    # the copies
        priv = PrivateDir("isr-bot-gitleaks-")   # gitleaks' config and report
        copies = []
        for i, (name, data) in enumerate(named):
            os.mkdir(str(i), 0o700, dir_fd=src.fd)
            dfd = os.open(str(i), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=src.fd)
            try:
                src.write(name, data, dir_fd=dfd)
            finally:
                os.close(dfd)
            copies.append((data, os.path.join(src.path, str(i), name)))

        def marks():
            return [(x, st.st_ino, st.st_dev, st.st_ctime_ns, st.st_mtime_ns, st.st_size, st.st_mode, st.st_nlink)
                    for x in [src.path] + [y for _, q in copies for y in (os.path.dirname(q), q)] for st in (os.lstat(x),)]
        before = marks()
        leaks, _ = gitleaks_private(exe, src.path, priv)
        if leaks is None or not src.same() or marks() != before or any(_read_plain(q, len(data)) != data for data, q in copies):
            return None
        return [[l for l in leaks if isinstance(l, dict) and os.path.normpath(str(l.get("File") or "")) == q] for _, q in copies]
    except (OSError, ValueError):
        return None
    finally:
        for d in (src, priv):
            if d is not None:
                d.close()


TOOLCHAIN_TREE = re.compile(r"/\.local/go[^/]*/|/\.local/share/pnpm/|/go/pkg/mod/|/\.rustup/toolchains/|/\.cargo/registry/")


def in_toolchain_tree(p):
    """Item 8 dry run (Oct 13): a Go toolchain kept as a rollback (~/.local/go.prev-1.27.1) and the pnpm store gave 11 gitleaks
    lines from their own crypto test vectors. SKIP_PATH_PARTS already skipped ~/.local/go/ for the other stages."""
    return bool(TOOLCHAIN_TREE.search(os.path.normpath(os.path.abspath(p)) + "/"))


def installed_python_packages():
    """Packages in the computer's own Python, not ISR Bot's venv."""
    py = "/usr/bin/python3" if os.path.exists("/usr/bin/python3") else (shutil.which("python3") or "python3")
    code, out_s, _ = run([py, "-m", "pip", "list", "--format", "json", "--disable-pip-version-check"], 60)
    try:
        return {p["name"]: p["version"] for p in json.loads(out_s)}
    except (ValueError, KeyError, TypeError):
        return {}


def user_python_packages():
    """Packages the user (or a Bot) installed themselves with pip. Everything else came with the computer."""
    py = "/usr/bin/python3" if os.path.exists("/usr/bin/python3") else (shutil.which("python3") or "python3")
    code, out_s, _ = run([py, "-m", "pip", "list", "--user", "--format", "json", "--disable-pip-version-check"], 60)
    try:
        return {p["name"].lower() for p in json.loads(out_s)}
    except (ValueError, KeyError, TypeError, AttributeError):
        return set()


def package_findings(notes):
    exe = tool("pip-audit")
    if not exe:
        scanner_absent(notes, "pip-audit", "pip-audit not installed: installed Python packages not checked for known vulnerabilities.")
        return []
    pkgs = installed_python_packages()
    if not pkgs:
        return []
    req = state_path("installed-requirements.txt")
    with open(req, "w") as f:
        f.write("\n".join(f"{n}=={v}" for n, v in sorted(pkgs.items())))
    code, out_s, err = run([exe, "-r", req, "--no-deps", "--disable-pip", "-f", "json", "--progress-spinner", "off"], 120)
    out = []
    try:
        data = json.loads(out_s)
        if not isinstance(data, dict):
            raise ValueError
    except ValueError:
        fail_note(notes, f"pip-audit FAILED ({(err.strip().splitlines() or ['no answer'])[-1][:120]}): installed Python packages were NOT checked this run.")
        return []
    mine = user_python_packages()
    for d in (data.get("dependencies", []) if isinstance(data, dict) else []):
        vulns = d.get("vulns", [])
        if not vulns:
            continue
        fixes = sorted({fv for v in vulns for fv in v.get("fix_versions", [])}, key=vtuple)
        ids = list(dict.fromkeys(v.get("id", "") for v in vulns))
        if str(d.get("name", "")).lower() not in mine:      # came with the computer: the platform's to update, not the user's
            out.append(finding("ISR-D001", f"Built-in Python package {d.get('name')} {d.get('version')} has known holes", "low", ["ASI04", "AST02"],
                               f"system python package {d.get('name')}", f"{len(ids)} known: {', '.join(ids[:4])}{'…' if len(ids) > 4 else ''}",
                               "It came with the computer and every Bot shares it. The platform's updates fix it; ISR Bot doesn't touch system packages.",
                               source="pip-audit", ident=f"{d.get('name')} {d.get('version')}"))
            continue
        out.append(finding("ISR-D001", f"Vulnerable package {d.get('name')} {d.get('version')}", "high", ["ASI04", "AST02"],
                           f"python package {d.get('name')}", f"{len(ids)} known: {', '.join(ids[:4])}{'…' if len(ids) > 4 else ''}",
                           f"Upgrade to {fixes[-1]} or later." if fixes else "No fixed version yet; remove it if nothing needs it.",
                           source="pip-audit"))
    save_json(state_path("package_vulns.json"), {"at": now(), "packages": len(pkgs), "findings": out})
    return out


def scanners_python():
    """ISR Bot's scanner venv Python (scanners/bin/python), only when it leads to the pinned, root-owned interpreter
    (trusted_interpreter). run() starts it as that interpreter, never through the link."""
    py = os.path.join(scanner_bin(), "python")
    return py if os.path.lexists(py) and trusted_interpreter(py) else None


def self_findings(notes):
    """ISR Bot holds its own tools to the same standard: known holes in the scanners' packages, and whether they were
    installed from the checksum lock."""
    py, exe, out = scanners_python(), tool("pip-audit"), []
    update_notes(notes)
    if not py:
        # Codex, batch 3 round 1: a missing or refused scanner Python returned here with the stage marked finished, so last
        # run's ISR-W001 lines read as fixed. When there is a Python that isn't trusted, or there were W001 results to keep,
        # this is "not checked", never "clean". A computer that never had the scanners stays a plain skip, as before.
        if os.path.lexists(os.path.join(scanner_bin(), "python")) or carry(("ISR-W001",)):
            fail_note(notes, "ISR Bot's own tools were NOT checked for known holes this run (its scanner Python is missing or "
                             "isn't the computer's own); the last results are kept.")
        return out
    if not os.path.isfile(os.path.join(os.path.dirname(os.path.dirname(py)), "LOCKED")):
        out.append(finding("ISR-W002", "ISR Bot's scanners were installed without the checksum lock", "low", ["ASI04", "AST02"], "isr-bot scanners",
                           "no LOCKED marker", "Run `bash /workspace/isr-bot/app/scripts/install.sh --scanners` again; it installs only from the lock, and stops and says why if this computer's Python doesn't fit it."))
    if not exe:
        if scanner_unavailable("pip-audit")[0]:   # batch 3: pip-audit's own line says why; this stage's last results are kept too
            fail_note(notes, "ISR Bot's own tools were NOT checked for known holes this run (pip-audit didn't run); the last results are kept.")
        return out
    code, out_s, _ = run([py, "-m", "pip", "list", "--format", "json", "--disable-pip-version-check"], 60)
    try:
        pkgs = {p_["name"]: p_["version"] for p_ in json.loads(out_s)}
    except (ValueError, KeyError, TypeError):
        fail_note(notes, "ISR Bot's own tools FAILED to list their packages: they were NOT checked this run.")
        return out
    req = state_path("scanner-requirements.txt")
    with open(req, "w") as f:
        f.write("\n".join(f"{n}=={v}" for n, v in sorted(pkgs.items()) if n.lower() != "skillspector"))
    code, out_s, err = run([exe, "-r", req, "--no-deps", "--disable-pip", "-f", "json", "--progress-spinner", "off"], 90)
    try:
        data = json.loads(out_s)
        deps = data.get("dependencies", [])
    except (ValueError, AttributeError):
        fail_note(notes, f"ISR Bot's own tools FAILED their package check ({(err.strip().splitlines() or ['no answer'])[-1][:100]}): NOT checked this run.")
        return out
    for d in deps:
        if d.get("vulns"):
            ids = list(dict.fromkeys(v.get("id", "") for v in d["vulns"]))
            out.append(finding("ISR-W001", f"ISR Bot's own tool needs an update: {d.get('name')} {d.get('version')}", "low", ["ASI04", "AST02"],
                               "isr-bot scanners", f"{len(ids)} known: {', '.join(ids[:3])}",
                               "Update ISR Bot: each release carries newer pinned scanners. This package lives only in ISR Bot's own folder.", source="pip-audit"))
    return out
