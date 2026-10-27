# Part of isr.py: runs inside isr.py's namespace (loaded by _isr_part); not a module on its own.
def now():
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def home():
    return os.environ.get("ISR_BOT_HOME", "/workspace/isr-bot")


def state_path(*p):
    d = os.path.join(home(), "state")
    os.makedirs(d, exist_ok=True)
    return os.path.join(d, *p)


def load_json(path, default):
    """Read a state file. A missing, half-written or wrong-shaped file (a restart mid-save) counts as not there."""
    try:
        with open(path) as f:
            data = json.load(f)
    except (OSError, ValueError):
        return default
    if default is not None and data is not None and isinstance(default, (dict, list)) and not isinstance(data, type(default)):
        return default
    return data


def load_json_regular(path, default):
    """load_json for a state file someone could swap: opened without following a link and without waiting on a FIFO, and read
    only if what was opened is a regular file. Anything else counts as not there."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        return default
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return default
        with os.fdopen(fd) as f:
            fd = None                          # the file object owns it now
            data = json.load(f)
    except (OSError, ValueError):
        return default
    finally:
        if fd is not None:
            os.close(fd)
    if default is not None and data is not None and isinstance(default, (dict, list)) and not isinstance(data, type(default)):
        return default
    return data


def save_json(path, obj):
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(obj, f, indent=2, sort_keys=True)
    os.replace(tmp, path)


def save_json_keep_mode(path, obj):
    """Write a state file to a new file beside it, synced, then swapped in, so a reader never sees half of it. The file keeps
    the mode it had (a file tightened to 0600 stays 0600), and a link put where the file goes is replaced, not written through."""
    try:
        st = os.lstat(path)
        mode = stat.S_IMODE(st.st_mode) if stat.S_ISREG(st.st_mode) else None
    except OSError:
        mode = None
    tmp = f"{path}.{os.getpid()}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
    try:
        fd = os.open(tmp, flags, 0o666 if mode is None else 0o600)
    except FileExistsError:                    # left by an earlier run with this pid; a link is removed as a link
        os.remove(tmp)
        fd = os.open(tmp, flags, 0o666 if mode is None else 0o600)
    try:
        with os.fdopen(fd, "w") as f:
            if mode is not None:
                os.fchmod(f.fileno(), mode)
            json.dump(obj, f, indent=2, sort_keys=True)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.remove(tmp)
        except OSError:
            pass
        raise


def load_rules():
    with open(RULES_PATH) as f:
        r = json.load(f)
    for rule in r["rules"]:
        rule["rx"] = re.compile(rule["pattern"])
    for k in ("write_verbs", "approval_terms", "draft_terms", "schedule_terms", "nodata_terms", "high_freq"):
        r[k] = re.compile(r[k])
    r["context_guard"] = re.compile(f"(?i)^(?:{r['context_guard']})$")   # matched against one whole word
    r["guard_filler"] = {k: re.compile(f"(?i)^(?:{v})$") for k, v in r["guard_filler"].items()}
    return r


def sha256_file(path):
    """Fingerprint of a file. A file that can't be read (no permission, vanished, a broken link) gets a marker instead of an error."""
    h = hashlib.sha256()
    try:
        if not stat.S_ISREG(os.stat(path).st_mode):
            return "unreadable:not-a-regular-file"
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
    except OSError as e:
        return "unreadable:" + (e.strerror or "error").replace(" ", "-")[:30]
    return h.hexdigest()


def read_scanned(path, limit=1_000_000):
    """(text, sha256) from one read of the file's bytes: the text as read_text gives it (None when it isn't a plain file or is
    over `limit`) and the fingerprint as sha256_file gives it. PR A, Codex round 1 (8): the audit read the text, scanned it, then
    hashed the file by name again, so bytes swapped back in between got the hash of other bytes than the ones scanned."""
    h, kept, size = hashlib.sha256(), [], 0
    try:
        if not stat.S_ISREG(os.stat(path).st_mode):   # never opens a device; fstat below says what was really opened
            return None, "unreadable:not-a-regular-file"
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError as e:
        return None, "unreadable:" + (e.strerror or "error").replace(" ", "-")[:30]
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return None, "unreadable:not-a-regular-file"
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            h.update(chunk)
            size += len(chunk)
            if size <= limit:
                kept.append(chunk)
    except OSError as e:
        return None, "unreadable:" + (e.strerror or "error").replace(" ", "-")[:30]
    finally:
        os.close(fd)
    if size > limit:
        return None, h.hexdigest()
    # what open(path, "r", encoding="utf-8", errors="replace").read() gives, universal newlines included
    return b"".join(kept).decode("utf-8", errors="replace").replace("\r\n", "\n").replace("\r", "\n"), h.hexdigest()


def read_text(path, limit=1_000_000):
    try:
        st = os.stat(path)
        if not stat.S_ISREG(st.st_mode) or st.st_size > limit:   # never open a pipe, socket or device: it would block
            return None
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    except (OSError, ValueError):
        return None


def secret_fp(value):
    """v0.8.2 (items 1, 2; decision D1: plain sha256): a found secret's fingerprint, 12 hex characters, so copies of one secret
    count once. Kept in memory for the run only (drop_fingerprints); None for anything that isn't a secret's text."""
    if not isinstance(value, str) or not value:
        return None
    return hashlib.sha256(value.encode("utf-8", "surrogatepass")).hexdigest()[:12]


def finding(rule_id, title, severity, owasp, where, evidence, fix, source="isr-bot", ident=None, path=None, shown=None):
    """`ident` names the finding when its evidence holds a count that drifts (63 logins, 6 advisories): the same problem
    keeps the same key, so it is never reported as fixed and new in one run. `key0` is the key older versions gave it.
    `path` is the literal file a "<file>:<line>" where is about (item 8, from Codex's batch 3 round 2), kept with the finding
    when it is carried to later runs, so a file named gateway.json:3 stays itself even after it is gone.
    Batch 4 (R11): the key is made from `evidence` exactly as before; what is stored is masked first, then cut. `shown`: the
    uncut text the caller cut `evidence` from (or that it masked its own way), so a value cut short is masked as a whole."""
    key = finding_key(rule_id, where, evidence)
    stored =mask_secrets(((evidence if shown is None else shown) or "")[:MASK_WINDOW]).replace("\n", " ")[:160]
    out = {"key": key, "rule": rule_id, "title": title, "severity": severity, "owasp": owasp,
           "where": where, "evidence": stored, "fix": fix, "source": source}
    if path is not None:
        out["path"] = path
    if ident is not None:
        out["key"], out["key0"] = hashlib.sha1(f"{rule_id}|{where}|id:{ident}".encode()).hexdigest()[:16], key
    return out


def finding_key(rule_id, where, evidence):
    """The key finding() gives: from the raw evidence, cut at 160, exactly as before batch 4."""
    return hashlib.sha1(f"{rule_id}|{where}|{(evidence or '').replace(chr(10), ' ')[:160]}".encode()).hexdigest()[:16]


def keys_of(findings):
    return {k for f in findings for k in (f.get("key"), f.get("key0")) if k}


def known(f, keys):
    return f["key"] in keys or (f.get("key0") in keys if f.get("key0") else False)


def line_of(text, pos):
    return text.count("\n", 0, pos) + 1
