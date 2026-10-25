# Part of isr.py: runs inside isr.py's namespace (loaded by _isr_part); not a module on its own.
# Item 8 (R3, roadmap row 8): vendor provenance for the platform's own folders. None of them ships a manifest, signature or hash
# list ISR Bot can use, and anything inside the home folder is the Bot's to write. The only vendor hash list the Bot can't
# silently change is one in ISR Bot's own release: rules/platform-release.lock, listed in MANIFEST.sha256 and held to it here
# like the scanner lock. Lines are `sha256sum` output run from the home folder: "<sha256>  <path under the home folder>". A file
# whose path and exact bytes are listed is the vendor's. Filled Oct 18 from the maintainer's box (see its header); a `<bucket>`
# line lists a file in every account's sync bucket; the platform's sync bookkeeping (PLATFORM_CHURN) is never listed and never
# needs to be. v0.8.1 (§2): ownership is decided by location (ownership.py), so nothing in an audit, daily or vet reads these
# lists any more. The parsers below are kept as a library for their own tests until v0.8.2, and the three lists are frozen
# copies under tests/fixtures/platform_v080/ (bytes unchanged).
PLATFORM_LOCK_REL = "tests/fixtures/platform_v080/platform-release.lock"
PLATFORM_LOCK = os.path.join(HERE, "..", PLATFORM_LOCK_REL)   # tests point this at a file in their box; never read from the environment
PLATFORM_LOCK_MAX_BYTES = 4 * 1024 * 1024
_PLATFORM_LOCK_CACHE = {}
_SHA256SUM_LINE = re.compile(r"(?:(canonical) )?([0-9a-fA-F]{64}) [ *](.+)")
# Batch 6 fix round 1 (Codex 1): a line says which form it lists. "<sha256>  <path>" is the file's raw bytes (platform_listed);
# "canonical <sha256>  <path>" is the digest of its canonical form (platform_canonical_listed), which vouches for the file only
# after platform_verified normalized it and checked every unit. A file whose raw bytes are a listed canonical form isn't listed.


def _platform_lock_state():
    """({path under the home folder: {sha256 of the raw bytes, ...}}, why it can't be used or "", {path: {sha256 of the
    canonical form, ...}}). One bad line makes the whole list unusable."""
    path = PLATFORM_LOCK
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError as e:
        return {}, f"it can't be opened as a plain file ({errno.errorcode.get(e.errno, 'error')})", {}
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            return {}, "it isn't a plain file", {}
        key = (path, st.st_size, st.st_mtime_ns, st.st_ino)
        if _PLATFORM_LOCK_CACHE.get("key") == key:
            return _PLATFORM_LOCK_CACHE["lock"], _PLATFORM_LOCK_CACHE["why"], _PLATFORM_LOCK_CACHE["canonical"]
        data = b""
        while len(data) <= PLATFORM_LOCK_MAX_BYTES:
            chunk = os.read(fd, PLATFORM_LOCK_MAX_BYTES + 1 - len(data))
            if not chunk:
                break
            data += chunk
    except OSError as e:
        return {}, f"it can't be read ({errno.errorcode.get(e.errno, 'error')})", {}
    finally:
        os.close(fd)
    lock, why, canon = _parse_platform_lock(data)
    _PLATFORM_LOCK_CACHE.update(key=key, lock=lock, why=why, canonical=canon)
    return lock, why, canon


def _parse_platform_lock(data):
    if len(data) > PLATFORM_LOCK_MAX_BYTES:
        return {}, "it is larger than 4 MB", {}
    want = release_want(PLATFORM_LOCK, PLATFORM_LOCK_REL)   # batch 6 (KL4): whatever the folder's layout
    if want is not None and hashlib.sha256(data).hexdigest() != want:
        return {}, _not_shipped(want), {}
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return {}, "it isn't UTF-8 text", {}
    roots = tuple(sub + "/" for sub in PLATFORM_ROOT_SUBS)
    out, canon = {}, {}
    for n, line in enumerate(text.split("\n"), 1):
        line = line[:-1] if line.endswith("\r") else line
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        m = _SHA256SUM_LINE.fullmatch(line)
        rel = m.group(3) if m else ""
        rel = rel[2:] if rel.startswith("./") else rel
        if not m:
            why = "it isn't \"<sha256>  <path>\" or \"canonical <sha256>  <path>\""
        elif rel.startswith("/"):
            why = "its path starts at / (paths are under the home folder)"
        elif ":" in rel:
            why = "its path has a colon"
        elif any(ord(c) < 32 or 127 <= ord(c) < 160 or ord(c) in (0x2028, 0x2029) for c in rel):
            why = "its path has a control character"
        elif ".." in rel.split("/") or os.path.normpath(rel) != rel:
            why = "its path isn't plain (.., //, ./ or a trailing /)"
        elif not rel.startswith(roots):
            why = "its path isn't inside one of the platform's own folders"
        elif ("<" in rel or ">" in rel) and not re.fullmatch(r"\.claude/plugins/synced/<bucket>/[^<>]+", rel):
            why = "its path has a placeholder other than <bucket> as the folder right under .claude/plugins/synced"
        else:
            (canon if m.group(1) else out).setdefault(rel, set()).add(m.group(2).lower())
            continue
        return {}, f"line {n}: {why}", {}
    return out, "", canon


def platform_lock():
    """The usable vendor release list's raw-bytes lines ({} when it is empty or can't be used whole)."""
    return _platform_lock_state()[0]


def platform_lock_canonical():
    """The usable vendor release list's "canonical" lines ({path: {sha256 of the canonical form}}; {} when there are none)."""
    return _platform_lock_state()[2]


def platform_lock_problem():
    """Why the vendor release list can't be used, or "" (an empty list is usable: it lists nothing)."""
    return _platform_lock_state()[1]


def _home_rels(p):
    """p relative to each home base it sits under (the home folder and /home/box, as written and as their real folders)."""
    out = set()
    for b in home_bases():
        for base in {os.path.normpath(b), os.path.realpath(b)}:
            if p.startswith(base + os.sep):
                out.add(p[len(base) + 1:])
    return out


def _lock_hashes(lock, rel):
    """The hashes a release list (raw or canonical lines) has for one path under the home folder. b8i4: a file in one of
    Claude's sync buckets (the <id>_<id> folder right under .claude/plugins/synced) also gets its `<bucket>` line's; a path
    with a < or > is never looked up as written."""
    if "<" in rel or ">" in rel:
        return set()
    out = set(lock.get(rel, ()))
    m = re.fullmatch(r"\.claude/plugins/synced/" + _BUCKET_PAIR + r"/(.+)", rel)
    if m:
        out |= lock.get(".claude/plugins/synced/<bucket>/" + m.group(1), set())
    return out


def platform_listed(p, h, lock=None):
    """True only when p is strictly inside a platform root as written and as its real path (platform_skill_path, no colon
    reading) and both, relative to their home base, are listed in the vendor release list with exactly the sha256 h. A path plus
    its hash is the provenance: vendor bytes at a new path aren't listed there. Only raw-bytes lines (fix round 1: `lock` is
    the "canonical" lines for platform_canonical_listed)."""
    if not isinstance(h, str) or not re.fullmatch(r"[0-9a-f]{64}", h) or not platform_skill_path(p, line=False):
        return False
    lock = platform_lock() if lock is None else lock
    if not lock:
        return False
    try:
        n = _path_part(p, line=False)
        if os.path.islink(n):   # b8i4 fix round 1 (Codex 3): a file that is itself a link is never listed, whatever both names say
            return False
        rn = os.path.realpath(n)
    except OSError:
        return False
    return all(any(h in _lock_hashes(lock, r) for r in _home_rels(q)) for q in (n, rn))


def platform_lock_path(p):
    """b8i4: True when p's path (as written and its real path, each strictly inside a platform root: platform_skill_path) is on
    the usable release list with any hash, a raw or a "canonical" line, `<bucket>` lines included."""
    if not platform_skill_path(p, line=False):
        return False
    raw, canon = platform_lock(), platform_lock_canonical() or {}
    if not raw and not canon:
        return False
    try:
        n = _path_part(p, line=False)
        if os.path.islink(n):   # fix round 1 (Codex 3)
            return False
        rn = os.path.realpath(n)
    except OSError:
        return False
    return all(any(_lock_hashes(raw, r) or _lock_hashes(canon, r) for r in _home_rels(q)) for q in (n, rn))


def platform_canonical_listed(p, c):
    """platform_listed for the digest `c` of p's canonical form, against the release list's "canonical" lines only. Only
    platform_verified asks, after it normalized p and checked every unit."""
    return platform_listed(p, c, platform_lock_canonical() or {})


def platform_ish(p):
    """The loosest platform test: anything this says may be the platform's must prove itself with a release-list line before it
    is treated as a platform update. The whole path as written, and separately where it really leads, are each held to every
    platform root (as written and real). Codex, item 8 review 1: under_platform_root cut at the first colon and both helpers
    said no for a path in or through an owner's folder, so a platform file linked into a workflow, or helper:alias leading into
    .grok/bundled, was an ordinary change that --revet or roll_builtin approved. No user-root exclusion and no colon reading here."""
    try:
        n = os.path.normpath(os.path.abspath(str(p)))
        roots = set(platform_roots())
        roots |= {os.path.realpath(r) for r in roots}
        return _under(n, roots) or _under(os.path.realpath(n), roots)
    except (OSError, ValueError):
        return True


# Batch 5 (d2, decision 1, Oct 18): findings ISR Bot's team read in exact versions of the platform's own files. One entry
# names the paths (under the home folder), the file's sha256, the rule and the line; it applies only to those bytes there, so any
# change to the file (another sha256) ends it. The list ships in ISR Bot's release and is held to MANIFEST.sha256 like the
# release lock; its path is a constant tests point at their own file, never read from the environment or from state/. Nothing on
# the computer can add an entry.
PLATFORM_REVIEWED_REL = "tests/fixtures/platform_v080/platform-reviewed.json"
PLATFORM_REVIEWED = os.path.join(HERE, "..", PLATFORM_REVIEWED_REL)
PLATFORM_REVIEWED_MAX_BYTES = 256 * 1024
_PLATFORM_REVIEWED_CACHE = {}


def _platform_reviewed_state():
    """([entries], why the list can't be used or ""). One malformed entry makes the whole list unusable."""
    key = _stat_key(PLATFORM_REVIEWED)
    if key is not None and _PLATFORM_REVIEWED_CACHE.get("key") == key:
        return _PLATFORM_REVIEWED_CACHE["state"]
    data, why = _release_file(PLATFORM_REVIEWED, PLATFORM_REVIEWED_REL, PLATFORM_REVIEWED_MAX_BYTES)
    if why:
        _PLATFORM_REVIEWED_CACHE.update(key=key, state=([], why))
        return [], why
    try:
        doc = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        doc = None
    entries = doc.get("entries") if isinstance(doc, dict) else None
    out, why = [], "" if isinstance(entries, list) else "it isn't a JSON object with an entries list"
    for n, e in enumerate(entries if isinstance(entries, list) else [], 1):
        ok = (isinstance(e, dict) and set(e) == {"paths", "sha256", "rule", "line", "note"} and isinstance(e["paths"], list) and e["paths"]
              and all(_plain_rel(r) for r in e["paths"]) and isinstance(e["sha256"], str) and re.fullmatch(r"[0-9a-f]{64}", e["sha256"])
              and isinstance(e["rule"], str) and re.fullmatch(r"ISR-[A-Z]\d{3}", e["rule"]) and type(e["line"]) is int and e["line"] >= 1
              and isinstance(e["note"], str) and 0 < len(e["note"]) <= 400 and not any(ord(c) < 32 for c in e["note"]))
        if not ok:
            out, why = [], f"entry {n} isn't {{paths, sha256, rule, line, note}} with plain platform paths"
            break
        out.append(e)
    _PLATFORM_REVIEWED_CACHE.update(key=key, state=(out, why))
    return out, why


def platform_reviewed_problem():
    """Why the reviewed list (PLATFORM_REVIEWED_REL) can't be used, or ""."""
    return _platform_reviewed_state()[1]


def platform_reviewed(f, manifest, snap=None):
    """The reviewed-list entry for a platform finding, or None. It applies only when the finding is platform scope, it was found
    in the bytes this run's manifest fingerprinted (`snap`, the sha256 of the very bytes scanned, is the manifest's: PR A, Codex
    round 1, 8), its file is on the release list with that sha256 (platform_listed), that sha256 is the entry's, the file's path
    under the home folder (as written and where it really leads) is one of the entry's paths, and rule and line are the entry's."""
    w = f.get("where") or ""
    path, _, ln = w.rpartition(":")
    if f.get("scope") != "platform" or f.get("guarded") or not ln.isdigit() or not path.startswith("/"):
        return None
    entries = [e for e in _platform_reviewed_state()[0] if e["rule"] == f["rule"] and e["line"] == int(ln)]
    if not entries:
        return None
    h = (manifest or {}).get(path)
    if not isinstance(h, str) or snap != h or not platform_listed(path, h):
        return None
    try:
        n = os.path.normpath(path)
        rels = (_home_rels(n), _home_rels(os.path.realpath(n)))
    except OSError:
        return None
    return next((e for e in entries if e["sha256"] == h and all(r & set(e["paths"]) for r in rels)), None)


# Batch 5 (d3b, decision 3, Oct 18): a release-shipped normalization spec for the platform's metadata JSON. An entry names a
# path under the home folder and the exact key paths whose values the platform's own sync rewrites, each with a type. The file is
# read strictly (a plain file of at most 1 MB, UTF-8 without a BOM, no duplicate keys, no NaN or Infinity, at most 64 deep); each
# named value present must have exactly its type, or nothing is normalized; those values are dropped and the rest is written
# compactly in its own key order. The release list then holds the sha256 of that canonical form for the path, like any other
# line. Any other difference gives another digest, so it stays a counted ISR-I001. The spec ships EMPTY: nothing is normalized until
# a spike (the maintainer's shape diff with scripts/platform-json-shape.py, then a check of the host loader) proves which fields are unused.
PLATFORM_NORMALIZE_REL = "tests/fixtures/platform_v080/platform-normalize.json"
PLATFORM_NORMALIZE = os.path.join(HERE, "..", PLATFORM_NORMALIZE_REL)
PLATFORM_NORMALIZE_MAX_BYTES = 64 * 1024
NORMALIZE_FILE_MAX = 1024 * 1024
NORMALIZE_TYPES = {"iso8601": re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})"),
                   "epoch_ms": re.compile(r"1\d{12}"), "hex_digest": re.compile(r"[0-9a-f]{12,128}"),
                   # batch 6 (B1): a JSON number of milliseconds (an int, never a bool or a float) and a UUID
                   "epoch_ms_number": None, "uuid": re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")}
_PLATFORM_NORMALIZE_CACHE = {}

# Batch 6 (B1, decision: option D): an entry may also name `units`, where the per-skill or per-file units of the file are and
# the file in the same platform root each must equal. ISR Bot then checks, by content, that the file says nothing beyond what it
# fingerprinted itself in this run (platform_verified): a skill_text unit (each element of the list at `at`, named by its `id`
# field) has text fields equal to its `file` (the whole SKILL.md, what follows its frontmatter, or one frontmatter field); a
# file_digest unit (each entry of the {relpath: sha256} map at `at`) has the sha256 of its file. Those text fields and digests are
# replaced by {"$unit": <id>} in the canonical form; identities, order and every other field stay. A key step "*" in `fields` is
# every element of a list. An unknown kind or a malformed unit refuses the whole spec.
UNIT_TEXT = re.compile(r"file|after_frontmatter|frontmatter:[a-z_]{1,40}")
UNIT_ID = re.compile(r"[A-Za-z0-9._-]{1,128}")


def _plain_relpath(rel):
    """A relative path inside a folder: no .., not absolute, no colon or control character, already normal."""
    return (isinstance(rel, str) and rel and not rel.startswith("/") and ":" not in rel and ".." not in rel.split("/")
            and os.path.normpath(rel) == rel and not any(ord(c) < 32 or 127 <= ord(c) < 160 for c in rel))


def _key_path(k, star=False):
    return (isinstance(k, list) and k and all(isinstance(x, str) and x and (star or x != "*") for x in k) and k[-1] != "*")


def _unit_ok(u):
    if not isinstance(u, dict) or not _key_path(u.get("at")):
        return False
    if u.get("kind") == "skill_text":
        f, t = u.get("file"), u.get("text")
        return (set(u) == {"kind", "at", "id", "file", "text"} and isinstance(u["id"], str) and u["id"] != ""
                and isinstance(f, str) and f.count("{id}") == 1 and _plain_relpath(f.replace("{id}", "x"))
                and isinstance(t, dict) and t and all(isinstance(k, str) and k and isinstance(v, str) and UNIT_TEXT.fullmatch(v) for k, v in t.items()))
    if u.get("kind") == "file_digest":
        return set(u) == {"kind", "at", "base"} and (u["base"] == "" or _plain_relpath(u["base"]))
    return False


def _platform_normalize_state():
    """({path under the home folder: {"fields": [(key path tuple, type)], "units": [unit]}}, why the spec can't be used or "")."""
    key = _stat_key(PLATFORM_NORMALIZE)
    if key is not None and _PLATFORM_NORMALIZE_CACHE.get("key") == key:
        return _PLATFORM_NORMALIZE_CACHE["state"]
    data, why = _release_file(PLATFORM_NORMALIZE, PLATFORM_NORMALIZE_REL, PLATFORM_NORMALIZE_MAX_BYTES)
    if why:
        _PLATFORM_NORMALIZE_CACHE.update(key=key, state=({}, why))
        return {}, why
    try:
        doc = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        doc = None
    entries = doc.get("entries") if isinstance(doc, dict) else None
    out, why = {}, "" if isinstance(entries, list) else "it isn't a JSON object with an entries list"
    for n, e in enumerate(entries if isinstance(entries, list) else [], 1):
        fields = e.get("fields") if isinstance(e, dict) else None
        units = e.get("units", []) if isinstance(e, dict) else None
        ok = (isinstance(e, dict) and {"path", "fields"} <= set(e) <= {"path", "fields", "units"} and _plain_rel(e["path"])
              and isinstance(fields, list) and isinstance(units, list) and (fields or units) and ("units" not in e or units)
              and all(isinstance(x, dict) and set(x) == {"key", "type"} and _key_path(x["key"], star=True) and x["type"] in NORMALIZE_TYPES
                      for x in fields)
              and all(_unit_ok(u) for u in units))
        if not ok:
            out, why = {}, (f"entry {n} isn't {{path, fields: [{{key: [...], type}}], units: [...]}} with a plain platform path, known "
                            "types and units of a known kind")
            break
        out[e["path"]] = {"fields": [(tuple(x["key"]), x["type"]) for x in fields], "units": units}
    _PLATFORM_NORMALIZE_CACHE.update(key=key, state=(out, why))
    return out, why


def platform_normalize_problem():
    """Why the normalization spec (PLATFORM_NORMALIZE_REL) can't be used, or ""."""
    return _platform_normalize_state()[1]


class _Refused(ValueError):
    pass


def _strict_pairs(pairs):
    seen = set()
    for k, _ in pairs:
        if k in seen:
            raise _Refused("duplicate key")
        seen.add(k)
    return dict(pairs)


def _refuse_constant(name):
    raise _Refused(name)


def _typed(v, typ):
    if typ == "epoch_ms_number":
        return type(v) is int and 10 ** 12 <= v < 2 * 10 ** 12
    return isinstance(v, str) and NORMALIZE_TYPES[typ].fullmatch(v) is not None


def _drop_field(node, key, typ):
    """Drop the value at `key` ("*": every element of a list) from node; False when a value there hasn't exactly its type."""
    if key[0] == "*":
        return all(_drop_field(x, key[1:], typ) for x in node) if isinstance(node, list) else True
    if not isinstance(node, dict) or key[0] not in node:
        return True   # not there: nothing to drop
    if len(key) > 1:
        return _drop_field(node[key[0]], key[1:], typ)
    if not _typed(node[key[0]], typ):
        return False   # a named field holding anything but its type: nothing is normalized, the file stays counted
    del node[key[0]]
    return True


def canonical_platform_json(data, fields, units=(), check=None):
    """The sha256 of `data` (a platform metadata file's bytes) with the spec's `fields` dropped and each of its `units` (batch 6,
    B1) replaced by {"$unit": <id>} once check(unit, id, how, value) says it equals what ISR Bot fingerprinted, or None when it
    can't be read strictly, a named value hasn't exactly its type, or a unit isn't verified (check(unit, id, None, None): its
    file is there and fine; how is a text kind, or "digest")."""
    if len(data) > NORMALIZE_FILE_MAX or data[:3] == b"\xef\xbb\xbf":
        return None
    try:
        doc = json.loads(data.decode("utf-8"), object_pairs_hook=_strict_pairs, parse_constant=_refuse_constant)
    except (UnicodeDecodeError, ValueError, RecursionError):
        return None

    def depth(x, d=0):
        if d > 64:
            raise _Refused("too deep")
        for v in (x.values() if isinstance(x, dict) else x if isinstance(x, list) else ()):
            depth(v, d + 1)
    try:
        depth(doc)
    except (_Refused, RecursionError):
        return None
    for key, typ in fields:
        if not _drop_field(doc, key, typ):
            return None
    for u in units:
        node = doc
        for k in u["at"]:
            node = node.get(k) if isinstance(node, dict) else None
        if node is None:
            continue   # not there: the canonical form shows that, and the release list decides
        if u["kind"] == "skill_text":
            if not isinstance(node, list):
                return None
            for el in node:
                ident = el.get(u["id"]) if isinstance(el, dict) else None
                if not isinstance(ident, str) or check is None or not check(u, ident, None, None):
                    return None   # a unit with no checked file behind it
                for t, how in u["text"].items():
                    if t in el:
                        if not isinstance(el[t], str) or not check(u, ident, how, el[t]):
                            return None
                        el[t] = {"$unit": ident}
        else:
            if not isinstance(node, dict):
                return None
            for rel in list(node):
                if not isinstance(node[rel], str) or check is None or not check(u, rel, "digest", node[rel]):
                    return None
                node[rel] = {"$unit": rel}
    return hashlib.sha256(json.dumps(doc, separators=(",", ":"), ensure_ascii=False).encode("utf-8")).hexdigest()


def _read_plain(n, limit):
    """The bytes of n: a plain file opened without following a link, at most `limit` bytes; None otherwise."""
    try:
        fd = os.open(n, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError:
        return None
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return None
        data = b""
        while len(data) <= limit:
            chunk = os.read(fd, limit + 1 - len(data))
            if not chunk:
                break
            data += chunk
    except OSError:
        return None
    finally:
        os.close(fd)
    return data if len(data) <= limit else None


def _frontmatter(text):
    """(the frontmatter's lines, what follows it) of a SKILL.md, or None when it has none."""
    if not text.startswith("---\n"):
        return None
    end = text.find("\n---\n", 3)
    if end < 0:
        return None
    return text[4:end].split("\n"), text[end + 5:]


def _unit_text(data, how):
    """What a unit's text field must equal for a file with these bytes (how: UNIT_TEXT), or None when it can't be said exactly."""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if how == "file":
        return text
    fm = _frontmatter(text)
    if fm is None:
        return None
    if how == "after_frontmatter":
        return fm[1]
    name = how.split(":", 1)[1]
    found = [l[len(name) + 1:].strip() for l in fm[0] if l.startswith(name + ":")]
    if len(found) != 1 or found[0][:1] in ("|", ">", ""):
        return None   # missing, twice, or a block value: never guessed
    v = found[0]
    return v[1:-1] if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'" else v


def _unit_checker(n, manifest, used=None):
    """check() for canonical_platform_json on the metadata file n: a unit's file is in the same platform root as n (as written
    and where it leads, no link at or below the root), a plain file in this run's manifest, still the bytes the scan
    fingerprinted; a text equals what UNIT_TEXT names of it, a digest its sha256. `used` (a list) gets (path, sha256, its
    _stat_key before the read) of each unit's file found (fix round 1: metadata_proof holds each to the release list)."""
    root = next((r for r in platform_roots() if _under(n, {r}, strict=True)), None)
    seen = {}

    def backing(u, ident):
        if u["kind"] == "skill_text":
            if not UNIT_ID.fullmatch(ident) or ident in (".", ".."):
                return None
            rel = u["file"].replace("{id}", ident)
        else:
            if not _plain_relpath(ident):
                return None
            rel = os.path.join(u["base"], ident) if u["base"] else ident
        q = os.path.normpath(os.path.join(os.path.dirname(n), rel))
        if q not in seen:
            seen[q] = None
            try:
                ok = (root is not None and _under(q, {root}, strict=True)
                      and os.path.realpath(q) == os.path.join(os.path.realpath(root), os.path.relpath(q, root)))
            except (OSError, ValueError):
                ok = False
            before = _stat_key(q)
            want = (manifest if manifest is not None else {}).get(q)
            data = _read_plain(q, NORMALIZE_FILE_MAX) if ok and isinstance(want, str) else None
            if data is not None and hashlib.sha256(data).hexdigest() == want:
                seen[q] = (data, want)
                if used is not None:
                    used.append((q, want, before))
        return seen[q]

    def check(u, ident, how, value):
        got = backing(u, ident)
        if got is None:
            return False
        if how is None:
            return True
        if how == "digest":
            return value == got[1]
        return _unit_text(got[0], how) == value
    return check


# This run's metadata files verified by content (B1): {path: the bytes verified}, for the Platform refresh Tip's wording and (fix
# round 1, Codex 2) the private copy gitleaks_findings scans. In memory only: nothing stored vouches for a file.
VERIFIED_METADATA = {}


def platform_verified(p, h, manifest=None, used=None):
    """True when the spec names p (under the home folder, as written and where it really leads), p is a plain file (never a
    link), and the release list holds the digest of its canonical form for it (a "canonical" line: platform_canonical_listed).
    PR A, Codex round 2 (9): `h` is the sha256 of the bytes the scan read (the manifest's); the bytes read here are normalized
    only when they are those same bytes, so a file swapped between the scan and this read is never vouched for by what it
    became. Batch 6 (B1): its units are checked against `manifest`, this run's fingerprints (none: no unit is verified); `used`
    gets each unit's file (_unit_checker)."""
    spec = _platform_normalize_state()[0]
    if not spec:
        return False
    try:
        n = os.path.normpath(str(p))
        rels = _home_rels(n) & _home_rels(os.path.realpath(n))
        entry = next((spec[r] for r in sorted(rels) if r in spec), None)
    except (OSError, ValueError):
        return False
    if entry is None:
        return False
    data = _read_plain(n, NORMALIZE_FILE_MAX)
    if data is None or not isinstance(h, str) or hashlib.sha256(data).hexdigest() != h:
        return False
    c = canonical_platform_json(data, entry["fields"], entry["units"], _unit_checker(n, manifest, used))
    if c is None or not platform_canonical_listed(n, c):   # fix round 1 (Codex 1): a "canonical" line, never a raw one
        return False
    VERIFIED_METADATA[n] = data
    return True


class _DiskManifest(dict):
    """A manifest taken from the disk when asked: a plain file's sha256, read without following a link (None otherwise)."""
    def get(self, p, default=None):
        if p not in self:
            data = _read_plain(p, NORMALIZE_FILE_MAX)
            self[p] = hashlib.sha256(data).hexdigest() if data is not None else None
        return dict.get(self, p, default)


_METADATA_PROOF = {}   # {(path, sha256): (answer, what it was decided from)}; audit() clears it


def metadata_proof(p, h):
    """Fix round 1 (Codex 2, 3, 4): True when the metadata file p has the bytes `h` now, those bytes verify against the release
    list (platform_verified: the release's spec, a "canonical" line, each unit checked against its file on disk now), and every
    unit's file is itself on the release list with those bytes (platform_listed). Recomputed whenever it is asked, in the audit
    and in report, doctor or fix alike; no flag or record on the computer answers it. A file with any unit that isn't listed
    (an unlisted skill whose text the file repeats) is never proven, so a hit in it stays counted with its cleanup."""
    try:
        n = os.path.normpath(str(p))
    except (TypeError, ValueError):
        return False
    if not isinstance(h, str) or not re.fullmatch(r"[0-9a-f]{64}", h) or not _platform_normalize_state()[0]:
        return False
    # the stat keys are taken before each read, so a file changed while it is checked is checked again next time
    now = (_stat_key(n), _stat_key(PLATFORM_LOCK), _stat_key(PLATFORM_NORMALIZE))
    got = _METADATA_PROOF.get((n, h))
    if got is not None and got[1] == now and all(_stat_key(q) == k for q, k in got[2]):
        return got[0]
    data, used = _read_plain(n, NORMALIZE_FILE_MAX), []
    ok = (data is not None and hashlib.sha256(data).hexdigest() == h and platform_verified(n, h, _DiskManifest(), used)
          and all(platform_listed(q, d) for q, d, _ in used))
    _METADATA_PROOF[(n, h)] = (ok, now, [(q, k) for q, _, k in used])
    return ok


def platform_listed_normalized(p, h, manifest=None):
    """platform_verified under its batch 5 name."""
    return platform_verified(p, h, manifest)


# PR #9 (owner decision: few false alarms): the platform's own sync bookkeeping, rewritten at every sync with no release (the maintainer's box, Oct 18:
# the empty .bucket-<id> marker Claude's plugin sync writes). It is no provenance subject: not walked, fingerprinted or listed
# (rules/platform-release.lock's fill command skips exactly the files platform_churn_file skips). Exact name at exact place only:
# it sits at a platform folder's top, never in a skill folder.
# Codex, lock-trim review 1 (high): the bucket's *.meta.json, manifest.json and .marketplaces.json were skipped too, but Claude's
# plugin loader reads them (installation_preference "required" enables a plugin the user disabled; manifest name/generation pick
# the plugin folders; .marketplaces.json builds the source choices), so they are provenance subjects again.
# Codex, lock-trim review 2 (high): managed-skills/cache.json is read too (the host's skill store takes each skill's name,
# description and body from it, and Run-now sends `@<name>` from it as the prompt), so it is a provenance subject again. Only the
# .bucket-<id>_<id> marker is left: Claude's plugin discovery tests that it exists and never reads it.
_SYNC_BUCKET = r"[0-9a-f-]{36}_[0-9a-f-]{36}"
PLATFORM_CHURN = re.compile(r"\.claude/plugins/synced/\.bucket-" + _SYNC_BUCKET)
# b8i4 fix round 1 (Codex 8): the folder a `<bucket>` line stands for is a real UUID pair, 8-4-4-4-12 lowercase hex digits
# twice, joined by "_"; 36 hyphens, a hyphen out of place or a third part never takes that line's trust
_SYNC_BUCKET_ID = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
_BUCKET_PAIR = _SYNC_BUCKET_ID + "_" + _SYNC_BUCKET_ID


def platform_churn(rel):
    """True when a path under the home folder is one of the platform's sync bookkeeping files by name and place (PLATFORM_CHURN)."""
    return isinstance(rel, str) and PLATFORM_CHURN.fullmatch(rel) is not None


def platform_churn_file(p):
    """platform_churn for a file on disk, exactly what the lock's fill command tests when it is run from a home base (Codex,
    lock-trim reviews 1 and 2, medium): for some home base (home_bases, as written or real) the file sits under, its path relative
    to that base is a churn name and its real path is that same path under the base's real folder (no link anywhere below that
    home folder: not the file, not a folder above it); lstat says a regular file with no exec bit and one name (st_nlink 1: no
    hardlink alias). One base is enough, as the fill from that base skips it: with HOME inside BOX_HOME (or a home linked into
    itself) the same file is also under the outer base by a longer, non-churn path, which a fill from there lists at most as an
    unused line. Anything else is a provenance subject."""
    try:
        n = os.path.normpath(os.path.abspath(str(p)))
        real, seen = os.path.realpath(n), False
        for b in home_bases():
            for base in {os.path.normpath(b), os.path.realpath(b)}:
                if n.startswith(base + os.sep):
                    rel = n[len(base) + 1:]
                    if platform_churn(rel) and real == os.path.join(os.path.realpath(base), rel):
                        seen = True
        if not seen:
            return False
        st = os.lstat(n)
        return stat.S_ISREG(st.st_mode) and not st.st_mode & 0o111 and st.st_nlink == 1
    except (OSError, ValueError):
        return False
