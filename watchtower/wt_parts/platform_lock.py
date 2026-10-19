# Part of wt.py: runs inside wt.py's namespace (loaded by _wt_part); not a module on its own.
# Item 8 (R3, roadmap row 8): vendor provenance for the platform's own folders. None of them ships a manifest, signature or hash
# list Watchtower can use, and anything inside the home folder is the Bot's to write. The only vendor hash list the Bot can't
# silently change is one in Watchtower's own release: rules/platform-release.lock, listed in MANIFEST.sha256 and held to it here
# like the scanner lock. Lines are `sha256sum` output run from the home folder: "<sha256>  <path under the home folder>". A new or
# changed file in a platform folder is a platform update only when its path and its exact bytes are listed; anything else is a
# counted high until a Watchtower release lists it. Ken's decision (Oct 18): release list only. Nothing on the computer approves a
# platform file (no owner's yes, no record, no first-run trust): all of that is state the Bot can write. Filled Oct 18 from Ken's
# box (see its header); the platform's sync bookkeeping (PLATFORM_CHURN) is never listed and never needs to be.
PLATFORM_LOCK_REL = "rules/platform-release.lock"
PLATFORM_LOCK = os.path.join(HERE, "..", PLATFORM_LOCK_REL)   # tests point this at a file in their box; never read from the environment
PLATFORM_LOCK_MAX_BYTES = 4 * 1024 * 1024
_PLATFORM_LOCK_CACHE = {}
_SHA256SUM_LINE = re.compile(r"([0-9a-fA-F]{64}) [ *](.+)")


def _platform_lock_state():
    """({path under the home folder: {sha256, ...}}, why it can't be used or ""). One bad line makes the whole list unusable."""
    path = PLATFORM_LOCK
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError as e:
        return {}, f"it can't be opened as a plain file ({errno.errorcode.get(e.errno, 'error')})"
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            return {}, "it isn't a plain file"
        key = (path, st.st_size, st.st_mtime_ns, st.st_ino)
        if _PLATFORM_LOCK_CACHE.get("key") == key:
            return _PLATFORM_LOCK_CACHE["lock"], _PLATFORM_LOCK_CACHE["why"]
        data = b""
        while len(data) <= PLATFORM_LOCK_MAX_BYTES:
            chunk = os.read(fd, PLATFORM_LOCK_MAX_BYTES + 1 - len(data))
            if not chunk:
                break
            data += chunk
    except OSError as e:
        return {}, f"it can't be read ({errno.errorcode.get(e.errno, 'error')})"
    finally:
        os.close(fd)
    lock, why = _parse_platform_lock(data)
    _PLATFORM_LOCK_CACHE.update(key=key, lock=lock, why=why)
    return lock, why


def _parse_platform_lock(data):
    if len(data) > PLATFORM_LOCK_MAX_BYTES:
        return {}, "it is larger than 4 MB"
    want = release_digest(PLATFORM_LOCK_REL)
    if want is not None and hashlib.sha256(data).hexdigest() != want:
        return {}, "it isn't the file this release of Watchtower shipped (MANIFEST.sha256)"
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return {}, "it isn't UTF-8 text"
    roots = tuple(sub + "/" for sub in PLATFORM_ROOT_SUBS)
    out = {}
    for n, line in enumerate(text.split("\n"), 1):
        line = line[:-1] if line.endswith("\r") else line
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        m = _SHA256SUM_LINE.fullmatch(line)
        rel = m.group(2) if m else ""
        rel = rel[2:] if rel.startswith("./") else rel
        if not m:
            why = "it isn't \"<sha256>  <path>\""
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
        else:
            out.setdefault(rel, set()).add(m.group(1).lower())
            continue
        return {}, f"line {n}: {why}"
    return out, ""


def platform_lock():
    """The usable vendor release list ({} when it is empty or can't be used whole)."""
    return _platform_lock_state()[0]


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


def platform_listed(p, h):
    """True only when p is strictly inside a platform root as written and as its real path (platform_skill_path, no colon
    reading) and both, relative to their home base, are listed in the vendor release list with exactly the sha256 h. A path plus
    its hash is the provenance: vendor bytes at a new path aren't listed there."""
    if not isinstance(h, str) or not re.fullmatch(r"[0-9a-f]{64}", h) or not platform_skill_path(p, line=False):
        return False
    lock = platform_lock()
    if not lock:
        return False
    try:
        n = _path_part(p, line=False)
        rn = os.path.realpath(n)
    except OSError:
        return False
    return all(any(h in lock.get(r, ()) for r in _home_rels(q)) for q in (n, rn))


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


def platform_vendor(p):
    """Whose platform folder p is in, for the owner: Codex, Claude, or Grok Bot."""
    n = _path_part(p, line=False)
    try:
        places = (n, os.path.realpath(n))
    except OSError:
        places = (n,)
    for q in places:
        for b in home_bases():
            if _under(q, {os.path.normpath(os.path.join(b, ".codex/skills/.system"))}, strict=True):
                return "Codex"
            if _under(q, {os.path.normpath(os.path.join(b, ".claude/plugins/synced"))}, strict=True):
                return "Claude"
    return "Grok Bot"


# Batch 5 (d3a): the platform's own metadata JSON (what a platform folder loads and how). The vendor rewrites it when it updates
# itself, so "treat it like a file someone added" and "remove it" are the wrong advice; it is still a counted high, as any file
# the release list doesn't include.
PLATFORM_METADATA = re.compile(r"(?:manifest|cache|\.marketplaces|.+\.meta)\.json")


def unverified_platform_finding(p, h, was=None):
    """A new or changed file in a platform folder that the vendor release list doesn't include, with these bytes at this path:
    a counted high. No `refresh` key, so it never goes into the Platform refresh Tip and an audit never rolls it into the
    baseline; `unverified_platform` keeps it out of the platform scope, `fix --revet`, `accept` and `dismiss`. Only a Watchtower
    release that lists it clears it (Ken's decision, Oct 18)."""
    v = platform_vendor(p)
    fix = (f"Nothing shows {v} made this change, so treat it like a file someone added. Don't use this skill until you've looked. "
           "Watchtower can't approve it on this computer: it clears only when a Watchtower release lists this exact file in its "
           "platform list. If you didn't expect it, remove it.")
    if PLATFORM_METADATA.fullmatch(os.path.basename(_path_part(p, line=False))):
        f = finding("WT-I002" if was is None or was == h else "WT-I001",
                    f"{v}'s list of what it loads {'changed' if was is not None and was != h else 'is new here'}, and Watchtower's "
                    "release list doesn't have this version yet", "high", ["AST07"] if was is not None and was != h else ["AST09", "AST07"], p,
                    f"sha256 {was[:12]}→{h[:12]}" if was is not None and was != h else f"sha256 {h[:12]}, not on the release list",
                    f"{v} rewrites this file when it updates itself, but the file also decides which skills and plugins load, so "
                    f"Watchtower can't tell an update from a change someone else made. Don't delete it ({v} needs it). It stays on "
                    "this list until a Watchtower release includes this version. If it's still here after the next Watchtower update, "
                    "tell Watchtower support.")
        f["unverified_platform"] = True
        return f
    if was is None:
        f = finding("WT-I002", f"A new file appeared in {v}'s own skill folder, and {v}'s release list doesn't include it", "high",
                    ["AST09", "AST07"], p, h[:12], fix)
    elif was == h:   # Codex, item 8 review 2 (high 3): in baseline.json, which the Bot can write; a baseline line is never provenance
        f = finding("WT-I002", f"A file in {v}'s own skill folder is on Watchtower's list, but {v}'s release list doesn't include it", "high",
                    ["AST09", "AST07"], p, f"sha256 {h[:12]}, not on the release list", fix)
    else:
        f = finding("WT-I001", f"One of {v}'s own files changed, and the new version isn't on {v}'s release list", "high",
                    ["AST07"], p, f"sha256 {was[:12]}→{h[:12]}", fix)
    f["unverified_platform"] = True
    return f


# Codex, item 8 review 2 (high 3): a matching line in baseline.json skipped the release-list check. Reviews 2 and 3 then added an
# owner's yes (`fix --approve-platform`), a record of it in state/platform_approved.json bound to a ledger line, and a first baseline
# that vouched for every platform file on a new box. All of that lived in Watchtower's state, which the Bot can write, so a Bot
# that wrote the record and its ledger line, or wiped the state for a new first run, made its own plant a platform file.
# Ken's decision (Oct 18): release list only. A file in a platform folder is trusted only by platform_listed, on every run, first
# or not; baseline.json, the old record and the ledger are never read for it, and `--approve-platform` is refused (approve_platform).
OLD_PLATFORM_APPROVALS = "platform_approved.json"   # written by earlier versions; never read, never deleted (one note while it exists)


def platform_unproven(manifest):
    """The files in this manifest that sit in a platform folder and aren't on the release list with these bytes (platform_listed),
    nor with the digest of their canonical form where the release's normalization spec names them (platform_listed_normalized)."""
    return {p for p, h in manifest.items() if not p.startswith("persist:") and platform_ish(p) and not platform_listed(p, h)
            and not platform_churn_file(p) and not platform_listed_normalized(p, h)}


def _release_file(path, rel, max_bytes):
    """(bytes, why it can't be used or "") of one of Watchtower's own rules files: a plain file (never a link), at most max_bytes,
    and in an installed copy exactly the bytes MANIFEST.sha256 lists for it."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError as e:
        return b"", f"it can't be opened as a plain file ({errno.errorcode.get(e.errno, 'error')})"
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return b"", "it isn't a plain file"
        data = b""
        while len(data) <= max_bytes:
            chunk = os.read(fd, max_bytes + 1 - len(data))
            if not chunk:
                break
            data += chunk
    except OSError as e:
        return b"", f"it can't be read ({errno.errorcode.get(e.errno, 'error')})"
    finally:
        os.close(fd)
    if len(data) > max_bytes:
        return b"", f"it is larger than {max_bytes // 1024} KB"
    want = release_digest(rel)
    if want is not None and hashlib.sha256(data).hexdigest() != want:
        return b"", "it isn't the file this release of Watchtower shipped (MANIFEST.sha256)"
    return data, ""


def _stat_key(path):
    """What says a rules file is unchanged since it was last read (its path, size, change time and inode), or None."""
    try:
        st = os.lstat(path)
    except OSError:
        return None
    return (path, st.st_size, st.st_mtime_ns, st.st_ino, st.st_mode)


def _plain_rel(rel):
    return (isinstance(rel, str) and rel and not rel.startswith("/") and ":" not in rel and ".." not in rel.split("/")
            and os.path.normpath(rel) == rel and not any(ord(c) < 32 or 127 <= ord(c) < 160 for c in rel)
            and rel.startswith(tuple(sub + "/" for sub in PLATFORM_ROOT_SUBS)))


# Batch 5 (d2, Ken's decision 1, Oct 18): findings Watchtower's team read in exact versions of the platform's own files. One entry
# names the paths (under the home folder), the file's sha256, the rule and the line; it applies only to those bytes there, so any
# change to the file (another sha256) ends it. The list ships in Watchtower's release and is held to MANIFEST.sha256 like the
# release lock; its path is a constant tests point at their own file, never read from the environment or from state/. Nothing on
# the computer can add an entry.
PLATFORM_REVIEWED_REL = "rules/platform-reviewed.json"
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
              and isinstance(e["rule"], str) and re.fullmatch(r"WT-[A-Z]\d{3}", e["rule"]) and type(e["line"]) is int and e["line"] >= 1
              and isinstance(e["note"], str) and 0 < len(e["note"]) <= 400 and not any(ord(c) < 32 for c in e["note"]))
        if not ok:
            out, why = [], f"entry {n} isn't {{paths, sha256, rule, line, note}} with plain platform paths"
            break
        out.append(e)
    _PLATFORM_REVIEWED_CACHE.update(key=key, state=(out, why))
    return out, why


def platform_reviewed_problem():
    """Why rules/platform-reviewed.json can't be used, or ""."""
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


# Batch 5 (d3b, Ken's decision 3, Oct 18): a release-shipped normalization spec for the platform's metadata JSON. An entry names a
# path under the home folder and the exact key paths whose values the platform's own sync rewrites, each with a type. The file is
# read strictly (a plain file of at most 1 MB, UTF-8 without a BOM, no duplicate keys, no NaN or Infinity, at most 64 deep); each
# named value present must have exactly its type, or nothing is normalized; those values are dropped and the rest is written
# compactly in its own key order. The release list then holds the sha256 of that canonical form for the path, like any other
# line. Any other difference gives another digest, so it stays a counted WT-I001. The spec ships EMPTY: nothing is normalized until
# a spike (Ken's shape diff with scripts/platform-json-shape.py, then a check of the host loader) proves which fields are unused.
PLATFORM_NORMALIZE_REL = "rules/platform-normalize.json"
PLATFORM_NORMALIZE = os.path.join(HERE, "..", PLATFORM_NORMALIZE_REL)
PLATFORM_NORMALIZE_MAX_BYTES = 64 * 1024
NORMALIZE_FILE_MAX = 1024 * 1024
NORMALIZE_TYPES = {"iso8601": re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})"),
                   "epoch_ms": re.compile(r"1\d{12}"), "hex_digest": re.compile(r"[0-9a-f]{12,128}")}
_PLATFORM_NORMALIZE_CACHE = {}


def _platform_normalize_state():
    """({path under the home folder: [(key path tuple, type)]}, why the spec can't be used or "")."""
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
        ok = (isinstance(e, dict) and set(e) == {"path", "fields"} and _plain_rel(e["path"]) and isinstance(fields, list) and fields
              and all(isinstance(x, dict) and set(x) == {"key", "type"} and isinstance(x["key"], list) and x["key"]
                      and all(isinstance(k, str) and k for k in x["key"]) and x["type"] in NORMALIZE_TYPES for x in fields))
        if not ok:
            out, why = {}, f"entry {n} isn't {{path, fields: [{{key: [...], type}}]}} with a plain platform path and a known type"
            break
        out[e["path"]] = [(tuple(x["key"]), x["type"]) for x in fields]
    _PLATFORM_NORMALIZE_CACHE.update(key=key, state=(out, why))
    return out, why


def platform_normalize_problem():
    """Why rules/platform-normalize.json can't be used, or ""."""
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


def canonical_platform_json(data, fields):
    """The sha256 of `data` (a platform metadata file's bytes) with the spec's `fields` dropped, or None when it can't be read
    strictly or a named value hasn't exactly its type."""
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
        node = doc
        for k in key[:-1]:
            node = node.get(k) if isinstance(node, dict) else None
        if not isinstance(node, dict) or key[-1] not in node:
            continue
        v = node[key[-1]]
        if not (isinstance(v, str) and NORMALIZE_TYPES[typ].fullmatch(v)):
            return None   # a named field holding anything but its type: nothing is normalized, the file stays counted
        del node[key[-1]]
    return hashlib.sha256(json.dumps(doc, separators=(",", ":"), ensure_ascii=False).encode("utf-8")).hexdigest()


def platform_listed_normalized(p, h):
    """True when the spec names p (under the home folder, as written and where it really leads), p is a plain file (never a
    link), and the release list holds the digest of its canonical form for it (platform_listed). PR A, Codex round 2 (9): `h` is
    the sha256 of the bytes the scan read (the manifest's); the bytes read here are normalized only when they are those same
    bytes, so a file swapped between the scan and this read is never vouched for by what it became."""
    spec = _platform_normalize_state()[0]
    if not spec:
        return False
    try:
        n = os.path.normpath(str(p))
        rels = _home_rels(n) & _home_rels(os.path.realpath(n))
        fields = next((spec[r] for r in sorted(rels) if r in spec), None)
        if fields is None:
            return False
        fd = os.open(n, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                return False
            data = b""
            while len(data) <= NORMALIZE_FILE_MAX:
                chunk = os.read(fd, NORMALIZE_FILE_MAX + 1 - len(data))
                if not chunk:
                    break
                data += chunk
        finally:
            os.close(fd)
    except (OSError, ValueError):
        return False
    if not isinstance(h, str) or hashlib.sha256(data).hexdigest() != h:
        return False
    c = canonical_platform_json(data, fields)
    return c is not None and platform_listed(n, c)


# PR #9 (Ken: few false alarms): the platform's own sync bookkeeping, rewritten at every sync with no release (Ken's box, Oct 18:
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


# Codex, item 8 review 2 (high 1): the platform files were only what the scanner's inventory kept, so a baselined SKILL.md turned
# into a link into Watchtower's quarantine (a "not live" skill), a folder link, a loose script outside any skill folder, or a file
# under node_modules (which the walk skips) never reached the provenance check. Provenance has its own walk of each platform folder
# inside the roots: no skip list, no live or quarantine test, every literal name kept (a file reached by two names is two entries),
# folder links followed with a cycle check and limits. A folder it can't finish is a counted high (WT-I011), never a quiet gap.
PLATFORM_WALK_MAX_FILES = 20000
PLATFORM_WALK_MAX_DEPTH = 32
PLATFORM_WALK_MAX_LINKS = 1000   # folder links followed in one walk


def platform_walk_starts(roots):
    """Where platform_inventory walks: each platform folder that lies within these roots, and each requested root that lies
    inside a platform folder (as written or where it leads). Codex, item 8 review 3 (high 3): only the first kind was walked, so
    `--roots ~/.grok/bundled/bin` fingerprinted none of its loose scripts and `--roots ~/.grok/bundled/skills` none of the files
    the scanner's inventory skips (node_modules). A start inside another one is walked once, under the outer one."""
    scope = {os.path.normpath(os.path.abspath(os.path.expanduser(r))) for r in roots}
    rscope = {os.path.realpath(r) for r in scope}
    starts = []
    for root in platform_roots():
        rroot = os.path.realpath(root)
        if _under(root, scope) or _under(rroot, rscope):
            starts.append(root)
            continue
        starts += [s for s in sorted(scope) if _under(s, {root}, strict=True) or _under(os.path.realpath(s), {rroot}, strict=True)]
    starts = list(dict.fromkeys(starts))
    return [s for s in starts if not _under(s, set(starts) - {s}, strict=True)]


def platform_inventory(roots):
    """([every file name in the platform folders that lie within these roots, and in the roots that lie within a platform folder],
    [(folder, why) for what it couldn't finish])."""
    files, short, links = [], [], 0
    for root in platform_walk_starts(roots):
        try:
            st = os.stat(root)
        except OSError:
            continue   # no such folder here
        if not stat.S_ISDIR(st.st_mode):
            files.append(root)   # a file where the folder should be: fingerprinted, so it's an alert
            continue
        stack = [(root, 0, ((st.st_dev, st.st_ino),))]
        while stack:
            d, depth, chain = stack.pop()
            try:
                with os.scandir(d) as it:
                    entries = sorted(it, key=lambda e: e.name)
            except OSError as e:
                short.append((d, f"a folder in it can't be read ({errno.errorcode.get(e.errno, 'error')})"))
                continue
            for e in entries:
                p = os.path.join(d, e.name)
                if platform_churn_file(p):
                    continue   # sync bookkeeping (PLATFORM_CHURN): not a provenance subject, not counted in the limits
                if len(files) >= PLATFORM_WALK_MAX_FILES:
                    short.append((root, f"it holds more than {PLATFORM_WALK_MAX_FILES} files"))
                    stack = []
                    break
                try:
                    link = e.is_symlink()
                    st = os.stat(p)   # where a link leads
                except OSError:
                    files.append(p)   # a broken link, or a name that vanished: fingerprinted as unreadable
                    continue
                if not stat.S_ISDIR(st.st_mode):
                    files.append(p)
                    continue
                if (st.st_dev, st.st_ino) in chain:
                    continue   # a folder link back up into itself: its files are already listed under the shorter name
                if link:
                    links += 1
                    if links > PLATFORM_WALK_MAX_LINKS:
                        short.append((p, f"more than {PLATFORM_WALK_MAX_LINKS} folder links"))
                        continue
                if depth + 1 > PLATFORM_WALK_MAX_DEPTH:
                    short.append((p, f"folders nested more than {PLATFORM_WALK_MAX_DEPTH} deep"))
                    continue
                stack.append((p, depth + 1, chain + ((st.st_dev, st.st_ino),)))
    return files, short


def platform_coverage_finding(d, why):
    v = platform_vendor(d)
    f = finding("WT-I011", f"Watchtower couldn't check all of {v}'s own skill folder", "high", ["AST07", "AST09"], d, why,
                f"A file added or changed in the part it couldn't check would raise no alert. Look at this folder; when {v}'s folder "
                "is back to a normal size and readable, the next audit checks it again.", ident=f"platform-coverage|{d}")
    f["unverified_platform"] = f["platform_coverage"] = True
    return f
