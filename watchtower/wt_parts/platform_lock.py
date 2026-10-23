# Part of wt.py: runs inside wt.py's namespace (loaded by _wt_part); not a module on its own.
# Item 8 (R3, roadmap row 8): vendor provenance for the platform's own folders. None of them ships a manifest, signature or hash
# list Watchtower can use, and anything inside the home folder is the Bot's to write. The only vendor hash list the Bot can't
# silently change is one in Watchtower's own release: rules/platform-release.lock, listed in MANIFEST.sha256 and held to it here
# like the scanner lock. Lines are `sha256sum` output run from the home folder: "<sha256>  <path under the home folder>". A file
# whose path and exact bytes are listed is the vendor's. Decision, Oct 22 (b8i4, the middle path): versions differ per user, so
# the shipped list can't be the only trust. A new or changed file at a path that already exists (on the list, any hash, or in the
# baseline), or in a new platform skill folder, that Watchtower's rules find nothing in and no two scanners name a dangerous
# behavior in, is the quiet Platform refresh line and rolls into the baseline on the next full audit (platform_update_candidates,
# settle_platform_updates). Anything else stays a counted high. Nothing on the computer approves a platform file (no owner's yes,
# no record). Filled Oct 18 from the maintainer's box (see its header); a `<bucket>` line lists a file in every account's sync
# bucket; the platform's sync bookkeeping (PLATFORM_CHURN) is never listed and never needs to be.
PLATFORM_LOCK_REL = "rules/platform-release.lock"
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


def unverified_platform_finding(p, h, was=None, why=""):
    """A new or changed file in a platform folder that the vendor release list doesn't include, with these bytes at this path:
    a counted high. No `refresh` key, so it never goes into the Platform refresh Tip and an audit never rolls it into the
    baseline; `unverified_platform` keeps it out of the platform scope, `fix --revet`, `accept` and `dismiss`. Only a Watchtower
    release that lists it clears it (decision, Oct 18), or (b8i4) a later version that passes the middle path's checks. `why`:
    the one sentence that says why a middle-path candidate was held (settle_platform_updates); it starts the fix, and rule,
    title, evidence and key stay as they are. Fix round 1 (Codex 1): such a finding is marked `platform_candidate`; one without
    the mark (a first run's, or any held outside the middle path) keeps a new skill folder's files held (platform_held_before)."""
    f = _unverified_platform_finding(p, h, was)
    if why:
        f["fix"] = f"{why} {f['fix']}"
        f["platform_candidate"] = True
    return f


def _unverified_platform_finding(p, h, was=None):
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
# Decision, Oct 18: release list only; the old record and the ledger are never read, and `--approve-platform` is refused
# (approve_platform). Decision, Oct 22 (b8i4): the middle path. A path that already exists (a release-list line with any hash, or
# a baseline line) or a new platform skill folder makes a file a candidate, and only Watchtower's own checks of its bytes this run
# let it through. The baseline is Bot-writable, so a Bot that writes a line makes a path "already existing" (accepted, Oct 22);
# a loose file, a link in or out, a colon, an unusable release list, and a first run's loose files stay counted highs. Fix round 1
# (Codex 1): a new skill folder, or a new file in one, is a candidate only in an update run (an established baseline), and never
# while the last run held it outside the middle path (a first run's file stays held on every later run, platform_held_before).
OLD_PLATFORM_APPROVALS = "platform_approved.json"   # written by earlier versions; never read, never deleted (one note while it exists)


def platform_unproven(manifest):
    """The files in this manifest that sit in a platform folder and aren't on the release list with these bytes (platform_listed),
    nor with the digest of their canonical form where the release's normalization spec names them (platform_verified, which
    checks the spec's units against this same manifest: batch 6, B1)."""
    return {p for p, h in manifest.items() if not p.startswith("persist:") and platform_ish(p) and not platform_listed(p, h)
            and not platform_churn_file(p) and not platform_listed_normalized(p, h, manifest)}


def platform_skill_folder(p, manifest):
    """b8i4: the nearest folder above p, strictly inside the platform root p is in, whose SKILL.md is in this run's manifest,
    or None (a loose file)."""
    n = os.path.normpath(str(p))
    root = max((r for r in platform_roots() if _under(n, {r}, strict=True)), key=len, default=None)
    if root is None:
        return None
    d = os.path.dirname(n)
    while _under(d, {root}, strict=True):
        if os.path.join(d, "SKILL.md") in manifest:
            return d
        d = os.path.dirname(d)
    return None


def _known_under(d, base):
    """True when the baseline or the release list (any line, any hash) has a path under the folder d."""
    if any(q.startswith(d + os.sep) for q in base):
        return True
    keys = [k for lk in (platform_lock(), platform_lock_canonical() or {}) for k in lk]
    try:
        rels = _home_rels(d) | _home_rels(os.path.realpath(d))
    except OSError:
        return True
    for r in rels:
        m = re.fullmatch(r"(\.claude/plugins/synced/)" + _BUCKET_PAIR + r"(/.*)?", r)
        forms = {r} | ({m.group(1) + "<bucket>" + (m.group(2) or "")} if m else set())
        if any(k.startswith(x + "/") for x in forms for k in keys):
            return True
    return False


def platform_real_roots():
    """Fix round 1 (Codex 2): where each platform folder really is, worked out from each home base's own real folder, never from
    where the platform folder itself leads: a .grok/bundled replaced by a link to a folder outside makes that folder no platform
    folder. A link from one platform folder into another (agent-data's managed skills leading into sand-data's) still lands in one."""
    return {os.path.normpath(os.path.join(os.path.realpath(b), sub)) for b in home_bases() for sub in PLATFORM_ROOT_SUBS}


PLATFORM_HELD = "platform_held.json"   # fix round 2 (Codex 1): the held paths, kept by every run and by `wt.py baseline`


def _held_paths(fs):
    """The paths of the findings in fs held outside the middle path (an unverified_platform finding without `platform_candidate`),
    with the other places a merged finding names."""
    out = set()
    for f in expand_groups(fs):
        if isinstance(f, dict) and f.get("unverified_platform") and not f.get("platform_candidate") and not f.get("platform_coverage"):
            out.update(q for q in [f.get("where")] + list(f.get("also_at") or []) if isinstance(q, str))
    return out


def platform_held_before():
    """Fix round 1 (Codex 1): the platform files the last run held outside the middle path (an unverified_platform finding without
    `platform_candidate`: a first run's, or one held while the release list couldn't be used or its folder couldn't be walked),
    with the other places a merged finding names. Such a file isn't new in this run, so it is no "new-skill" or "in-skill"
    candidate: held on a first run, held on every run after. Read from state/last_findings.json and (fix round 2, Codex 1)
    state/platform_held.json, which `wt.py baseline` writes too (its audit saves no findings), so a first baseline taken by the
    command holds as a first audit does. The Bot can write both (deleting them is like writing a baseline line: the accepted limit)."""
    prev = load_json(state_path("last_findings.json"), {}) or {}
    out = _held_paths(list(prev.get("findings") or []) + list(prev.get("suppressed") or [])) if isinstance(prev, dict) else set()
    kept = load_json(state_path(PLATFORM_HELD), None)
    if isinstance(kept, dict) and isinstance(kept.get("paths"), list):
        out.update(q for q in kept["paths"] if isinstance(q, str))
    return out


def save_platform_held(fs, before):
    """Fix round 2 (Codex 1): every path this run held outside the middle path, and every one held before that is still there (a
    run with other roots doesn't see it, and must not forget it), in state/platform_held.json. Written once there is one."""
    paths = sorted(q for q in _held_paths(fs) | set(before or ()) if os.path.lexists(q))
    if paths or os.path.lexists(state_path(PLATFORM_HELD)):
        save_json(state_path(PLATFORM_HELD), {"paths": paths})


def platform_update_candidates(unproven, manifest, base, short, established=False, held_before=frozenset()):
    """b8i4 (decision, Oct 22: the middle path): {path: (kind, skill folder or None)} for the files in `unproven` that may be a
    platform update without a release-list line for their bytes. Only while the release list is usable (an unusable one turns
    the quiet path off, so its note stays true); only a path with no colon, strictly inside a platform root as written and as
    its real path (platform_skill_path: links in or out, lookalike folders and an owner's folder never are), whose real path is
    inside a platform folder where the home folder really has it (platform_real_roots: fix round 1, Codex 2), not itself a link
    (a folder above it may be one, inside the platform roots: agent-data linked to sand-data), fingerprinted as a
    sha256, and not under a folder platform_inventory couldn't finish (WT-I011). Kinds: "update", the path is on the release
    list (any hash, `<bucket>` lines included) or in the baseline; "new-skill", its skill folder (platform_skill_folder) has no
    path the baseline or the release list knows; "in-skill", it has. A loose file at no known path is no candidate. Fix round 1
    (Codex 1): "new-skill" and "in-skill" only in an update run (`established`: a baseline to compare with), and never for a file
    the last run held outside the middle path (`held_before`, platform_held_before). Fix round 2 (Codex 2): each candidate is
    bound to the real path it had here (PLATFORM_BOUND), and platform_still_bound checks it again before it is settled and rolled."""
    PLATFORM_BOUND.clear()
    if platform_lock_problem():
        return {}
    gaps = {os.path.normpath(d) for d, _ in short}
    real_roots = platform_real_roots()
    known, out = {}, {}
    for p in sorted(unproven):
        h = manifest.get(p)
        if (":" in p or not isinstance(h, str) or not re.fullmatch(r"[0-9a-f]{64}", h) or _under(os.path.normpath(p), gaps)
                or os.path.islink(p) or not platform_skill_path(p, line=False)):
            continue   # a file that is itself a link (to another file, even in the same root) is no vendor file: never quiet
        rp = os.path.realpath(p)
        if not _under(rp, real_roots, strict=True):
            continue
        d = platform_skill_folder(p, manifest)
        if p in base or platform_lock_path(p):
            out[p] = ("update", d)
        elif d is not None and established and p not in held_before:
            if d not in known:
                known[d] = _known_under(d, base)
            out[p] = ("in-skill" if known[d] else "new-skill", d)
        if p in out:
            PLATFORM_BOUND[p] = rp
    return out


PLATFORM_BOUND = {}   # fix round 2 (Codex 2): {candidate: the real path it had when platform_update_candidates chose it}


def platform_still_bound(p):
    """Fix round 2 (Codex 2): True while the candidate p still leads where it led when it was chosen, that place is still inside a
    platform folder where the home folder really has it, and p is still no link and still a platform skill path. A platform
    folder moved out and replaced by a link while the scanners ran (the file's bytes kept) fails this, so it is never quiet and
    never rolled in."""
    rp = PLATFORM_BOUND.get(p)
    try:
        return (rp is not None and os.path.realpath(p) == rp and not os.path.islink(p) and bool(platform_skill_path(p, line=False))
                and _under(rp, platform_real_roots(), strict=True))
    except (OSError, ValueError):
        return False


PLATFORM_MOVED = "It moved out of the platform's own folders while Watchtower was checking it."   # platform_still_bound failed
PLATFORM_UPDATE_MAX = 1_000_000   # bytes of a candidate Watchtower reads whole (read_scanned's limit)


def platform_scan_verdict(batch, t):
    """What settle_platform_updates needs from one scan of a file's text: the rules that hit at medium or above (guarded
    records count, at the scan's own severity), and whether the text isn't plain UTF-8 (a NUL, or bytes that didn't decode)."""
    return (sorted({f["rule"] for f in batch if f.get("severity") in ("critical", "high", "medium")}),
            "\x00" in t or "\N{REPLACEMENT CHARACTER}" in t)


def _instruction_texts(t):
    """Fix round 1 (Codex 4): the text values of a platform metadata JSON file (cache.json's skill bodies and descriptions, a
    plugin's description, a prompt): every string value in it, duplicate keys included, each read on its own (once). Fix round 2
    (Codex 3): with or without a blank in it, as decoded: "eval\\u0028payload\\u0029" is eval(payload) to the platform. None when it
    isn't JSON, so nothing in it can be read as an instruction."""
    out = {}

    def pairs(ps):
        for _, v in ps:
            walk(v)
        return {}

    def walk(v):
        if isinstance(v, str):
            out[v] = None
        elif isinstance(v, list):
            for x in v:
                walk(x)

    try:
        walk(json.loads(t, object_pairs_hook=pairs))
    except (ValueError, RecursionError):
        return None
    return list(out)


def platform_full_verdict(p, t, rules):
    """Fix round 1 (Codex 4): the rules that hit at medium or above in the text t of the platform file p, read as the owner's own
    file would be (the whole rule set: a SKILL.md as a skill, anything else as a reference file; never the reduced vendor set),
    with DQ-024's template exception kept (story wording in a built-in deck template is info). A metadata JSON file
    (PLATFORM_METADATA) also has each of its text values read as skill text (WT-T013 included): that is what the platform loads as
    a skill's instructions. Returns platform_scan_verdict's (rules, not plain text); "WT-JSON" stands for metadata that isn't JSON."""
    batch = scan_text(t, p, rules, kind="skill" if os.path.basename(p) == "SKILL.md" else "reference")
    if is_vendor_template_file(p):   # DQ-024, as the skill scan does
        for f in batch:
            if f["rule"] in ("WT-T008", "WT-T016"):
                f["severity"] = "info"
    hit, binary = platform_scan_verdict(batch, t)
    if PLATFORM_METADATA.fullmatch(os.path.basename(p)):
        texts = _instruction_texts(t)
        if texts is None:
            hit = sorted(set(hit) | {"WT-JSON"})
        for s in texts or ():
            hit = sorted(set(hit) | set(platform_scan_verdict(scan_text(s, p, rules, kind="skill"), s)[0]))
    return hit, binary


def finding_files(g):
    """Fix round 2 (Codex 4): every file a finding is about, with its rule: its own place, each file a grouped finding stands for
    (gitleaks's WT-S002 on a folder keeps them in `affected_files`) and each finding folded into it (`also_flagged_by`)."""
    out = [(g.get("rule"), g.get("where"))] + [(g.get("rule"), q) for q in g.get("affected_files") or []]
    out += [(a.get("rule"), a.get("where")) for a in g.get("also_flagged_by") or [] if isinstance(a, dict)]
    return [(str(r or ""), _path_part(w)) for r, w in out if isinstance(w, str) and w.startswith("/")]


def coverage_gaps(g):
    """Fix round 3 (Codex 2): the folders a grouped finding stands for without naming every file in them: a result on a folder
    (its `where` is one) saved without its list of files (`affected_files`: one from before fix round 2, carried by a daily or by
    an audit whose gitleaks failed), and a root-cause group with more members than it names (`also_count`), by its skill folder.
    Told by what the finding holds and what is on disk, never by a folder's name."""
    w = g.get("where")
    if not isinstance(w, str) or not w.startswith("/"):
        return []
    q, out = _path_part(w), []
    if not isinstance(g.get("affected_files"), list) and os.path.isdir(q):
        out.append(q)
    named = g.get("also_flagged_by") if isinstance(g.get("also_flagged_by"), list) else []
    if isinstance(g.get("also_count"), int) and g["also_count"] > len(named):
        out.append(skill_root(q) or os.path.dirname(q))
    return out


def flag_index(fs):
    """Fix round 2 (Codex 4): {path: rules} of the findings in fs at medium or above that _flagged_here counts, each file by its
    path as written and its real path, grouped findings by every file they stand for (finding_files). A line carried from the last
    run by the severity it was found at: there it was a Platform line (mark_platform made it info, keeping `severity_was`). Fix
    round 3 (Codex 2): a grouped finding that doesn't name all its files (coverage_gaps) holds every file under its folder, keyed
    by the folder with a trailing separator, until a scan that finishes gives the files again."""
    idx = {}
    for g in fs:
        if (g.get("severity_was") or g.get("severity")) not in ("critical", "high", "medium"):
            continue
        keys = [(r, q, "") for r, q in finding_files(g)] + [(str(g.get("rule") or ""), d, os.sep) for d in coverage_gaps(g)]
        for r, q, tail in keys:
            if r.startswith(("WT-I", "WT-X")):
                continue
            try:
                rq = os.path.realpath(q)
            except (OSError, ValueError):
                rq = q
            for k in {q, rq}:
                idx.setdefault(k.rstrip(os.sep) + tail if tail else k, set()).add(r)
    return idx


def _flagged_here(p, idx):
    """Fix round 1 (Codex 4): the rules of this run's other findings at medium or above on the file p (or its real path): an
    unpinned MCP launcher (WT-M001), a key in it (WT-S001, gitleaks's WT-S002, carried from the last run when gitleaks failed),
    and every other family. The scanners' folder votes (WT-X) are decided by _vote_why; integrity lines (WT-I) are this check's.
    Fix round 2 (Codex 4): `idx` is flag_index's, so a grouped finding holds every file it stands for. Fix round 3 (Codex 2): and
    one that doesn't name them all holds every file in a folder above p (or above its real path)."""
    try:
        rp = os.path.realpath(p)
    except (OSError, ValueError):
        rp = p
    out = idx.get(p, set()) | idx.get(rp, set())
    for x in {p, rp}:
        d = os.path.dirname(x)
        while True:
            out = out | idx.get(d.rstrip(os.sep) + os.sep, set())
            if os.path.dirname(d) == d:
                break
            d = os.path.dirname(d)
    return sorted(out)


def _candidate_why(p, h, rules, idx):
    """Why the candidate p (sha256 h) can't be quiet on its own bytes, or "". Fix round 1 (Codex 4): its bytes are read again
    here and must be exactly the ones the audit fingerprinted (h), and the whole rule set reads them (platform_full_verdict);
    any other finding of this run at medium or above on the file holds it too (_flagged_here). Fix round 2 (Codex 2): it must
    still lead where it led when it was chosen, inside a platform folder (platform_still_bound), before and after the read."""
    if not platform_still_bound(p):
        return PLATFORM_MOVED
    t, h2 = read_scanned(p, limit=PLATFORM_UPDATE_MAX)
    if not platform_still_bound(p):
        return PLATFORM_MOVED
    if t is None:
        return ("It is over 1 MB, so Watchtower can't check all of it." if not h2.startswith("unreadable:")
                else "Watchtower couldn't read it.")
    if h2 != h:
        return "It changed while Watchtower was checking it."
    hit, binary = platform_full_verdict(p, t, rules)
    if binary:
        return "Watchtower can't read it as plain text, so its rules can't check it."
    hit = sorted(set(hit) | set(_flagged_here(p, idx)))
    if hit:
        return f"Watchtower's rules flagged the new version ({', '.join(hit[:4])})."
    return ""


def _vote_why(p, d, fs):
    """Why a scanner vote holds the candidate p (in skill folder d), or "": a WT-X003 on d or on a folder above p that isn't a
    wording-only vote on a platform skill (DQ-042: a dangerous kind, or an answer that may lack one, kinds_incomplete)."""
    for g in fs:
        if g.get("rule") != "WT-X003":
            continue
        x = _path_part(g.get("where") or "", line=False)
        if not (p.startswith(x + os.sep) or (d and (d == x or d.startswith(x + os.sep)))):
            continue
        if unconfirmed_platform_vote(g, fs):
            continue
        if g.get("kinds_incomplete"):
            return "The scanners' answer for its folder is out of date, so Watchtower can't tell what they found."
        return "Two scanners name a dangerous behavior in its folder."
    return ""


def settle_platform_updates(fs, cands, manifest, base, rules):
    """b8i4: decide each candidate (platform_update_candidates) at the end of audit(), after the engines. One is held when
    Watchtower's whole rule set hits at medium or above in exactly the bytes it fingerprinted, read again here, or another finding
    of this run at medium or above is on it (_candidate_why, fix round 1), when it is over 1 MB, not plain text or unreadable,
    or when a WT-X003 covers it that isn't a wording-only platform vote. A new skill folder is all or nothing; a new file in a
    known skill folder is quiet only beside an update of a file the baseline has in that folder that is quiet this run, with
    nothing in the folder held. A held one is a counted high (unverified_platform_finding, its fix starting with why) and its
    refresh finding goes; a quiet one's refresh finding (the drift loop's low WT-I001/I002) gets `platform_update` and goes into
    the Platform refresh line, and roll_builtin rolls it on a full audit. A quiet file the baseline already has with these
    bytes, or a changed file at a release-list path seen on a first run, raises nothing."""
    if not cands:
        return fs
    why, idx = {}, flag_index(fs)
    for p, (kind, d) in sorted(cands.items()):
        why[p] = _candidate_why(p, manifest[p], rules, idx) or _vote_why(p, d, fs)
    held_dirs = {d for p, (_, d) in cands.items() if d and why[p]}
    for f in fs:   # anything held this run under a skill folder (the files that are no candidate) holds the folder too
        if f.get("unverified_platform"):
            w = _path_part(f.get("where") or "", line=False)
            held_dirs |= {d for _, d in cands.values() if d and _covers(d, w)}
    # fix round 1 (Codex 1): an update is a change of a file the baseline has; a path missing from it is no update of the folder
    updated = {d for p, (kind, d) in cands.items() if kind == "update" and d and not why[p] and p in base and base[p] != manifest[p]}
    for p, (kind, d) in cands.items():
        if why[p] or kind == "update":
            continue
        if d in held_dirs:
            why[p] = ("Another file in this new skill folder didn't pass Watchtower's checks, so none of it is accepted." if kind == "new-skill"
                      else "Another file in this skill folder didn't pass Watchtower's checks.")
        elif kind == "in-skill" and d not in updated:
            why[p] = "It is a new file in a skill folder that wasn't updated in this run."
    out = []
    for f in fs:
        w = f.get("where")
        if f.get("rule") in ("WT-I001", "WT-I002") and "refresh" in f and w in cands:
            if why[w]:
                continue
            f["platform_update"] = True
        out.append(f)
    out += [unverified_platform_finding(p, manifest[p], base.get(p), why=why[p]) for p in sorted(cands) if why[p]]
    return out


def hold_on_kept_votes(fs, manifest):
    """b8i4, daily: a WT-X003 kept from the last run (kinds_incomplete: its answer may lack a kind) covering a quiet platform
    update turns it into a counted high until a full audit scans the folder again. The engines answer only in the audit, so this
    runs after daily keeps last run's scanner lines. Fix round 1 (Codex 4): so does a line kept from the last run at medium or
    above on the file itself (gitleaks's WT-S002: daily doesn't run gitleaks)."""
    if not any(f.get("platform_update") for f in fs):
        return fs
    kept = [_path_part(g.get("where") or "", line=False) for g in fs if g.get("rule") == "WT-X003" and g.get("kinds_incomplete")]
    base = load_baseline()[0]
    out, held, idx = [], {}, flag_index(fs)   # fix round 2 (Codex 4): a kept grouped line by every file it stands for
    for f in fs:
        if f.get("platform_update"):
            ps = [f["where"]] + list(f.get("also_at") or [])
            if any(q.startswith(x + os.sep) for q in ps for x in kept):
                why = "The scanners' answer for its folder is from an earlier run, so Watchtower can't tell what they found."
            else:
                hit = sorted({r for q in ps for r in _flagged_here(q, idx)})
                why = f"Watchtower's checks flagged it ({', '.join(hit[:4])})." if hit else ""
            if why:
                for q in ps:
                    if isinstance(manifest.get(q), str) and re.fullmatch(r"[0-9a-f]{64}", manifest[q]):
                        held.setdefault(q, why)
                continue
        out.append(f)
    return out + [unverified_platform_finding(q, manifest[q], base.get(q), why=held[q]) for q in sorted(held)]


def unbound_updates(fs):
    """Fix round 3 (Codex 1): the quiet platform updates in fs (`platform_update`) with a place, a merged one's also_at included,
    that no longer leads where it led when it was chosen (platform_still_bound)."""
    return [f for f in fs if f.get("platform_update")
            and not all(platform_still_bound(q) for q in [f.get("where")] + list(f.get("also_at") or []))]


def hold_moved_updates(fs, moved, manifest):
    """Fix round 3 (Codex 1): fail closed on the quiet updates in `moved` (unbound_updates) found after settlement: each goes from
    fs, so the Platform refresh line never names it, and every place it names (also_at included) is a counted high instead
    (unverified_platform_finding, its fix starting with PLATFORM_MOVED) that never rolls: the baseline keeps its old hash."""
    if not moved:
        return fs
    gone = {id(f) for f in moved}
    places = sorted({q for f in moved for q in [f["where"]] + list(f.get("also_at") or [])})
    base = load_baseline()[0]
    held = [unverified_platform_finding(q, manifest[q], base.get(q), why=PLATFORM_MOVED) for q in places
            if isinstance(manifest.get(q), str) and re.fullmatch(r"[0-9a-f]{64}", manifest[q])]   # every candidate's is
    return merge_managed_mirrors([f for f in fs if id(f) not in gone] + held, manifest)


def hold_unbound_updates(fs, manifest):
    """Fix round 3 (Codex 1): every run, after settlement and daily's carried lines and before roll_builtin's gate and the Platform
    refresh line, each quiet update is checked again where it leads; one that moved is a counted high (hold_moved_updates)."""
    return hold_moved_updates(fs, unbound_updates(fs), manifest)


def merge_managed_mirrors(fs, manifest):
    """b8i4: the platform keeps the same managed skills under sand-data/managed-skills and agent-data/managed-skills. The same
    file (same path below each, same sha256, same rule, both held or both quiet) is one finding: the sand-data one keeps its key
    and names the other place (`also_at`, and a sentence in its fix)."""
    pairs = [(os.path.join(os.path.normpath(b), "sand-data", "managed-skills"), os.path.join(os.path.normpath(b), "agent-data", "managed-skills"))
             for b in home_bases()]

    def sort_key(f):   # fix round 1: and both middle-path holds or both not (platform_held_before reads each place's)
        return (f["rule"], bool(f.get("unverified_platform")), bool(f.get("platform_update")), bool(f.get("platform_candidate")))

    sand, agent, was = {}, [], {}
    for f in fs:
        if (f.get("rule") not in ("WT-I001", "WT-I002", "WT-I003") or not ("refresh" in f or f.get("unverified_platform"))
                or f.get("platform_coverage")):
            continue
        w = str(f.get("where") or "")
        for s, a in pairs:
            if w.startswith(s + os.sep):
                sand.setdefault((s, w[len(s) + 1:]) + sort_key(f), f)
            elif w.startswith(a + os.sep):
                agent.append(((s, w[len(a) + 1:]) + sort_key(f), f))

    def sha_of(f):   # a removed file (WT-I003) by the bytes the baseline had for it
        if f["rule"] != "WT-I003":
            return manifest.get(f["where"])
        if "base" not in was:
            was["base"] = load_baseline()[0]
        return was["base"].get(f["where"])

    gone = set()
    for k, f in agent:
        g = sand.get(k)
        h = sha_of(f) if g is not None else None
        if g is None or not isinstance(h, str) or h != sha_of(g):
            continue
        g.setdefault("also_at", []).append(f["where"])
        g["fix"] = f"{g['fix']} The same file (same sha256) is also at {f['where']}."
        gone.add(id(f))
    return [f for f in fs if id(f) not in gone] if gone else fs


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
    want = release_want(path, rel)   # batch 6 (KL4): held to MANIFEST.sha256 in every layout, a developer checkout included
    if want is not None and hashlib.sha256(data).hexdigest() != want:
        return b"", _not_shipped(want)
    return data, ""


def _not_shipped(want):
    """Why a rules file that isn't its MANIFEST.sha256 line is refused."""
    if not want and release_files_unchecked():
        return "Watchtower's release files can't be checked (its MANIFEST.sha256 is missing or unreadable)"
    if not want:
        return "MANIFEST.sha256 doesn't list it, so it can't be checked"
    return "it isn't the file this release of Watchtower shipped (MANIFEST.sha256)"


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


# Batch 5 (d2, decision 1, Oct 18): findings Watchtower's team read in exact versions of the platform's own files. One entry
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


# Batch 5 (d3b, decision 3, Oct 18): a release-shipped normalization spec for the platform's metadata JSON. An entry names a
# path under the home folder and the exact key paths whose values the platform's own sync rewrites, each with a type. The file is
# read strictly (a plain file of at most 1 MB, UTF-8 without a BOM, no duplicate keys, no NaN or Infinity, at most 64 deep); each
# named value present must have exactly its type, or nothing is normalized; those values are dropped and the rest is written
# compactly in its own key order. The release list then holds the sha256 of that canonical form for the path, like any other
# line. Any other difference gives another digest, so it stays a counted WT-I001. The spec ships EMPTY: nothing is normalized until
# a spike (the maintainer's shape diff with scripts/platform-json-shape.py, then a check of the host loader) proves which fields are unused.
PLATFORM_NORMALIZE_REL = "rules/platform-normalize.json"
PLATFORM_NORMALIZE = os.path.join(HERE, "..", PLATFORM_NORMALIZE_REL)
PLATFORM_NORMALIZE_MAX_BYTES = 64 * 1024
NORMALIZE_FILE_MAX = 1024 * 1024
NORMALIZE_TYPES = {"iso8601": re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})"),
                   "epoch_ms": re.compile(r"1\d{12}"), "hex_digest": re.compile(r"[0-9a-f]{12,128}"),
                   # batch 6 (B1): a JSON number of milliseconds (an int, never a bool or a float) and a UUID
                   "epoch_ms_number": None, "uuid": re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")}
_PLATFORM_NORMALIZE_CACHE = {}

# Batch 6 (B1, decision: option D): an entry may also name `units`, where the per-skill or per-file units of the file are and
# the file in the same platform root each must equal. Watchtower then checks, by content, that the file says nothing beyond what it
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
    B1) replaced by {"$unit": <id>} once check(unit, id, how, value) says it equals what Watchtower fingerprinted, or None when it
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
