# Part of isr.py: runs inside isr.py's namespace (loaded by _isr_part); not a module on its own.
# ---------------------------------------------------------------- ownership (v0.8.1)
# Who owns a file is decided by where it is: path prefixes, on the path as written and where it really leads, never a list of
# files or hashes. Every other part's name used here (_under, walk, home_bases, literal_path, _place, home, SELF_ROOT,
# ACCESS_WORKSPACE, score, scored, status_of) is read when a function runs: access.py, which binds ACCESS_WORKSPACE, loads after
# this part.
OWNER_CLASSES = ("user", "vendor", "isr_self", "fixture-echo")
OWNER_VENDOR_HOME = ("sand-data/managed-skills", "agent-data/managed-skills", "sand-data/plugins/cache", "agent-data/plugins/cache",
                     ".claude/plugins", ".codex/skills", ".codex/plugins", ".grok/bundled")
OWNER_SELF_WORKSPACE = ("isr-bot-dev", "backups")
OWNER_SELF_WORKSPACE += ("watchtower-dev",)   # the dev checkout's real folder name: the dev tree is never scored
OWNER_ECHO_HOME = (".claude/projects", ".claude/plans")


def _owner_places(cls):
    """(base, sub, leaf) for each prefix of a non-user class. leaf None: base/sub and everything below it; leaf "agent-tools":
    base/sub/<exactly one folder>/agent-tools and everything below it."""
    hs = list(home_bases())
    if cls == "vendor":
        return [(h, s, None) for h in hs for s in OWNER_VENDOR_HOME] + [("/tmp", "hooks", None)]   # the platform's hook scripts
    if cls == "isr_self":
        return [(SELF_ROOT, "", None), (home(), "tests", None)] + [(ACCESS_WORKSPACE, s, None) for s in OWNER_SELF_WORKSPACE]
    return ([(h, s, None) for h in hs for s in OWNER_ECHO_HOME] + [(h, ".cursor/projects", "agent-tools") for h in hs]
            + [(ACCESS_WORKSPACE, "agent-tools", None)])


def _owner_roots(cls):
    """(as written, as resolved). As written: base/sub for the base as given and for its realpath. As resolved: realpath(base)/sub
    only, so a base's own link is followed and the sub-folder's is not: a vendor root that is itself a link elsewhere doesn't make
    elsewhere vendor."""
    written, real = [], []
    for base, sub, leaf in _owner_places(cls):
        b = os.path.normpath(os.path.abspath(base))
        rb = os.path.realpath(b)
        written += [(os.path.normpath(os.path.join(b, sub)), leaf), (os.path.normpath(os.path.join(rb, sub)), leaf)]
        real.append((os.path.normpath(os.path.join(rb, sub)), leaf))
    return written, real


def _owner_in(p, roots):
    for root, leaf in roots:
        if leaf is None:
            if _under(p, (root,)):
                return True
        elif _under(p, (root,), strict=True):
            parts = os.path.relpath(p, root).split(os.sep)
            if len(parts) >= 2 and parts[1] == leaf:
                return True
    return False


def owner_of(p):
    """user, vendor, isr_self or fixture-echo for a plain filesystem path (never a finding's where: owner_of_finding picks the
    path). A class only when the path as written and its realpath are both in it; a link between two classes is user."""
    if not isinstance(p, str) or not p.startswith("/"):
        return "user"
    w = os.path.normpath(os.path.abspath(p))
    r = os.path.realpath(w)
    for cls in OWNER_CLASSES[1:]:   # no two prefixes nest, so the order never changes an answer
        written, real = _owner_roots(cls)
        if _owner_in(w, written) and _owner_in(r, real):
            return cls
    return "user"


def owner_link_into_vendor(p):
    """G8 (decision, Oct 25): the owner's path whose real file is in a vendor folder. Its drift is the owner's, never a built-in update."""
    return owner_of(p) == "user" and owner_of(os.path.realpath(p)) == "vendor"


def vendor_link_out(p):
    """U4fix (decision (b), Oct 25): a path written in a platform folder whose real file is outside every one. Never built-in."""
    written, real = _owner_roots("vendor")
    return _owner_in(os.path.normpath(os.path.abspath(p)), written) and not _owner_in(os.path.realpath(p), real)


def vendor_links_out(roots):
    """E3 (decision, Oct 25, option B): the files behind each vendor_link_out link, by the names written in the vendor folder: a
    vendor folder within the roots (or a root inside one) that is itself such a link, or a folder or file link inside one. Only
    links are looked for; no ordinary vendor file is listed. Their files are the owner's (owner_of), so the audit scans and
    fingerprints them. os.walk follows no link inside a vendor folder; a linked folder's files are walk()'s, with its limits."""
    written = _owner_roots("vendor")[0]
    scope = {os.path.normpath(os.path.abspath(os.path.expanduser(r))) for r in roots}
    rscope = {os.path.realpath(r) for r in scope}
    starts = [w for w, _ in written if _under(w, scope) or _under(os.path.realpath(w), rscope)]
    starts = list(dict.fromkeys(starts + [s for s in sorted(scope) if _owner_in(s, written)]))
    out = []
    for s in starts:
        if _under(s, set(starts) - {s}, strict=True):
            continue   # walked under the outer one
        links, base = ([s] if vendor_link_out(s) else []), s.rstrip("/").count("/")
        for d, ds, fs in ([] if links else os.walk(s)):   # walk()'s limits: 8 folders deep, and never past the run's deadline
            if time_left() <= 0:
                break
            links += [p for p in (os.path.join(d, n) for n in ds + fs) if os.path.islink(p) and vendor_link_out(p)]
            if d.count("/") - base >= 8:
                ds[:] = []
        for p in links:
            out += list(walk([p])) if os.path.isdir(p) else [p] if os.path.isfile(p) else []
    return out


def _owner_members(paths, first=False):
    """A finding with members is the owner's when any member is. Otherwise: the first member's class (first=True, D002's
    projects), else vendor when any member is vendor, then isr_self, then fixture-echo."""
    got = [owner_of(p) for p in paths]
    if "user" in got:
        return "user"
    if first:
        return got[0]
    return next(c for c in OWNER_CLASSES[1:] if c in got)


def owner_of_finding(f):
    """The class of the place a finding names. A decoy finding (ISR-K*) is the owner's wherever it is. One with members (an S002
    group's files, D002's projects, I004/I005's roots) by its members, never its folder. Otherwise the producer's own file
    (literal_path), else _place: one trailing :line off a file finding, a folder verdict's name kept as it is. A where that isn't
    a path is the owner's."""
    if (f.get("rule") or "").startswith("ISR-K"):
        return "user"
    if f.get("member_hits"):
        return _owner_members([m.get("file") for m in f["member_hits"]])
    for k in ("affected_files", "projects", "roots"):
        if f.get(k):
            return _owner_members(f[k], first=k == "projects")
    return owner_of(literal_path(f) or _place(f))


def split_owned(fs, key_status=None):
    """(the owner's findings, vendor findings). isr_self and fixture-echo findings are dropped: they are never shown. A finding
    with members some of which aren't the owner's keeps only the owner's members, rebuilt from them with its key made again
    (§3.4). `key_status`: {"files", "ran"}, the TruffleHog answers the run applied (state/key_status.json when not given)."""
    user, vendor = [], []
    for f in fs:
        c = owner_of_finding(f) if isinstance(f, dict) else "user"   # a stored entry that isn't a finding is left to its reader, as before
        if c == "user" and isinstance(f, dict):
            user.append(_owner_members_kept(f, key_status))
        elif c == "user":
            user.append(f)
        elif c == "vendor":
            vendor.append(f)
    return user, vendor


def _owner_members_kept(f, key_status):
    """f with only its owner's members: an S002 group's member_hits (regroup_s002), D002's projects (_owner_d002)."""
    if (f.get("rule") or "").startswith("ISR-K"):
        return f
    if f.get("member_hits"):
        kept = [m for m in f["member_hits"] if owner_of(m.get("file")) == "user"]
        if len(kept) == len(f["member_hits"]):
            return f
        if key_status is None:
            key_status = load_json(state_path("key_status.json"), {}) or {}
        return regroup_s002(f, kept, key_status.get("files") or {}, bool(key_status.get("ran")))
    if f.get("rule") == "ISR-D002" and f.get("projects") and f.get("ident"):
        kept = [p for p in f["projects"] if owner_of(p) == "user"]
        return f if len(kept) == len(f["projects"]) else _owner_d002(f, kept)
    return f


def _owner_d002(f, kept):
    """D002 on the owner's projects only: the first one is its where, "· used in N projects" is said again (dropped for one), and
    key and key0 are made with finding()'s formula, so a backup copy coming or going never makes a new/fixed pair."""
    ev = re.sub(r" · used in \d+ projects$", "", f.get("evidence") or "") + (f" · used in {len(kept)} projects" if len(kept) > 1 else "")
    return dict(f, where=kept[0], projects=kept, evidence=ev, key0=finding_key(f["rule"], kept[0], ev),
                key=hashlib.sha1(f"{f['rule']}|{kept[0]}|id:{f['ident']}".encode()).hexdigest()[:16])


def plugin_move_line(e):
    """A pending plugin's version-folder event as the sentence audit notes and daily say."""
    return (f"Plugin {e['name']} changed version folder ({', '.join(os.path.basename(r) for r in e['from'])} → "
            f"{', '.join(os.path.basename(r) for r in e['to'])}); it is still waiting for your decision (ISR-I004).")


def owner_gate(fs, meta):
    """The one gate (§3.3 item 1), in run_audit_locked before anything is scored: (the owner's findings, vendor records). Vendor
    records are labelled, keep their severity for breakdown and lose _snap; isr_self and fixture-echo ones are dropped; no
    finding keeps a secret's fingerprint (drop_fingerprints). Plugin
    version events (data, audit.py) become the notes and daily's plugin_version_changes for the owner's plugins only."""
    fs, vendor = split_owned(fs, meta.get("key_status"))
    drop_fingerprints(fs + vendor)   # v0.8.2 (D1): the owner split was the last use of a found secret's fingerprint
    for v in vendor:
        v.pop("_snap", None)
    lines = [plugin_move_line(e) for e in meta.get("plugin_version_changes") or []
             if isinstance(e, dict) and owner_of((e.get("roots") or [""])[0]) == "user"]
    meta["plugin_version_changes"] = lines
    meta["notes"] += lines
    return fs, label_findings(vendor)


def owned_dict(d):
    """The entries of a {path: ...} map whose path is the owner's."""
    return {k: v for k, v in d.items() if owner_of(k) == "user"}


def _owner_older(v):
    """True for a snapshot written before 0.8.1 (or with no version ISR Bot can read)."""
    try:
        return tuple(int(x) for x in str(v).split(".")[:3]) < (0, 8, 1)
    except ValueError:
        return True


def normalize_snapshot(snap):
    """A stored snapshot as v0.8.1 shows it: findings and suppressed split by owner (vendor records move to "vendor"; isr_self
    and fixture-echo ones are dropped), and the score, grade and status it holds made again from the findings kept, when it is
    older than 0.8.1 or anything was split out. The input isn't changed; the file on disk isn't rewritten."""
    if not isinstance(snap, dict):
        return snap
    out, vendor, split = dict(snap), list(snap.get("vendor") or []), False
    for k in ("findings", "suppressed"):
        if isinstance(snap.get(k), list):
            out[k], v = split_owned(snap[k])
            split = split or len(out[k]) != len(snap[k])
            vendor += v
    if vendor or "vendor" in snap:
        out["vendor"] = vendor
    if split or _owner_older(snap.get("version")):
        live = scored(out.get("findings") or [])
        s, g = score(live)
        for k, v in (("score", s), ("grade", g), ("status", status_of(live))):
            if k in snap:
                out[k] = v
    return out


def load_snapshot(default):
    """last_findings.json through normalize_snapshot; `default` when it is missing or unreadable."""
    return normalize_snapshot(load_json(state_path("last_findings.json"), default))
