# Part of isr.py: runs inside isr.py's namespace (loaded by _isr_part); not a module on its own.
# ---------------------------------------------------------------- canaries (zero-token tripwires)
# Where the decoys live. Until v0.6.5 they sat in /workspace and the home folder. The platform backs those up after a Bot's turn
# and reads every file to do it, so the decoys were read within minutes of each reset and could not tell the backup from a snoop.
# A test on a real box (Oct 8 2026) showed files in /var/tmp and /tmp are not read by the backup, and that reads there are recorded.
CANARY_SPECS = [
    ("customers", "/var/tmp/.archive/customers-export-2025.csv",
     "name,email,phone,card_last4,notes\nDana Whitfield,{tok}@example.com,555-0101,4417,priority account\n"),
    ("cloud-keys", "/var/tmp/.backup/aws-credentials.bak",
     "[default]\naws_access_key_id = AKIA{tokU}\naws_secret_access_key = {tok}{tok}\n"),
    ("api-env", "/tmp/.archive/payments.env", "STRIPE_SECRET_KEY=rk_live_{tok}{tok}\nPAYOUT_ACCOUNT=acct_{tok}\n"),
]
OLD_CANARY_PATHS = ("/workspace/.archive/customers-export-2025.csv", "~/.config/backup/aws-credentials.bak", "/workspace/.archive/payments.env")
# v0.6.8: the spec paths above were the same on every install and printed in ISR Bot's own docs, so anything that read the
# docs knew which files not to touch. Each install now picks its own folder and file names (kept in state/decoy_layout.json);
# the spec gives only the place (/var/tmp or /tmp) and the kind of file. Decoys found at a published name are moved once.
PUBLISHED_CANARY_PATHS = tuple(x for _, x, _ in CANARY_SPECS)
DECOY_FOLDERS = ("cache", "backup", "old", "export", "sync", "restore", "snapshots", "archive", "tmpdata", "stash")
DECOY_STEMS = {"customers": ("customers", "clients", "crm-export", "contacts", "accounts"),
               "cloud-keys": ("aws-credentials", "cloud-keys", "credentials", "deploy-keys", "iam-backup"),
               "api-env": ("payments", "billing", "prod", "stripe", "secrets")}
_RANDOM_DECOY = re.compile(r"^\.[a-z]+-[0-9a-f]{6}/[a-z0-9-]+-[0-9a-f]{4}\.[a-z0-9]+$")


def _spec_base(path):
    return os.path.dirname(os.path.dirname(path))


def valid_layout_path(name, logical):
    """A layout entry is used, and its file may ever be removed, only if it is one of this install's random names in the spec's own
    place (or a published or older name, which ISR Bot once used). Anything else in the layout file is ignored, so a Bot that
    edits it can't point ISR Bot at another file."""
    spec = {n: x for n, x, _ in CANARY_SPECS}.get(name)
    if not spec or not isinstance(logical, str):
        return False
    if logical in (spec,) + PUBLISHED_CANARY_PATHS + OLD_CANARY_PATHS:
        return True
    base = _spec_base(spec)
    rel = logical[len(base):].lstrip("/") if logical.startswith(base.rstrip("/") + "/") else ""
    return bool(_RANDOM_DECOY.match(rel)) and os.path.splitext(rel)[1] == os.path.splitext(spec)[1]


def random_decoy_path(name, spec):
    import secrets as _s
    stem = _s.choice(DECOY_STEMS.get(name, ("data",)))
    return os.path.join(_spec_base(spec), f".{_s.choice(DECOY_FOLDERS)}-{_s.token_hex(3)}", f"{stem}-{_s.token_hex(2)}{os.path.splitext(spec)[1]}")


def decoy_layout(renew=()):
    """This install's decoy places, one per spec, picked at random the first time and kept. `renew` names get new places.
    v1.2.0: the chaff names, far-sentinel folders and value salt kept in the same file (LAYOUT_EXTRAS) are carried over as they are."""
    path = state_path("decoy_layout.json")
    raw = load_json(path, {}) or {}
    raw = raw if isinstance(raw, dict) else {}
    lay = {n: v for n, v in raw.items() if valid_layout_path(n, v)}
    changed = False
    for name, spec, _ in CANARY_SPECS:
        if name not in lay or name in renew:
            lay[name] = random_decoy_path(name, spec); changed = True
    if changed:
        save_json(path, dict(lay, **{k: raw[k] for k in LAYOUT_EXTRAS if k in raw}))
    return lay


# v1.2.0: chaff and far sentinels. A same-user sweep (grep -r, a key scanner, tar, an indexer) reads every file in a decoy's folder
# and far beyond it; a Bot that goes for the decoy opens the decoy. Two dull, readable files beside each decoy (chaff) and one
# plain folder two levels down in each decoy root (the far sentinel) are armed like a decoy, so a sweep moves their read times
# too. Their names are picked at random per install and kept in decoy_layout.json; nothing in them matches a key rule.
LAYOUT_EXTRAS = ("chaff", "sentinels", "salt")
CHAFF_STEMS = ("defaults", "index", "readme", "settings", "sample", "manifest", "notes")
CHAFF_TEXT = {".csv": "id,label,updated\n1,sample row,2025-01-01\n", ".bak": "# settings backup\noutput = json\n",
              ".env": "LOG_LEVEL=info\nTZ=UTC\n", ".txt": "Index of exported files.\n"}
SENTINEL_DIRS = ("build", "jobs", "runs", "work", "logs", "data", "session", "spool")
SENTINEL_FILES = (("notes.txt", "Scratch notes.\n"), ("settings.env", "LOG_LEVEL=info\n"))
CHAFF_STATE = "canaries-chaff.json"   # each chaff and sentinel file as armed: {path: {kind, atime, ino, ctime_ns, planted_ts}}
_CHAFF_NAME = re.compile(r"^[a-z]+-[0-9a-f]{4}\.[a-z0-9]+$")
_SENTINEL_REL = re.compile(r"^[a-z]+-[0-9a-f]{4}/[a-z]+-[0-9a-f]{4}$")


def layout_extras(create=False):
    """(chaff names per decoy, far-sentinel folder per decoy root, value salt) for this install. An entry a Bot edited into
    something else is dropped, so the layout can never name a file outside the decoy folders. create: pick what is missing."""
    import secrets as _s
    path = state_path("decoy_layout.json")
    raw = load_json(path, {}) or {}
    raw = raw if isinstance(raw, dict) else {}
    specs = {n: s for n, s, _ in CANARY_SPECS}
    got = raw.get("chaff") if isinstance(raw.get("chaff"), dict) else {}
    chaff = {n: [x for x in v if isinstance(x, str) and _CHAFF_NAME.match(x)][:2] for n, v in got.items()
             if n in specs and isinstance(v, list)}
    got = raw.get("sentinels") if isinstance(raw.get("sentinels"), dict) else {}
    bases = {_spec_base(s) for s in specs.values()}
    sent = {b: r for b, r in got.items() if b in bases and isinstance(r, str) and _SENTINEL_REL.match(r)}
    salt = raw.get("salt") if isinstance(raw.get("salt"), str) and re.fullmatch(r"[0-9a-f]{32}", raw["salt"]) else None
    if not create:
        return chaff, sent, salt
    changed = False
    for n, spec in specs.items():
        if len(chaff.get(n, [])) < 2:
            a, b = _s.SystemRandom().sample(CHAFF_STEMS, 2)
            chaff[n] = [f"{a}-{_s.token_hex(2)}{os.path.splitext(spec)[1]}", f"{b}-{_s.token_hex(2)}.txt"]; changed = True
    for b in sorted(bases):
        if b not in sent:
            x, y = _s.SystemRandom().sample(SENTINEL_DIRS, 2)
            sent[b] = f"{x}-{_s.token_hex(2)}/{y}-{_s.token_hex(2)}"; changed = True
    if not salt:
        salt = _s.token_hex(16); changed = True
    if changed:
        lay = {n: v for n, v in raw.items() if valid_layout_path(n, v)}
        save_json(path, dict(lay, chaff=chaff, sentinels=sent, salt=salt))
    return chaff, sent, salt


def chaff_paths():
    """{chaff file: decoy name}: the chaff beside each decoy's own random place."""
    lay = load_json(state_path("decoy_layout.json"), {}) or {}
    lay = {n: v for n, v in lay.items() if valid_layout_path(n, v)} if isinstance(lay, dict) else {}
    chaff, _, _ = layout_extras()
    return {os.path.normpath(os.path.join(os.path.dirname(decoy_path(lay[n])), x)): n for n, xs in chaff.items() if n in lay for x in xs}


def sentinel_paths():
    """{far sentinel file: its decoy root (the spec's /tmp or /var/tmp)}."""
    _, sent, _ = layout_extras()
    return {os.path.normpath(os.path.join(decoy_path(b), rel, fn)): b for b, rel in sent.items() for fn, _ in SENTINEL_FILES}


def decoy_files():
    """Every file ISR Bot plants as a tripwire: the decoys, the chaff beside them and the far sentinels. Never read as a key file."""
    return canary_paths() | set(chaff_paths()) | set(sentinel_paths())


def plant_chaff(refused=None):
    """Write the chaff beside each decoy that is there, and the far sentinel in each decoy root that holds one, where it is missing
    or isn't the file ISR Bot armed (a read leaves it alone). A link where one goes is refused, as for a decoy (ISR-K006).
    Returns (chaff written, sentinel files written)."""
    reg = load_json(state_path("canaries.json"), {}) or {}
    if not reg:
        return 0, 0
    lay = decoy_layout()
    chaff, sent, _ = layout_extras(create=True)
    want = {}                                             # path -> (kind, owner name, content, folders ISR Bot makes)
    for name, v in reg.items():
        fixed = PUBLISHED_CANARY_PATHS + OLD_CANARY_PATHS + tuple(s for _, s, _ in CANARY_SPECS)
        if not isinstance(v, dict) or name not in lay or lay[name] in fixed:
            continue                                      # a decoy at a fixed name is moved first (tend_canaries), then gets chaff
        p = os.path.expanduser(str(v.get("path", "")))
        if os.path.normpath(p) != os.path.normpath(decoy_path(lay[name])) or os.path.islink(p) or not os.path.isfile(p):
            continue                                      # only beside a decoy that is where its layout says
        for x in chaff.get(name, []):
            want[os.path.join(os.path.dirname(p), x)] = ("chaff", name, CHAFF_TEXT.get(os.path.splitext(x)[1], CHAFF_TEXT[".txt"]), 1)
        b = _spec_base(lay[name])
        if b in sent:
            for fn, text in SENTINEL_FILES:
                want[os.path.join(decoy_path(b), sent[b], fn)] = ("sentinel", "far sentinel", text, 2)
    arm = load_json(state_path(CHAFF_STATE), {}) or {}
    bad, n_chaff, n_far, refused_at = [], 0, 0, set()
    for p, (kind, name, text, levels) in sorted(want.items()):
        if chaff_armed(p, arm.get(p)):
            continue
        if os.path.dirname(p) in refused_at:
            arm.pop(p, None)                              # the sentinel's other file: its folder was already refused
            continue
        try:
            atime, mtime, ident = write_decoy(p, text, levels=levels)
        except (DecoyLink, OSError) as e:
            if isinstance(e, DecoyLink):
                bad.append(decoy_link_finding(f"{name} {kind}" if kind == "chaff" else name, p, f"{link_target(p)}. {e}"))
                ledger({"event": "canary-refused", "decoy": name, "kind": kind, "path": p, "why": str(e)[:200]})
                if kind == "sentinel":
                    refused_at.add(os.path.dirname(p))
            arm.pop(p, None)
            continue
        arm[p] = dict({"kind": kind, "decoy": name, "atime": atime, "mtime": mtime, "planted_ts": time.time()}, **ident)
        n_chaff, n_far = n_chaff + (kind == "chaff"), n_far + (kind == "sentinel")
    save_json(state_path(CHAFF_STATE), {p: r for p, r in arm.items() if p in want})
    if bad:
        remember_events(bad)
        if refused is not None:
            refused += bad
    return n_chaff, n_far


def chaff_armed(p, rec):
    """The chaff or sentinel at p is the one ISR Bot armed: a plain file, never a link, with the inode and ctime it recorded."""
    try:
        st = os.lstat(p)
    except OSError:
        return False
    return isinstance(rec, dict) and stat.S_ISREG(st.st_mode) and decoy_ident(st) == {"ino": rec.get("ino"), "ctime_ns": rec.get("ctime_ns")}


def chaff_reads(arm):
    """{path: read time} for each chaff or sentinel file read since it was armed. One whose times were set by hand (a new ctime)
    or that was replaced proves nothing and is left out."""
    out = {}
    for p, rec in arm.items():
        if chaff_armed(p, rec):
            t = os.lstat(p).st_atime
            if t > rec.get("atime", 0) + 1:
                out[p] = t
    return out


def rearm_chaff(within=None):
    """Reset the chaff and far sentinels that were read (only those under `within`), never through a link. Returns the paths reset."""
    arm = load_json(state_path(CHAFF_STATE), {}) or {}
    done = []
    for p in chaff_reads(arm):
        if not in_roots(p, within) or not owned_path(p, "decoy", log=False):
            continue
        try:
            st = os.lstat(p)
            os.utime(p, (st.st_mtime - 86400, st.st_mtime), follow_symlinks=False)
            st = os.lstat(p)
            arm[p].update(atime=st.st_atime, **decoy_ident(st))
            done.append(p)
        except OSError:
            pass
    if done:
        save_json(state_path(CHAFF_STATE), arm)
    return done


def remove_chaff(log=True):
    """Remove every chaff and far-sentinel file this install planted (owned-path checked), then their folders if empty. Returns
    how many files went."""
    n = 0
    far = sentinel_paths()
    for p in sorted(set(chaff_paths()) | set(far)):
        if os.path.lexists(p) and owned_path(p, "decoy", log=log):
            try:
                os.remove(p); n += 1
            except OSError:
                pass
    for d in sorted({os.path.dirname(p) for p in far}):
        for x in (d, os.path.dirname(d)):                # the sentinel's two folders, only when nothing else is in them
            try:
                os.rmdir(x)
            except OSError:
                break
    save_json(state_path(CHAFF_STATE), {})
    return n


def decoy_places():
    """Every place a decoy of this install may be: its own random ones, plus the published and older names it may have used."""
    lay = load_json(state_path("decoy_layout.json"), {}) or {}
    mine = [v for n, v in lay.items() if valid_layout_path(n, v)] if isinstance(lay, dict) else []
    return {os.path.normpath(decoy_path(x)) for x in list(mine) + [x for _, x, _ in CANARY_SPECS] + list(PUBLISHED_CANARY_PATHS)}


def decoy_path(path):
    """The spec's path on this computer. ISR_BOT_DECOY_ROOT moves them under another folder (the tests use it)."""
    p = os.path.expanduser(path)
    root = os.environ.get("ISR_BOT_DECOY_ROOT", "")
    return os.path.join(root, p.lstrip("/")) if root and not path.startswith("~") else p


def boot_time():
    """When this computer last started (seconds since 1970), or None if it can't be told."""
    try:
        for line in open("/proc/stat"):
            if line.startswith("btime "):
                return float(line.split()[1])
    except (OSError, ValueError):
        pass
    return None


class DecoyLink(Exception):
    """Something other than a plain folder or file sits where a decoy goes."""


def write_decoy(p, content, levels=1):
    """Write a decoy without ever following a link. The decoys live in /tmp and /var/tmp, where every Bot can write, so a link
    planted at the decoy's folder or file would make ISR Bot overwrite whatever it points to. The decoy's own folder and file
    are opened with O_NOFOLLOW from an open handle on the folder above, and every check is made on the opened handle, never on
    the name, so nothing can be swapped in between the check and the write. Returns (atime, mtime, {ino, ctime_ns}) after
    re-arming: the last two say later whether the file's times were set by hand (fix round 1). levels: how many folders above
    the file are made and opened that way (v1.2.0: a far sentinel sits two folders down)."""
    folder, fn = os.path.split(p)
    subs = []
    for _ in range(levels):
        folder, sub = os.path.split(folder)
        subs.insert(0, sub)
    os.makedirs(folder, exist_ok=True)                # /tmp, /var/tmp (or the test root): the system's own folders
    dfd = os.open(folder, os.O_RDONLY | os.O_DIRECTORY)
    fd = None
    try:
        for sub in subs:
            folder = os.path.join(folder, sub)
            try:
                os.mkdir(sub, 0o755, dir_fd=dfd)
            except FileExistsError:
                pass
            try:
                nfd = os.open(sub, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=dfd)
            except OSError as e:
                raise DecoyLink(f"{folder} is a link or not a folder") from e
            os.close(dfd)
            dfd = nfd
        try:
            # R09: O_NONBLOCK so a FIFO planted at the decoy can't hang the run before its type is checked
            fd = os.open(fn, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o644, dir_fd=dfd)
        except OSError as e:
            raise DecoyLink(f"{p} is a link or not a plain file") from e
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
            raise DecoyLink(f"{p} is not a plain file of its own ({st.st_nlink} names point at it)")   # a hard link to another file
        os.ftruncate(fd, 0)
        os.write(fd, content.encode())
        st = os.fstat(fd)
        os.utime(fd, (st.st_mtime - 86400, st.st_mtime))  # atime < mtime so the next read updates atime
        st = os.fstat(fd)
        return st.st_atime, st.st_mtime, decoy_ident(st)
    finally:
        for x in (fd, dfd):
            if x is not None:
                os.close(x)


# Hardening batch 2 (R2): the backup's fingerprint. Next to each decoy sits a witness file with mode 000. Every Bot runs as the
# same user as ISR Bot: it can't read the witness without chmod, or move its read time without utime, and both stamp a new
# ctime no unprivileged process can set back; recreating it changes its inode. Only a privileged reader (the platform's backup)
# moves its atime and nothing else. A learned pattern (time of day, file count) could be copied: every Bot can read this state.
WITNESS = ".lock"
WITNESS_SLACK = 2   # seconds: the witness must be read with the decoy, not later


def _decoy_dir_fd(folder):
    """An open handle on a decoy folder, never reached through a link."""
    base, sub = os.path.split(folder)
    bfd = os.open(base, os.O_RDONLY | os.O_DIRECTORY)
    try:
        return os.open(sub, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=bfd)
    finally:
        os.close(bfd)


def arm_witness(reg, folder):
    """Write a new witness in a decoy folder (its atime set below its mtime) and record it on every decoy there: each time it is
    armed, never re-armed by name. Fix round 1 (R2): it is written, re-timed and measured through the descriptor that created
    it, then the name must still point at that same file, so a file a Bot holds open and swaps in meanwhile is never recorded.
    A failure is silent: the old record is dropped, so there is no proof and reads stay high. Returns True when reg changed."""
    vs = [v for v in reg.values() if isinstance(v, dict) and os.path.dirname(os.path.expanduser(str(v.get("path", "")))) == folder]
    for v in vs:
        v.pop("witness", None)
    try:
        dfd = _decoy_dir_fd(folder)
    except OSError:
        return bool(vs)
    try:
        try:
            os.unlink(WITNESS, dir_fd=dfd)                # a link put there is removed as a link
        except FileNotFoundError:
            pass
        fd = os.open(WITNESS, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o000, dir_fd=dfd)
        try:
            os.write(fd, os.urandom(16))
            st = os.fstat(fd)
            os.utime(fd, ns=(st.st_mtime_ns - 86400 * 10 ** 9, st.st_mtime_ns))
            st = os.fstat(fd)
        finally:
            os.close(fd)
        named = os.stat(WITNESS, dir_fd=dfd, follow_symlinks=False)
    except OSError:
        return bool(vs)
    finally:
        os.close(dfd)
    if ((named.st_dev, named.st_ino, named.st_ctime_ns) != (st.st_dev, st.st_ino, st.st_ctime_ns)
            or not stat.S_ISREG(st.st_mode) or stat.S_IMODE(st.st_mode)):
        return bool(vs)                                   # something else sits at the name now: no proof
    for v in vs:
        v["witness"] = {"ino": st.st_ino, "ctime_ns": st.st_ctime_ns, "atime": st.st_atime}
    return bool(vs)


def _witness(v):
    """(state, stat) of the witness beside v, both from one lstat. state: 'ok' (armed, unread), 'read' (intact and read since
    armed), or 'damaged' (missing, replaced, opened up, or its ctime moved); stat is None when damaged."""
    w = v.get("witness")
    if not isinstance(w, dict):
        return "damaged", None
    try:
        st = os.lstat(os.path.join(os.path.dirname(os.path.expanduser(v["path"])), WITNESS))
    except OSError:
        return "damaged", None
    if not stat.S_ISREG(st.st_mode) or stat.S_IMODE(st.st_mode) or st.st_ino != w.get("ino") or st.st_ctime_ns != w.get("ctime_ns"):
        return "damaged", None
    return ("read" if st.st_atime > w.get("atime", 0) + 1 else "ok"), st


def witness_state(v):
    return _witness(v)[0]


def witness_proves(v, t):
    """The decoy read at t was the platform's backup: the intact witness beside it was read within WITNESS_SLACK seconds of t.
    Fix round 2 (R2): the read time is the one from the stat that was checked, never a second stat taken after a Bot re-timed it."""
    state, st = _witness(v)
    return state == "read" and abs(st.st_atime - t) <= WITNESS_SLACK


def remove_witness(folder):
    w = os.path.join(folder, WITNESS)
    if owned_path(w, "decoy"):
        try:
            os.remove(w)
        except OSError:
            pass


def reads_recorded(folder):
    """Does the filesystem under this decoy folder record reads? A probe is written the way a decoy is, read without following a
    link, then removed. None when it can't be told."""
    import secrets as _s
    p = os.path.join(folder, f".probe-{_s.token_hex(3)}")
    try:
        before, _, _ = write_decoy(p, "x")
        fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            os.read(fd, 1)
        finally:
            os.close(fd)
        return os.lstat(p).st_atime > before + 1
    except (OSError, DecoyLink):
        return None
    finally:
        if not os.path.islink(folder):
            try:
                os.remove(p)
            except OSError:
                pass


def link_target(p):
    for q in (p, os.path.dirname(p)):
        if os.path.islink(q):
            try:
                return f"{q} -> {os.readlink(q)}"
            except OSError:
                return f"{q} is a link"
    return p


def decoy_link_finding(name, p, why):
    return finding("ISR-K006", "A link was put where a decoy goes", "high", ["ASI10", "ASI05"], p, f"{name}: {why}"[:160],
                   "ISR Bot refused to write the decoy, because writing through that link would have changed the file it points to. "
                   "Something put the link there on purpose. Tell ISR Bot \"incident check\"; once you know what did it, remove the link and plant the decoys again.",
                   ident=f"{name}|{p}")


def plant_canaries(only=None, token_file=None, refused=None):
    """Write the decoys that aren't there. Returns the names planted. A decoy whose place holds a link is not written: it is
    recorded as an event (ISR-K006) and, when `refused` is a list, added to it."""
    import secrets as _s
    reg = load_json(state_path("canaries.json"), {}) or {}
    planted, bad = [], []
    layout = decoy_layout()
    _, _, salt = layout_extras(create=True)
    for name, path, body in CANARY_SPECS:
        p = decoy_path(layout[name])
        if (only is not None and name not in only) or (name in reg and os.path.lexists(os.path.expanduser(reg[name]["path"]))
                                                         and not os.path.islink(os.path.expanduser(reg[name]["path"]))):
            continue
        old = reg.get(name) if isinstance(reg.get(name), dict) else {}
        tok = old.get("token") if only is not None and name in reg else None
        # an older registry's re-planted decoy keeps its value; v1.2.0 keeps no value, so a new one is made and the old one's hash
        # stays in past_tokens: a copy made earlier is still recognised either way
        tok = tok or _s.token_hex(8)
        content = body.format(tok=tok, tokU=tok.upper()[:16])
        if token_file and name == "cloud-keys":
            content = open(token_file).read()
        try:
            atime, mtime, ident = write_decoy(p, content)
        except DecoyLink as e:
            bad.append(decoy_link_finding(name, p, f"{link_target(p)}. {e}"))
            ledger({"event": "canary-refused", "decoy": name, "path": p, "why": str(e)[:200]})
            continue
        now_value = value_record(tok, salt, p)
        past = [x for x in past_values(old) if x["token_sha256"] != value_hash(x["salt"], tok)]
        reg[name] = dict({"path": p, "atime": atime, "mtime": mtime, "planted": now(), "planted_ts": time.time()}, **ident, **now_value,
                         **({"past_tokens": past} if past else {}))
        arm_witness(reg, os.path.dirname(p))
        planted.append(name)
    save_json(state_path("canaries.json"), reg)
    if bad:
        remember_events(bad)
        if refused is not None:
            refused += bad
    plant_chaff(refused)
    return planted


# v1.2.0: the registry keeps no decoy value. Each value is kept as sha256(install salt + value) with its first four hex
# characters, which only pick the places worth hashing; a copy of ISR Bot's state then spreads no real value.
VALUE_LEN = 16   # every value is token_hex(8)
_HEX_WINDOW = re.compile(r"[0-9a-f]{16}")


def value_hash(salt, tok):
    return hashlib.sha256((str(salt) + str(tok).lower()).encode()).hexdigest()


def value_record(tok, salt, path):
    return {"token_sha256": value_hash(salt, tok), "token_prefix": str(tok).lower()[:4], "salt": salt, "token_path": path}


def past_values(v):
    """Every value a registry entry holds or held, as value records (an unmigrated raw value is hashed here, never kept)."""
    if not isinstance(v, dict):
        return []
    past = [x for x in v.get("past_tokens") or [] if isinstance(x, dict) and x.get("token_sha256") and x.get("salt")]
    if isinstance(v.get("token"), str) and v["token"]:
        past.append(value_record(v["token"], layout_extras(create=True)[2], v.get("path")))
    elif v.get("token_sha256") and v.get("salt"):
        past.append({k: v.get(k) for k in ("token_sha256", "token_prefix", "salt", "token_path")})
    return past


def migrate_registry():
    """v1.2.0, once: each decoy value an older registry kept is replaced by its salted hash; the decoys, their paths and the
    values in them are not touched. Returns how many entries were rewritten."""
    reg = load_json(state_path("canaries.json"), {}) or {}
    raw = [n for n, v in reg.items() if isinstance(v, dict) and "token" in v]
    if not raw:
        return 0
    _, _, salt = layout_extras(create=True)
    for n in raw:
        v = reg[n]
        tok = v.pop("token")
        if isinstance(tok, str) and tok:
            v.update(value_record(tok, salt, v.get("path")))
    save_json(state_path("canaries.json"), reg)
    return len(raw)


def tend_canaries(notes):
    """Before the decoys are checked: move ones still in the old backed-up places, and put back ones a restart wiped.
    A decoy that vanished with no restart since it was planted is left for the check to report as removed."""
    reg = load_json(state_path("canaries.json"), {}) or {}
    if not reg:
        return
    old = {os.path.expanduser(p) for p in OLD_CANARY_PATHS}
    published = {os.path.normpath(decoy_path(p)) for p in PUBLISHED_CANARY_PATHS}
    moved = [n for n, v in reg.items() if os.path.expanduser(v["path"]) in old and n in {s_[0] for s_ in CANARY_SPECS}]
    renamed = [n for n, v in reg.items() if n not in moved and os.path.normpath(os.path.expanduser(v["path"])) in published
               and n in {s_[0] for s_ in CANARY_SPECS}]
    from_old = set(moved)
    moved += renamed
    pending = []
    for n in moved:                                       # a read that no run has recorded yet goes in the log before the file does
        try:
            t = os.stat(os.path.expanduser(reg[n]["path"])).st_atime
            if t > reg[n].get("atime", 0) + 1:
                pending.append({"name": n, "path": reg[n]["path"], "read_at": dt.datetime.fromtimestamp(t, dt.timezone.utc).isoformat(timespec="seconds")})
        except OSError:
            pass
    if pending:
        ledger({"event": "canary-read", "decoys": pending, "note": "read in the old place, recorded as the decoys were moved"})
        notes.append(f"Before the move, {len(pending)} of the old decoys had been read at {pending[0]['read_at'][11:16]} UTC (most likely the backup). It is in the log.")
    for n in moved:
        p = os.path.expanduser(reg[n]["path"])
        if not owned_path(p, "decoy"):
            continue
        try:
            os.remove(p)
        except OSError:
            pass
        remove_witness(os.path.dirname(p))
        try:
            os.rmdir(os.path.dirname(p))
        except OSError:
            pass                                          # someone else's files are in that folder: it stays
    if moved:
        decoy_layout(renew=set(moved))                    # new random names, never the published ones again
        plant_canaries(only=set(moved))
        store = [e for e in load_json(state_path("events.json"), []) if e.get("key") not in BULK_KEYS | {OLD_K005_KEY}]   # calm lines only, never an alarm
        save_json(state_path("events.json"), store)
        if from_old:
            notes.append(f"Moved {len(from_old)} decoys to /var/tmp and /tmp. The platform's file backup read the old ones in /workspace and your home folder "
                         "after every Bot turn, so a read there meant nothing. It doesn't read the new places, so a read now is worth an alarm.")
        if renamed:
            notes.append(f"Moved {len(renamed)} decoys to new folders and names picked at random for this computer. The old names were printed in "
                         "ISR Bot's own instructions, so anything that read them knew which files to leave alone.")
        ledger({"event": "canary-move", "count": len(moved)})
        reg = load_json(state_path("canaries.json"), {}) or {}
    boot = boot_time()
    gone = [n for n, v in reg.items() if not os.path.lexists(os.path.expanduser(v["path"])) and boot and boot > v.get("planted_ts", float("inf"))]
    wiped = [n for n in gone if cleared_by_restart(reg[n], boot)]
    kept = sorted(set(gone) - set(wiped))
    new_kept = [n for n in kept if not reg[n].get("gone_noted")]
    if new_kept:                                          # left missing: the check reports each one as removed, with what is known
        ledger({"event": "canary-gone-not-replanted", "decoys": [{"name": n, "path": reg[n]["path"], "read_at": reg[n].get("read_at")} for n in new_kept]})
        for n in new_kept:
            reg[n]["gone_noted"] = now()
        save_json(state_path("canaries.json"), reg)
    if wiped:
        plant_canaries(only=set(wiped))
        notes.append(f"{len(wiped)} decoy(s) were cleared when the computer restarted and have been put back.")
        ledger({"event": "canary-replant", "decoys": sorted(wiped)})
    # v1.2.0: chaff and far sentinels beside the decoys that are there (the first run after the upgrade plants them all), then the
    # registry keeps hashes only. A read made before the chaff was there is judged as before (sweep_signal).
    n_chaff, n_far = plant_chaff()
    if migrate_registry():
        arm = load_json(state_path(CHAFF_STATE), {}) or {}
        ledger({"event": "canary-migrate", "chaff": sum(1 for r in arm.values() if r.get("kind") == "chaff"),
                "sentinels": len({os.path.dirname(p) for p, r in arm.items() if r.get("kind") == "sentinel"})})
    elif n_chaff or n_far:
        ledger({"event": "canary-chaff", "chaff": n_chaff, "sentinels": n_far})


def cleared_by_restart(v, boot):
    """A missing decoy is put back quietly only when a restart explains it: it was never seen read, and its folder is gone too or
    hasn't changed since the computer started. A decoy that was read and then disappeared, or one deleted from a folder that
    changed after the restart, is evidence: it stays missing and is reported, and the owner decides when to plant it again."""
    if v.get("read_at"):
        return False
    try:
        st = os.lstat(os.path.dirname(os.path.expanduser(v["path"])))
    except OSError:
        return True                                       # the whole folder went, as /tmp does on a restart
    return stat.S_ISDIR(st.st_mode) and st.st_mtime <= boot


def canary_paths():
    reg = load_json(state_path("canaries.json"), {})
    return {os.path.expanduser(v["path"]) for v in reg.values()}


def cmd_canary(args):
    reg = load_json(state_path("canaries.json"), {})
    if args.action == "plant":
        refused = []
        plant_canaries(token_file=args.token_file, refused=refused)
        for f in refused:
            print(f"REFUSED {f['evidence']}. Not written: a link sits where the decoy goes. It is recorded as a high finding.")
        reg = load_json(state_path("canaries.json"), {})
        # batch 2 (R2): read tracking is checked where the decoys are (/tmp and /var/tmp), not in ISR Bot's own folder
        tracked = {d: reads_recorded(d) is True for d in sorted({os.path.dirname(os.path.expanduser(v["path"])) for v in reg.values()})}
        print(f"Planted {len(reg)} canaries: " + ", ".join(v["path"] for v in reg.values()))
        blind = [d for d, ok in tracked.items() if not ok]
        if blind:
            print(f"Note: {', '.join(blind)} {'doesn' if len(blind) == 1 else 'don'}'t record reads, so the decoys there catch deletion and copying, not reading.")
        ledger({"event": "canary-plant", "count": len(reg), "reads_recorded": tracked})
        return 0
    if args.action == "remove":
        if not getattr(args, "owner_said_yes", False):   # R10: removing the tripwires is the owner's call, never a Bot's
            print("NOT REMOVED: the decoys are how ISR Bot notices someone going through files. Ask the owner; only after their yes "
                  "in this conversation run `isr.py canary remove --owner-said-yes`.")
            return 1
        for v in reg.values():
            p = os.path.expanduser(v["path"])
            if not owned_path(p, "decoy"):
                print(f"Not removed: {p} is not one of the decoy places.")
                continue
            try:
                os.remove(p)
            except OSError:
                pass
            remove_witness(os.path.dirname(p))
        chaff = remove_chaff()                            # v1.2.0: the chaff and far sentinels go with them
        save_json(state_path("canaries.json"), {})
        ledger({"event": "canary-remove", "count": len(reg), "chaff": chaff})
        print("Canaries removed.")
        return 0
    fs = canary_findings(record=False)   # status only looks: it never resets a decoy or drops evidence
    print(json.dumps([compact(f) for f in fs], indent=1) if fs else "CANARIES_QUIET")
    if fs:
        print("Not reset and not logged yet: the next `isr.py daily` or `isr.py audit` records this and re-arms the decoys.")
    return 0


BULK_KEY, OLD_K005_KEY = "bulk-decoy-read", "own-scan-decoy-read"
BULK_KEYS = frozenset((BULK_KEY,))   # batch 2: only the backup's proven sweep is one updated line; every other sweep is its own event


def decoy_ident(st):
    """What a decoy's times can't be set back to by hand: its inode and ctime (utime, chmod, a new file all move one)."""
    return {"ino": st.st_ino, "ctime_ns": st.st_ctime_ns}


def decoy_untouched(v, st):
    """Fix round 1 (R2): the decoy's times were moved only by a read since ISR Bot armed it. A Bot that sets a decoy's atime
    to match a witness the backup read stamps a new ctime. A registry from before this (no ctime) proves nothing."""
    return decoy_ident(st) == {"ino": v.get("ino"), "ctime_ns": v.get("ctime_ns")}


def decoy_rewritten(v, st):
    """True when the file was rewritten after this registry planted it AND is still armed (unread since that write: atime is
    the re-arm value mtime - 1 day). A file read after the rewrite is still a read (ISR-K001), so no read is ever hidden."""
    planted = v.get("mtime", v.get("planted_ts"))
    if not isinstance(planted, (int, float)) or st.st_mtime <= planted + 5:
        return False
    return abs(st.st_atime - (st.st_mtime - 86400)) <= 1


def canary_findings(record=True):
    """A decoy opened on its own means something went looking: critical. Batch 2 (R2): two or more decoys read, every read proven
    by its witness, is the platform's backup: one calm line. Without that proof, reads during a recorded ISR Bot run are high
    (any Bot can write that record), and two or more within a few minutes are high (a Bot grepping every file reads them
    together too). A single read is never downgraded. record=False only looks: nothing is reset, saved or logged."""
    reg = load_json(state_path("canaries.json"), {})
    out, reads, forged, backup = [], [], set(), False
    for name, v in reg.items():
        p = os.path.expanduser(v["path"])
        if os.path.islink(p) or os.path.islink(os.path.dirname(p)):
            out.append(decoy_link_finding(name, p, f"{link_target(p)}, where the decoy was"))
            continue                                      # never stat or touch through it
        if not os.path.exists(p):
            seen = f"; it had been read at {v['read_at'][11:16]} UTC before it disappeared" if v.get("read_at") else ""
            out.append(finding("ISR-K002", "Canary file deleted or moved", "high", ["ASI10"], p, name + seen,
                               "Something removed a decoy" + (" after reading it" if seen else "") + ". It has not been put back, so the evidence stays. "
                               "Check recent routine runs, then re-plant with `isr.py canary plant`."))
            continue
        st = os.lstat(p)
        if decoy_rewritten(v, st):
            # DQ-041 (Oct 14 replay): the file here was written after this registry planted it, so its atime says nothing
            # about a read of *our* decoy (a dry run with a copied registry and its own /tmp re-planted it). Never silent:
            out.append(finding("ISR-K007", "Decoy file rewritten since it was planted", "high", ["ASI10"], p,
                               f"{name}: written {dt.datetime.fromtimestamp(st.st_mtime, dt.timezone.utc).isoformat(timespec='minutes')}, "
                               f"planted {str(v.get('planted', ''))[:16]}",
                               "The decoy on disk is not the one ISR Bot recorded: something rewrote it, or this state was copied from "
                               "another run. Re-plant with `isr.py canary plant`; if no ISR Bot run or dry run explains it, tell ISR Bot \"incident check\"."))
            continue
        if st.st_atime > v["atime"] + 1:
            reads.append((name, p, st.st_atime))
            if not decoy_untouched(v, st):
                forged.add(name)                          # its times were set by hand, or the registry predates the check
    # Fix round 1 (R2): every read is judged before anything is re-armed or saved, so a failure never erases the evidence
    signals, reads_all, backup = {}, reads, False
    if reads:
        when = lambda t: dt.datetime.fromtimestamp(t, dt.timezone.utc).isoformat(timespec="minutes")
        backup = len(reads) >= 2 and not forged and all(witness_proves(reg[n], t) for n, _, t in reads)
        arm = load_json(state_path(CHAFF_STATE), {}) or {}
        cread, walks, probed = chaff_reads(arm), {}, {}
        for name, p, t in ([] if backup else reads):
            if name not in forged:                        # a decoy whose times were set by hand is never part of a sweep
                signals[name] = sweep_signal(p, t, arm, cread, walks, probed)
        swept = [r for r in reads if (signals.get(r[0]) or {}).get("sweep")]
        if swept:                                         # v1.2.0: one calm line per day; using the value is still critical (K003)
            out.append(sweep_finding(swept, signals, len(reg)))
        reads = [r for r in reads if r not in swept]
    if reads:
        times = [t for _, _, t in reads]
        each = ", ".join(f"{n} {dt.datetime.fromtimestamp(t, dt.timezone.utc).strftime('%H:%M:%S')}" for n, _, t in sorted(reads, key=lambda r: r[2]))
        places = ", ".join(sorted({os.path.dirname(p) for _, p, _ in reads}))
        runs = run_windows()
        own = lambda t: any(a - 2 <= t <= b + 5 for a, b in runs)
        if backup:
            f = finding("ISR-K004", "Several decoys were read by the platform's backup", "low", ["ASI03"], places,
                        f"{len(reads)} of {len(reg)} decoys within {int(max(times) - min(times))}s at {when(min(times))} ({each})",
                        "The file next to each decoy that only a privileged reader can open was read with it: the platform's file backup. "
                        "It is listed once and updated each time. If it lines up with something you didn't expect, tell ISR Bot \"incident check\".")
            f["key"] = BULK_KEY                           # one line that is updated, not a new finding every time the backup runs
            out.append(f)
        elif all(own(t) for t in times):
            out.append(finding("ISR-K005", "Decoys were read while an ISR Bot run was recorded", "high", ["ASI03", "ASI10"], places,
                               f"{len(reads)} decoy(s) at {when(min(times))}, during a recorded ISR Bot run ({each})",   # v0.8.0: renamed; the evidence is part of the finding key
                               "The run record can be written by any Bot, so it doesn't prove the read was ISR Bot's, and the backup's proof "
                               "is missing. Tell ISR Bot \"incident check\"."))
        elif len(reads) >= 2 and max(times) - min(times) <= 180:
            out.append(finding("ISR-K004", "Several decoys were read together", "high", ["ASI03", "ASI10"], places,
                               f"{len(reads)} of {len(reg)} decoys within {int(max(times) - min(times))}s at {when(min(times))} ({each})",
                               "Something read several decoys at once, and nothing shows it was the platform's backup. A Bot searching every "
                               "file does this. Tell ISR Bot \"incident check\"."))
        else:
            for name, p, t in reads:
                f = finding("ISR-K001", "Something opened a decoy file", "critical", ["ASI03", "ASI10"], p, f"{name} read at {when(t)}",
                            "Nothing legitimate needs this file, and nothing else was searched with it. "
                            "Find which Bot or routine ran then (Agent Computer view, run history) and tell ISR Bot \"incident check\".")
                out.append(with_suspects(f, t))
    if not record:
        return out
    if reads_all:
        stamp = lambda t: dt.datetime.fromtimestamp(t, dt.timezone.utc).isoformat(timespec="seconds")
        for name, _, t in reads_all:                      # remembered, so a decoy read and then removed is never put back quietly
            if not backup:                                # a run window any Bot can write never hides a read
                reg[name]["read_at"] = stamp(t)
            if (signals.get(name) or {}).get("sweep"):
                reg[name]["sweep_at"] = stamp(t)          # a value used later links this read (decoy_value_findings)
        save_json(state_path("canaries.json"), reg)
        judged = {n: s for n, s in signals.items() if s}
        ledger(dict({"event": "canary-read", "decoys": [{"name": n, "path": p, "read_at": stamp(t)} for n, p, t in reads_all]},
                    **({"backup": True} if backup else {}), **({"sweep": judged} if judged else {})))
        for name, p, _ in reads_all:                      # only now: the reads are judged and logged
            v = reg[name]
            try:
                st = os.lstat(p)
                if owned_path(p, "decoy", log=False) and stat.S_ISREG(st.st_mode):
                    os.utime(p, (st.st_mtime - 86400, st.st_mtime), follow_symlinks=False)  # re-arm; a link swapped in since the check is not followed
                    st = os.lstat(p)
                    v["atime"] = st.st_atime
                    v.update(decoy_ident(st))
            except OSError:
                pass
    rearm_chaff()                                         # v1.2.0: every chaff or sentinel read, so the next sweep moves it again
    if tend_witnesses(reg) or reads_all:
        save_json(state_path("canaries.json"), reg)
    return out


# v1.2.0: the sweep rule. A decoy read is a sweep only when the chaff in its own folder was read within SWEEP_LOCAL seconds of it
# AND something far from it was read within SWEEP_BROAD seconds: a far sentinel in another folder, or at least SWEEP_FILES other
# files in SWEEP_FOLDERS folders of the decoy's root (a stat-only walk with a time and entry budget; its counts are reported).
# No learned times or counts and no list of scanners or routines: any Bot can read this state and copy a learned pattern.
SWEEP_LOCAL, SWEEP_BROAD = 5, 180
SWEEP_FILES, SWEEP_FOLDERS = 100, 3
SWEEP_WALK_SECONDS, SWEEP_WALK_ENTRIES = 2.0, 20000
SWEEP_KEY = "decoy-sweep:"   # one K008 line per day (remember_events updates it)


def sweep_signal(p, t, arm, cread, walks, probed):
    """What the files around the decoy at p say about its read at t: {chaff, sentinels, files, folders, walk_complete, sweep}, or
    None when the sweep rule can't judge it (no chaff there before the read, or a folder that doesn't record reads): then the
    read is judged as before. walks and probed are caches for one check."""
    folder = os.path.dirname(p)
    mine = [c for c, r in arm.items() if r.get("kind") == "chaff" and os.path.dirname(c) == folder]
    if not mine or min(arm[c].get("planted_ts", float("inf")) for c in mine) >= t:
        return None                                       # migration: a read from before the chaff existed has no evidence
    if folder not in probed:
        probed[folder] = reads_recorded(folder)
    if probed[folder] is False:
        return None                                       # noatime: a read time there was set by hand, never a sweep
    local = [c for c in mine if c in cread and abs(cread[c] - t) <= SWEEP_LOCAL]
    far = {os.path.dirname(c) for c, r in arm.items() if r.get("kind") == "sentinel" and os.path.dirname(c) != folder
           and c in cread and abs(cread[c] - t) <= SWEEP_BROAD}
    root = os.path.dirname(folder)
    if local and root not in walks:
        walks[root] = sweep_walk(root, decoy_files() | {os.path.join(os.path.dirname(x), WITNESS) for x in canary_paths()})
    seen, complete = walks.get(root, ([], False))
    near = [d for a, d in seen if abs(a - t) <= SWEEP_BROAD]
    out = {"chaff": len(local), "sentinels": len(far), "files": len(near), "folders": len(set(near)), "walk_complete": complete}
    out["sweep"] = bool(local) and (bool(far) or (out["files"] >= SWEEP_FILES and out["folders"] >= SWEEP_FOLDERS))
    return out


def sweep_walk(root, skip):
    """([(read time, folder)], finished) for each plain file under root read since it was last written (atime past mtime), by
    stat only: nothing is opened and no link is followed. Stops after SWEEP_WALK_ENTRIES entries or SWEEP_WALK_SECONDS."""
    out, n, stack, t0 = [], 0, [root], time.monotonic()
    while stack:
        d = stack.pop()
        try:
            it = os.scandir(d)
        except OSError:
            continue
        with it:
            for e in it:
                n += 1
                if n > SWEEP_WALK_ENTRIES or time.monotonic() - t0 > SWEEP_WALK_SECONDS:
                    return out, False
                try:
                    if e.is_dir(follow_symlinks=False):
                        stack.append(e.path)
                    elif e.is_file(follow_symlinks=False) and os.path.normpath(e.path) not in skip:
                        st = e.stat(follow_symlinks=False)
                        if st.st_atime > st.st_mtime:
                            out.append((st.st_atime, d))
                except OSError:
                    pass
    return out, True


def sweep_finding(swept, signals, total):
    """ISR-K008: the decoys a sweep read, one calm line per day that each later sweep that day updates. Never scored."""
    times = [t for _, _, t in swept]
    hm = lambda t: dt.datetime.fromtimestamp(t, dt.timezone.utc).strftime("%H:%M:%S")
    each = ", ".join(n for n, _, _ in sorted(swept, key=lambda r: r[2]))
    s = [signals[n] for n, _, _ in swept]
    far = max(x["sentinels"] for x in s)
    files = max(x["files"] for x in s)
    f = finding("ISR-K008", "A file sweep passed over a decoy", "info", ["ASI03"], ", ".join(sorted({os.path.dirname(p) for _, p, _ in swept})),
                f"{len(swept)} of {total} decoys at {hm(min(times))} UTC ({each}) with their chaff; "
                f"{far} far sentinel(s), {files} other files read within 3 min",
                "Something read every file around the decoy and far beyond it, as grep -r, a key scanner, a backup or an indexer does; "
                "a Bot going for the decoy opens the decoy. Nothing to do unless no sweep of yours ran then. If a decoy's value is "
                "ever used or written out, that is still critical (ISR-K003) and names this read.")
    f["key"] = SWEEP_KEY + (et_date(dt.datetime.fromtimestamp(min(times), dt.timezone.utc).isoformat()) or "")
    f["sweep"] = {n: signals[n] for n, _, _ in swept}
    return with_suspects(f, min(times))


# v1.2.0: evidence, never severity. A decoy line names the agent session logs that made a tool call near the time, by path only.
SESSION_LOG_HOME = (".claude/projects", ".codex/sessions", ".grok/sessions")
SESSION_WINDOW = 120
_TOOL_MARKS = (b'"tool_use"', b'"function_call"', b'"local_shell_call"', b'"custom_tool_call"', b'"tool_call"')
_STAMP = re.compile(rb'"timestamp"\s*:\s*"([0-9][0-9T:.+\-Z ]{9,40})"')


def session_logs():
    """Every agent session log under this home's Claude, Codex and Grok session folders, never reached through a link."""
    h = os.path.expanduser("~")
    for rel in SESSION_LOG_HOME:
        base = os.path.join(h, rel)
        if os.path.islink(base) or not os.path.isdir(base):
            continue
        for dp, _, fns in os.walk(base):
            for fn in sorted(fns):
                p = os.path.join(dp, fn)
                if os.path.splitext(fn)[1].lower() in (".jsonl", ".json", ".ndjson", ".log", ".txt") and not os.path.islink(p) and os.path.isfile(p):
                    yield p


def stamp_seconds(raw):
    """A log's ISO time (2026-11-11T14:01:07.123Z) as seconds since 1970, or None."""
    try:
        s = raw.decode() if isinstance(raw, bytes) else str(raw)
        s = re.sub(r"(\.\d{6})\d+", r"\1", s.strip().replace("Z", "+00:00").replace(" ", "T"))
        t = dt.datetime.fromisoformat(s)
        return (t if t.tzinfo else t.replace(tzinfo=dt.timezone.utc)).timestamp()
    except ValueError:
        return None


def session_suspects(t, limit=5):
    """Session logs with a tool call stamped within SESSION_WINDOW seconds of t: who to ask first. Paths only."""
    out = []
    for p in session_logs():
        try:
            if os.stat(p).st_mtime < t - SESSION_WINDOW:
                continue                                  # written to last before the window opened
            with open(p, "rb") as f:
                for line in f:
                    if any(m in line for m in _TOOL_MARKS):
                        got = [stamp_seconds(x) for x in _STAMP.findall(line)]
                        if any(x is not None and abs(x - t) <= SESSION_WINDOW for x in got):
                            out.append(p)
                            break
        except OSError:
            continue
    return out[:limit]


def with_suspects(f, t):
    """The finding with the session logs active at t named in its fix text and kept in `sessions` (paths only)."""
    near = session_suspects(t)
    if near:
        f["sessions"] = near
        f["fix"] += " Session logs with a tool call within 2 minutes of it: " + ", ".join(short_path(p) for p in near) + "."
    return f


def run_windows():
    """The recorded ISR Bot runs as (start, end). Any Bot can write this file, so an entry that isn't two numbers in order is
    dropped (fix round 1, R2): never an error that loses a read, and never a window."""
    raw = load_json(state_path("run_windows.json"), [])
    num = lambda x: isinstance(x, (int, float)) and not isinstance(x, bool) and math.isfinite(x)
    if not isinstance(raw, list):
        return []
    return [(r[0], r[1]) for r in raw if isinstance(r, (list, tuple)) and len(r) == 2 and num(r[0]) and num(r[1]) and r[0] <= r[1]]


def tend_witnesses(reg, within=None, only_read=False):
    """After the reads are judged: re-arm each witness that was read, and write a new one where it is missing or damaged (also an
    install from before the witness). only_read: never write a new one. Only next to a decoy that is there, never through a link."""
    changed = False
    for folder in sorted({os.path.dirname(os.path.expanduser(v["path"])) for v in reg.values() if isinstance(v, dict) and v.get("path")}):
        vs = [v for v in reg.values() if isinstance(v, dict) and os.path.dirname(os.path.expanduser(str(v.get("path", "")))) == folder]
        if not in_roots(folder, within):
            continue
        if os.path.islink(folder) or not any(owned_path(os.path.expanduser(v["path"]), "decoy", log=False)
                                             and os.path.isfile(os.path.expanduser(v["path"])) for v in vs):
            continue
        states = {witness_state(v) for v in vs}
        if ("damaged" in states and not only_read) or "read" in states:
            changed |= arm_witness(reg, folder)
    return changed


def cmd_events(args):
    """List or clear one-time events (history lines, canary trips) that stay open for 14 days."""
    store = load_json(state_path("events.json"), [])
    if args.action == "clear":
        going = [e for e in store if not (args.rule and e["rule"] != args.rule)]
        alarms = sorted({e["rule"] for e in going if e["severity"] in ("critical", "high")})
        if alarms and not getattr(args, "owner_said_yes", False):
            print(f"NOT CLEARED: {', '.join(alarms)} are alarms. Show them to the owner (`isr.py events list`), and only after their yes "
                  "in this conversation run the same command with --owner-said-yes.")
            return 1
        keep = [e for e in store if args.rule and e["rule"] != args.rule]
        save_json(state_path("events.json"), keep)
        snap = load_json(state_path("last_findings.json"), None)
        if snap:
            snap["findings"] = [f for f in snap["findings"] if not (args.rule is None and f["rule"].startswith(("ISR-H", "ISR-K"))) and f["rule"] != args.rule]
            save_json(state_path("last_findings.json"), snap)
        ledger({"event": "events-clear", "rule": args.rule or "all", "removed": len(store) - len(keep)})
        print(f"Cleared {len(store) - len(keep)} event(s).")
        return 0
    for e in store:
        print(f"{e.get('first_seen', '')}  {e['severity']:8} {e['rule']}  {e['title']}  {e['where']}")
    return 0


def in_roots(p, within):
    """True when `within` is None (everywhere) or p is inside one of those folders."""
    return within is None or _under(os.path.normpath(p), {os.path.normpath(os.path.abspath(os.path.expanduser(r))) for r in within})


def rearm_canaries(within=None):
    """Reset the decoys that were read, and their witnesses. within: only decoys under these folders. The full audit's closing
    re-arm passes the folders its scanners read (batch 2, R2: it used to reset every decoy and erase a read made meanwhile);
    the owner-approved fix resets them all."""
    reg = load_json(state_path("canaries.json"), {})
    changed = False
    for v in reg.values():
        p = os.path.expanduser(v["path"])
        if not in_roots(p, within):
            continue
        if os.path.islink(p) or os.path.islink(os.path.dirname(p)) or not owned_path(p, "decoy", log=False):
            continue                                      # never touch through a link, or a file that isn't a decoy; the check reports it
        try:
            st = os.lstat(p)
            if "ctime_ns" in v and not decoy_untouched(v, st):
                continue                                  # fix round 1 (R2): its times were set by hand; the check reports it, never reset quietly
            if st.st_atime > v.get("atime", 0) + 1:
                os.utime(p, (st.st_mtime - 86400, st.st_mtime), follow_symlinks=False)
                st = os.lstat(p)
                v["atime"] = st.st_atime
                v.update(decoy_ident(st))
                changed = True
        except OSError:
            pass
    if tend_witnesses(reg, within, only_read=True) or changed:
        save_json(state_path("canaries.json"), reg)
    rearm_chaff(within)                                   # v1.2.0: the chaff and far sentinels under the same folders


def canary_copies(text, path):
    """The ISR-K003 finding for a decoy value in this text, or None (v1.2.0: decoy_value_findings, critical findings only)."""
    return next((f for f in decoy_value_findings(text, path) if f["rule"] == "ISR-K003"), None)


# v1.2.0: the token-use stage. Each value, current or past, is found by its salted hash in 16-hex windows that start with a known
# prefix, in any case (the cloud-keys decoy holds it upper-cased). Where it sits decides the finding: in a command, critical
# "used"; anywhere else critical "copied", unless it is only a scanner's listing (the decoy's own folder/name in the same line or
# JSON record) or a copy of the whole decoy root (its folder and name with a chaff copy and a far-sentinel copy): then info.
CMD_TYPES = frozenset(("tool_use", "server_tool_use", "function_call", "local_shell_call", "custom_tool_call", "tool_call"))
CMD_KEYS = frozenset(("command", "cmd", "cmdline", "argv", "args", "arguments"))
_CMD_LINE = re.compile(r"""(?i)["']?\b(cmdline|argv|args|arguments|command|cmd)\b["']?\s*[=:]""")


def decoy_value_index(reg=None):
    """What the check looks for: {"hashed": {prefix: [(name, salt, sha256, decoy path then)]}, "raw": [(name, value, path)]}.
    "raw" holds only a not-yet-migrated value that isn't 16 hex characters, matched as before. None when there is nothing."""
    reg = load_json(state_path("canaries.json"), {}) if reg is None else reg
    hashed, raw = {}, []
    for name, v in (reg or {}).items():
        if not isinstance(v, dict):
            continue
        tok = v.get("token") if isinstance(v.get("token"), str) else ""
        if _HEX_WINDOW.fullmatch(tok.lower()):            # not migrated yet: judged by the same rules, hashed in memory only
            hashed.setdefault(tok.lower()[:4], []).append((name, "", value_hash("", tok), v.get("path")))
        elif tok:
            raw.append((name, tok, v.get("path")))
        for x in [v] + [x for x in v.get("past_tokens") or [] if isinstance(x, dict)]:
            sha, pre, salt = x.get("token_sha256"), x.get("token_prefix"), x.get("salt")
            if isinstance(sha, str) and isinstance(salt, str) and isinstance(pre, str) and re.fullmatch(r"[0-9a-f]{4}", pre):
                hashed.setdefault(pre, []).append((name, salt, sha, x.get("token_path") or v.get("path")))
    return {"hashed": hashed, "raw": raw} if hashed or raw else None


def value_hits(text, index):
    """(decoy name, start, end, the decoy's path when it held the value, found by hash) for each decoy value in text."""
    out, low = [], text.lower()
    for pre, cands in index["hashed"].items():
        i = low.find(pre)
        while i >= 0:
            w = low[i:i + VALUE_LEN]
            if _HEX_WINDOW.fullmatch(w):
                hit = next((c for c in cands if value_hash(c[1], w) == c[2]), None)
                if hit:
                    out.append((hit[0], i, i + VALUE_LEN, hit[3], True))
            i = low.find(pre, i + 1)
    for name, tok, path in index["raw"]:
        i = text.find(tok)
        if i >= 0:
            out.append((name, i, i + len(tok), path, False))
    return out


def path_tail(p):
    """A decoy's folder/name: what a listing or a tree copy reproduces wherever it is rooted."""
    p = os.path.normpath(os.path.expanduser(str(p or "")))
    return os.path.join(os.path.basename(os.path.dirname(p)), os.path.basename(p)) if p not in (".", "/") else ""


def _in_command(node, w, inside=False):
    """True when w sits in a command inside this JSON value: a tool call's input, or a command, argv or arguments field."""
    if isinstance(node, dict):
        inside = inside or (isinstance(node.get("type"), str) and node["type"] in CMD_TYPES)
        return any(_in_command(v, w, inside or k in CMD_KEYS) for k, v in node.items())
    if isinstance(node, list):
        return any(_in_command(x, w, inside) for x in node)
    return inside and isinstance(node, str) and w in node.lower()


def _record_of(node, w):
    """The top-level JSON record holding w: a JSON line's own value, or, for a whole-document report (gitleaks' array), the
    element that holds it. Never a smaller object inside it: TruffleHog keeps the value again in a nested SecretParts, away from
    the path in SourceMetadata, and the record is still one finding of a scanner's report (F1)."""
    if isinstance(node, list):
        return next((x for x in node if w in json.dumps(x).lower()), None)
    return node if isinstance(node, dict) and w in json.dumps(node).lower() else None


def value_use(text, a, b, then, whole=None):
    """'command', 'listing' or 'copy' for the value at text[a:b]: in a command (JSON tool call or command field, or a line that
    names its command or argv); in a listing (the decoy's own folder/name in the same line or JSON record); else a copy."""
    w, tail = text[a:b].lower(), path_tail(then)
    s, e = text.rfind("\n", 0, a) + 1, text.find("\n", b)
    line = text[s:] if e < 0 else text[s:e]
    obj = whole
    if obj is None and line.lstrip().startswith(("{", "[")):
        try:
            obj = json.loads(line)
        except ValueError:
            obj = None
    try:
        if obj is not None:
            if _in_command(obj, w):
                return "command"
            rec = _record_of(obj, w)
            return "listing" if tail and rec is not None and tail in json.dumps(rec) else "copy"
    except RecursionError:
        return "copy"
    if _CMD_LINE.search(line):
        return "command"
    return "listing" if tail and tail in line else "copy"


def mirrored_copy(path, name):
    """True when path is decoy `name`'s file inside a copy of its whole root (tar or cp -a of /tmp): its folder and name, a chaff
    file beside it and its root's far sentinel are all reproduced under one folder."""
    lay = load_json(state_path("decoy_layout.json"), {}) or {}
    if not isinstance(lay, dict) or not valid_layout_path(name, lay.get(name)):
        return False
    here, tail = os.path.normpath(path), path_tail(decoy_path(lay[name]))
    if here == os.path.normpath(decoy_path(lay[name])) or not here.endswith(os.sep + tail):
        return False
    top = here[:-len(tail) - 1]
    chaff, sent, _ = layout_extras()
    b = _spec_base(lay[name])
    return (any(os.path.isfile(os.path.join(os.path.dirname(here), c)) for c in chaff.get(name, []))
            and b in sent and any(os.path.isfile(os.path.join(top, sent[b], fn)) for fn, _ in SENTINEL_FILES))


def value_kinds(text, path, index, history=False, line_no=None):
    """[(decoy name, how it sits, line)] for each decoy value in text: a whole file, or one line of a streamed log (line_no)."""
    hits = value_hits(text, index)
    if not hits:
        return []
    whole = None
    if line_no is None and not history and os.path.splitext(path)[1].lower() == ".json":
        try:
            whole = json.loads(text)                      # a report written as one JSON document (gitleaks)
        except ValueError:
            whole = None
    out = []
    for name, a, b, then, hashed in hits:
        if then and os.path.normpath(os.path.expanduser(then)) == os.path.normpath(path):
            continue                                      # the decoy itself
        if history:
            kind = "command"
        elif not hashed:
            kind = "copy"                                 # a registry not migrated yet: as before
        elif mirrored_copy(path, name):
            kind = "mirror"
        else:
            kind = value_use(text, a, b, then, whole)
        out.append((name, kind, line_no or line_of(text, a)))
    return out


def value_findings(path, kinds):
    """One finding for the decoy values in one file: ISR-K003 critical when any is in a command or copied, else ISR-K009 info."""
    if not kinds:
        return []
    bad = [x for x in kinds if x[1] == "command"] or [x for x in kinds if x[1] == "copy"]
    if bad:
        name, kind, line = bad[0]
        if kind == "command":
            f = finding("ISR-K003", "Decoy value used in a command", "critical", ["ASI03", "ASI04"], path, f"{name} in a command on line {line}",
                        "A decoy's value was put in a command: something read the decoy and tried to use what it found. Nothing "
                        "legitimate does that. Tell ISR Bot \"incident check\".")
        else:
            f = finding("ISR-K003", "Canary value copied into another file", "critical", ["ASI03", "ASI04"], path, name,
                        "A decoy's contents turned up somewhere else: something read it and wrote it out. Tell ISR Bot \"incident check\".")
        v = (load_json(state_path("canaries.json"), {}) or {}).get(name)
        if isinstance(v, dict) and isinstance(v.get("sweep_at"), str):   # the read this value most likely came from
            f["linked_read"] = {"rule": "ISR-K008", "decoy": name, "read_at": v["sweep_at"]}
            f["fix"] += (f" The decoy was last read on {v['sweep_at'][:10]} at {v['sweep_at'][11:19]} UTC in what looked like a file "
                         "sweep (ISR-K008): that read is how the value was taken.")
        return [f]
    name, kind, _ = kinds[0]
    f = finding("ISR-K009", "A decoy's value shows up only in a scan listing or a copy of its folder", "info", ["ASI03"], path,
                f"{name}: " + ("a copy of the decoy's whole folder tree" if kind == "mirror" else "listed beside the decoy's own path, as a scanner's report does"),
                "A scanner or a backup that read the decoy wrote down what it saw; nothing used the value. Delete the file if you "
                "don't need it. If the value is ever used, that is critical (ISR-K003).", ident=f"{name}|{path}")
    try:
        return [with_suspects(f, os.stat(path).st_mtime)]
    except OSError:
        return [f]


def decoy_value_findings(text, path, index=None):
    """K003 or K009 for the decoy values in one file's text."""
    index = index or decoy_value_index()
    return value_findings(path, value_kinds(text, path, index)) if index else []


# v1.2.0 (rev1 R8, Codex C4): what the stream found in each log, so an unchanged log is not read again on every run. It holds
# {"index": stream_index_key, "files": {path: [dev, ino, size, mtime_ns, [[decoy name, kind, line], ...]]}}: paths, names and
# line numbers only, never a value. Named canaries* so backup.sh leaves it out; it can always be rebuilt.
STREAM_CACHE = "canaries-stream.json"


def stream_index_key(index):
    """sha256 of the sorted (prefix, hash) list the check looks for, or None. A new or past value changes it."""
    pairs = sorted({(pre, c[2]) for pre, cands in index["hashed"].items() for c in cands})
    return hashlib.sha256(json.dumps(pairs).encode()).hexdigest() if pairs else None


def decoy_stream_findings(index):
    """K003 or K009 for decoy values in the agent session logs and shell histories, each read whole, line by line: no size cap,
    so a value used in a long session is still found. A shell history line is always a command. A log whose stat matches the
    cache (STREAM_CACHE) is not opened again: what it held is reused, so its finding stays open. A changed or new log is read
    whole; a new index drops the cache."""
    if not index:
        return []
    pres = [x.encode() for x in index["hashed"]]
    raws = [t.encode("utf-8", "replace") for _, t, _ in index["raw"]]
    key, cache_path = stream_index_key(index), state_path(STREAM_CACHE)
    cache = (load_json_regular(cache_path, {}) or {}) if key else {}
    seen = cache.get("files") if cache.get("index") == key and isinstance(cache.get("files"), dict) else {}
    found, files, fresh = {}, {}, {}
    hist_paths = {os.path.expanduser(h) for h in HISTORY_FILES}
    for p, hist in [(p, False) for p in session_logs()] + [(p, True) for p in sorted(hist_paths) if os.path.isfile(p)]:
        try:
            st = os.stat(p)
        except OSError:
            continue
        mark, old = [st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns], seen.get(p)
        if isinstance(old, list) and len(old) == 5 and old[:4] == mark and isinstance(old[4], list):
            files[p] = old                                # unchanged since the last run: not opened
            found[p] = [tuple(x) for x in old[4] if isinstance(x, list) and len(x) == 3]
        else:
            files[p], fresh[p] = mark + [[]], hist

    def lines():
        for p in [p for p, hist in fresh.items() if not hist]:
            try:
                with open(p, "rb") as f:
                    for n, line in enumerate(f, 1):
                        yield p, n, line, False
            except OSError:
                files.pop(p, None)                        # read again next run
                continue
        for p, n, line in history_lines(only={p for p, hist in fresh.items() if hist}):
            yield p, n, line, True
    for p, n, line, hist in lines():
        low = line.lower()
        if any(x in low for x in pres) or any(x in line for x in raws):
            kinds = value_kinds(line.decode("utf-8", "replace"), p, index, history=hist, line_no=n)
            found.setdefault(p, []).extend(kinds)
            if p in files:
                files[p][4] += [list(k) for k in kinds]
    if key and (cache.get("index"), cache.get("files")) != (key, files):
        try:
            os.close(os.open(cache_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600))   # 0600 from the start
        except FileExistsError:
            pass
        save_json_keep_mode(cache_path, {"index": key, "files": files})
    out = []
    for p in sorted(found):
        out += value_findings(p, found[p])
    return out
