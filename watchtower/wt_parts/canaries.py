# Part of wt.py: runs inside wt.py's namespace (loaded by _wt_part); not a module on its own.
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
# v0.6.8: the spec paths above were the same on every install and printed in Watchtower's own docs, so anything that read the
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
    place (or a published or older name, which Watchtower once used). Anything else in the layout file is ignored, so a Bot that
    edits it can't point Watchtower at another file."""
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
    """This install's decoy places, one per spec, picked at random the first time and kept. `renew` names get new places."""
    path = state_path("decoy_layout.json")
    lay = load_json(path, {}) or {}
    lay = {n: v for n, v in lay.items() if valid_layout_path(n, v)} if isinstance(lay, dict) else {}
    changed = False
    for name, spec, _ in CANARY_SPECS:
        if name not in lay or name in renew:
            lay[name] = random_decoy_path(name, spec); changed = True
    if changed:
        save_json(path, lay)
    return lay


def decoy_places():
    """Every place a decoy of this install may be: its own random ones, plus the published and older names it may have used."""
    lay = load_json(state_path("decoy_layout.json"), {}) or {}
    mine = [v for n, v in lay.items() if valid_layout_path(n, v)] if isinstance(lay, dict) else []
    return {os.path.normpath(decoy_path(x)) for x in list(mine) + [x for _, x, _ in CANARY_SPECS] + list(PUBLISHED_CANARY_PATHS)}


def decoy_path(path):
    """The spec's path on this computer. WT_DECOY_ROOT moves them under another folder (the tests use it)."""
    p = os.path.expanduser(path)
    root = os.environ.get("WT_DECOY_ROOT", "")
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


def write_decoy(p, content):
    """Write a decoy without ever following a link. The decoys live in /tmp and /var/tmp, where every Bot can write, so a link
    planted at the decoy's folder or file would make Watchtower overwrite whatever it points to. The decoy's own folder and file
    are opened with O_NOFOLLOW from an open handle on the folder above, and every check is made on the opened handle, never on
    the name, so nothing can be swapped in between the check and the write. Returns (atime, mtime, {ino, ctime_ns}) after
    re-arming: the last two say later whether the file's times were set by hand (fix round 1)."""
    folder, fn = os.path.split(p)
    base, sub = os.path.split(folder)
    os.makedirs(base, exist_ok=True)                  # /tmp, /var/tmp (or the test root): the system's own folders
    bfd = os.open(base, os.O_RDONLY | os.O_DIRECTORY)
    dfd = fd = None
    try:
        try:
            os.mkdir(sub, 0o755, dir_fd=bfd)
        except FileExistsError:
            pass
        try:
            dfd = os.open(sub, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=bfd)
        except OSError as e:
            raise DecoyLink(f"{folder} is a link or not a folder") from e
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
        for x in (fd, dfd, bfd):
            if x is not None:
                os.close(x)


# Hardening batch 2 (R2): the backup's fingerprint. Next to each decoy sits a witness file with mode 000. Every Bot runs as the
# same user as Watchtower: it can't read the witness without chmod, or move its read time without utime, and both stamp a new
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
    for name, path, body in CANARY_SPECS:
        p = decoy_path(layout[name])
        if (only is not None and name not in only) or (name in reg and os.path.lexists(os.path.expanduser(reg[name]["path"]))
                                                         and not os.path.islink(os.path.expanduser(reg[name]["path"]))):
            continue
        tok = reg.get(name, {}).get("token") if only is not None and name in reg else None
        tok = tok or _s.token_hex(8)                      # a re-planted decoy keeps its value, so a copy made earlier is still recognised
        content = body.format(tok=tok, tokU=tok.upper()[:16])
        if token_file and name == "cloud-keys":
            content = open(token_file).read()
        try:
            atime, mtime, ident = write_decoy(p, content)
        except DecoyLink as e:
            bad.append(decoy_link_finding(name, p, f"{link_target(p)}. {e}"))
            ledger({"event": "canary-refused", "decoy": name, "path": p, "why": str(e)[:200]})
            continue
        reg[name] = dict({"path": p, "token": tok, "atime": atime, "mtime": mtime, "planted": now(), "planted_ts": time.time()}, **ident)
        arm_witness(reg, os.path.dirname(p))
        planted.append(name)
    save_json(state_path("canaries.json"), reg)
    if bad:
        remember_events(bad)
        if refused is not None:
            refused += bad
    return planted


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
        # batch 2 (R2): read tracking is checked where the decoys are (/tmp and /var/tmp), not in Watchtower's own folder
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
                  "in this conversation run `wt.py canary remove --owner-said-yes`.")
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
        save_json(state_path("canaries.json"), {})
        ledger({"event": "canary-remove", "count": len(reg)})
        print("Canaries removed.")
        return 0
    fs = canary_findings(record=False)   # status only looks: it never resets a decoy or drops evidence
    print(json.dumps([compact(f) for f in fs], indent=1) if fs else "CANARIES_QUIET")
    if fs:
        print("Not reset and not logged yet: the next `wt.py daily` or `wt.py audit` records this and re-arms the decoys.")
    return 0


BULK_KEY, OLD_K005_KEY = "bulk-decoy-read", "own-scan-decoy-read"
BULK_KEYS = frozenset((BULK_KEY,))   # batch 2: only the backup's proven sweep is one updated line; every other sweep is its own event


def decoy_ident(st):
    """What a decoy's times can't be set back to by hand: its inode and ctime (utime, chmod, a new file all move one)."""
    return {"ino": st.st_ino, "ctime_ns": st.st_ctime_ns}


def decoy_untouched(v, st):
    """Fix round 1 (R2): the decoy's times were moved only by a read since Watchtower armed it. A Bot that sets a decoy's atime
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
    by its witness, is the platform's backup: one calm line. Without that proof, reads during a recorded Watchtower run are high
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
                               "Check recent routine runs, then re-plant with `wt.py canary plant`."))
            continue
        st = os.lstat(p)
        if decoy_rewritten(v, st):
            # DQ-041 (Oct 14 replay): the file here was written after this registry planted it, so its atime says nothing
            # about a read of *our* decoy (a dry run with a copied registry and its own /tmp re-planted it). Never silent:
            out.append(finding("ISR-K007", "Decoy file rewritten since it was planted", "high", ["ASI10"], p,
                               f"{name}: written {dt.datetime.fromtimestamp(st.st_mtime, dt.timezone.utc).isoformat(timespec='minutes')}, "
                               f"planted {str(v.get('planted', ''))[:16]}",
                               "The decoy on disk is not the one ISR Bot recorded: something rewrote it, or this state was copied from "
                               "another run. Re-plant with `wt.py canary plant`; if no ISR Bot run or dry run explains it, tell ISR Bot \"incident check\"."))
            continue
        if st.st_atime > v["atime"] + 1:
            reads.append((name, p, st.st_atime))
            if not decoy_untouched(v, st):
                forged.add(name)                          # its times were set by hand, or the registry predates the check
    # Fix round 1 (R2): every read is judged before anything is re-armed or saved, so a failure never erases the evidence
    if reads:
        when = lambda t: dt.datetime.fromtimestamp(t, dt.timezone.utc).isoformat(timespec="minutes")
        times = [t for _, _, t in reads]
        each = ", ".join(f"{n} {dt.datetime.fromtimestamp(t, dt.timezone.utc).strftime('%H:%M:%S')}" for n, _, t in sorted(reads, key=lambda r: r[2]))
        places = ", ".join(sorted({os.path.dirname(p) for _, p, _ in reads}))
        runs = run_windows()
        own = lambda t: any(a - 2 <= t <= b + 5 for a, b in runs)
        backup = len(reads) >= 2 and not forged and all(witness_proves(reg[n], t) for n, _, t in reads)
        if backup:
            f = finding("ISR-K004", "Several decoys were read by the platform's backup", "low", ["ASI03"], places,
                        f"{len(reads)} of {len(reg)} decoys within {int(max(times) - min(times))}s at {when(min(times))} ({each})",
                        "The file next to each decoy that only a privileged reader can open was read with it: the platform's file backup. "
                        "It is listed once and updated each time. If it lines up with something you didn't expect, tell ISR Bot \"incident check\".")
            f["key"] = BULK_KEY                           # one line that is updated, not a new finding every time the backup runs
            out.append(f)
        elif all(own(t) for t in times):
            out.append(finding("ISR-K005", "Decoys were read while an ISR Bot run was recorded", "high", ["ASI03", "ASI10"], places,
                               f"{len(reads)} decoy(s) at {when(min(times))}, during a recorded Watchtower run ({each})",   # v0.7.4: the old name kept, the evidence is part of the finding key
                               "The run record can be written by any Bot, so it doesn't prove the read was ISR Bot's, and the backup's proof "
                               "is missing. Tell ISR Bot \"incident check\"."))
        elif len(reads) >= 2 and max(times) - min(times) <= 180:
            out.append(finding("ISR-K004", "Several decoys were read together", "high", ["ASI03", "ASI10"], places,
                               f"{len(reads)} of {len(reg)} decoys within {int(max(times) - min(times))}s at {when(min(times))} ({each})",
                               "Something read several decoys at once, and nothing shows it was the platform's backup. A Bot searching every "
                               "file does this. Tell ISR Bot \"incident check\"."))
        else:
            for name, p, t in reads:
                out.append(finding("ISR-K001", "Something opened a decoy file", "critical", ["ASI03", "ASI10"], p, f"{name} read at {when(t)}",
                                   "Nothing legitimate needs this file, and nothing else was searched with it. "
                                   "Find which Bot or routine ran then (Agent Computer view, run history) and tell ISR Bot \"incident check\"."))
    if not record:
        return out
    if reads:
        stamp = lambda t: dt.datetime.fromtimestamp(t, dt.timezone.utc).isoformat(timespec="seconds")
        for name, _, t in reads:                          # remembered, so a decoy read and then removed is never put back quietly
            if not backup:                                # a run window any Bot can write never hides a read
                reg[name]["read_at"] = stamp(t)
        save_json(state_path("canaries.json"), reg)
        ledger(dict({"event": "canary-read", "decoys": [{"name": n, "path": p, "read_at": stamp(t)} for n, p, t in reads]},
                    **({"backup": True} if backup else {})))
        for name, p, _ in reads:                          # only now: the reads are judged and logged
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
    if tend_witnesses(reg) or reads:
        save_json(state_path("canaries.json"), reg)
    return out


def run_windows():
    """The recorded Watchtower runs as (start, end). Any Bot can write this file, so an entry that isn't two numbers in order is
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
            print(f"NOT CLEARED: {', '.join(alarms)} are alarms. Show them to the owner (`wt.py events list`), and only after their yes "
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


def canary_copies(text, path):
    reg = load_json(state_path("canaries.json"), {})
    for name, v in reg.items():
        if v.get("token") and v["token"] in text and os.path.expanduser(v["path"]) != path:
            return finding("ISR-K003", "Canary value copied into another file", "critical", ["ASI03", "ASI04"], path, name,
                           "A decoy's contents turned up somewhere else: something read it and wrote it out. Tell ISR Bot \"incident check\".")
    return None
