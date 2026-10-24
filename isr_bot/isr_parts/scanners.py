# Part of isr.py: runs inside isr.py's namespace (loaded by _isr_part); not a module on its own.
# Hardening batch 3 (R7, Oct 16): tool() looked on PATH first, so any program a Bot named skillspector there was Watchtower's
# second engine, and a copy in Watchtower's folder ran whatever it contained. Now the only candidate is Watchtower's own
# scanners/bin/<name>, and only when its sha256 is in scripts/scanner-bins.lock for this computer's architecture.
SCANNER_LOCK = os.path.join(HERE, "..", "scripts", "scanner-bins.lock")
SCANNER_NAMES = {"skillspector": "SkillSpector", "husk": "husk", "gitleaks": "gitleaks", "trufflehog": "TruffleHog",
                 "osv-scanner": "OSV-Scanner", "pip-audit": "pip-audit"}
SCANNER_LOCK_EXTRA = {}   # tests only: name -> digest (or a set of them). An in-process dict, never fed by a file or the environment.
SCANNER_PROBLEMS = {}     # name -> (kind, why) for this run: "changed", "unreadable", "unlisted" or "old-folder"; (kind, why, "launch") when refused at launch
_SCANNER_OK = {}          # (path, size, mtime_ns, ctime_ns, inode) -> (digest, venv Python named on its first line or None)
_SCANNER_LOCK_CACHE = {}
# Codex, batch 3 round 1: hashing read the whole file into memory, so a huge or sparse "program" could exhaust memory or stall
# the run outside every subprocess timeout. A program is now read in chunks, at most this much and for at most this long.
SCANNER_MAX_BYTES = 512 * 1024 * 1024
SCANNER_HASH_SECONDS = 60
_LAUNCH = threading.Lock()   # a sealed copy is made, and every program started, one at a time (see scanner_launch)
# The audit stage each single-scanner stage runs in (audit.py's soft() names): a scanner whose stage failed this run isn't used.
SCANNER_STAGES = {"trufflehog": "TruffleHog (which keys still work)", "gitleaks": "gitleaks (keys in files)",
                  "pip-audit": "pip-audit (installed Python packages)", "osv-scanner": "OSV-Scanner (project dependencies)"}


class ScannerUnusable(OSError):
    """A scanner program Watchtower may not run; the message says why in plain words."""


class ScannerUnreadable(ScannerUnusable):
    """Claude review 1 (4): the program couldn't be read or copied right now (too slow, out of memory or file descriptors,
    sealing refused, no /proc). Not run and its last results are kept, but this is no verdict on its contents, so no ISR-X005."""


class SealUnavailable(ScannerUnreadable):
    """Claude review 2 (1): the sealed copy couldn't be made (memfd, sealing, writing the copy or /proc). Nothing runs, but the
    program file itself is still hashed once for a verdict, so a swapped copy is a ISR-X005 even then."""


# Claude review 2 (1): every OSError was "unreadable", so a swapped copy chmod 0111 (or a link swapped in after the lstat) gave
# EACCES or ELOOP at open, no ISR-X005, every run. Only these say the computer is short of something; any other failure to open
# or read the program file comes from the file itself, so it isn't the copy Watchtower installed.
_PRESSURE_ERRNOS = {errno.ENOMEM, errno.EMFILE, errno.ENFILE, errno.EAGAIN, errno.EINTR}


def _program_error(e):
    """The ScannerUnusable for an error opening, reading or hashing a program file: ScannerUnreadable (no verdict) for memory
    or file-descriptor pressure, otherwise the file itself is the problem."""
    if isinstance(e, ScannerUnusable):
        return e
    if isinstance(e, MemoryError) or getattr(e, "errno", None) in _PRESSURE_ERRNOS:
        return ScannerUnreadable(f"its program file can't be read right now ({errno.errorcode.get(getattr(e, 'errno', None), 'out of memory')})")
    return ScannerUnusable(f"its program file can't be opened or read ({errno.errorcode.get(getattr(e, 'errno', None), type(e).__name__)})")


def _problem_of(e):
    """(kind, why) for an error from _program_error's family."""
    e = _program_error(e)
    return ("unreadable" if isinstance(e, ScannerUnreadable) else "changed"), str(e)


class LaunchTimedOut(Exception):
    """run()'s deadline passed before the program could start (waiting for another launch, or making its sealed copy). A time
    out, as if it had run too long; not a verdict on the program, which is judged again at its next launch."""


def _launch_lock(deadline):
    """Take _LAUNCH, waiting until the deadline at most (None: as long as it takes). False when the deadline came first."""
    if deadline is None:
        return _LAUNCH.acquire()
    return _LAUNCH.acquire(timeout=max(0, deadline - time.monotonic()))


def scanner_arch():
    m = platform.machine().lower()
    return {"arm64": "aarch64", "amd64": "x86_64"}.get(m, m)


def scanner_bin():
    return os.path.join(home(), "scanners", "bin")


def _venv_shebang(line):
    """True when this first line names this install's venv Python (scanners/bin/python, python3, python3.12...)."""
    for b in dict.fromkeys((scanner_bin(), os.path.join(os.path.realpath(home()), "scanners", "bin"))):
        if re.fullmatch(re.escape(b) + r"/python[0-9.]*", line):
            return True
    return False


def _read_program(fd, sink=None):
    """(sha256, venv Python or None) of the open program file fd, read in chunks; sink(chunk) gets every byte as it is read.
    A pip entry point's first line names the venv's Python by its full path, so it is hashed as "#!python": the lock's
    checksum then doesn't depend on where Watchtower is installed. Raises ScannerUnusable for anything that isn't a plain
    file, is over SCANNER_MAX_BYTES (checked before reading, so a sparse file costs nothing) or takes too long to read."""
    st = os.fstat(fd)
    if not stat.S_ISREG(st.st_mode):
        raise ScannerUnusable("it isn't a plain program file")
    if st.st_size > SCANNER_MAX_BYTES:
        raise ScannerUnusable(f"its program file is too large to be a scanner ({st.st_size} bytes)")
    deadline = time.monotonic() + max(1, min(SCANNER_HASH_SECONDS, time_left()))
    head = b""
    while len(head) <= 4096 and b"\n" not in head:
        chunk = os.read(fd, 4097 - len(head))
        if not chunk:
            break
        head += chunk
    first, nl, rest = head.partition(b"\n")
    shebang = first[2:].decode("utf-8", "replace").strip() if first.startswith(b"#!") else ""
    # Claude review 1 (1): a file whose first line really is "#!python" hashed the same as a pip entry point, wasn't a venv
    # entry point (so no interpreter check), and the kernel then ran "python" from the folder Watchtower was started in. A
    # first line that names its program without a full path is never run, so the "#!python" form can't be met by a real file.
    if first.startswith(b"#!") and not shebang.startswith("/"):
        raise ScannerUnusable("its first line names the program it runs with without a full path")
    venv = shebang if shebang and _venv_shebang(shebang) else None
    h = hashlib.sha256(b"#!python" + nl + rest if venv else head)
    total = len(head)
    if sink:
        sink(head)
    while True:
        chunk = os.read(fd, 1 << 20)
        if not chunk:
            break
        total += len(chunk)
        if total > SCANNER_MAX_BYTES:
            raise ScannerUnusable(f"its program file is too large to be a scanner (over {SCANNER_MAX_BYTES} bytes)")
        if time.monotonic() > deadline:
            raise ScannerUnreadable("its program file took too long to read")
        h.update(chunk)
        if sink:
            sink(chunk)
    return h.hexdigest(), venv


def _open_program(path):
    # O_NONBLOCK: a FIFO swapped in after the lstat must not hang the run; _read_program then refuses it (not a plain file)
    return os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)


def _in_hash_time(fn, cleanup=None, deadline=None):
    """fn() run in a worker thread, waited for at most SCANNER_HASH_SECONDS (or the run's time left). Codex, batch 3 round 2:
    the deadline in _read_program was checked only between reads, and a read of a regular file can't be interrupted, so one
    slow read (then EOF) took as long as it liked. The worker owns every fd it opens; when it is given up on, its result is
    never used and cleanup(result) releases it whenever it does finish. Raises ScannerUnusable on time out, or LaunchTimedOut
    when run()'s deadline (final review) comes before that limit and is what ran out."""
    limit = max(1, min(SCANNER_HASH_SECONDS, time_left()))
    launch_bound = deadline is not None and deadline - time.monotonic() < limit
    if launch_bound:
        limit = deadline - time.monotonic()
        if limit <= 0:
            raise LaunchTimedOut()
    box, lock, done = {}, threading.Lock(), threading.Event()

    def work():
        try:
            res, err = fn(), None
        except BaseException as e:   # noqa: BLE001 - handed to the caller
            res, err = None, e
        with lock:
            if box.get("abandoned"):
                if cleanup and err is None:
                    cleanup(res)
                return
            box.update(res=res, err=err)
            done.set()
    threading.Thread(target=work, name="isr-bot-hash", daemon=True).start()
    done.wait(limit)
    with lock:
        if not done.is_set():
            box["abandoned"] = True
            if launch_bound:
                raise LaunchTimedOut()
            raise ScannerUnreadable("its program file took too long to read")
    if box["err"] is not None:
        raise box["err"]
    return box["res"]


def _read_program_at(path):
    try:
        fd = _open_program(path)
    except OSError as e:
        raise _program_error(e)
    try:
        return _read_program(fd)
    except OSError as e:
        raise _program_error(e)
    finally:
        os.close(fd)


def scanner_digest(path):
    """sha256 of a scanner's program file, as the lock lists it (see _read_program), read within the hashing time limit."""
    return _in_hash_time(lambda: _read_program_at(path))[0]


def _sealed_copy(path, deadline=None):
    """_seal_copy within the hashing time limit and run()'s deadline (see _in_hash_time); a copy finished after either is
    closed unused."""
    return _in_hash_time(lambda: _seal_copy(path), cleanup=lambda r: os.close(r[0]), deadline=deadline)


def _seal_copy(path):
    """(fd, sha256, venv Python or None) for the program at path. Its bytes are copied into a sealed in-memory file while they
    are hashed, and the fd is read-only: nobody, this user included, can change what it holds. Running the program from this
    fd runs exactly the bytes that were checked (Codex, batch 3 round 1: checking a path and then running the path let a
    program swapped in between run unchecked)."""
    import fcntl
    try:
        src = _open_program(path)
    except OSError as e:
        raise _program_error(e)
    mfd = None
    try:
        # Claude review 2 (1): a failure of the copy (not of the program file) is SealUnavailable, never a verdict on the program.
        # No memfd or sealing on this computer: nothing is run from a copy that could still change.
        try:
            mfd = os.memfd_create("isr-bot-scanner", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
        except (AttributeError, OSError):
            raise SealUnavailable("this computer can't keep a sealed copy of it to run")

        def sink(b):
            view = memoryview(b)
            try:
                while view:
                    view = view[os.write(mfd, view):]
            except OSError:
                raise SealUnavailable("its sealed copy couldn't be written right now")
        try:
            digest, venv = _read_program(src, sink)
        except OSError as e:
            raise _program_error(e)
        try:
            fcntl.fcntl(mfd, fcntl.F_ADD_SEALS, fcntl.F_SEAL_WRITE | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SEAL)
            ro = os.open(f"/proc/self/fd/{mfd}", os.O_RDONLY | os.O_CLOEXEC)   # the writable fd is closed before anything runs
        except (AttributeError, OSError):
            raise SealUnavailable("this computer can't keep a sealed copy of it to run")
    finally:
        os.close(src)
        if mfd is not None:
            os.close(mfd)
    return ro, digest, venv


LOCK_READER_REL = "scripts/scanner_lock.py"
SCANNER_LOCK_REL = "scripts/scanner-bins.lock"
LOCK_READER_MAX_BYTES = 256 * 1024


_RELEASE = {}   # the MANIFEST.sha256 this process checked itself against: {"root": ..., "files": {rel: sha256}}


def remember_manifest(root, text):
    """Keep the manifest self_check is checking (or, when it didn't run, the first one read) for the rest of this process."""
    files = {}
    for line in (text or "").splitlines():
        parts = line.split(None, 1)
        if len(parts) == 2:
            files.setdefault(parts[1].lstrip("*").strip(), parts[0])
    _RELEASE.clear()
    _RELEASE.update(root=root, files=files, at=SELF_ROOT)


def installed_root():
    """The real folder of the installed copy this isr.py runs from, or None in a developer checkout. PR A, Codex round 1 (6): it
    was an installed copy only while ISR_BOT_HOME/app led to it, so changing that variable made one a developer checkout, whose
    rules files (the reviewed list, the normalization spec, the locks) are never held to MANIFEST.sha256. An installed copy is the
    `app` folder install.sh makes, whatever ISR_BOT_HOME says now.
    PR A, Codex round 2 (5): SELF_ROOT is the real folder of the isr.py that runs (isr.py follows links to itself), so a folder
    holding only an `isr-bot` link to the installed copy runs it as the installed copy; and only that real folder's name
    counts, never a ISR_BOT_HOME whose app leads somewhere.
    PR A, Codex round 3 (3): the name alone made `mv app app.real` (with or without `ln -s app.real app`) a developer checkout:
    no self-check, and planted rules files accepted. It is also an installed copy when it has what install.sh leaves: its
    MANIFEST.sha256 and the commit record in the folder holding it (state/installed_commit), or when it is anywhere under
    install.sh's default home. A developer checkout is a folder with none of these."""
    root = os.path.realpath(SELF_ROOT)
    if os.path.basename(root) == "app" or (root + "/").startswith(os.path.realpath(DEFAULT_INSTALL_HOME) + "/"):
        return root
    if os.path.isfile(os.path.join(root, "MANIFEST.sha256")) and os.path.lexists(os.path.join(install_home(root), "state", COMMIT_FILE)):
        return root
    return None


DEFAULT_INSTALL_HOME = "/workspace/isr-bot"   # install.sh's ISR_HOME when ISR_BOT_HOME isn't set


def install_home(root):
    """The Watchtower folder the installed copy at `root` (its real folder) was installed into: install.sh's ISR_HOME, the real
    folder holding `app`. PR A, Codex round 2 (5): never ISR_BOT_HOME, whose `app` may be a link to the installed copy while
    its state/installed_commit says what someone wants."""
    return os.path.dirname(root)


def release_manifest():
    """{rel: sha256} from the MANIFEST.sha256 of the folder this isr.py runs from ({} when it is missing or unreadable). Claude
    review 1 (2): this was read from disk again at each use, so a MANIFEST.sha256 rewritten after the self-check vouched for
    whatever it listed. It is now the one self_check checked, read once per process.

    Claude review 2 (2): it was read again whenever the real folder behind `app` changed, so `mv app app.real; ln -s evil app`
    after the self-check had the Bot's manifest vouch for its own lock reader, which then ran inside Watchtower. Once one is
    remembered it is never read again, and a different folder behind the same name lists nothing (the lock then reads as
    changed: scanner_lock).

    Batch 6 (KL4, #15 high 4): it was None in a developer checkout, so a copy that only looked like one (moved out of `app`
    without its commit record, a renamed custom home) read planted rules files as they were. Whatever the layout, Watchtower's
    release files are now held to this folder's manifest; installed_root and self_check still say what is an installed copy."""
    root = os.path.realpath(SELF_ROOT)
    if _RELEASE.get("at") == SELF_ROOT:
        return _RELEASE["files"] if root == _RELEASE["root"] else {}
    remember_manifest(root, read_text(os.path.join(root, "MANIFEST.sha256")))   # a checkout's too (no self-check reads it)
    return _RELEASE["files"]


def release_digest(rel):
    """The sha256 MANIFEST.sha256 lists for rel, or "" when it lists none (or there is no manifest): the file is then refused.
    Batch 6 (KL4): never None, a developer checkout included."""
    return release_manifest().get(rel, "")


def release_files_unchecked():
    """True when this folder's MANIFEST.sha256 is missing, unreadable or lists nothing: none of Watchtower's release files can
    be checked, so each is refused (KL4)."""
    return not release_manifest()


def shipped_path(path, rel):
    """True when `path` is where this copy ships rel (SELF_ROOT/rel, as written or where it really leads)."""
    try:
        want = os.path.normpath(os.path.join(SELF_ROOT, rel))
        p = os.path.normpath(os.path.abspath(str(path)))
        return p == want or os.path.realpath(p) == os.path.realpath(want)
    except (OSError, ValueError):
        return True


def release_want(path, rel):
    """The sha256 a rules file read from `path` must have (release_digest; "" refuses it), or None when it is used as it is.
    Only one file is used as it is: in a developer checkout, a file a test pointed the module constant at (never the shipped
    path, never from the environment or state/; nothing but an edit to Watchtower's own code can change it), unless the test
    stands in for another manifest by replacing release_digest. An installed copy holds every path to its manifest, as before."""
    want = release_digest(rel)
    if installed_root() is None and not shipped_path(path, rel) and want == release_manifest().get(rel, ""):
        return None
    return want


def _lock_reader():
    """scripts/scanner_lock.py as a namespace, run from its source bytes. Codex, batch 3 round 2: importing it let Python load a
    bytecode cache (scripts/__pycache__/scanner_lock.*.pyc) instead, which self_check never looks at, so a planted cache
    replaced the scanner allowlist. Now the source is read once (a plain file, never a link), held to its MANIFEST.sha256 line
    in an installed copy, compiled from those bytes and run; no cache is read or written. None when it can't be used."""
    try:
        src = _reader_source()
        want = release_want(_reader_path(), LOCK_READER_REL)
        if want is not None and hashlib.sha256(src).hexdigest() != want:
            return None
        return _reader_namespace(src)
    except Exception:   # noqa: BLE001 - a reader that can't be read or run means no program is listed, never every program
        return None


def _reader_source():
    """The bytes of scripts/scanner_lock.py: a plain file, never a link, at most LOCK_READER_MAX_BYTES. Raises OSError when it
    can't be read, ValueError when it isn't a plain file or is too large."""
    fd = os.open(_reader_path(), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ValueError("not a plain file")
        src = b""
        while len(src) <= LOCK_READER_MAX_BYTES:
            chunk = os.read(fd, LOCK_READER_MAX_BYTES + 1 - len(src))
            if not chunk:
                break
            src += chunk
    finally:
        os.close(fd)
    if len(src) > LOCK_READER_MAX_BYTES:
        raise ValueError("too large")
    return src


def _reader_path():
    return os.path.join(HERE, "..", LOCK_READER_REL)


def _reader_namespace(src):
    path = _reader_path()
    ns = {"__name__": "isr_bot_scanner_lock", "__file__": path, "__builtins__": builtins}
    exec(compile(src, path, "exec", dont_inherit=True), ns)   # noqa: S102 - Watchtower's own checked file, from its bytes
    return ns


def scanner_lock():
    """{(name, arch): {sha256, ...}} from scripts/scanner-bins.lock, read by scripts/scanner_lock.py, the same reader publish.sh
    uses (Codex, batch 3 round 1), with its file limits too (round 2). A line it doesn't accept is never used; if the reader
    itself can't be loaded, or the lock can't be used whole, nothing is.

    Claude review 1 (2): the lock was read at the first scanner, minutes after the self-check, and again whenever its size or
    time changed, and never held to MANIFEST.sha256, so a line added during a run (and removed after) made any program a
    verified scanner. In an installed copy the lock and its reader are now read once per process and used only when both
    match the manifest the self-check checked. Claude review 2 (6): one that doesn't match lists nothing, as before, and is
    remembered as changed (scanner_list_changed), never read as the "not listed yet" of an empty lock. Batch 6 (KL4): a
    developer checkout's shipped lock is held to its manifest the same way (release_want)."""
    want = release_want(SCANNER_LOCK, SCANNER_LOCK_REL)
    if want is not None:
        if _SCANNER_LOCK_CACHE.get("installed") is None:
            lock = _installed_lock(want)
            _SCANNER_LOCK_CACHE.update(installed=lock or {}, changed=lock is None)
        return _SCANNER_LOCK_CACHE["installed"]
    try:
        st = os.stat(SCANNER_LOCK)
        rst = os.stat(os.path.join(HERE, "..", LOCK_READER_REL))
        key = (SCANNER_LOCK, st.st_size, st.st_mtime_ns, st.st_ino, HERE, rst.st_size, rst.st_mtime_ns, rst.st_ctime_ns, rst.st_ino)
    except OSError:
        return {}
    if _SCANNER_LOCK_CACHE.get("key") != key:
        out = {}
        reader = _lock_reader()
        try:
            if reader:
                text, why = reader["read_lock"](SCANNER_LOCK)
                out = {} if why else reader["parse"](text)[0]
        except Exception:   # noqa: BLE001
            out = {}
        _SCANNER_LOCK_CACHE.update(key=key, lock=out if isinstance(out, dict) else {})
    return _SCANNER_LOCK_CACHE["lock"]


def _installed_lock(want):
    """The installed copy's lock, read once, when its bytes and its reader's both match the remembered manifest. None when
    either isn't the file that manifest lists (changed, gone, a link, unreadable by permission, or no longer in the folder the
    self-check checked); {} when it can't be read right now (no memory or file descriptors) or can't be used."""
    reader_want = release_want(_reader_path(), LOCK_READER_REL)
    if not want or reader_want == "":
        return None
    try:
        src = _reader_source()
    except ValueError:
        return None
    except OSError as e:
        return {} if e.errno in _PRESSURE_ERRNOS else None
    if reader_want is not None and hashlib.sha256(src).hexdigest() != reader_want:
        return None
    try:
        reader = _reader_namespace(src)
        text, why = reader["read_lock"](SCANNER_LOCK)
        if why:   # read_lock names the error type: a plain OSError on a plain file is pressure (EMFILE, ENOMEM), not a change
            try:
                plain = stat.S_ISREG(os.lstat(SCANNER_LOCK).st_mode)
            except OSError:
                plain = False
            return {} if plain and why.endswith("(OSError)") else None
        if not isinstance(text, str) or hashlib.sha256(text.encode("utf-8")).hexdigest() != want:
            return None
        out = reader["parse"](text)[0]
        return out if isinstance(out, dict) else {}
    except Exception:   # noqa: BLE001
        return {}


def scanner_list_changed():
    """True when this installed copy's lock or its reader isn't what the self-check checked (scanner_lock read it so)."""
    return bool(_SCANNER_LOCK_CACHE.get("changed")) and release_want(SCANNER_LOCK, SCANNER_LOCK_REL) is not None


def _scanner_extra(name):
    extra = SCANNER_LOCK_EXTRA.get(name)
    return {extra} if isinstance(extra, str) else set(extra) if isinstance(extra, (set, frozenset, list, tuple)) else set()


def _scanner_listed(name):
    lock = scanner_lock()
    return lock.get((name, scanner_arch()), set()) | lock.get((name, "any"), set())


def _digest_problem(name, digest):
    """None when this sha256 may run as `name`, else (kind, why)."""
    if digest in _scanner_extra(name):
        return None
    want = _scanner_listed(name)
    if not want and scanner_list_changed():
        return "changed", "ISR Bot's scanner list (scripts/scanner-bins.lock or its reader) changed after the self-check, during this run"  # v0.8.0: renamed; this is ISR-X005's evidence, part of the finding key
    if not want:
        return "unlisted", f"its checksum isn't in ISR Bot's list for this computer ({scanner_arch()}) yet"
    if digest not in want:
        return "changed", "its program file isn't the one ISR Bot installed"  # v0.8.0: renamed; this is ISR-X005's evidence, part of the finding key
    return None


def running_interpreter():
    """(path, (dev, inode)) of the program this process is running, from /proc/self/exe; None when that can't be read or no
    longer names the same file. Codex, batch 3 round 2: realpath(sys.executable) follows the launcher name Watchtower was
    started through, and a writable venv link retargeted after start made another program (perl) the "pinned" Python."""
    try:
        st = os.stat("/proc/self/exe")
        path = os.readlink("/proc/self/exe")
        here = os.stat(path)
    except OSError:
        return None
    if not path.startswith("/") or (here.st_dev, here.st_ino) != (st.st_dev, st.st_ino) or not stat.S_ISREG(st.st_mode):
        return None
    return path, (st.st_dev, st.st_ino)


def trusted_interpreter(path):
    """The running interpreter's real path, when `path` (a venv Python link) leads to that very file (same device and inode as
    /proc/self/exe, never a name) and that file and every folder above it belong to root with no group or other write; else
    None. Codex, batch 3 round 1: a Python the Bot owned passed the old check once it was chmod 0555 (the Bot can chmod it
    back), and so did one under a folder the Bot can write (it can be replaced). Round 2: pinned to /proc/self/exe."""
    try:
        me = running_interpreter()
        st = os.stat(path)
        if not me or (st.st_dev, st.st_ino) != me[1]:
            return None
        real = p = me[0]
        while True:
            st = os.lstat(p)
            if st.st_uid != 0 or st.st_mode & 0o022 or stat.S_ISLNK(st.st_mode):
                return None
            up = os.path.dirname(p)
            if up == p:
                return real
            p = up
    except OSError:
        return None


def scanner_verdict(name):
    """(path, None) for Watchtower's own checked copy, else (None, (kind, why)); kind None means simply not there."""
    path = os.path.join(scanner_bin(), name)
    try:
        st = os.lstat(path)
    except OSError:
        if os.path.lexists(os.path.join(home(), "bin", name)):
            return None, ("old-folder", "it is in ISR Bot's old scanner folder")
        return None, (None, "")
    if not stat.S_ISREG(st.st_mode) or not os.access(path, os.X_OK):
        return None, ("changed", "it isn't a plain program file")
    if not st.st_mode & stat.S_IRUSR:   # Claude review 2 (1): Watchtower's own copy is always readable by its owner
        return None, ("changed", "its program file can't be read (no read permission)")
    if not _scanner_extra(name) and not _scanner_listed(name):   # nothing it could match: not read at all (Codex, round 1)
        return None, _digest_problem(name, "")
    key = (path, st.st_size, st.st_mtime_ns, st.st_ctime_ns, st.st_ino)
    if key not in _SCANNER_OK:
        try:
            _SCANNER_OK[key] = _in_hash_time(lambda: _read_program_at(path))
        except (OSError, MemoryError) as e:   # Claude review 2 (1): by errno; only memory or fd pressure is "unreadable"
            return None, _problem_of(e)
    digest, venv = _SCANNER_OK[key]
    problem = _digest_problem(name, digest)
    if problem:
        return None, problem
    if venv and not trusted_interpreter(venv):
        return None, _interpreter_problem()
    return path, None


def _interpreter_problem():
    """(kind, why) for a venv Python trusted_interpreter refused: "unreadable" when this computer can't say which Python
    Watchtower runs (no /proc; Claude review 1, finding 4), else "changed"."""
    if running_interpreter() is None:
        return "unreadable", "this computer doesn't say which Python ISR Bot runs with (/proc/self/exe)"
    return "changed", "the Python it runs with isn't the computer's own"


def _refuse(name, kind, why):
    """A program in the scanner folder that may not run right now: remembered for the rest of this run (so swapping the
    checked copy back afterwards hides nothing), its stage marked not checked, and nothing is started."""
    SCANNER_PROBLEMS[name] = (kind, why, "launch")
    SCANNERS_HELD.add(name)
    STAGE_FAILS.append(f"{SCANNER_NAMES.get(name, name)} NOT run: {why}")
    raise ScannerUnusable(why)


def scanner_launch(cmd, deadline=None):
    """How run() starts cmd when cmd[0] is in Watchtower's scanner folder: (argv, executable, fds), else None for any other
    program. The program is checked again at launch from a sealed copy of its bytes and run from that copy; a venv Python
    (an entry point's first line, or scanners/bin/python itself) is run as the pinned trusted_interpreter, never through the
    link, which keeps only its name as argv[0] so the venv is found. Raises ScannerUnusable when it may not run, and
    LaunchTimedOut when run()'s deadline passes while it waits for another launch or its copy is made."""
    if not cmd or not isinstance(cmd[0], str):
        return None
    p = os.path.normpath(os.path.abspath(cmd[0]))
    if os.path.dirname(p) not in {os.path.normpath(scanner_bin()), os.path.realpath(scanner_bin())}:
        return None
    name = os.path.basename(p)
    if re.fullmatch(r"python[0-9.]*", name):
        interp = trusted_interpreter(p)
        if not interp:
            kind, why = _interpreter_problem()
            _refuse("python", kind, "ISR Bot's scanner Python isn't the computer's own" if kind == "changed" else why)
        return [p, "-I"] + list(cmd[1:]), interp, ()
    try:
        st = os.lstat(p)
    except OSError:
        _refuse(name, None, "it isn't there")
    if not stat.S_ISREG(st.st_mode) or not os.access(p, os.X_OK):
        _refuse(name, "changed", "it isn't a plain program file")
    if not st.st_mode & stat.S_IRUSR:
        _refuse(name, "changed", "its program file can't be read (no read permission)")
    if not _scanner_extra(name) and not _scanner_listed(name):
        _refuse(name, *_digest_problem(name, ""))
    if not _launch_lock(deadline):
        raise LaunchTimedOut()
    no_copy = None
    try:
        fd, digest, venv = _sealed_copy(p, deadline)
    except (SealUnavailable, MemoryError) as e:
        no_copy = _program_error(e)
    except OSError as e:   # Claude review 2 (1): by errno; out of memory or file descriptors is no verdict on the program
        _refuse(name, *_problem_of(e))
    finally:
        _LAUNCH.release()
    if no_copy:
        # Claude review 2 (1): no sealed copy to run from, so nothing runs; the file is still hashed once (no copy) for a verdict
        try:
            digest = _in_hash_time(lambda: _read_program_at(p), deadline=deadline)[0]
        except (OSError, MemoryError) as e:
            _refuse(name, *_problem_of(e))
        _refuse(name, *(_digest_problem(name, digest) or ("unreadable", str(no_copy))))
    problem = _digest_problem(name, digest)
    interp = trusted_interpreter(venv) if venv and not problem else None
    if venv and not problem and not interp:
        problem = _interpreter_problem()
    if problem:
        os.close(fd)
        _refuse(name, *problem)
    if venv:
        return [venv, "-I", f"/proc/self/fd/{fd}"] + list(cmd[1:]), interp, (fd,)
    return [p] + list(cmd[1:]), f"/proc/self/fd/{fd}", (fd,)


def tool(name):
    """Watchtower's own copy of a scanner (scanners/bin/<name>, where install.sh --scanners puts it), only when it is the
    program the lock lists. Never PATH, .venv or the old bin folder. Why one isn't used is kept in SCANNER_PROBLEMS. One that
    was refused at launch this run stays refused for the rest of it, whatever its file holds now. What runs is decided again
    at launch (run(), scanner_launch).

    Claude review 2 (3): only a refusal at launch was kept, so a swapped copy whose stage was skipped, put back before the end
    of the run, read as verified at the last check: no ISR-X005, and it counted as used. A copy found changed now stays changed
    for the rest of the run too, and any scanner with a problem this run is in SCANNERS_HELD (not counted as used)."""
    held = SCANNER_PROBLEMS.get(name, ())
    if len(held) == 3 or held[:1] == ("changed",):
        return None
    path, problem = scanner_verdict(name)
    if problem and problem[0]:
        SCANNER_PROBLEMS[name] = problem
        SCANNERS_HELD.add(name)
    else:
        SCANNER_PROBLEMS.pop(name, None)
    return path


SCANNERS_HELD = set()   # scanners that had a problem at some point this run (found by tool() or refused at launch)


def scanner_used(name):
    """Whether `name` counts as a scanner this run used: Watchtower's checked copy now, with no problem at any point this run.
    b8i1: and its stage didn't fail (TruffleHog that exits before scanning anything didn't run)."""
    return bool(tool(name)) and name not in SCANNERS_HELD and SCANNER_STAGES.get(name) not in STAGE_FAILED


def reset_scanner_checks():
    SCANNER_PROBLEMS.clear()
    SCANNERS_HELD.clear()
    _SCANNER_OK.clear()


def scanner_ran_before(label):
    used = load_json(state_path("engines_used.json"), {}) or {}
    return any(label in (used.get(k) or []) for k in ("expected", "engines")) if isinstance(used, dict) else False


def scanner_unavailable(name):
    """(keep_last_results, plain line) for a scanner tool() didn't return. A copy that isn't the one installed, one not
    listed yet, or one that ran last time and is gone now means "not checked", never "clean"; one that was never installed
    is a plain note, as before. (False, None) means nothing to add beyond the caller's own note."""
    label = SCANNER_NAMES.get(name, name)
    kind, why = SCANNER_PROBLEMS.get(name, (None, ""))[:2]
    ran = scanner_ran_before(label)
    if kind == "changed":
        line = f"{label} NOT run: {why}, so its checks weren't done this time and its last results are kept (ISR-X005)."
    elif kind == "unreadable":   # Claude review 1 (4): not checked, so kept and revet is blocked, but no verdict on the copy
        line = f"{label} NOT run: {why}, so its checks weren't done this time and its last results are kept."
    elif kind == "unlisted":
        line = f"{label} not run: this copy is not listed in ISR Bot's scanner checksums ({why}), so its last results are kept."
    elif kind == "old-folder":
        line = f"{label} is in ISR Bot's old scanner folder; run install.sh --scanners once to move it."
    elif ran:
        line = f"{label} ran last time and is gone now, so its last results are kept. Run install.sh --scanners to put it back."
    else:
        line = None
    return kind in ("changed", "unreadable", "unlisted") or ran, line


def scanner_absent(notes, name, plain):
    keep, line = scanner_unavailable(name)
    if keep:
        fail_note(notes, line)
    elif line or plain:
        notes.append(line or plain)


def engines_blocked():
    """Why SkillSpector and husk can't give a trusted answer this run (either changed, not listed, or gone after it ran), or None."""
    whys = []
    for name in ("skillspector", "husk"):
        if not tool(name):
            keep, line = scanner_unavailable(name)
            if keep:
                whys.append(line)
    return " ".join(whys) or None


# Codex, batch 3 final review: codescan's optional semgrep, refused at launch (exit 126) or changed, still said "semgrep
# found and used too" and raised nothing, because only SCANNER_NAMES could be a ISR-X005. It is X005-eligible too.
X005_OPTIONAL = {"semgrep": "semgrep"}


def scanner_x005():
    """ISR-X005, once per scanner whose copy isn't the one Watchtower installed."""
    out = []
    for name, problem in sorted(SCANNER_PROBLEMS.items()):
        kind, why = problem[:2]
        if kind != "changed" or name not in SCANNER_NAMES and name not in X005_OPTIONAL:
            continue
        label = SCANNER_NAMES.get(name) or X005_OPTIONAL[name]
        put_back = (f"Put it back with `bash {home()}/app/scripts/install.sh --scanners`." if name in SCANNER_NAMES else
                    f"install.sh doesn't install {label}: put back the copy scripts/scanner-bins.lock lists, or remove it from {scanner_bin()}.")
        out.append(finding("ISR-X005", f"ISR Bot's copy of {label} isn't the one it installed", "high", ["ASI04", "AST02"],
                           os.path.join(scanner_bin(), name), why,
                           f"ISR Bot didn't run {label}: its program file isn't the one ISR Bot installed, so its checks weren't "
                           f"done this time and its last results are kept. {put_back} "
                           "If this comes back, something on this computer is changing ISR Bot's files: tell the owner.",
                           source="isr-bot", ident=name))
    return out


def scanner_check():
    """For `isr.py doctor`: what Watchtower makes of each scanner's copy, with the full sha256 to fill the lock from."""
    out = {}
    for name in SCANNER_NAMES:
        path, problem = scanner_verdict(name)
        p = os.path.join(scanner_bin(), name)

        def digest():
            try:
                return scanner_digest(p)
            except OSError:   # too large, too slow to read, a link or not readable (ScannerUnusable included)
                return "unreadable"
        if path:
            out[name] = "verified"
        elif problem[0] == "old-folder":
            out[name] = "in the old folder"
        elif problem[0] == "unlisted":
            out[name] = f"not listed (sha256 {digest()})"
        elif problem[0] == "unreadable":
            out[name] = f"can't be checked now ({problem[1]})"
        elif problem[0] == "changed":
            out[name] = f"not the release's copy (sha256 {digest()})" if os.path.isfile(p) and not os.path.islink(p) else "not the release's copy (not a plain file)"
        else:
            out[name] = "missing"
    return out
