# Part of wt.py: runs inside wt.py's namespace (loaded by _wt_part); not a module on its own.
# ---------------------------------------------------------------- collection
def walk(roots, max_depth=8, errors=None, skipped=None):
    """Every plain file under roots. `errors` (a list) gets each folder the walk couldn't list (batch 5 PR B, Codex round 2, 3:
    the access map then never says there is none). Round 3 (1): `errors` also gets each file it couldn't look at (not one that
    vanished), and `skipped` (a list) each folder it left out: a link to a folder, one past max_depth, one of the folders it never
    scans (SKIP_DIRS, SKIP_PATH_PARTS). Watchtower's own folder is left out too, but not counted: it is Watchtower's, not the Bots'."""
    for root in roots:
        root = os.path.expanduser(root)
        if not os.path.isdir(root):
            continue
        base = root.rstrip("/").count("/")
        for dirpath, dirnames, filenames in os.walk(root, onerror=errors.append if errors is not None else None):
            ap = os.path.abspath(dirpath)
            if any(x in ap + "/" for x in SKIP_PATH_PARTS):
                dirnames[:] = []
                if skipped is not None:
                    skipped.append(ap)
                continue
            if _under(ap, {os.path.abspath(home()), SELF_ROOT}):   # R08: separator-aware; watchtower-customer-skill is not inside
                dirnames[:] = []
                continue
            kept = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith((".venv",) + SKIP_PREFIXES)]
            if dirpath.count("/") - base >= max_depth:
                kept = []
            if skipped is not None:
                skipped += [os.path.join(dirpath, d) for d in dirnames if d not in kept or os.path.islink(os.path.join(dirpath, d))]
            dirnames[:] = kept
            for fn in filenames:
                p = os.path.join(dirpath, fn)
                try:
                    if stat.S_ISREG(os.stat(p).st_mode):
                        yield p
                except FileNotFoundError:
                    continue   # vanished, or a broken link
                except OSError as e:
                    if errors is not None:
                        errors.append(e)
                    continue   # no permission


def is_skill_file(path):
    fn = os.path.basename(path)
    return fn == "SKILL.md" or fn == "plugin.json" or fn == "marketplace.json" or (
        fn.endswith(".json") and ("mcp" in fn.lower())) or "/.grok-plugin/" in path or "/.cursor-plugin/" in path


MCP_CONFIG = re.compile(r"(?i)^(\.?mcp|mcp[_-]?(config|servers|settings)|[\w-]*[_-]mcp[_-]?(config|servers|settings)|claude_desktop_config)\.json$")


def collect_inventory(roots, errors=None, skipped=None):
    inv = {"skills": [], "plugin_files": [], "mcp_configs": [], "non_live_skills": []}
    for p in walk(roots, errors=errors, skipped=skipped):
        fn = os.path.basename(p)
        if fn == "SKILL.md":
            if is_live_skill_path(p):
                inv["skills"].append(p)
            else:
                inv["non_live_skills"].append(p)
        elif MCP_CONFIG.search(fn):
            inv["mcp_configs"].append(p)
        elif fn in ("plugin.json", "marketplace.json") or "/.grok-plugin/" in p or "/.cursor-plugin/" in p:
            inv["plugin_files"].append(p)
    aliases = []
    for k in list(inv):
        seen, out = set(), []
        for p in sorted(set(inv[k])):
            try:
                real = os.path.realpath(p)
            except OSError:
                real = p
            if real not in seen:      # the same file reached through a linked folder is scanned once
                seen.add(real)
                out.append(p)
            elif k != "non_live_skills" and platform_ish(p):
                aliases.append(p)
        inv[k] = out
    # Codex, item 8 review 1 (high 1): the alphabetically first name was kept and a platform name of the same file dropped, so a
    # baselined .agents/skills/x/SKILL.md turned into a link to a new .grok/bundled/skills/x/SKILL.md hid the platform file from
    # the integrity and provenance checks. Only the scanning is done once; every platform name is fingerprinted (audit).
    inv["platform_aliases"] = aliases
    return inv


def skill_dir_files(skill_md):
    d = os.path.dirname(skill_md)
    files = []
    for dirpath, dirnames, filenames in os.walk(d):
        dirnames[:] = [x for x in dirnames if x not in SKIP_DIRS]
        for fn in filenames:
            files.append(os.path.join(dirpath, fn))
    files = sorted(files)
    if len(files) > SKILL_FILE_CAP:   # R07: never silently: the skill is recorded as only partly fingerprinted
        INCOMPLETE_SKILLS[os.path.normpath(d)] = (SKILL_FILE_CAP, len(files))
    return files[:SKILL_FILE_CAP]


SKILL_FILE_CAP = 2000
INCOMPLETE_SKILLS = {}   # skill folder -> (files fingerprinted, files there)


RUN_LIMIT = int(os.environ.get("WT_RUN_LIMIT", "540"))     # seconds a full audit may take, whatever is installed or broken
DAILY_LIMIT = int(os.environ.get("WT_DAILY_LIMIT", "150"))
MAX_BUDGET = 3600   # `audit --budget` tops out at an hour of scanner time
DEADLINE = None                                             # set for the length of one audit


def time_left(default=10 ** 6):
    return default if DEADLINE is None else DEADLINE - time.monotonic()


def run(cmd, timeout=120, cwd=None):
    timeout = max(1, min(timeout, time_left()))
    # Codex, batch 3 round 2: the program gets what is left of its time after the sealed copy was made. Final review: one
    # absolute deadline for the whole launch. Waiting for another launch (_LAUNCH, taken twice), hashing and copying the
    # program, and running it all come out of this one timeout; the lock waits had no limit and the copy had its own
    # (SCANNER_HASH_SECONDS), so a 2-second call could take a minute while the other engine's copy was made.
    deadline = time.monotonic() + timeout
    timed_out = (124, "", f"timed out after {int(timeout)}s")
    try:
        launch = scanner_launch(cmd, deadline)   # batch 3: a program in Watchtower's scanner folder runs only from its checked, sealed copy
    except LaunchTimedOut:
        return timed_out
    except ScannerUnusable as e:
        return 126, "", f"not run: {e}"
    argv, exe, fds = launch or (cmd, None, ())
    try:
        if not _launch_lock(deadline):
            return timed_out
        try:
            if time.monotonic() >= deadline:
                return timed_out
            p = subprocess.Popen(argv, executable=exe, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, cwd=cwd, pass_fds=fds)
        finally:
            _LAUNCH.release()
        with p:
            try:
                out, err = p.communicate(timeout=max(0, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                p.kill()
                p.wait()
                return timed_out
        return p.returncode, out, err
    except OSError as e:
        return 127, "", str(e)
    finally:
        for fd in fds:
            os.close(fd)


CRONTAB_SEEN = {}   # "crontab": what the last persistence_snapshot's `crontab -l` said (crontab_state; batch 5 PR B, Codex round 2, 3)
SYSTEM_CRON = "/etc/cron.d"   # batch 5 PR B, Codex round 3 (5): the access map counts its jobs too (tests point it at their box)


def persistence_snapshot():
    snap = {}
    code, out, err = run(["crontab", "-l"], 10)
    snap["crontab"] = out.strip() if code == 0 else ""
    CRONTAB_SEEN["crontab"] = crontab_state(code, err)
    for d in (SYSTEM_CRON, os.path.expanduser("~/.config/systemd/user")):
        if os.path.isdir(d):
            snap[d] = sorted(os.listdir(d))
    for rc in ("~/.bashrc", "~/.profile", "~/.bash_profile", "~/.zshrc"):
        p = os.path.expanduser(rc)
        if os.path.isfile(p):
            snap[rc] = sha256_file(p)
    return snap


def _sha(text):
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()


def persistence_stored(snap):
    """Codex, batch 4 round 1 (R11): persistence.json keeps the crontab masked for display and its raw text only as a hash,
    which is what the next run compares. An older file holding the raw crontab is compared as it is, then saved this way."""
    out = dict(snap)
    if isinstance(snap.get("crontab"), str):
        out["crontab"], out["crontab_sha256"] = mask_secrets(snap["crontab"]), _sha(snap["crontab"])
    return out


def persistence_changed(old, k, v):
    if k == "crontab" and isinstance(old.get("crontab_sha256"), str) and isinstance(v, str):
        return old["crontab_sha256"] != _sha(v)
    return old.get(k) != v


KNOWN_CRED_FILES = {
    ".claude/.credentials.json": "Claude Code login",
    ".config/gh/hosts.yml": "GitHub CLI login",
    ".aws/credentials": "AWS CLI keys",
    ".netrc": "netrc logins",
    ".git-credentials": "git stored credentials",
    ".docker/config.json": "Docker registry login",
    ".npmrc": "npm token",
    ".config/gcloud/credentials.db": "Google Cloud CLI login",
    ".codex/auth.json": "OpenAI Codex CLI login",
}


def cli_credentials():
    out = []
    for rel, what in KNOWN_CRED_FILES.items():
        p = os.path.join(os.path.expanduser("~"), rel)
        if os.path.isfile(p):
            out.append(finding("WT-S003", f"CLI credential on the shared computer: {what}", "high", ["ASI03", "AST06"], p, what,
                               "Expected if a Bot uses this CLI, but every Bot (and anything injected into one) can use it. "
                               "Keep only the CLIs your Bots need, scope tokens to least privilege, and rotate them; sign out of unused ones."))
    return out


USER_SKILL_DIRS = ("/sand-data/workflows/", "/agent-data/workflows/")


def user_skill_roots():
    """The owner's own skill folders: under their home folder, and under /home/box, where Grok Bot always keeps them."""
    out = []
    for base in (os.path.expanduser("~"), "/home/box"):
        for sub in USER_SKILL_DIRS:
            out.append(os.path.normpath(base + sub))
    return list(dict.fromkeys(out))


def _under(p, roots, strict=False):
    return any((p == r and not strict) or p.startswith(r + os.sep) for r in roots)


def skill_tier(path):
    """user: the user's own saved skills (full rules). Everything else (first-party bundles, marketplace
    plugins, other agents' skill folders, copies sitting in /workspace) gets malicious-indicator rules only.
    Decided by where the path starts (or where it really leads), never by a folder name anywhere in it: v0.6.6 called
    /tmp/x/agent-data/workflows/s one of the owner's own skills, which quarantine and restore then trusted."""
    p = os.path.normpath(os.path.abspath(str(path).split(":")[0]))
    roots = user_skill_roots()
    if _under(p, roots) or _under(os.path.realpath(p), {os.path.realpath(r) for r in roots}):
        return "user"
    return "vendor"


# DQ-022/023/028–030: sample folders outside loadable locations, and real quarantine holding places,
# are not scored as installed skills (never hard-code a checkout path; never match a bare segment name).
SAMPLE_SKILL_PATH = re.compile(
    r"(?i)(^|/)(tests?|__tests__|fixtures?|testdata|examples?|docs|references)(/|$)")
# Shipped by the platform itself, not marketplace plugins (/plugins/, /plugin-cache/ stay fully scored).
# Claude v0.7.1 F3: match realpath prefixes of these roots only — never a segment anywhere in the path.
# The built-in pptx skill on the main box is /home/box/.grok/bundled/skills/pptx (realpath, checked 2026-10-12).
PLATFORM_ROOT_SUBS = (
    ".grok/bundled",
    "sand-data/managed-skills",
    "agent-data/managed-skills",
    ".codex/skills/.system",
    ".claude/plugins/synced",
)
VENDOR_TEMPLATE_PATH = re.compile(r"(?i)/(templates|examples)/")
BOX_HOME = "/home/box"   # where Grok Bot keeps its folders; the platform rules check it beside the home folder (tests point it at their box)


def home_bases():
    """The home folders the platform rules check: the home folder, and BOX_HOME when that isn't it. One may sit inside the other."""
    return dict.fromkeys((os.path.expanduser("~"), BOX_HOME))


def platform_roots():
    """The platform's real skill folders under the home folder(s)."""
    out = []
    for base in home_bases():
        for sub in PLATFORM_ROOT_SUBS:
            out.append(os.path.normpath(os.path.join(base, sub)))
    return list(dict.fromkeys(out))


def under_platform_root(path):
    """True only when the path really sits under a platform root (realpath prefix). A user skill whose folder is
    named like a platform folder (e.g. workflows/managed-skills) is never platform (Claude v0.7.1 F3)."""
    p = os.path.normpath(os.path.abspath(str(path).split(":")[0]))
    try:
        pr = os.path.realpath(p)
    except OSError:
        pr = p
    uroots = user_skill_roots()
    try:
        ruroots = {os.path.realpath(r) for r in uroots}
    except OSError:
        ruroots = set(uroots)
    if _under(p, uroots) or _under(pr, ruroots):
        return False
    proots = platform_roots()
    rproots = set()
    for r in proots:
        try:
            rproots.add(os.path.realpath(r))
        except OSError:
            rproots.add(r)
    return _under(p, set(proots)) or _under(pr, rproots)


def _path_part(where, line=True):
    """A path finding's file or folder with only a trailing ":line" (or ":line:col") dropped. A colon inside a folder name
    stays: splitting at the first colon read ~/.grok/bundled/skills:escape/learn as ~/.grok/bundled/skills (Codex, DQ-042).
    line=False keeps the path verbatim: a folder (X003's where) has no line, so skills/learn:3 is skills/learn:3 (Codex, round 2)."""
    return os.path.normpath(os.path.abspath(re.sub(r"(:\d+)+$", "", str(where)) if line else str(where)))


def platform_skill_path(path, line=True):
    """Stricter than under_platform_root (DQ-042): the path as written AND where it really leads both sit inside a platform root,
    and neither is a user root. ~/.grok/bundled-evil, a link in a platform folder that leads out (a folder named skills:escape
    or skills/learn:3 included), and a link elsewhere that leads in are never platform. When a trailing ":3" may be a line or part
    of the name, both readings must be platform (Codex, DQ-042 round 2: when in doubt, never platform)."""
    try:
        rproots = {os.path.realpath(r) for r in platform_roots()}
        uroots = user_skill_roots()
        ruroots = {os.path.realpath(r) for r in uroots}
        for p in {_path_part(path, line=False), _path_part(path, line=line)}:
            pr = os.path.realpath(p)
            if _under(p, uroots) or _under(pr, ruroots):
                return False
            if not (_under(p, set(platform_roots()), strict=True) and _under(pr, rproots, strict=True)):
                return False
    except OSError:
        return False
    return True


# Item 8 (R3), ported from harden/item8-wip: wherever a check lowers scrutiny (built-in, vendor rules, a key's severity), a path
# is vendor only when it really sits inside one of these folders under the home folder(s). builtin() and is_vendor() matched
# /plugins/, /managed-skills/ and the like anywhere in the path, so the owner's own skill under workflows/x/managed-skills/ had
# its high "changed" alert rolled away as a built-in update. What is scanned (is_loadable_skill_location), which plugin.json is a
# plugin (note_plugins), the hook check and the cleanup exclusions stay broad on purpose: those add coverage.
VENDOR_ROOT_SUBS = PLATFORM_ROOT_SUBS + ("sand-data/plugins", "agent-data/plugins", ".agents/skills", ".codex/skills", ".claude/plugins")


def vendor_roots():
    return list(dict.fromkeys(os.path.normpath(os.path.join(base, sub)) for base in dict.fromkeys((os.path.expanduser("~"), "/home/box"))
                              for sub in VENDOR_ROOT_SUBS))


def vendor_root_path(where, line=True):
    """Shaped like platform_skill_path: the path as written AND where it really leads are both strictly inside a vendor root,
    neither is a user root, and both readings of a trailing ":3" agree. A lookalike folder, a link that leads out or in, and a
    user folder named plugins are never vendor."""
    if not str(where or "").startswith("/"):
        return False
    try:
        roots = set(vendor_roots())
        rroots = {os.path.realpath(r) for r in roots}
        uroots = user_skill_roots()
        ruroots = {os.path.realpath(r) for r in uroots}
        for p in {_path_part(where, line=False), _path_part(where, line=line)}:
            pr = os.path.realpath(p)
            if _under(p, uroots) or _under(pr, ruroots):
                return False
            if not (_under(p, roots, strict=True) and _under(pr, rroots, strict=True)):
                return False
    except OSError:
        return False
    return True


def is_platform_config(where):
    """Grok Bot's own config file (PLATFORM_FILES), at exactly that place under the home folder(s); a project folder named
    sand-data is not Grok Bot's config. A finding at line 1 of a file literally named gateway.json:3 reads gateway.json:3:1:
    only a trailing :line or :line:col may be dropped, and only when no shorter reading names a file that is on disk."""
    return _exactly_at(where, platform_config_places())


def platform_config_places():
    return {os.path.normpath(base + pf) for base in dict.fromkeys((os.path.expanduser("~"), "/home/box")) for pf in PLATFORM_FILES}


def literal_path(f):
    """The file a finding is about, exactly as its producer recorded it (finding(path=...)), or None for one that didn't."""
    p = f.get("path") if isinstance(f, dict) else None
    return os.path.normpath(p) if isinstance(p, str) and p.startswith("/") else None


def platform_config_finding(f):
    """is_platform_config for a finding. Read from the where alone, gateway.json:3:1 (line 1 of a file named gateway.json:3)
    became the config again once that file was renamed or deleted. A finding whose producer recorded its file is judged by that
    file only; one that didn't (older runs) by its where."""
    p = literal_path(f)
    if p:
        return p in platform_config_places()
    return is_platform_config(f.get("where", "") if isinstance(f, dict) else f)


def _exactly_at(where, places):
    """True when a finding's where is one of these files, with at most a trailing :line or :line:col after it, and no shorter
    reading of it names some other file on disk (a file named gateway.json:3 is not gateway.json)."""
    w = str(where or "")
    if not w.startswith("/"):
        return False
    for _ in range(3):
        p = os.path.normpath(w)
        if p in places:
            return True
        if os.path.lexists(p):   # a file by this exact name is what the finding may be about
            return False
        m = re.fullmatch(r"(.*):\d+", w)
        if not m:
            return False
        w = m.group(1)
    return False
