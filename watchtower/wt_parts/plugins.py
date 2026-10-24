# Part of wt.py: runs inside wt.py's namespace (loaded by _wt_part); not a module on its own.
def norm_body(t):
    t = re.sub(r"(?s)\A---\n.*?\n---\n", "", t or "")
    return re.sub(r"\s+", " ", t).strip()


# v0.7.4 (display rename): a getting-started copy saved earlier says "You are Watchtower", and a brief saved earlier names the
# update Watchtower; both still count
GETTING_STARTED_MARKERS = ("You are ISR Bot", "You are Watchtower")
UPDATE_NAMES = ("isr bot", "watchtower")


def saved_skill_notes(notes):
    """The template's first-run skill is the owner's saved `getting-started` skill, and an update doesn't refresh it. After
    v0.6.6 moved the decoys, the saved copy on the main computer still named the old places. Say so when it differs."""
    app = read_text(os.path.join(SELF_ROOT, "bot", "getting-started.md"))
    if not app:
        return
    seen = set()
    for root in [os.path.normpath(os.path.expanduser("~") + sub) for sub in USER_SKILL_DIRS]:   # this home folder only
        p = os.path.join(root, "getting-started", "SKILL.md")
        rp = os.path.realpath(p)
        if rp in seen or not os.path.isfile(p):
            continue
        seen.add(rp)
        saved = read_text(p) or ""
        if not any(x in saved for x in GETTING_STARTED_MARKERS) or norm_body(saved) == norm_body(app):
            continue
        old = [x for x in OLD_CANARY_PATHS + PUBLISHED_CANARY_PATHS if x in saved]
        msg = (f"Your saved getting-started skill ({short_path(p)}) is older than this ISR Bot"
               + (f": it still names the old decoy places ({', '.join(old)})" if old else "")
               + ". A template made from this Bot would ship it. Re-save it from /workspace/watchtower/app/bot/getting-started.md.")
        if msg not in notes:                   # the check can run twice in one audit; say it once
            notes.append(msg)


def update_notes(notes):
    """Tell the owner a newer Watchtower is out. Only tells: nothing here installs or updates anything."""
    b = load_json(state_path("last_brief.json"), {}) or {}
    upd = [u for u in b.get("updates", []) if any(n in u.get("name", "").lower() for n in UPDATE_NAMES)]
    if upd:
        u = upd[0]
        notes.append(f"A newer ISR Bot is out ({u.get('have')} → {u.get('latest')}" + (f", commit {u['commit'][:12]}" if u.get("commit") else "")
                     + "). Tell ISR Bot \"update yourself\" when you want it.")
    moved = b.get("watchtower_tag_moved")
    if moved:
        notes.append(f"The {moved.get('tag')} tag on GitHub now points at commit {str(moved.get('now'))[:12]}, not {str(moved.get('installed'))[:12]}, "
                     "the one installed here. A published tag should never move: don't update from it until you know why.")


def find_key(obj, keys):
    if isinstance(obj, dict):
        for k in keys:
            if k in obj and isinstance(obj[k], (int, float)):
                return obj[k]
        for v in obj.values():
            r = find_key(v, keys)
            if r is not None:
                return r
    elif isinstance(obj, list):
        for v in obj:
            r = find_key(v, keys)
            if r is not None:
                return r
    return None


# Batch 6 (B8): an MCP server a package launcher fetches and runs is pinned only by an exact version of that package. npx, uvx,
# bunx, `pnpm dlx` and `npm exec` alike (also behind /usr/bin/env); "@latest", a range and a dist-tag can each change what runs.
# Read from the command and args of every object in the file that has a "command" (mcpServers, servers, …); a JSONC file is
# read as JSON with its comments and trailing commas blanked (round 2, H8). The old "an @ within 200 characters" test let `npx -y @scope/pkg` (or an email nearby) pass as pinned.
# PR3, Codex round 1 (12-14): each launcher's options are read with their arity (a value option takes the next word, a switch
# doesn't), before and after its subcommand (`npm --yes exec`, `pnpm --silent dlx`) and behind env's own options (`env -u X`);
# every package it fetches is checked (each --package, uvx's --from and --with), and an option it doesn't know, a shell string
# (-c), or a launcher word it can't place is "couldn't read the launch": a finding, never a pass. One pass over the words (an
# index, no copies), every server in the file (no cap).
# Codex round 2 (H7): only the options in these tables are read, each exactly as written. Anything else is "couldn't read the
# launch", --name=value and --no-name forms included: npm takes any unambiguous abbreviation (`--c="npx mutable"` is --call), so
# an option it doesn't list is never one word of no consequence. Options that point the launcher at other configuration or code
# (npm's --userconfig, --node-options, --script-shell; uvx's --config-file, --directory, --project) are not read either.
MCP_LAUNCHERS = {"npx": None, "uvx": None, "bunx": None, "pnpm": frozenset(("dlx",)), "npm": frozenset(("exec", "exe", "x"))}
_NPM_SWITCHES = frozenset(("-y", "--yes", "-n", "--no", "-q", "--quiet", "-s", "--silent", "-d", "--verbose", "--offline", "--prefer-offline",
                           "--prefer-online", "--ignore-scripts", "--workspaces", "-ws", "--include-workspace-root", "-g", "--global"))
_NPM_VALUES = frozenset(("--registry", "--loglevel", "--cache", "--prefix", "--workspace", "-w"))
MCP_OPTIONS = {   # launcher: (switches, options with a value, options whose value is a package it fetches, options it can't read)
    "npx": (_NPM_SWITCHES, _NPM_VALUES, frozenset(("-p", "--package")), frozenset(("-c", "--call"))),
    "npm": (_NPM_SWITCHES, _NPM_VALUES, frozenset(("-p", "--package")), frozenset(("-c", "--call"))),
    "pnpm": (frozenset(("-s", "--silent", "-r", "--recursive", "-w", "--workspace-root", "--verbose")),
             frozenset(("--dir", "-C", "--filter", "-F", "--reporter", "--loglevel", "--allow-build")), frozenset(("--package",)),
             frozenset(("-c", "--shell-mode"))),
    "bunx": (frozenset(("--bun", "--silent", "--verbose", "--no-install")), frozenset(()), frozenset(("-p", "--package")), frozenset(())),
    "uvx": (frozenset(("-q", "--quiet", "-v", "--verbose", "--offline", "--isolated", "--refresh", "--no-cache", "-n", "--native-tls",
                       "--reinstall", "--no-config", "--no-progress")),
            frozenset(("-p", "--python", "--index", "--index-url", "--default-index", "--extra-index-url", "--cache-dir",
                       "--python-preference", "--refresh-package", "--color")),
            frozenset(("--from", "--with")), frozenset(("--with-requirements", "--with-editable", "--constraints", "--overrides"))),
}
_ENV_SWITCHES = frozenset(("-i", "--ignore-environment", "-0", "--null", "-v", "--debug", "-"))
_ENV_VALUES = frozenset(("-u", "--unset", "-C", "--chdir", "-P"))
_NPM_EXACT = re.compile(r"(?:@[A-Za-z0-9._~-]+/)?[A-Za-z0-9._~-]+@v?\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.+-]*)?")
_PY_EXACT = re.compile(r"[A-Za-z0-9._-]+(?:\[[^\]]*\])?(?:===?|@)v?\d[0-9A-Za-z.+-]*")
_NPM_RANGE = re.compile(r"[\^~<>=*| ]|^[\dxX*]+(?:\.[\dxX*]+){0,2}$")
_JSON_STR = r'"((?:[^"\\\n]|\\.)*)"'


def _launcher_name(word):
    """A command word's program name: its base name after a / or a \\ (batch 7c: C:\\tools\\npx.cmd too), lower case, without a
    Windows .cmd/.exe/.bat/.ps1 (npx.cmd is npx)."""
    b = os.path.basename(word.replace("\\", "/")).lower()
    return re.sub(r"\.(cmd|exe|bat|ps1)$", "", b)


def _mcp_options(w, i, name, fetched):
    """Read launcher `name`'s options from w[i]: (index of the first word that isn't one, None) or (i, the option it couldn't
    read). `fetched` (a list) gets (option, package) for each option whose value is a package it fetches."""
    switches, values, pkgs, unread = MCP_OPTIONS[name]
    n = len(w)
    while i < n and w[i].startswith("-") and w[i] not in ("-", "--"):
        x = w[i]
        opt, eq, val = x.partition("=") if x.startswith("--") else (x, "", "")
        if opt in unread:
            return i, x   # a shell string or a requirements file: what it runs isn't in the words
        if opt in pkgs or opt in values:
            if not eq:
                if i + 1 >= n:
                    return i, x   # its value is missing
                val, i = w[i + 1], i + 1
            if opt in pkgs:
                fetched.append((opt, val))
            i += 1
        elif opt in switches and not eq:
            i += 1   # a switch it knows, as written
        else:
            return i, x   # an option it doesn't know (an abbreviation, an alias, --name=value, --no-name): unknown is never safe
    return i, None


# Batch 7c (KNOWN-LIMITS 8, Codex round 4 high): a wrapper never hides what it runs. env, timeout and nice are read with their
# options exactly as written (any other option, or a value that isn't a signal, a duration or a niceness, is "couldn't read the
# launch"), in any order, at the top and in a launch, and the command after them is read as if it stood alone. A shell (the ones
# in _SHELLS) is never read, -c or not, wherever it is the command. Other wrappers (nohup, sudo, xargs, …) are not read: a launcher,
# shell or wrapper name among their words, a $ or a ` (an expansion), or xargs's argument file is "couldn't read the launch".
# Names among a command's words are seen with quotes and backslashes taken out and the words split at shell punctuation
# (`"npx"`, `n\px`, `C:\tools\npx.cmd`, `x;npx`). A package's own command is never unwrapped: `npx -y nice@1.0.0 …` runs the
# npm package nice, not GNU nice, so any word it gets is "couldn't read the launch". Unwrapping never clears a launch it couldn't
# read before: npm or pnpm without a launch subcommand behind a wrapper (`timeout 30 npm install`) stays one.
_SHELLS = frozenset(("sh", "bash", "rbash", "dash", "zsh", "ksh", "ksh93", "mksh", "lksh", "oksh", "pdksh", "ash", "yash", "posh",
                     "busybox", "csh", "tcsh", "fish", "cmd", "powershell", "pwsh", "wsl"))
_WRAPPERS = frozenset(("env", "timeout", "nice"))
_OTHER_WRAPPERS = frozenset(("nohup", "setsid", "stdbuf", "sudo", "doas", "su", "runuser", "sg", "xargs", "chrt", "ionice", "taskset",
                             "numactl", "nsenter", "unshare", "chroot", "setpriv", "prlimit", "flock", "watch", "time", "caffeinate",
                             "systemd-run", "firejail", "bwrap", "strace", "ltrace", "valgrind", "unbuffer", "script", "faketime",
                             "fakeroot", "eatmydata", "nocache", "trickle", "proxychains", "proxychains4", "torsocks", "tini", "dumb-init",
                             "gosu", "su-exec", "chpst", "setuidgid", "s6-setuidgid", "xvfb-run", "dbus-run-session", "setarch"))
_TIMEOUT_SWITCHES = frozenset(("--preserve-status", "--foreground", "-v", "--verbose"))
_SIGNAL = re.compile(r"(?:SIG)?(?:HUP|INT|QUIT|ILL|TRAP|ABRT|IOT|BUS|FPE|KILL|USR1|SEGV|USR2|PIPE|ALRM|TERM|STKFLT|CHLD|CLD|CONT|STOP|"
                     r"TSTP|TTIN|TTOU|URG|XCPU|XFSZ|VTALRM|PROF|WINCH|IO|POLL|PWR|SYS|RTMIN(?:\+\d+)?|RTMAX(?:-\d+)?)|\d+")
_DURATION = re.compile(r"(?:\d+(?:\.\d*)?|\.\d+)[smhd]?")
_NICENESS = re.compile(r"[+-]?\d+")
_SCAN_SPLIT = re.compile(r"[\s;&|()<>`$={},]+")
# Batch 7c fix round (Codex round 1 high): a command word is script text when a shell would read it as more than a program
# name: whitespace, a quote or other shell syntax (cmd.exe's % and ^ too), or a backslash whose escape names a launcher, shell
# or wrapper (n\px; C:\tools\npx.cmd is a Windows path). npm exec hands its command word to a shell as written.
_SCRIPT_SYNTAX = re.compile(r"[\s'\"`;&|$<>(){}\[\]*?!#%^]")
# Batch 7d: the host fills in a ${NAME} placeholder in an MCP command field before launch, with no shell; one at the start of
# a word, then a path, is that path. Any other $ (bare $HOME, $(…), ${A}${B}, ${A:-x}, one mid-word) stays script text.
_HOST_PLACEHOLDER = re.compile(r"\$\{[A-Za-z_][A-Za-z0-9_]*\}(?=[/\\])")


def _script_text(word, host=True):
    """True when `word`, in command position, is script text (_SCRIPT_SYNTAX), not one program's name. Batch 7d: a blank word
    is too (npm runs its shell in place of an empty command); with `host`, one leading host placeholder (_HOST_PLACEHOLDER)
    followed by a path whose last part names a program is read as that path (the rest of the word is checked as before)."""
    if not word.strip():
        return True
    m = _HOST_PLACEHOLDER.match(word) if host else None
    if m and _launcher_name(word):
        word = word[m.end():]
    if _SCRIPT_SYNTAX.search(word):
        return True
    if "\\" in word:
        bare = _launcher_name(word.replace("\\", ""))
        return bare != _launcher_name(word) and bare in _COMMAND_NAMES
    return False


def _unwrap(w, i, text=None):
    """Read the wrappers env, timeout and nice in front of w[i:], each with its options exactly as written: (the index of the
    command after them, None, None), or (i, the wrapper, the word it couldn't read). Every step reads at least one word.
    `text` (a list) gets the first command-position word that is script text (each wrapper's name and the command's)."""
    n = len(w)
    while i < n:
        if text is not None and not text and _script_text(w[i]):
            text.append(w[i])
        name = _launcher_name(w[i])
        i += 1
        if name == "env":   # /usr/bin/env [options] [VAR=value …] npx …
            opts = True
            while i < n:
                x = w[i]
                if opts and x == "--":
                    opts, i = False, i + 1
                elif opts and (x in _ENV_SWITCHES or re.fullmatch(r"-[i0v]+", x)):
                    i += 1
                elif opts and x in _ENV_VALUES:
                    i += 2
                elif opts and (x.startswith(("--unset=", "--chdir=")) or (x[:2] in _ENV_VALUES and len(x) > 2)):
                    i += 1
                elif opts and x.startswith("-"):
                    return i, "env", x   # -S splits a string into more words; any other option: not read
                elif "=" in x:
                    i += 1   # VAR=value
                else:
                    break
        elif name == "timeout":   # GNU and busybox: [options] DURATION command …; the options end at the first word that isn't one
            while i < n and w[i].startswith("-") and w[i] != "-":
                x = w[i]
                if x == "--":
                    i += 1
                    break
                if x in _TIMEOUT_SWITCHES:
                    i += 1
                    continue
                if x in ("-s", "--signal", "-k", "--kill-after"):
                    if i + 1 >= n:
                        return i, "timeout", x   # its value is missing
                    val, step = w[i + 1], 2
                elif x.startswith(("--signal=", "--kill-after=")):
                    val, step = x.partition("=")[2], 1
                elif x[:2] in ("-s", "-k"):
                    val, step = x[2:], 1
                else:
                    return i, "timeout", x   # an abbreviation, a cluster (-vk5), any other option: not read
                if not (_SIGNAL if x.startswith(("-s", "--signal")) else _DURATION).fullmatch(val):
                    return i, "timeout", x
                i += step
            if i >= n:
                return i, "timeout", "(no duration)"
            if not _DURATION.fullmatch(w[i]):
                return i, "timeout", w[i]
            i += 1
        elif name == "nice":   # GNU and busybox: [-n N | --adjustment=N | -N] [command …]
            while i < n and w[i].startswith("-") and w[i] != "-":
                x = w[i]
                if x == "--":
                    i += 1
                    break
                if re.fullmatch(r"-[+-]?\d+", x):
                    i += 1   # the old -N form
                elif x in ("-n", "--adjustment"):
                    if i + 1 >= n or not _NICENESS.fullmatch(w[i + 1]):
                        return i, "nice", x
                    i += 2
                elif x.startswith("--adjustment=") or (x.startswith("-n") and not x.startswith("--")):
                    if not _NICENESS.fullmatch(x.partition("=")[2] if x.startswith("--") else x[2:]):
                        return i, "nice", x
                    i += 1
                else:
                    return i, "nice", x
        else:
            return i - 1, None, None
    return i, None, None


def _scan_names(word):
    """The program name of each piece of `word` with its quotes taken out, split at shell punctuation: once with its backslashes
    taken out (\\npx, n\\px), once with them kept as path separators (C:\\tools\\npx.cmd). Linear in the word."""
    s = word.replace('"', "").replace("'", "")
    for t in _SCAN_SPLIT.split(s.replace("\\", "")):
        yield _launcher_name(t)
    if "\\" in s:
        for t in _SCAN_SPLIT.split(s):
            yield _launcher_name(t)


def mcp_package(w, i=0, nested=False, own=False, text=None):
    """(launcher, [the packages it fetches], why it couldn't read the launch or None, what it runs) when the words w[i:] (a
    server's command and args, strings) run a package launcher, or a launch it couldn't read; else None. Its packages are the
    values of each --package (uvx: --from and --with), or else the first word after its options; the wrappers in front (_unwrap)
    and npm's and pnpm's options before their subcommand are read with their arity. Any doubt is a reason it couldn't read the
    launch, never a pinned launch. What it runs (round 3, H8): (the index of the command word, whether that word is a package
    spec), or None. `nested`: w[i:] is what a launch runs; `own`: w[i] is a package's own command (batch 7c: never unwrapped).
    `text` (a list) gets the first command-position word that is script text (batch 7c fix round); the result is as without it."""
    n, start = len(w), i
    if not own:
        i, wrapper, bad = _unwrap(w, i, text)
        if wrapper is not None:
            return wrapper, [], bad, None
    if i >= n:
        return None
    if own and text is not None and not text and _script_text(w[i]):
        text.append(w[i])
    name, wrapped = _launcher_name(w[i]), i > start
    if name in _SHELLS:   # batch 7c: a shell is never read, -c or not
        return name, [], " ".join(w[i:i + 3]), None
    if own and name in _WRAPPERS:   # npx -y nice@1.0.0 …: the npm package nice; what it does with its words isn't read
        return (name, [], w[i + 1], None) if i + 1 < n else None
    if nested and name in _NESTED_UNREAD:   # yarn, pipx, …: what they run isn't read
        return name, [], w[i], None
    if name not in MCP_LAUNCHERS:   # a launcher or shell word further on (node run.js "npx …"): a launch it can't read
        names = _IN_LAUNCH_WORDS if nested else _TOP_WORDS
        other = name in _OTHER_WRAPPERS   # and among another wrapper's words: a wrapper name, an expansion, an argument file
        if other:
            names = names | _WRAPPER_WORDS
        for j in range(i + 1, n):
            x = w[j]
            argfile = name == "xargs" and (x.startswith("--a") or (x[:1] == "-" and x[1:2] != "-" and "a" in x))   # -a, -0a, --arg-file
            if (other and ("$" in x or "`" in x or argfile)) or any(t in names for t in _scan_names(x)):
                return name, [], x, None
        return None
    label, fetched = name, []
    i += 1
    if MCP_LAUNCHERS[name] is not None:   # npm, pnpm: their own options, then the subcommand
        i, bad = _mcp_options(w, i, name, fetched)
        if bad is not None:
            return label, [], bad, None
        if i >= n or w[i] not in MCP_LAUNCHERS[name]:
            # npm run, pnpm install: not a launch of a fetched package; in a launch or behind a wrapper, what it runs isn't read
            return (name, [], name, None) if nested or wrapped else None
        label = "npm exec" if name == "npm" else f"{name} {w[i]}"
        i += 1
    i, bad = _mcp_options(w, i, name, fetched)
    dashes = bad is None and i < n and w[i] == "--"
    i += dashes
    first = w[i] if bad is None and i < n else ""
    pkgs = [v for o, v in fetched if o != "--from"] if name == "uvx" else [v for o, v in fetched]
    froms = [v for o, v in fetched if o == "--from"]
    spec = not (froms if name == "uvx" else pkgs)   # the first word is the package itself (else a command of the packages)
    if name == "uvx":
        pkgs += froms or ([first] if bad is None else [])   # with --from, the first word is the command it runs
    elif not pkgs and bad is None:
        pkgs = [first]   # with --package, the first word is a command of those packages
    if name == "npm" and bad is None and not dashes:   # npm reads its options after the command's name too (npx doesn't)
        # round 2 (H7): every one of them; only a switch it knows, as written, is not a reason
        import itertools
        bad = next((x for x in itertools.takewhile(lambda y: y != "--", w[i + 1:])
                    if x.startswith("-") and x != "-" and x not in MCP_OPTIONS["npm"][0]), None)
    return label, pkgs, bad, ((i, spec) if bad is None and i < n else None)   # batch 7d: an empty command word is read too


# PR3, Codex round 3 (H8): a pinned outer package never vouches for what it runs. `npm exec --package=npm@11.21.0 -- npx -y
# mutable` runs npx, which fetches mutable; `npx -y npm@11.21.0 exec mutable` runs npm exec. The command after the package
# options (or the package's own command) is read again: a launcher or env as a launch of its own; yarn, pipx, uv, bun, deno or
# a shell (what it runs isn't read), npm or pnpm without a launch subcommand, or a launcher word among a command's arguments,
# as "couldn't read the launch". A chain of nested launchers is read 16 deep, then is "couldn't read the launch" too.
# Batch 7c: all of that is mcp_package's now (nested=True), behind any wrappers; the shells moved to _SHELLS. Wrappers don't count
# toward the 16.
_NESTED_UNREAD = frozenset(("yarn", "pipx", "pnpx", "uv", "bun", "deno"))
_NESTED_WORDS = frozenset(MCP_LAUNCHERS) | _NESTED_UNREAD
_TOP_WORDS = frozenset(MCP_LAUNCHERS) | _SHELLS   # the names looked for among a command's words, at the top and in a launch
_IN_LAUNCH_WORDS = _NESTED_WORDS | _SHELLS
_WRAPPER_WORDS = _WRAPPERS | _OTHER_WRAPPERS   # and among another wrapper's words
_COMMAND_NAMES = _IN_LAUNCH_WORDS | _WRAPPER_WORDS   # a name a backslash escape mustn't hide in command position (_script_text)
_NESTING = 16


def mcp_launches(words):
    """[(launcher, [the packages it fetches], why it couldn't read the launch or None)] for a server's command and args: the
    launch (mcp_package) and each launch nested in what it runs (round 3, H8), outermost first; [] when it isn't a launch.
    Batch 7c fix round: script text in command position, at the top, after wrappers, after a launcher's -- or in a launch, is
    also "couldn't read the launch" (labelled with the launch that runs it, or "(command)" at the top), in front of whatever
    that level read before, so no finding is lost. Batch 7d: npx and npm exec hand the command word they run to a shell as
    written, so there a host placeholder counts as script text too (what it is filled in with is read by the shell); a launch
    with a blank name is labelled with the launch that runs it."""
    w = [x for x in words if isinstance(x, str)]
    out, i, nested, own, shell = [], 0, False, False, False
    for _ in range(_NESTING):
        text = [w[i]] if shell and i < len(w) and _script_text(w[i], host=False) else []
        got = mcp_package(w, i, nested, own, text)
        if text:
            out.append((out[-1][0] if out else "(command)", [], text[0]))
        if got is None:
            return out
        label, pkgs, bad, run = got
        out.append((label if label.strip() else out[-1][0] if out else "(command)", pkgs, bad))
        if run is None:
            return out
        i, own = run
        shell = label in ("npx", "npm exec")
        if own:   # the package's own command (npx@10.0.0 runs npx), read by its name
            w, i = [_launcher_name(re.split(r"(?<=.)[@=<>~!\[]", w[i], maxsplit=1)[0])] + w[i + 1:], 0
        nested = True
    out.append((out[-1][0], [], "(launchers nested over %d deep)" % _NESTING))
    return out


def mcp_pin_problem(launcher, spec):
    """Why `spec` isn't an exact version for this launcher ("no version", "@latest", "range …", "tag …"), or None when it is."""
    s = spec.strip()
    if launcher == "uvx":
        if _PY_EXACT.fullmatch(s):
            return None
        m = re.search(r"(===?|~=|!=|>=|<=|[<>@])", s)
        return "no version" if not m else "@latest" if s.endswith("@latest") else "range " + s[m.start():][:40]
    if _NPM_EXACT.fullmatch(s):
        return None
    at = s.find("@", 1)
    if at == -1:
        return "no version"
    v = s[at + 1:]
    if v == "latest":
        return "@latest"
    return ("range " if _NPM_RANGE.search(v) else "tag ") + v[:40]


_JSONC_TOKEN = re.compile(r'"(?:[^"\\\n]|\\.)*"|//[^\n]*|/\*|[,}\]]|[^"/,}\]]+|/')
_JSON_KEY = re.compile(r'"((?:[^"\\\n]|\\.)*)"\s*:')
# Batch 7d: whitespace right after sh's backslash, cmd.exe's ^ or PowerShell's backtick (a line continuation or an escaped
# space) joins what a split at whitespace parts: `n\<newline>px` is npx to a shell, "n\" and "px" to str.split.
_SPLIT_ERASES = re.compile(r"[\\^`]\s")
_COLON_AFTER = re.compile(r"\s*:")


def _json_keys(text):
    """PR3, Codex round 3 (H9): [(offset, body)] of each "…": key in `text`, exactly the matches of _JSON_KEY.finditer, in one
    pass. A string that starts at a quote ends at the first later quote on its line with an even run of backslashes before it
    (escapes pair the same way from any start after a quote), so every start before that quote shares its end, and whether a
    colon follows an end is read once. The regex restarted at every escaped quote and rescanned the line: quadratic."""
    import bisect
    qs = [m.start() for m in re.finditer('"', text)]
    nls = [m.start() for m in re.finditer("\n", text)]
    nxt, after = [None] * len(qs), None
    for k in range(len(qs) - 1, -1, -1):   # nxt[k]: the next quote after quote k that ends a string
        nxt[k] = after
        b = qs[k]
        while b > 0 and text[b - 1] == "\\":
            b -= 1
        if (qs[k] - b) % 2 == 0:
            after = k
    out, last, colon = [], 0, {}
    for k, s in enumerate(qs):
        if s < last or nxt[k] is None:
            continue
        e = qs[nxt[k]]
        if bisect.bisect_left(nls, e) != bisect.bisect_left(nls, s):
            continue   # a line break first: no string starts here
        if e not in colon:
            colon[e] = _COLON_AFTER.match(text, e + 1)
        if colon[e]:
            out.append((s, text[s + 1:e]))
            last = colon[e].end()
    return out


def _jsonc_to_json(text):
    """PR3, Codex round 2 (H8): `text` (JSON with // and /* */ comments and trailing commas) as JSON: each comment and each comma
    before a } or ] blanked to spaces outside strings, line breaks kept, so every offset and line number stays where it was.
    None when a string or a comment never ends. One pass, a token at a time."""
    out, i, n, comma = [], 0, len(text), None
    while i < n:
        m = _JSONC_TOKEN.match(text, i)
        if not m:
            return None   # a string that never ends (or one with a raw line break)
        t = m.group(0)
        if t == "/*":
            j = text.find("*/", i + 2)
            if j == -1:
                return None
            t = re.sub(r"[^\n]", " ", text[i:j + 2])
            i = j + 2
            out.append(t)
            continue
        i = m.end()
        if t.startswith("//"):
            out.append(" " * len(t))
            continue
        if t == ",":
            comma = len(out)
        elif t in ("}", "]"):
            if comma is not None:
                out[comma] = " "   # a trailing comma
            comma = None
        elif t.strip():
            comma = None
        out.append(t)
    return "".join(out)


def _mcp_servers(text):
    """[(the offset of its "command", [command, *args], or None when they couldn't be read)] for each MCP server in `text`.
    PR3, Codex round 2 (H8): a file that isn't JSON is read as JSON once its comments and trailing commas are blanked
    (_jsonc_to_json), so each command and its args come from the same object whatever their order; a file that still isn't
    JSON gives each "command" key None (its args can't be told from another server's)."""
    out = []
    try:
        doc = json.loads(text)
    except (ValueError, RecursionError):
        doc = None
        norm = _jsonc_to_json(text)
        if norm is not None:
            try:
                doc, text = json.loads(norm), norm
            except (ValueError, RecursionError):
                doc = None
        if doc is None:
            for at, key in _json_keys(norm if norm is not None else text):   # round 3 (H9): one pass, the same keys
                if _json_str(key) == "command":
                    out.append((at, None))
            return out
    if isinstance(doc, (dict, list)):
        import collections
        where = collections.defaultdict(collections.deque)   # each "command" value -> its places in the text, in order
        for j, m in enumerate(re.finditer(r'"command"\s*:\s*' + _JSON_STR, text)):
            try:
                where[json.loads('"' + m.group(1) + '"')].append((j, m.start()))
            except ValueError:
                pass
        used, found, stack = 0, [], [doc]
        while stack:   # every object with a "command", in the file's order; all of them (PR3, Codex round 1, 13: no cap)
            x = stack.pop()
            if isinstance(x, dict):
                if isinstance(x.get("command"), str):
                    found.append(x)
                stack += reversed(list(x.values()))
            elif isinstance(x, list):
                stack += reversed(x)
        for cfg in found:
            args = cfg.get("args") if isinstance(cfg.get("args"), list) else []
            q, at = where.get(cfg["command"]), 0
            while q and q[0][0] < used:   # the next "command" in the text with this value
                q.popleft()
            if q:
                j, at = q.popleft()
                used = j + 1
            cmd = cfg["command"]
            head = cmd.split()
            if not head or _SPLIT_ERASES.search(cmd):   # batch 7d: a blank command, or syntax the split would erase: kept whole
                head = [cmd]
            out.append((at, head + [a for a in args if isinstance(a, str)]))
    return out


MCP_NOT_JSON = "(the file isn't JSON)"


def _json_str(s):
    """A JSON string's body decoded (\\u006e is n), or as written when it isn't valid JSON."""
    try:
        return json.loads('"' + s + '"')
    except ValueError:
        return s


def mcp_unpinned(text):
    """[(line, evidence)] for each MCP server in `text` that a package launcher runs without an exact version, one for each
    package it fetches, and one for a launch it couldn't read whole (PR3, Codex round 1, 12)."""
    out, line, pos = [], 1, 0
    for at, words in sorted(_mcp_servers(text), key=lambda x: x[0]):
        got = mcp_launches(words) if words is not None else [("(launch)", [], MCP_NOT_JSON)]   # round 2 (H8): never a pass
        if not got:
            continue
        line += text.count("\n", pos, at)
        pos = at
        for launcher, specs, bad in got:   # round 3 (H8): and each launch nested in what it runs
            for spec in specs:
                why = mcp_pin_problem(launcher.split()[0], spec)
                if why is not None:
                    name = re.split(r"(?<=.)[@=<>~!]", spec, maxsplit=1)[0]
                    out.append((line, f"{launcher} {name or '(no package named)'} ({why})"))
            if bad is not None:
                out.append((line, f"{launcher} (couldn't read the launch at {bad[:40]!r}; treated as unpinned)"))
    return out


PLATFORM_FILES = ("/sand-data/gateway.json", "/agent-data/gateway.json", "/sand-data/teach-queue-key.json", "/agent-data/teach-queue-key.json")   # Grok Bot's own config; the user can't change it


PLUGIN_META_DIRS = (".grok-plugin", ".cursor-plugin", ".claude-plugin", ".codex-plugin", ".plugin")   # one plugin, one folder, whichever app it is packaged for
_PENDING = {"at": None, "roots": ()}


def plugin_identity(plugin_json):
    """(name, folder) for a plugin.json. The name comes from the file, so the same plugin reinstalled under a new
    folder name after a restart, or updated to a new version, is still the same plugin."""
    d = os.path.dirname(plugin_json)
    if os.path.basename(d) in PLUGIN_META_DIRS:
        d = os.path.dirname(d)
    data = load_json(plugin_json, None)
    name = data.get("name") if isinstance(data, dict) and isinstance(data.get("name"), str) else None
    name = name or re.sub(r"([-_@]v?\d[\w.]*)?(-[0-9a-f]{4,})?$", "", os.path.basename(d)) or os.path.basename(d)
    return name[:80], os.path.normpath(d)


def _plugin_version(manifests):
    """DQ-047: "name@version[+...]" from one plugin folder's manifests; None when there are none or one states no version."""
    v = set()
    for p in manifests:
        data = load_json(p, None)
        ver = data.get("version") if isinstance(data, dict) else None
        v.add(f"{plugin_identity(p)[0]}@{ver[:40]}" if isinstance(ver, str) and ver.strip() else None)
    return "+".join(sorted(v)) if v and None not in v else None


def plugin_versions(plugin_files):
    """DQ-047: {plugin folder: "name@version[+...]"} from the plugin's own manifests (every plugin.json the folder holds, as
    plugin_identity finds its folder). A folder whose manifests state no version gets no entry: its files keep path keys only.
    Fix round 1 (Codex): a folder that shares its place and name@version with another on disk (both catalog folders at once, or
    a copy beside the original) gets no entry: not a move.
    Fix round 2 (Codex): the count is taken on disk (each folder in the place, its plugin.json and <meta dir>/plugin.json), not
    from the inventory, which scans a linked manifest once under whichever name sorts first: a sibling whose manifest links to
    the original's, or that is a link to the whole folder, shares the place and gets no entry."""
    found = {}
    for p in plugin_files:
        if os.path.basename(p) != "plugin.json" or not any(x in p for x in ("/plugins/", "/plugin-cache/")):
            continue
        found.setdefault(plugin_identity(p)[1], []).append(p)
    out = {}
    for d, ps in found.items():
        v = _plugin_version(ps)
        if v:
            out[d] = v
    disk = {}
    for place in {os.path.dirname(d) for d in out}:
        try:
            kids = os.listdir(place)
        except OSError:
            kids = []
        for k in kids:
            ms = [m for m in [os.path.join(place, k, "plugin.json")] + [os.path.join(place, k, x, "plugin.json") for x in PLUGIN_META_DIRS]
                  if os.path.isfile(m)]
            v = _plugin_version(ms)
            if v:
                disk[(place, v)] = disk.get((place, v), 0) + 1
    return {d: v for d, v in out.items() if disk.get((os.path.dirname(d), v)) == 1}


def plugin_file_key(rule_id, path, sha, versions):
    """DQ-047: the content key of a file inside a plugin folder: its rule, the place the plugin's folders sit in (the folder above
    the version or catalog-commit folder), the plugin's name and version from its manifests, the file's path inside the plugin
    and its full sha256. The platform moving a plugin to a new catalog-commit folder with the same version and the same bytes
    keeps it; any changed byte, another version or another place does not. None when the file is in no versioned plugin folder."""
    n = os.path.normpath(path)
    root = max((d for d in versions if n.startswith(d + "/")), key=len, default=None)
    if root is None or not sha or sha.startswith("unreadable"):
        return None
    ident = f"{rule_id}|plugin:{os.path.dirname(root)}|{versions[root]}|{os.path.relpath(n, root)}|{sha}"
    return hashlib.sha1(ident.encode()).hexdigest()[:16]


def plugin_place_key(name, roots, files):
    """DQ-047: the key a pending plugin's ISR-I004 is also known by: its name, the place its folders sit in, how many there are
    and the files inside each (`files`: each root's sorted paths relative to it, in root order), not the version folder. A
    version bump with the same files under the same name and place, while it waits for the owner's decision, is the same open
    finding; a file added, removed or renamed is not (fix round 1, Codex)."""
    places = sorted({os.path.dirname(os.path.normpath(r)) for r in roots})
    return hashlib.sha1(f"ISR-I004|plugin:{name}|{'|'.join(places)}|{len(roots)}|{json.dumps(files)}".encode()).hexdigest()[:16]


PLUGIN_MOVES = {}   # DQ-047: this run's pending plugins whose folders changed, {name: (old roots, new roots)}


CATALOG_MARKETS = ("cursor-public", "claude-plugins-official")
CATALOG_WINDOW = 600   # seconds: one sync lands its plugins within minutes of each other


def runs_code(root):
    """A plugin that brings a hook, a script or a locally launched MCP server runs code on this computer."""
    for dp, _, fns in os.walk(root):
        for fn in fns:
            p = os.path.join(dp, fn)
            if fn == "hooks.json" or os.path.splitext(fn)[1].lower() in (".sh", ".py", ".js", ".mjs", ".cjs", ".ts", ".rb", ".pl", ".ps1") \
                    or (os.path.isfile(p) and not os.path.islink(p) and os.access(p, os.X_OK)):
                return True
            if fn == "mcp.json" and re.search(r'"command"\s*:', read_text(p) or ""):
                return True
    return False


def catalog_sync(new_plugins):
    """DQ-017: new plugins that arrived together from the platform's own catalog (same marketplace, same catalog commit, within
    minutes) and run no code here are a catalog sync, not an install. Returns [(market, commit, names)] and marks them known."""
    groups = {}
    for name, roots in new_plugins.items():
        for r in roots:
            m = re.search(r"/plugins/cache/([^/]+)/[^/]+/([^/]+)$", r)
            if m and m.group(1) in CATALOG_MARKETS and not runs_code(r):
                try:
                    groups.setdefault((m.group(1), m.group(2)), []).append((name, os.stat(r).st_mtime))
                except OSError:
                    pass
                break
    out = []
    for (market, commit), items in sorted(groups.items()):
        if len(items) >= 2 and max(t for _, t in items) - min(t for _, t in items) <= CATALOG_WINDOW:
            out.append((market, commit, sorted(n for n, _ in items)))
    if out:
        st = load_json(state_path("plugins.json"), {}) or {}
        for _, _, names in out:
            for n in names:
                if n in st:
                    st[n]["status"] = "catalog"
        save_json(state_path("plugins.json"), st)
    return out


def note_plugins(inv):
    """Remember which plugins are on the computer. The first run records what is there. After that, a plugin name not
    seen before is new: the owner (or a template they said yes to) added it, and nothing vetted it first."""
    here, manifests = {}, {}
    for p in inv["plugin_files"]:
        if os.path.basename(p) == "plugin.json" and any(x in p for x in ("/plugins/", "/plugin-cache/")):
            name, d = plugin_identity(p)
            here.setdefault(name, []).append(d)
            manifests.setdefault(name, []).append(p)
    st = load_json(state_path("plugins.json"), None)
    first = not isinstance(st, dict)
    st = {} if first else st
    # Updating from a version that kept no list of plugins: "what is there" is not all known. A plugin that wasn't on the
    # computer when the owner's baseline was taken was added since, and nobody has been told about it yet.
    base = load_baseline()[0] if first else {}
    base_hashes = set(base.values())
    in_baseline = lambda name: not base or any(p in base or sha256_file(p) in base_hashes for p in manifests[name])
    PLUGIN_MOVES.clear()
    for name, roots in here.items():
        was = st.get(name, {}).get("roots") if isinstance(st.get(name), dict) else None
        if was and st[name].get("status") == "new" and sorted(set(roots)) != was:
            PLUGIN_MOVES[name] = (was, sorted(set(roots)))
        if name not in st:
            st[name] = {"since": now(), "status": "known" if first and in_baseline(name) else "new"}
            # Already there on Watchtower's first run, inside the platform's catalog cache, and runs no code: the catalog's, as a
            # catalog sync would have filed it. One that runs code stays "known" and counts like any installed plugin (F1).
            if first and st[name]["status"] == "known" and all(any(x in r + "/" for x in CATALOG_CACHE) and not runs_code(r) for r in roots):
                st[name].update(status="catalog", filed="first-run")
        st[name]["roots"] = sorted(set(roots))
    if not first:
        recheck_known_plugins(st, here)
    save_json(state_path("plugins.json"), st)
    _PENDING["at"] = None
    return {name: v["roots"] for name, v in st.items() if v.get("status") == "new" and name in here}


def last_owner_baseline(before):
    """When the owner last took a baseline (the ledger's "baseline" events), at or before `before`; None if never."""
    best = None
    try:
        with open(state_path("ledger.jsonl")) as f:
            for line in f:
                try:
                    e = json.loads(line)
                except ValueError:
                    continue
                if isinstance(e, dict) and e.get("event") == "baseline" and e.get("at") and e["at"] <= before:
                    best = e["at"] if best is None or e["at"] > best else best
    except OSError:
        return None
    try:
        return dt.datetime.fromisoformat(best).timestamp() if best else None
    except ValueError:
        return None


def owner_baseline_skills(base_ts):
    """The skills the owner's baseline held, by the content of their SKILL.md: the approved copies `baseline` keeps were saved
    at or before that baseline. Later copies (the platform roll's, re-approvals) don't count, so a plugin the roll accepted
    after the baseline isn't mistaken for one the owner saw."""
    out = set()
    try:
        names = os.listdir(state_path("approved"))
    except OSError:
        return out
    for fn in names:
        try:
            with gzip.open(state_path("approved", fn), "rt", encoding="utf-8") as f:
                d = json.load(f)
            if dt.datetime.fromisoformat(d["at"]).timestamp() > base_ts + 1:
                continue
            out.update(h for rel, h in (d.get("hashes") or {}).items() if os.path.basename(rel) == "SKILL.md")
        except (OSError, ValueError, KeyError, TypeError, EOFError):
            continue
    return out


def plugin_in_baseline(roots, owned):
    """True when one of the plugin's skills is, word for word, a skill the owner's baseline held: the platform moved or
    reinstalled its folders, it didn't add it."""
    if not owned:
        return False
    for r in roots:
        for dp, dns, fns in os.walk(r):
            dns[:] = [d for d in dns if d not in SKIP_DIRS]
            if "SKILL.md" in fns and sha256_file(os.path.join(dp, "SKILL.md")) in owned:
                return True
    return False


def recheck_known_plugins(st, here):
    """Once, after updating: v0.6.3 to v0.6.5 made the plugin list on their first run and filed every plugin there as known,
    including one added after the owner's baseline (AgentMail on the main computer, installed the evening after). v0.6.6's
    fix only covered computers with no list yet. A plugin on that first list whose folders were all created after the
    owner's last baseline before it is filed as new, so it is announced once and the owner decides, unless one of its
    skills is word for word one the owner's baseline held (the platform moved or reinstalled it)."""
    flag = state_path("plugins_rechecked.json")
    if os.path.exists(flag):
        return
    firsts = [v.get("since", "") for v in st.values() if isinstance(v, dict) and v.get("since")]
    first_at = min(firsts) if firsts else None
    base_ts = last_owner_baseline(first_at) if first_at else None
    moved, kept = [], []
    if base_ts:
        owned = owner_baseline_skills(base_ts)
        for name, v in st.items():
            if not isinstance(v, dict) or v.get("status") != "known" or v.get("kept") or v.get("since") != first_at or name not in here:
                continue
            try:
                born = min(os.stat(r).st_ctime for r in here[name])
            except (OSError, ValueError):
                continue
            if born > base_ts + 1:
                if plugin_in_baseline(here[name], owned):   # its folders changed in a platform update; its skills are the owner's baseline's
                    kept.append(name)
                    continue
                v.update(status="new", rechecked=now())
                moved.append(name)
    save_json(flag, {"at": now(), "baseline": base_ts, "filed_as_new": moved, "kept_in_baseline": kept})
    if moved:
        ledger({"event": "plugin-recheck", "new": moved})


def pending_plugin_roots():
    path = state_path("plugins.json")
    try:
        at = os.stat(path).st_mtime
    except OSError:
        return ()
    if _PENDING["at"] != at:
        st = load_json(path, {}) or {}
        _PENDING.update(at=at, roots=tuple(r for v in st.values() if isinstance(v, dict) and v.get("status") == "new" for r in v.get("roots", [])))
    return _PENDING["roots"]


def in_pending_plugin(where):
    w = (where or "").split(":")[0]
    return any(w == r or w.startswith(r + "/") for r in pending_plugin_roots())


def keep_plugin(where):
    """The owner said this plugin is theirs: from now on it is treated like any other installed plugin."""
    st = load_json(state_path("plugins.json"), {}) or {}
    w = os.path.normpath((where or "").split(":")[0])
    kept = [n for n, v in st.items() if v.get("status") == "new" and w in v.get("roots", [])]
    for n in kept:
        st[n].update(status="known", kept=now())
    if kept:
        save_json(state_path("plugins.json"), st)
        _PENDING["at"] = None
        ledger({"event": "plugin-kept", "plugins": kept})
    return kept


REFRESH_RULE = "ISR-I008"
PLATFORM_DANGER_KINDS = frozenset(RISK_KIND[r] for r in BEHAVIOR_RULES)   # credential, exfil, pipe, obfuscation, exec


def unconfirmed_platform_vote(f, fs):
    """DQ-042 (decision, Oct 16): vendor skill updates shouldn't be flagged. A routine update to the bundled learn skill came back
    "SkillSpector + husk; Memory Poisoning: Memory Manipulation; analysis-evasion: …" and daily raised a high alert. On the
    platform's own skill folders (platform_skill_path), two engines agreeing is Confirmed only when their words name a dangerous
    behavior (the kinds of BEHAVIOR_RULES), or a Confirmed critical/high Watchtower finding in the same skill backs it. Engines
    that agree only on wording (override, secrecy) or name no kind at all are a Platform line, the same line v0.7.1 item 2
    draws: wording alone is never Confirmed. A built-in that turns bad in a way Watchtower sees still alerts (Claude v0.7.1 F4)."""
    if (f["rule"] != "ISR-X003" or f.get("kinds_incomplete") or not platform_skill_path(f.get("where") or "", line=False)
            or kinds_of(f) & PLATFORM_DANGER_KINDS):
        return False
    here = _path_part(f["where"], line=False)
    return not any(g is not f and not g["rule"].startswith(("ISR-I", "ISR-X")) and g.get("label") == CONFIRMED
                   and (g.get("severity_was") or g["severity"]) in ("critical", "high")
                   and _covers(here, _path_part(g["where"]) if str(g.get("where") or "").startswith("/") else _place(g)) for g in fs)


def summarize_refresh(fs):
    """v0.7.1 precision item 6 (decision, Oct 12): change alerts name the source. Changes to Grok Bot's own files (a platform refresh)
    are one summary line, a Tip, never an alert — unless the change brings a new Confirmed critical or high (Claude v0.7.1 F4).
    Then daily gets a real alert: the built-in turned bad; don't use it until Grok Bot fixes it. Unflagged platform changes
    still roll into the one Tip. Owner skill changes and installed-plugin changes still alert as before."""
    ref = [f for f in fs if f.get("refresh") and f["rule"] in ("ISR-I001", "ISR-I002", "ISR-I003")]
    if not ref:
        return fs
    # Confirmed critical/high on a platform path (label may already be set; else evidence/corroboration still counts).
    bad, index = [], None
    for f in fs:
        if f in ref or f["severity"] not in ("critical", "high"):
            continue
        if not (f.get("scope") == "platform" or platform_file(f)) or unconfirmed_platform_vote(f, fs):   # DQ-042
            continue
        if not (f.get("label") == CONFIRMED or is_evidence(f)) and CORROB_INDEX and index is None:
            index = CorrobIndex(fs)   # batch 5 (c5): one index for every finding here, not a read of all of them per finding
        if f.get("label") == CONFIRMED or is_evidence(f) or corroborated(f, fs, index):
            bad.append(f)

    def skill_of_path(w):
        w = w.split(":")[0]
        root = skill_root(w) if os.path.exists(w) else None
        return root or os.path.dirname(w), skill_name(root) if root else os.path.basename(os.path.dirname(w))

    def bad_for(rf):
        w = rf["where"].split(":")[0]
        root, _ = skill_of_path(w)
        for b in bad:
            bw = b["where"].split(":")[0]
            if bw == w or bw.startswith(w.rstrip("/") + "/") or (root and (bw == root or bw.startswith(root.rstrip("/") + "/"))):
                return b
        return None

    flagged, unflagged = [], []
    for rf in ref:
        (flagged if bad_for(rf) else unflagged).append(rf)

    out = [f for f in fs if f not in ref]
    seen = set()
    for rf in flagged:
        b = bad_for(rf)
        root, n = skill_of_path(rf["where"])
        if n in seen:
            continue
        seen.add(n)
        title = (f"Grok Bot's own {n} changed and now {b['title']}; it's theirs to fix, but don't use it until they do")
        alert = finding(rf["rule"], title, b["severity"], ["AST07", "ASI03"], rf["where"],
                        rf.get("evidence") or b.get("evidence", ""),
                        "Grok Bot's own skill went bad. Don't use it until they fix it. ISR Bot keeps it listed.",
                        ident=f"platform-bad-{n}")
        alert["scope"] = "platform"
        alert["label"] = CONFIRMED
        alert["class"] = "corroborated"
        out.append(alert)
    if unflagged:
        names = []
        for f in unflagged:
            _, n = skill_of_path(f["where"])
            if n not in names:
                names.append(n)
        c = {r: sum(1 for f in unflagged if f["rule"] == r) for r in ("ISR-I001", "ISR-I002", "ISR-I003")}
        shown = ", ".join(names[:6]) + (f", +{len(names) - 6} more" if len(names) > 6 else "")
        # b8i4: each vendor's count (platform_vendor), Grok Bot first; one vendor alone keeps the title as it was for Grok Bot
        per = {}
        for f in unflagged:
            v = platform_vendor(f["where"]) if f["where"].startswith("/") else "Grok Bot"
            per[v] = per.get(v, 0) + 1 + len(f.get("also_at") or [])
        vendors = sorted(per, key=lambda v: (("Grok Bot", "Codex", "Claude") + (v,)).index(v))
        head = ", ".join([f"{per[vendors[0]]} of {vendors[0]}'s own files changed"] + [f"{per[v]} of {v}'s" for v in vendors[1:]])
        fix = ("Nothing to do. Grok Bot updated its own skills or plugin catalog; every new or changed file here from its own "
               "skill folders is on Grok Bot's release list. ISR Bot re-checks the new files and accepts them on the next full audit when nothing "
               "flags them.")
        if any(f.get("platform_update") for f in unflagged):   # b8i4: some aren't on the release list; the middle path let them through
            # fix round 1 (Codex 7): a full audit that accepted them (roll_builtin) still shows this line, and says so
            fix = ("Nothing to do. " + ", ".join([f"{vendors[0]} updated {per[vendors[0]]} of its own files"] + [f"{v} {per[v]}" for v in vendors[1:]])
                   + ". ISR Bot's rules found nothing in the new versions and no two scanners name a dangerous behavior; "
                   + ("this full audit accepted them." if all(f.get("platform_accepted") for f in unflagged)
                      else "it accepts them on the next full audit when nothing flags them."))
        files = sorted({min(_home_rels(q), key=lambda r: (len(r), r), default=q)
                        for f in unflagged for q in [f["where"]] + list(f.get("also_at") or [])})
        evidence, n = f"{c['ISR-I001']} updated, {c['ISR-I002']} added, {c['ISR-I003']} removed", 0
        for q in files:   # the paths that fit in the evidence's 160 characters, then how many more
            rest = len(files) - n - 1
            if len(f"{evidence}, {q}") + (len(f", +{rest} more") if rest else 0) > 160:
                break
            evidence, n = f"{evidence}{': ' if not n else ', '}{q}", n + 1
        if n < len(files):
            evidence += f"{': ' if not n else ', '}+{len(files) - n} more"
        # batch 6 (B1): a metadata file verified by content (platform_verified) says how it was checked
        meta = sorted(dict.fromkeys(_platform_place(f["where"])[0] for f in unflagged if _path_part(f["where"]) in VERIFIED_METADATA))
        if meta:
            fix = (f"Nothing to do. Grok Bot updated its list of what it loads ({', '.join(meta[:4])}{' …' if len(meta) > 4 else ''}). "
                   "ISR Bot compared it with the released version: only dates, and copies of files ISR Bot checked itself, changed."
                   + (" " + fix[len("Nothing to do. "):] if len(meta) < len(unflagged) else ""))
        tip = finding(REFRESH_RULE, f"Platform refresh: {head} ({shown})", "info", ["AST07"], "platform-refresh", evidence, fix,
                      ident="platform-refresh")
        tip["class"], tip["label"] = "tip", TIP   # created after label_findings; keep it a Tip
        tip["files"] = files   # b8i4: every file it covers, by its path under the home folder
        out.append(tip)
    return out


def builtin(f):
    """Shipped by the platform or a plugin, not made or installed by hand by the user. A plugin that is new and that the
    owner hasn't kept yet is not built-in: it counts in full until they decide."""
    w = f.get("where", "")
    if in_pending_plugin(w):
        return False
    # item 8 (R3): a real vendor folder or Grok Bot's config at exactly its place, never a name anywhere in the path
    return bool(vendor_root_path(w) or platform_config_finding(f) or w.startswith("system python package "))


SECRET_RULES = ("ISR-S001", "ISR-S002", "ISR-K003")   # a key or a decoy copy counts wherever it sits (v0.7.0 review R3)

# v0.7.1 precision item 4 (decision, Oct 12): built-ins never move the score. Grok Bot's own files (the bundled and managed skills,
# its config files, the platform's plugin catalog cache, the computer's own Python packages) go in a separate Platform section,
# one line each. Plugins the owner installed still count as before (critical and high), and a new plugin nobody kept counts in full.
PLATFORM = "Platform (Grok Bot's own file)"
PLATFORM_FIX = "This is Grok Bot's own file; nothing for you to do."
PLATFORM_CONFIRMED_FIX = ("This is Grok Bot's own file, so it doesn't move your score. Two checks agree it matters, so tell Grok Bot "
                          "support (it's theirs to fix); ISR Bot keeps it listed until it changes.")
CATALOG_CACHE = tuple(f"/plugins/cache/{m}/" for m in CATALOG_MARKETS)
_CATALOG = {"at": None, "roots": ()}
_RUNS_CODE = {}


def catalog_plugin_roots():
    """Folders of plugins the catalog sync filed as "catalog" (arrived together from the platform's catalog, run no code)."""
    path = state_path("plugins.json")
    try:
        at = os.stat(path).st_mtime
    except OSError:
        return ()
    if _CATALOG["at"] != at:
        st = load_json(path, {}) or {}
        _CATALOG.update(at=at, roots=tuple(r for v in st.values() if isinstance(v, dict) and v.get("status") == "catalog" for r in v.get("roots", [])))
    return _CATALOG["roots"]


def in_catalog_plugin(where):
    """Claude review Oct 13 (F1): the marketplace cache folders also hold plugins the owner installs. Only a plugin the catalog
    sync filed as "catalog" that still runs no code is Grok Bot's own; a known, kept or new plugin, or one that runs code, never is."""
    w = (where or "").split(":")[0]
    if not any(x in w for x in CATALOG_CACHE):
        return False
    # PR A, Codex round 1 (7): an owner's skill folder is never the catalog's, whatever state/plugins.json says about a folder in it
    try:
        if skill_tier(w) == "user":   # as written or where it really leads
            return False
    except (OSError, ValueError):
        return False
    for r in catalog_plugin_roots():
        if w == r or w.startswith(r + "/"):
            if r not in _RUNS_CODE:
                _RUNS_CODE[r] = runs_code(r)
            return not _RUNS_CODE[r]
    return False


# Decision, Oct 13 (item 8 dry run): Codex's and Claude's own built-in skills and plugins are the platform's, shown not scored.
# (Folded into PLATFORM_ROOT_SUBS / under_platform_root — Claude v0.7.1 F3.)
# Decision, Oct 13: the platform's masked-secret store (values saved through the secure secret request). Never read by Watchtower.
PLATFORM_SECRET_STORE = ("sand-data/box-secrets.json", "agent-data/box-secrets.json",
                         ".grok/auth.json")   # Decision, Oct 14: the Grok CLI sign-in file is expected; that exact path only
GROK_CLI_SIGN_IN = ".grok/auth.json"


def is_platform_secret_store(p):
    # item 8 (from Codex's batch 3 round 1): matched exactly like is_platform_config; cutting at the first colon made <store>:3 the store
    return _exactly_at(os.path.abspath(str(p)), secret_store_places())


def secret_store_places():
    return {os.path.normpath(os.path.join(b, s)) for b in dict.fromkeys((os.path.expanduser("~"), "/home/box")) for s in PLATFORM_SECRET_STORE}


def platform_secret_store_note(p):
    try:
        mode = os.stat(p).st_mode & 0o777
    except OSError:
        mode = None
    m = f"mode {mode:04o}" if mode is not None else "mode unknown"
    tight = mode is not None and not (mode & 0o077)
    if os.path.normpath(str(p)).endswith(os.sep + os.path.normpath(GROK_CLI_SIGN_IN)):
        return finding("ISR-I009", "Grok CLI sign-in file present" + ("" if tight else " (readable beyond its owner)"), "info", ["ASI03"], p,
                       f"{m}; value not read", "This is the platform's own Grok CLI sign-in file. ISR Bot never reads it. Nothing for you to do"
                       + ("." if tight else "; its permissions are wider than 0600, worth reporting to the platform."), ident="platform-grok-cli-sign-in")
    return finding("ISR-I009", "Platform secret store present" + ("" if tight else " (readable beyond its owner)"), "info", ["ASI03"], p,
                   f"{m}; value not read", "This is the platform's own store for secrets saved through the secure secret request. "
                   "ISR Bot never reads it. Nothing for you to do" + ("." if tight else "; its permissions are wider than 0600, worth reporting to the platform."),
                   ident="platform-secret-store")


def platform_file(f, catalog=True):
    """Grok Bot's own file: real platform skill roots (realpath prefix), its config files, catalog plugins, or system packages.
    A user skill whose path merely contains a platform-looking segment is never platform (Claude v0.7.1 F3). catalog=False
    leaves out catalog plugins, which only state/plugins.json says are the catalog's (platform_scope, PR A Codex round 1, 7)."""
    w = f.get("where", "") if isinstance(f, dict) else str(f)
    if isinstance(f, dict) and f.get("unverified_platform"):   # item 8 (R3): not shown to be the platform's, so it counts as the owner's
        return False
    if in_pending_plugin(w):
        return False
    if isinstance(f, dict) and f.get("platform_hook"):
        return True
    lit = literal_path(f)   # item 8: the producer's own file, when it recorded one
    if (lit in secret_store_places()) if lit else (f"{w}".startswith("/") and is_platform_secret_store(w)):
        return True
    if platform_config_finding(f) or (catalog and in_catalog_plugin(w)) or w.startswith("system python package "):
        return True
    path = lit or (w.split(":")[0] if isinstance(w, str) else "")
    return bool(path.startswith("/")) and under_platform_root(path)


REVIEWED_LABEL = "Platform note (checked)"


def mark_reviewed(fs, manifest):
    """Batch 5 (d2): a platform finding an entry of rules/platform-reviewed.json covers (platform_reviewed: that file's exact bytes,
    that rule and line) is a checked platform note: severity info (the rule's own kept as severity_was), the entry's note as its fix,
    never new and never a rug-pull alert. Run before summarize_refresh and mark_platform. Each finding's _snap (the fingerprint
    of the bytes it was found in, audit) is used here and dropped."""
    for f in fs:
        e = platform_reviewed(f, manifest, f.pop("_snap", None))
        if e is not None:
            f.update({"class": "platform", "label": REVIEWED_LABEL, "severity_was": f.get("severity_was") or f["severity"], "severity": "info",
                      "fix": e["note"], "reviewed": True})
    return fs


def mark_platform(fs):
    """Label Grok Bot's own findings. Worth-a-look and Tips there become one Platform line each; a Confirmed one stays
    Confirmed (it is still shown and still alerts when new) but never counts. Two engines agreeing on a platform skill in words
    that name no dangerous behavior is a Platform line too (DQ-042). A checked one (mark_reviewed) stays as it is."""
    for f in fs:
        if f.get("scope") != "platform" or f.get("guarded") or f.get("reviewed"):
            continue
        if f.get("class") in ("pattern", "tip") or f.get("platform_hook") or unconfirmed_platform_vote(f, fs):   # Decision, Oct 13: the platform's hook is a Platform line
            f["class"], f["label"] = "platform", PLATFORM
            f["fix"] = f["fix"] if f.get("platform_hook") or f["rule"] == "ISR-I009" else PLATFORM_FIX
            if f["severity"] != "info" and not f.get("platform_hook"):   # the hook keeps its low (listed fact), never scored
                f["severity_was"], f["severity"] = f["severity"], "info"
        elif f["rule"] not in SECRET_RULES:
            if f["rule"] == "ISR-X003" and f["severity"] == "info" and f.get("severity_was"):   # daily re-adds last run's Platform line;
                f["severity"] = f.pop("severity_was")                                        # Watchtower now backs it (DQ-042)
            f["fix"] = PLATFORM_CONFIRMED_FIX
    return fs


def counts(f):
    """Only what the user owns moves the score. Built-in findings count when they are critical or high (two scanners
    agreeing a plugin is dangerous still matters); the rest are listed for information.
    DQ-022/023/024/028–030: true quarantine, sample/test folders outside loadable locations, and fiction inside
    built-in templates never move the score. Sample-named folders inside a loadable skill still count.
    R3: keys and decoy copies (SECRET_RULES) count wherever they sit, including quarantine and sample folders."""
    if f.get("unverified_platform"):
        return True   # Codex, item 8 review 2 (high 1): a platform name is loaded from where it is, even when it leads into quarantine
    w = f.get("where", "")
    path = w.split(":")[0]
    if path and not w.startswith(("rollcall:", "system python package ")) and f["rule"] not in SECRET_RULES:
        if is_quarantined_path(path):
            return False
        if is_sample_skill_path(path) and not is_loadable_skill_location(path):
            return False
    if f.get("scope") == "platform" or platform_file(f):   # v0.7.1 item 4: never, except a real key outside Grok Bot's config
        # batch 6 (B2): nor a gitleaks pattern hit in a metadata file the release list vouches for (metadata_hit_note)
        return f["rule"] in SECRET_RULES and not platform_config_finding(f) and not metadata_hit_note(f)
    return not builtin(f) or f["severity"] in ("critical", "high")


def metadata_hit_note(f):
    """Batch 6 (B2), fix round 1 (Codex 2, 3, 4): a gitleaks pattern hit in Grok Bot's own metadata file that is a platform note,
    not counted. Decided again each time it is asked, never from a stored flag (6cd1ab4's `verified_metadata` is ignored): the
    hit is gitleaks' alone (no provider confirmed a key: TruffleHog's live, dead or unsure, or a critical, always counts), on
    one line of one file; its `metadata_sha256` is the bytes gitleaks_findings bound it to (a private copy of the verified
    bytes gave gitleaks exactly the same hits); and the file has those bytes now, they verify against the release list, and
    every unit's file is itself on it (metadata_proof). Anything else counts, with its cleanup."""
    if f.get("rule") != "ISR-S002" or f.get("source") != "gitleaks" or f.get("severity") == "critical":
        return False
    if f.get("title") not in ("gitleaks: secrets in file", KEY_MAYBE):
        return False
    path, _, ln = str(f.get("where") or "").rpartition(":")
    return path.startswith("/") and ln.isdigit() and metadata_proof(path, f.get("metadata_sha256"))


def platform_owned(fs):
    """The platform's own config and the computer's own Python packages can't be fixed by the user and aren't theirs to
    upgrade: they stay visible as low, for-information findings and never count."""
    for f in fs:
        w = f.get("where", "")
        if platform_config_finding(f) and f["rule"] in ("ISR-S001", "ISR-S002"):   # item 8: exactly Grok Bot's config, never a name in the path
            f.update(severity="low", title="The platform's own access token (every Bot can read it)" if "gateway.json" in w
                     else "The platform's own key file (every Bot can read it)",
                     fix="This is Grok Bot's own config file. You can't change it; it's listed so you know every Bot on this computer can read it.")
    return fs
