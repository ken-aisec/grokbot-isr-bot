"""Golden-output check for the wt.py split into watchtower/wt_parts (no behavior change; D1/D2/D3).

Not part of `make test` (the name doesn't match test*.py). Run it as `bash scripts/golden-check.sh PRE_REF [quick|full]`;
PRE_REF (required, no default: 9b106b9 for this split) is the commit before the split. It also holds the reassembly helpers
test_split_guard uses.

Step 0 rebuilds the pre-split wt.py from the working tree's wt.py and parts and compares it byte for byte with PRE_REF's.
The same commands then run on PRE_REF's tree twice (calibration) and once on the working tree's tracked files, one after the
other from the same path (/tmp/code inside the sandbox), so no path needs normalizing. They must give the same exit codes,
output and files (path, type, mode bits, content) after only the normalizations calibration shows are needed (N1-N9; N4,
durations, always, since two calibration runs can time a stage alike by chance). Paths,
scores, finding keys, rule ids, severity, key order, help text, file modes and exit codes are never normalized.

Every tier run is sealed: `unshare -rmn` (no network), scratch folders mounted over /home, /workspace and
/var/tmp and, last, this check's own folder over /tmp, a sentinel checked in each before Python starts, and an environment built
from scratch (never inherited, never printed). The real home folder, /workspace/watchtower and the decoys are never visible.
The check fails, and never prints its RESULT line, when the sandbox is unavailable (there is no unsealed fallback), when ONLY
selects no scenario, and when no scenario was compared. Everything is written under one mkdtemp folder in /tmp, removed when the check passes and kept (path printed) when it fails.

Expect mode (batch 5: changes that alter behavior on purpose; `--expect FILE --items A,B` to golden-check.sh): step 0 only checks
that the working tree's reassembled wt.py compiles and that PRE_REF's wt.py has the loader block. Calibration and N1-N9 are as
above; then every line by which a post item differs from pre must match an entry of an enabled item in FILE (see parse_expect),
and an enabled `must_see` entry that matched nothing, in a run where its scenarios ran, is a problem too (since batch 5 PR B,
Codex round 3: one that names its scenarios exactly, in each of them that ran, on its own; see unmet)."""
import datetime as dt, difflib, hashlib, json, os, re, shutil, statistics, subprocess, sys, tempfile, unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

BANNER = b"# Part of wt.py: runs inside wt.py's namespace (loaded by _wt_part); not a module on its own.\n"
LOADER_BEGIN = b"# >>> wt_parts loader (reassembly drops this block)\n"
LOADER_END = b"# <<< wt_parts loader\n"
CALL = re.compile(rb'_wt_part\("([a-z0-9_]+)"\)\n\Z')
# Decision D2: the one line of wt.py the split changes (doctor's crash frames). Reassembly maps it back to the line it replaced.
D2_OLD = (b'    frames = [f"wt.py line {m.group(1)} in {m.group(2)}" for m in re.finditer(r\'File "[^"]*wt\\.py", line (\\d+), in (\\w+)\', text)][-6:]\n')
D2_NEW = (b'    frames = [f"{m.group(1)}.py line {m.group(2)} in {m.group(3)}" for m in re.finditer(r\'File "[^"]*?(wt|wt_parts/[a-z0-9_]+)\\.py", line (\\d+), in (\\w+)\', text)][-6:]\n')


def lines_of(b):
    """Lines split on b"\\n" only (wt.py holds a literal U+2028, which str.splitlines would split on)."""
    parts = b.split(b"\n")
    return [p + b"\n" for p in parts[:-1]] + ([parts[-1]] if parts[-1] else [])


def read(p):
    with open(p, "rb") as f:
        return f.read()


def reassemble(wt_bytes, parts_dir):
    """(the pre-split wt.py, [(first line, label)]): every `_wt_part("x")` line replaced by x.py after its banner, the loader
    block and the two blank lines after it dropped, and the D2 line mapped back."""
    out, where, i, L, n = [], [(1, "wt.py")], 0, lines_of(wt_bytes), 1
    while i < len(L):
        line = L[i]
        if line == LOADER_BEGIN:
            j = L.index(LOADER_END, i)
            if L[j + 1:j + 3] != [b"\n", b"\n"]:
                raise ValueError("the loader block is not followed by two blank lines")
            i = j + 3
            continue
        m = CALL.match(line)
        if m:
            name = m.group(1).decode()
            body = read(os.path.join(parts_dir, name + ".py"))
            if not body.startswith(BANNER):
                raise ValueError(f"{name}.py does not start with the banner")
            body = body[len(BANNER):]
            where.append((n, f"wt_parts/{name}.py"))
            out.append(body)
            n += len(lines_of(body))
            where.append((n, "wt.py"))
        else:
            out.append(D2_OLD if line == D2_NEW else line)
            n += 1
        i += 1
    return b"".join(out), where


# ------------------------------------------------------------------------------------------------ what runs in the sandbox
SUBCOMMANDS = ("vet", "audit", "daily", "baseline", "status", "report", "breakdown", "dismiss", "show", "canary", "auto-allow", "fix",
               "quarantine", "uninstall", "diff", "doctor", "exception", "accept", "events", "rollcall", "prepublish", "incident",
               "codescan", "brief")
PROFILES = ("empty_account", "busy_clean_box", "power_user", "strict_auto_review", "emoji_names", "odd_layout", "fixtures_vendor",
            "platform_refresh")

# Runs inside the sandbox as `python3 -I -B /tmp/runner.py PLAN`; writes raw results (no normalization) to the plan's "out".
RUNNER = r'''
import hashlib, json, os, shutil, stat, subprocess, sys, time
PY = sys.executable
PLAN = json.load(open(sys.argv[1]))
S = PLAN["scratch"]                       # /tmp/run/<id>: the same path for every tree run of this scenario
X = S + "/x"
TREE = PLAN["tree"]
SEALED = PLAN["sealed"]
SCRATCH_ROOTS = ("/home", "/workspace", "/var/tmp")
if SEALED and not all(os.path.isfile(d + "/.golden-sentinel") for d in SCRATCH_ROOTS + ("/tmp",)):
    sys.exit("not inside the golden sandbox; nothing was done")
HOME_DIR = "/home/box" if SEALED else X + "/home"
WT_HOME = "/workspace/watchtower" if SEALED else X + "/wt"
items = {}

DRIVER = """
import os, random, sys
tree, argv = sys.argv[1], sys.argv[2:]
sys.path.insert(0, os.path.join(tree, "watchtower"))
import wt
b = os.path.join(os.environ["WATCHTOWER_HOME"], "scanners", "bin")
for n in sorted(os.listdir(b)) if os.path.isdir(b) else []:
    if n in wt.SCANNER_NAMES:
        wt.SCANNER_LOCK_EXTRA[n] = wt.scanner_digest(os.path.join(b, n))      # as test_boxes.Box.scanners registers them
lock = os.environ.get("GOLDEN_PLATFORM_LOCK", "")
if os.path.isfile(lock):
    wt.PLATFORM_LOCK = lock
wt.now = lambda: "2026-10-18T12:00:00+00:00"
import secrets
rng = random.Random(20261018)
secrets.token_hex = lambda n=32: "".join("%02x" % rng.randrange(256) for _ in range(n))
secrets.choice = lambda seq: seq[rng.randrange(len(seq))]
crash = os.environ.get("GOLDEN_CRASH")
if crash:
    def boom(*a, **k):
        raise RuntimeError("golden forced crash")
    setattr(wt, crash, boom)
try:
    code = wt.main(argv)
except SystemExit as e:
    code = e.code
sys.stdout.flush()
sys.exit(code if isinstance(code, int) else (0 if code is None else 1))
"""

BUILDER = """
import os, sys
tree, profile, phase = sys.argv[1:4]
sys.path.insert(0, os.path.join(tree, "tests"))
import test_boxes, profiles
class Duck:
    pass
box = Duck()
box.tmp = os.environ["GOLDEN_BOXTMP"]; box.home = os.environ["HOME"]; box.ws = "/workspace"; box.roots = [box.home, box.ws]
box.platform_lock = os.environ["GOLDEN_PLATFORM_LOCK"]
box.skills = test_boxes.Box.skills.__get__(box)
box.scanners = test_boxes.Box.scanners.__get__(box)
box.fixtures = test_boxes.FreshAccountLessons.fixtures.__get__(box)
if phase == "build":
    os.makedirs(box.home, exist_ok=True); os.makedirs(box.tmp, exist_ok=True)
    with open(box.platform_lock, "w") as f:
        f.write("# test box: no vendor files listed yet\\n")
    if profile in ("busy_clean_box", "platform_refresh"):
        profiles.busy_clean_box(box)
    elif profile == "power_user":
        profiles.power_user(box, skills=24, bots=4)
    elif profile == "fixtures_vendor":
        box.fixtures("bad/exfil-helper", "bad/hidden-unicode", "bad/silent-sender", "clean/meeting-notes", "clean/weekly-digest-safe", "evasive/notes-sync")
        learn = os.path.join(box.home, ".grok", "bundled", "skills", "learn", "SKILL.md")
        profiles._w(learn, "---\\nname: learn\\ndescription: Learn a topic.\\n---\\nExplain the topic step by step.\\n")
        profiles.vendor_release(box, learn)
    else:
        getattr(profiles, profile)(box)
    box.scanners()
elif phase == "refresh":
    pptx = os.path.join(box.home, ".grok", "bundled", "skills", "pptx")
    plugins = [os.path.join(box.home, "sand-data", "plugins", "cache", "cursor-public", n, profiles.CATALOG_COMMIT) for n in ("notion-workspace", "vercel-docs", "figma-notes")]
    profiles.platform_refresh(box, {"pptx": pptx, "plugins": plugins})
"""


def env(extra=None, driver=False):
    e = {"HOME": HOME_DIR, "WATCHTOWER_HOME": WT_HOME, "WT_DECOY_ROOT": X + "/decoys",
         "WATCHTOWER_SETTINGS": HOME_DIR + "/agent-data/settings.json", "TMPDIR": X + "/tmpdir", "XDG_CACHE_HOME": X + "/cache",
         "PATH": "/usr/bin:/bin", "TZ": "UTC", "LC_ALL": "C.UTF-8"}
    if driver:
        e["GOLDEN_PLATFORM_LOCK"] = X + "/box/platform-release.lock"
    e.update(extra or {})
    return e


n_cmd = [0]


def run(argv, mode="cli", cwd=None, stdin=None, extra=None, label=None, timeout=900, tree=TREE):
    """One wt.py command; its exit code, stdout and stderr become three items."""
    if mode == "cli":
        cmd = [PY, "-I", tree + "/watchtower/wt.py"] + list(argv)
    else:
        cmd = [PY, "-I", "-B", "-c", DRIVER, tree] + list(argv)
    p = subprocess.run(cmd, input=stdin if stdin is not None else b"", capture_output=True, env=env(extra, mode == "driver"),
                       cwd=cwd or X + "/cwd", timeout=timeout)
    n_cmd[0] += 1
    key = "%03d %s%s" % (n_cmd[0], label or " ".join(argv), "" if mode == "cli" else " [driver]")
    items[key + " :rc"] = str(p.returncode)
    items[key + " :stdout"] = p.stdout.decode("utf-8", "backslashreplace")
    items[key + " :stderr"] = p.stderr.decode("utf-8", "backslashreplace")
    return p


def build(profile, phase):
    p = subprocess.run([PY, "-I", "-B", "-c", BUILDER, "/tmp/trees/post", profile, phase], capture_output=True,
                       env=env({"GOLDEN_BOXTMP": X + "/box"}, driver=True), cwd=X + "/cwd", timeout=600)
    if p.returncode:
        raise SystemExit("box builder failed: " + p.stderr.decode("utf-8", "replace")[-2000:])


def content(p):
    try:
        with open(p, "rb") as f:
            b = f.read()
    except OSError as e:
        return "unreadable " + type(e).__name__
    if p.endswith(".gz") and b[:2] == b"\x1f\x8b":       # the header holds the time it was written; compare what it holds
        import gzip, struct, zlib
        try:
            b = b"gzip mtime %d\n" % struct.unpack("<I", b[4:8])[0] + gzip.decompress(b)
        except (OSError, EOFError, zlib.error):
            pass
    if b.startswith(b"SQLite format 3\x00"):            # a box's cookie jar: its rows, not its pages
        import sqlite3
        try:
            con = sqlite3.connect("file:%s?mode=ro&immutable=1" % p, uri=True)
            try:
                return "sqlite dump\n" + "\n".join(con.iterdump())
            finally:
                con.close()
        except sqlite3.Error as e:
            return "sqlite unreadable " + type(e).__name__
    if len(b) > 512 * 1024:
        return "sha256 " + hashlib.sha256(b).hexdigest()
    try:
        return b.decode("utf-8")
    except UnicodeDecodeError:
        return "binary sha256 " + hashlib.sha256(b).hexdigest()


def snapshot(label, top, skip=()):
    """Every entry under top: relative path, type, mode bits, and a file's content (or its sha256 when large or binary)."""
    if not os.path.lexists(top):
        items["tree %s" % label] = "absent"
        return
    errors = []
    for dp, dns, fns in os.walk(top, onerror=errors.append):
        dns.sort()
        dns[:] = [d for d in dns if os.path.join(dp, d) not in skip]
        for n in dns + sorted(fns):
            p = os.path.join(dp, n)
            rel = os.path.relpath(p, top)
            st = os.lstat(p)
            mode = "%04o" % stat.S_IMODE(st.st_mode)
            if stat.S_ISLNK(st.st_mode):
                v = "link %s -> %s" % (mode, os.readlink(p))
            elif stat.S_ISDIR(st.st_mode):
                v = "dir %s" % mode
            elif stat.S_ISREG(st.st_mode):
                v = "file %s\n%s" % (mode, content(p))
            else:
                v = "other %s %o" % (mode, stat.S_IFMT(st.st_mode))
            items["tree %s/%s" % (label, rel)] = v
    if errors:
        items["tree %s :errors" % label] = "\n".join(sorted(str(e) for e in errors))


def snapshot_all(skip=()):
    for label, top in ((("home", "/home"), ("workspace", "/workspace"), ("var-tmp", "/var/tmp")) if SEALED else ()) + (("scratch", X),):
        snapshot(label, top, skip)


def findings():
    try:
        return json.load(open(WT_HOME + "/state/last_findings.json")).get("findings", [])
    except (OSError, ValueError, AttributeError):
        return []


def wipe(d):
    subprocess.run(["chmod", "-R", "u+rwx", d], capture_output=True)
    for n in os.listdir(d):
        p = os.path.join(d, n)
        shutil.rmtree(p) if os.path.isdir(p) and not os.path.islink(p) else os.remove(p)


def fresh():
    """Empty scratch. A folder over which the sandbox mounted scratch is emptied only while its sentinel is there (the real
    /home, /workspace and /var/tmp never have one)."""
    for d in SCRATCH_ROOTS if SEALED else ():
        if not os.path.isfile(d + "/.golden-sentinel"):
            sys.exit("no sentinel in %s; nothing was done" % d)
        wipe(d)
    if os.path.isdir(X):
        wipe(X)
    for d in ("cwd", "decoys", "tmpdir", "cache", "box"):
        os.makedirs(os.path.join(X, d), exist_ok=True)
    os.makedirs(HOME_DIR, exist_ok=True)


SEQUENCE_HEAD = [["audit"], ["daily"]]
SEQUENCE_TAIL = [["status"], ["report"], ["breakdown"], ["fix"], ["accept", "--list"], ["exception", "list"], ["events", "list"],
                 ["canary", "status"], ["doctor"], ["audit"], ["daily"]]


def box_sequence(mode):
    for a in SEQUENCE_HEAD:
        run(a, mode)
    for rule in sorted({f.get("rule") for f in findings() if f.get("rule")}):
        run(["show", rule], mode)
    for a in SEQUENCE_TAIL:
        run(a, mode)


def tier_a():
    fx = TREE + "/tests/fixtures"
    targets = sorted(fx + "/" + k + "/" + n for k in ("bad", "clean", "evasive") for n in os.listdir(fx + "/" + k))
    targets += sorted(fx + "/exports/" + n for n in os.listdir(fx + "/exports") if n.endswith(".md"))
    brief = X + "/brief-offline.json"
    with open(brief, "w") as f:
        f.write("{}")
    cwds = [X + "/cwd"] + (["/", TREE] if PLAN.get("all_cwds") else [])
    for cwd in cwds:
        tag = "" if cwd == X + "/cwd" else " (cwd %s)" % cwd
        lab = lambda a: " ".join(a) + tag
        for a in [["--version"], ["--help"], ["-h"]] + [[c, "--help"] for c in PLAN["subcommands"]] + [[], ["nosuchcmd"], ["status", "--bogus-flag"]]:
            run(a, cwd=cwd, label=lab(a))
        for a in (["show", "WT-X004"], ["status"], ["report"], ["breakdown"], ["doctor"], ["doctor", "--save"], ["dismiss", "--list"],
                  ["accept", "--list"], ["exception", "list"], ["events", "list"], ["canary", "status"], ["rollcall", "--question"]):
            run(a, cwd=cwd, label=lab(a))
        run(["auto-allow", "list"], cwd=cwd, extra={"WATCHTOWER_SETTINGS": fx + "/exports/settings.json"}, label=lab(["auto-allow", "list"]) + " [settings fixture]")
        for a in (["brief", "--offline", brief], ["diff", "nosuch"]):
            run(a, cwd=cwd, label=lab(a))
        for t in targets:
            for a in (["vet", t], ["vet", t, "--json"], ["vet", t, "--page-only"], ["prepublish", t, "--json"]):
                run(a, cwd=cwd, label=lab(a))
            f = t if os.path.isfile(t) else t + "/SKILL.md"
            if os.path.isfile(f):
                run(["vet", "-"], cwd=cwd, stdin=open(f, "rb").read(), label=lab(["vet", "-", "<", f]))
        run(["vet", X + "/no-such-file.md"], cwd=cwd, label=lab(["vet", "<missing>"]))
        run(["codescan", fx], cwd=cwd, label=lab(["codescan", fx]))
    snapshot_all()


def layout_app():
    app = WT_HOME + "/app"
    if os.path.isdir(app):
        shutil.rmtree(app)
    lines = []
    for dp, dns, fns in os.walk(TREE):
        dns[:] = sorted(d for d in dns if d != "__pycache__")
        for n in sorted(fns):
            src = os.path.join(dp, n)
            rel = os.path.relpath(src, TREE)
            if rel == "MANIFEST.sha256":
                continue
            os.makedirs(os.path.dirname(os.path.join(app, rel)), exist_ok=True)
            shutil.copy2(src, os.path.join(app, rel))
            lines.append("%s  %s" % (hashlib.sha256(open(src, "rb").read()).hexdigest(), rel))
    with open(app + "/MANIFEST.sha256", "w") as f:
        f.write("\n".join(sorted(lines, key=lambda l: l.split(None, 1)[1])) + "\n")
    os.makedirs(app + "/.git")
    with open(app + "/.git/HEAD", "w") as f:
        f.write("a" * 40 + "\n")
    os.makedirs(WT_HOME + "/state", exist_ok=True)
    with open(WT_HOME + "/state/installed_commit", "w") as f:
        f.write("a" * 40 + "\n")
    return app


def tier_c():
    app = layout_app()
    for a in (["--version"], ["status"], ["audit"], ["status"]):
        run(a, tree=app, label="installed " + " ".join(a))
    with open(app + "/README.md", "a") as f:
        f.write("tampered\n")
    for a in (["--version"], ["status"], ["audit"]):
        run(a, tree=app, label="installed, README.md changed: " + " ".join(a))
    layout_app()
    os.makedirs(app + "/skills/x")
    with open(app + "/skills/x/SKILL.md", "w") as f:
        f.write("---\nname: x\n---\nplanted\n")
    for a in (["--version"], ["status"]):
        run(a, tree=app, label="installed, skills/x/SKILL.md added: " + " ".join(a))
    snapshot_all(skip=(app,))


def timing():
    out = {}
    trees = PLAN["timing_trees"]
    for r in range(10):
        for t in (trees if r % 2 == 0 else trees[::-1]):
            for a in (["--version"], ["--help"]):
                t0 = time.perf_counter()
                subprocess.run([PY, "-I", t + "/watchtower/wt.py"] + a, capture_output=True, env=env(), cwd=X + "/cwd", timeout=60)
                out.setdefault("%s %s" % (os.path.basename(t), a[0]), []).append(time.perf_counter() - t0)
    return out


fresh()
kind = PLAN["kind"]
result = {"items": items}
if kind == "tierA":
    tier_a()
elif kind == "box":
    mode = PLAN["mode"]
    build(PLAN["profile"], "build")
    if PLAN["profile"] == "platform_refresh":
        run(["audit"], mode)
        build(PLAN["profile"], "refresh")
    box_sequence(mode)
    snapshot_all()
elif kind == "crash":
    build("empty_account", "build")
    run(["audit"], "driver")
    run(["report"], "driver", extra={"GOLDEN_CRASH": "render_md"}, label="report (render_md raises)")
    for a in (["doctor"], ["status"]):
        run(a, "driver")
    snapshot_all()
elif kind == "extended":
    build("fixtures_vendor", "build")
    run(["audit"], "driver")
    fs = sorted(findings(), key=lambda f: (str(f.get("rule")), str(f.get("where")), str(f.get("key"))))
    run(["baseline", "--owner-said-yes"], "driver")
    if fs:
        run(["dismiss", str(fs[0].get("key")), "--reason", "golden check"], "driver", label="dismiss <first key>")
        run(["accept", str(fs[-1].get("rule")), str(fs[-1].get("where")), "--reason", "golden check"], "driver", label="accept <last rule> <where>")
    run(["exception", "add", "exfil-helper", "--reason", "golden check"], "driver")
    for a in (["status"], ["accept", "--list"], ["exception", "list"], ["dismiss", "--list"], ["report"], ["audit"], ["daily"]):
        run(a, "driver")
    snapshot_all()
elif kind == "tierC":
    tier_c()
elif kind == "timing":
    result["timing"] = timing()
with open(PLAN["out"], "w") as f:
    json.dump(result, f)
'''

# Run with bash inside `unshare -rmn --propagation private`. B is mounted over /tmp last, so after that every path of this
# check is /tmp/<name>. A missing sentinel (a mount that didn't happen) stops it with 97 before Python starts.
INNER = r'''
set -e
B="$1"; S="$2"; PLAN="$3"; PY="$4"
mount --bind "$S/mnt/home" /home
mount --bind "$S/mnt/workspace" /workspace
mount --bind "$S/mnt/var-tmp" /var/tmp
mount --bind "$B" /tmp
for d in /home /workspace /var/tmp /tmp; do [ -f "$d/.golden-sentinel" ] || exit 97; done
cd /
exec /usr/bin/env -i PATH=/usr/bin:/bin TZ=UTC LC_ALL=C.UTF-8 "$PY" -I -B /tmp/runner.py "$PLAN"
'''


# ------------------------------------------------------------------------------------------------ normalization (N1-N9)
def _today_dates():
    d = dt.datetime.now(dt.timezone.utc).date()
    return [d + dt.timedelta(days=k) for k in (-1, 0, 1)]


def rules():
    days = _today_dates()
    dates = "|".join(re.escape(x.isoformat()) for x in days)
    weeks = "|".join(sorted({re.escape("%d-W%02d" % x.isocalendar()[:2]) for x in days}))
    return [
        ("N1", re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?(?: ?(?:[+-]\d{2}:?\d{2}|Z|UTC))?"), "<TS>"),
        ("N2", re.compile(r"(?:%s|%s)" % (dates, weeks)), "<DATE>"),
        # time.time() seconds (a float anywhere, an integer after a JSON key or in a gzip header) and time.time_ns() (in names too)
        ("N3", re.compile(r'(?<![\w.])1[6-9]\d{8}\.\d+\b|(?<=": )1[6-9]\d{8}\b|(?<=^gzip mtime )1[6-9]\d{8}\b|(?<!\w)1[6-9]\d{17}(?!\d)', re.M), "<EPOCH>"),
        ("N4", re.compile(r'("(?:seconds|secs|elapsed|took|duration|[\w-]*_seconds|[\w-]*_s)": ?)\d+(?:\.\d+)?\b'), r"\1<DUR>"),
        ("N5", re.compile(r'("pid": ?)\d+'), r"\1<PID>"),
        ("N6", re.compile(r"\.[a-z]+-[0-9a-f]{6}/[a-z0-9-]+-[0-9a-f]{4}\.[a-z0-9]+"), "<DECOY>"),
        ("N9", re.compile(r'("(?:mtime|ctime|atime|ino|inode|mtime_ns|ctime_ns|atime_ns|st_[a-z_]+)": ?)\d+(?:\.\d+)?\b'), r"\1<STAT>"),
    ]


STAGE_TIMES = re.compile(r"(?<=: )\d+(?:\.\d+)?(?=[,\n}])")
STAGE_BLOCK = re.compile(r'("seconds_per_stage": \{)([^{}]*)(\})')
CHROME_TIME = re.compile(r"(?<!\d)1[34]\d{15}(?!\d)")      # a cookie's creation time, microseconds since 1601 (the box builder's clock)
# N8 (crash scenario only): a traceback frame or doctor's frame label from wt.py or a part; the function sequence must match.
FRAME_TB = re.compile(r'File "[^"]*/watchtower/(wt|wt_parts/[a-z0-9_]+)\.py", line \d+, in (\w+)')
FRAME_DOCTOR = re.compile(r"\b(wt|wt_parts/[a-z0-9_]+)\.py line \d+ in (\w+)")


ALWAYS = {"N4"}   # applied to post whether or not calibration happened to need it (durations: run speed)


def normalize(key, text, enabled, used, crash=False):
    for name, rx, repl in rules():
        if name in enabled:
            text, k = rx.subn(repl, text)
            if k:
                used[name] = used.get(name, 0) + k
    if "N4" in enabled:
        k = 0
        if key.endswith("state/stage_times.json"):
            text, k = STAGE_TIMES.subn("<DUR>", text)
        text, k2 = STAGE_BLOCK.subn(lambda m: m.group(1) + STAGE_TIMES.sub("<DUR>", m.group(2)) + m.group(3), text)
        if k + k2:
            used["N4"] = used.get("N4", 0) + k + k2
    if "N3" in enabled and text.startswith("file 0") and "\nsqlite dump\n" in text[:30]:
        text, k = CHROME_TIME.subn("<EPOCH>", text)
        if k:
            used["N3"] = used.get("N3", 0) + k
    if crash:
        text, k1 = FRAME_TB.subn(lambda m: f'File "<file>", line <N>, in {m.group(2)}', text)
        text, k2 = FRAME_DOCTOR.subn(lambda m: f"<file> line <N> in {m.group(2)}", text)
        if k1 + k2:
            used["N8"] = used.get("N8", 0) + k1 + k2
    return text


def norm_items(items, enabled, crash=False):
    """Items with normalized names and values. Names that normalize alike (two audit-<EPOCH>.json deltas) keep their order."""
    out, seen, used = {}, {}, {}
    for k in sorted(items):
        nk = normalize("", k, enabled, used, crash)
        seen[nk] = seen.get(nk, 0) + 1
        out[nk if seen[nk] == 1 else f"{nk} #{seen[nk]}"] = normalize(k, items[k], enabled, used, crash)
    return out


def differing(x, y):
    return [k for k in sorted(set(x) | set(y)) if x.get(k) != y.get(k)]


def frames(text):
    return [m.group(2) for m in FRAME_TB.finditer(text)] + ["|"] + [m.group(2) for m in FRAME_DOCTOR.finditer(text)]


def short_diff(a, b, n=30):
    d = list(difflib.unified_diff(a.splitlines(), b.splitlines(), "first", "second", lineterm="", n=1))
    return "\n".join("    | " + x[:220] for x in d[:n]) + ("\n    | ..." if len(d) > n else "")


# ------------------------------------------------------------------------------------------------ expected differences (batch 5)
EXPECT_FIELDS = {"item": str, "scenario_rx": str, "key_rx": str, "lines_rx": list, "must_see": bool, "why": str}
# PR A, Codex round 1 (11): instead of lines_rx, an entry may name the one JSON field whose value changes, from one exact value to
# another ({"field", "from", "to"}): the item is expected only when post is pre with exactly that change (parsed, everything else
# equal), never by its lines.
JSON_CHANGE_FIELDS = {"field": str, "from": (int, str), "to": (int, str)}
# PR B, Codex round 1 (4): for a new JSON item, an entry may give its whole shape instead of lines_rx ({"head": [the exact lines
# before the document], "doc": a schema}): the item is expected only when post is new and its document fits the schema exactly
# (json_shape_ok). Line patterns can't pin where a key sits, its type or its value; a schema can, and it has no free text: a
# string is one of an `enum`'s exact values.
JSON_SHAPE_FIELDS = {"head": list, "doc": dict}
SCHEMA_KINDS = {"object": dict, "list": dict, "int": list, "enum": list, "any": list}
NEW_ITEM, GONE_ITEM = "+<new item>", "-<item gone>"   # the pseudo line for an item only post (or only pre) has
# PR B, Codex round 2 (6): two exact kinds, each in place of lines_rx. `json_exact` {head, doc}: a new JSON item whose lines
# before the document are exactly `head` and whose document is exactly `doc` (_same: every value, its type and each object's key
# order). `block` [lines]: diff lines ("+text"/"-text", NEW_ITEM) that must all appear in the item's diff, in that order, once
# (_block_span); a line left out, moved or changed takes none of them, so all are unexpected; a line between them that isn't
# one of them is unexpected whatever else might take it, and a second copy is left to the other entries. No pattern in either:
# what they take is spelled out.
ALT_FIELDS = {"json_change": dict, "json_shape": dict, "json_exact": dict, "block": list}


def schema_ok(s):
    """True for a schema json_shape_ok can apply: exactly one kind per node, {"object": {key: schema}}, {"list": {"of": schema,
    "max": n}}, {"int": [lo, hi]}, {"enum": [values, at least one]} or {"any": [schemas, at least one]}; nothing else, nothing empty."""
    if not (isinstance(s, dict) and len(s) == 1):
        return False
    (kind, v), = s.items()
    if kind not in SCHEMA_KINDS or not isinstance(v, SCHEMA_KINDS[kind]):
        return False
    if kind == "object":
        return all(isinstance(k, str) for k in v) and all(schema_ok(x) for x in v.values())
    if kind == "list":
        return set(v) == {"of", "max"} and type(v["max"]) is int and v["max"] >= 0 and schema_ok(v["of"])
    if kind == "int":
        return len(v) == 2 and all(type(x) is int for x in v) and v[0] <= v[1]
    scalar = lambda x: x is None or isinstance(x, (str, int, bool))
    if kind == "enum":   # a value is a scalar, or a list of scalars matched whole (its order too)
        return bool(v) and all(scalar(x) or (isinstance(x, list) and all(scalar(y) for y in x)) for x in v)
    return bool(v) and all(schema_ok(x) for x in v)


def json_shape_ok(s, v):
    """True when value v fits schema s exactly: an object has exactly its keys, a list at most `max` items each fitting `of`, an
    int (never a bool) within [lo, hi], an enum value equal with its exact type (_same) to one listed, `any` one of its schemas."""
    (kind, spec), = s.items()
    if kind == "object":
        return isinstance(v, dict) and set(v) == set(spec) and all(json_shape_ok(spec[k], v[k]) for k in spec)
    if kind == "list":
        return isinstance(v, list) and len(v) <= spec["max"] and all(json_shape_ok(spec["of"], x) for x in v)
    if kind == "int":
        return type(v) is int and spec[0] <= v <= spec[1]
    if kind == "enum":
        return any(_same(v, x) for x in spec)
    return any(json_shape_ok(x, v) for x in spec)


def json_new_shape(pre, post, shape):
    """True when the item is new (no pre), its lines before the document are exactly shape["head"], and the document (strict
    JSON, _json_item) fits shape["doc"]."""
    b = _json_item(post)
    return pre is None and b is not None and b[0].splitlines() == shape["head"] and json_shape_ok(shape["doc"], b[1])


def json_new_exact(pre, post, exact):
    """True when the item is new, its lines before the document are exactly exact["head"], and the document is exact["doc"] with
    exact types and key order (_same). PR B, Codex round 2 (6): a scenario's map pinned value for value."""
    b = _json_item(post)
    if b is None or pre is not None or b[0].splitlines() != exact["head"]:
        return False
    doc = b[1]
    if isinstance(doc, dict) and isinstance(doc.get("at"), str) and EXACT_AT.fullmatch(doc["at"]):
        doc = dict(doc, at="<TS>")   # the one value that varies: when it was written (N1 normalizes it only when calibration needs it)
    return _same(doc, exact["doc"])


EXACT_AT = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})")
# Lines no narrow pattern accepts all of: a pattern that accepts every added (or every removed) one is refused as too broad.
BROAD_PROBES = (("+", "+zq 1", '+ "unrelated": [0]', "+<x>", NEW_ITEM, "+a", "+Z9 ~", '+   "k": "v",', "+\t#"),
                ("-", "-QX {}", '- "other": null', "-<y>", GONE_ITEM, "-b", "-Y8 ^", '-   "j": 2,', "-\t;"))


def _covers_a_side(compiled):
    """True when these patterns together accept every added or every removed probe line."""
    return any(all(any(c.search(p) for c in compiled) for p in probes) for probes in BROAD_PROBES)


def too_broad(rx):
    """True for a line pattern that is empty or accepts any added line or any removed line (.*, .+, ^[-+], ...)."""
    if not isinstance(rx, str) or not rx.strip():
        return True
    return _covers_a_side([re.compile(rx)])


def _entry_shape(e):
    """The entry's fields are EXPECT_FIELDS, or the same with json_change in place of lines_rx, each with its type."""
    if not isinstance(e, dict):
        return False
    want = dict(EXPECT_FIELDS)
    for alt, t in ALT_FIELDS.items():
        if alt in e:
            del want["lines_rx"]
            want[alt] = t
            break
    if set(e) != set(want) or not all(isinstance(e[k], t) for k, t in want.items()):
        return False
    if "block" in e:
        return bool(e["block"]) and all(isinstance(x, str) and (x[:1] in ("+", "-") or x == NEW_ITEM) for x in e["block"])
    if "json_exact" in e:
        ex = e["json_exact"]
        return set(ex) == set(JSON_SHAPE_FIELDS) and isinstance(ex["head"], list) and all(isinstance(x, str) for x in ex["head"]) and isinstance(ex["doc"], dict)
    if "json_shape" in e:
        sh = e["json_shape"]
        return (set(sh) == set(JSON_SHAPE_FIELDS) and all(isinstance(sh[k], t) for k, t in JSON_SHAPE_FIELDS.items())
                and all(isinstance(x, str) for x in sh["head"]) and schema_ok(sh["doc"]))
    j = e.get("json_change")
    return j is None or (set(j) == set(JSON_CHANGE_FIELDS) and j["field"].strip() != "" and j["from"] != j["to"]
                         and all(isinstance(j[k], t) and not isinstance(j[k], bool) for k, t in JSON_CHANGE_FIELDS.items()))


def parse_expect(doc, items):
    """The entries of the enabled `items` in an expect file's JSON: {"entries": [{item, scenario_rx, key_rx, lines_rx[] or
    json_change, must_see, why}]}. A line of a differing item ("+text" or "-text", diff_lines) is expected when an enabled entry's
    scenario_rx and key_rx search the scenario id and item name and one of its lines_rx searches the line; a json_change entry
    expects the whole item when only that field changed (json_only_change). ValueError for a malformed file, a pattern too_broad
    refuses, an entry whose patterns together accept any line, or a file whose entries together do (Codex round 1, 11); entries
    of other items are checked as strictly and then left out."""
    entries = doc.get("entries") if isinstance(doc, dict) else None
    if not isinstance(entries, list):
        raise ValueError("the expect file has no entries list")
    out, every = [], []
    for n, e in enumerate(entries):
        if not _entry_shape(e):
            raise ValueError(f"entry {n}: needs exactly {sorted(EXPECT_FIELDS)} with those types (or json_change {{field, from, to}} "
                             "or json_shape {head, doc} in place of lines_rx)")
        lines = e.get("lines_rx", [])
        if not e["why"].strip() or (not any(alt in e for alt in ALT_FIELDS) and not lines):
            raise ValueError(f"entry {n} ({e['item']}): an empty why or lines_rx")
        try:
            rxs = [re.compile(x) for x in (e["scenario_rx"], e["key_rx"])] + [re.compile(x) if isinstance(x, str) else None for x in lines]
        except re.error as err:
            raise ValueError(f"entry {n} ({e['item']}): bad pattern: {err}")
        broad = [x for x in lines if too_broad(x)]
        if broad:
            raise ValueError(f"entry {n} ({e['item']}): lines_rx {broad!r} would accept any line; write a narrow one")
        if lines and _covers_a_side(rxs[2:]):
            raise ValueError(f"entry {n} ({e['item']}): its lines_rx together would accept any line; write narrow ones")
        every += rxs[2:]
        if e["item"] in items:
            out.append(dict(e, id=n, _s=rxs[0], _k=rxs[1], _l=rxs[2:], _j=e.get("json_change"), _shape=e.get("json_shape"),
                            _exact=e.get("json_exact"), _block=e.get("block")))
    if every and _covers_a_side(every):
        raise ValueError("the entries' lines_rx together would accept any line; write narrow ones")
    return out


def _json_item(text):
    """(the item's lines before its JSON document, the document) or None: a tree item is "file <mode>" and, for a .gz, "gzip mtime
    <n>" lines, then the content."""
    if text is None:
        return None
    i = 0 if text.startswith(("{", "[")) else text.find("\n{") + 1
    if i == 0 and not text.startswith(("{", "[")):
        return None
    try:
        return text[:i], json.loads(text[i:], object_pairs_hook=_unique_pairs, parse_constant=_no_constant)
    except ValueError:
        return None


def _unique_pairs(pairs):
    """PR A, Codex round 2 (8): an object with a key twice is refused (json.loads keeps the last, hiding the first)."""
    out = {}
    for k, v in pairs:
        if k in out:
            raise ValueError(f"duplicate key {k!r}")
        out[k] = v
    return out


def _no_constant(name):
    raise ValueError(f"not JSON: {name}")   # NaN, Infinity, -Infinity


def _same(a, b):
    """Equal with exact types all the way down (1 is not true or 1.0) and object keys in the same order."""
    if type(a) is not type(b):
        return False
    if isinstance(a, dict):
        return list(a) == list(b) and all(_same(a[k], b[k]) for k in a)
    if isinstance(a, list):
        return len(a) == len(b) and all(_same(x, y) for x, y in zip(a, b))
    return a == b


def json_only_change(pre, post, change):
    """True when post is pre with exactly one change: the top-level field change["field"] is change["from"] in pre and
    change["to"] in post, and everything else (the lines before the document included) is equal once parsed. PR A, Codex round
    2 (8): both documents are strict JSON (no key twice, no NaN or Infinity) and equal with exact types (_same)."""
    a, b = _json_item(pre), _json_item(post)
    if a is None or b is None or a[0] != b[0] or not (isinstance(a[1], dict) and isinstance(b[1], dict)):
        return False
    f = change["field"]
    if f not in a[1] or f not in b[1] or not _same(a[1][f], change["from"]) or not _same(b[1][f], change["to"]):
        return False
    return _same(dict(a[1], **{f: change["to"]}), b[1])


def diff_lines(pre, post):
    """The lines by which `post` differs from `pre` (an item's text; None when the run has no such item): "+text" or "-text", a
    NEW_ITEM or GONE_ITEM line first when only one side has the item, and one "~" line when they differ in line ends only."""
    out = [NEW_ITEM] if pre is None else [GONE_ITEM] if post is None else []
    d = list(difflib.unified_diff((pre or "").splitlines(), (post or "").splitlines(), lineterm="", n=0))
    out += [x for x in d[2:] if not x.startswith("@@")]
    if not out and pre != post:
        out.append("~line ends differ")
    return out


def _block_span(lines, taken, run_):
    """([the positions of run_'s lines], [the other lines between them]) for the shortest stretch of not yet taken `lines` holding
    every line of run_ in order, or None when no stretch holds them all. A block's line left out, moved or changed is no match."""
    if not run_:
        return None
    best = None
    for start in (i for i, x in enumerate(lines) if x == run_[0] and not taken[i]):
        pos, i = [start], start + 1
        for want in run_[1:]:
            while i < len(lines) and (taken[i] or lines[i] != want):
                i += 1
            if i == len(lines):
                break
            pos.append(i)
            i += 1
        if len(pos) == len(run_) and (best is None or pos[-1] - pos[0] < best[-1] - best[0]):
            best = pos
    if best is None:
        return None
    return best, [i for i in range(best[0], best[-1] + 1) if i not in set(best) and not taken[i]]


def unexpected_lines(sid, key, pre, post, entries, hits):
    """The diff_lines of one differing item no entry expects; `hits` counts the lines each entry (by id) took."""
    cand = [e for e in entries if e["_s"].search(sid) and e["_k"].search(key)]
    lines = diff_lines(pre, post)
    whole = next((e for e in cand if (e["_j"] and json_only_change(pre, post, e["_j"])) or (e["_shape"] and json_new_shape(pre, post, e["_shape"]))
                  or (e.get("_exact") and json_new_exact(pre, post, e["_exact"]))), None)
    if whole is not None:   # exactly the one field changed, or a new item of exactly that shape or content: the whole item is expected
        hits[whole["id"]] = hits.get(whole["id"], 0) + len(lines)
        return []
    taken, bad = [False] * len(lines), []
    for e in cand:   # PR B, Codex round 2 (6): each block takes its run once, whole, before any pattern looks
        span = _block_span(lines, taken, e.get("_block"))
        if span is None:
            continue
        for i in span[0]:
            taken[i] = True
        for i in span[1]:   # a line inside the run that isn't one of its own: unexpected, whatever else might take it
            taken[i] = True
            bad.append(lines[i])
        hits[e["id"]] = hits.get(e["id"], 0) + len(span[0])
    cand = [e for e in cand if not e["_j"] and not e["_shape"] and not e.get("_exact") and not e.get("_block")]
    for line in [x for x, t in zip(lines, taken) if not t]:
        e = next((e for e in cand if any(r.search(line) for r in e["_l"])), None)
        if e is None:
            bad.append(line)
        else:
            hits[e["id"]] = hits.get(e["id"], 0) + 1
    return bad


EXACT_SCENARIOS = re.compile(r"\^(\((?:(?:[\w-]|\\-)+\|)*(?:[\w-]|\\-)+\)|(?:[\w-]|\\-)+)\$")   # ^(a|b-c)$, ^tierA$: literal ids only


def unmet(entries, hits_by, sids):
    """[(entry, scenario)]: the must_see entries that matched no line although one of their scenarios (`sids`: those compared)
    ran. PR B, Codex round 3 (4): an entry whose scenario_rx names its scenarios exactly (^(a|b)$, as item a's do) must match in
    each of them that ran, on its own (`hits_by` is {scenario: {entry id: lines}}): a scenario that left out its whole map or
    report section fails even when another scenario met the entry, and even when leaving it out made no difference from the
    baseline. A pattern (^box-) is met in any one of its scenarios, as before (PR A's changes don't happen in every box); the
    scenario is then the first of them that ran."""
    out = []
    for e in (e for e in entries if e["must_see"]):
        ran = [s for s in sids if e["_s"].search(s)]
        if EXACT_SCENARIOS.fullmatch(e["scenario_rx"]):
            out += [(e, s) for s in ran if not hits_by.get(s, {}).get(e["id"])]
        elif ran and not any(hits_by.get(s, {}).get(e["id"]) for s in ran):
            out.append((e, ran[0]))
    return out


# ------------------------------------------------------------------------------------------------ the check
def git(*args, **kw):
    return subprocess.run(["git", "-C", ROOT] + list(args), capture_output=True, check=True, timeout=120, **kw).stdout


class GoldenSplit(unittest.TestCase):
    PRE = os.environ.get("WT_GOLDEN_PRE", "")
    MODE = os.environ.get("WT_GOLDEN_TIERS", "full")
    EXPECT = os.environ.get("WT_GOLDEN_EXPECT", "")
    ITEMS = [x for x in os.environ.get("WT_GOLDEN_ITEMS", "").split(",") if x]
    expect = None   # expect mode: the enabled entries (parse_expect); None: post must equal pre

    @classmethod
    def setUpClass(cls):
        if not cls.PRE:
            raise RuntimeError("no baseline: run `bash scripts/golden-check.sh PRE_REF`, PRE_REF the commit before the split (9b106b9)")
        if cls.EXPECT:
            path = os.path.join(ROOT, cls.EXPECT)
            try:
                with open(path) as f:
                    cls.expect = parse_expect(json.load(f), cls.ITEMS)
            except (OSError, ValueError) as e:
                raise RuntimeError(f"expect file {cls.EXPECT}: {e}")
        cls.report = []
        cls.B = tempfile.mkdtemp(prefix="wt-golden-", dir="/tmp")
        real = os.path.realpath(cls.B)
        assert real.startswith("/tmp/") and not real.startswith("/workspace"), real
        cls.pre = os.path.join(cls.B, "trees", "pre")
        cls.post = os.path.join(cls.B, "trees", "post")
        os.makedirs(cls.pre); os.makedirs(cls.post)
        arch = subprocess.run(["git", "-C", ROOT, "archive", cls.PRE], capture_output=True, check=True, timeout=120).stdout
        subprocess.run(["tar", "-x", "-C", cls.pre], input=arch, check=True, timeout=120)
        for rel in git("ls-files", "-z").decode().split("\0"):
            if rel:
                os.makedirs(os.path.dirname(os.path.join(cls.post, rel)), exist_ok=True)
                shutil.copy2(os.path.join(ROOT, rel), os.path.join(cls.post, rel), follow_symlinks=False)
        cls.untracked = git("ls-files", "--others", "--exclude-standard", "watchtower").decode().split()
        cls.py = os.path.realpath(sys.executable)
        cls.sandbox = (not cls.py.startswith(("/home/", "/workspace/", "/tmp/", "/var/tmp/")) and shutil.which("unshare")
                       and subprocess.run(["unshare", "-rmn", "--propagation", "private", "true"], capture_output=True, timeout=30).returncode == 0)
        with open(os.path.join(cls.B, "runner.py"), "w") as f:
            f.write(RUNNER)
        with open(os.path.join(cls.B, ".golden-sentinel"), "w"):
            pass
        for d in ("out", "plans", "run"):
            os.makedirs(os.path.join(cls.B, d))
        cls.failed = False

    @classmethod
    def tearDownClass(cls):
        text = "\n".join(cls.report)
        with open(os.path.join(cls.B, "report.txt"), "w") as f:
            f.write(text + "\n")
        print("\n" + text)
        if cls.failed:
            print(f"golden check FAILED; everything is kept in {cls.B}")
        else:
            subprocess.run(["chmod", "-R", "u+rwx", cls.B], capture_output=True)
            shutil.rmtree(cls.B, ignore_errors=True)

    def say(self, line):
        self.report.append(line)

    def fail_with(self, msg):
        type(self).failed = True
        self.fail(msg)

    # -- step 0
    def test_0_reassembly(self):
        self.say(f"golden check: pre={self.PRE} ({git('rev-parse', '--short', self.PRE + '^{commit}').decode().strip()}), post=working tree, mode={self.MODE}")
        if self.untracked:
            self.fail_with(f"untracked files under watchtower/ (git add them): {self.untracked}")
        want = git("show", f"{self.PRE}:watchtower/wt.py")
        wt_post = read(os.path.join(self.post, "watchtower", "wt.py"))
        got, where = reassemble(wt_post, os.path.join(self.post, "watchtower", "wt_parts"))
        parts = len([w for w in where if w[1] != "wt.py"])
        if self.expect is not None:   # behavior changes on purpose: the reassembled file can't equal PRE's
            try:
                compile(got, "wt.py (reassembled)", "exec", dont_inherit=True)
            except SyntaxError as e:
                self.fail_with(f"step 0: the reassembled wt.py does not compile: {e}")
            if LOADER_BEGIN not in want:
                self.fail_with(f"step 0: {self.PRE}:watchtower/wt.py has no wt_parts loader block (expect mode compares split trees)")
            self.say(f"step 0: behavior-change mode, byte check not applicable (reassembled wt.py compiles: {len(got)} bytes, {parts} parts; "
                     f"{self.PRE} has the loader block; items: {','.join(self.ITEMS) or 'none'})")
            return
        if got != want:
            a, b = lines_of(want), lines_of(got)
            k = next((i for i, (x, y) in enumerate(zip(a, b)) if x != y), min(len(a), len(b)))
            self.fail_with(f"step 0: the reassembled wt.py differs from {self.PRE}:watchtower/wt.py at line {k + 1}")
        self.say(f"step 0 reassembly: byte-equal to {self.PRE}:watchtower/wt.py ({len(want)} bytes; {parts} parts; "
                 f"loader block {'present' if LOADER_BEGIN in wt_post else 'absent'}; D2 line {'present' if D2_NEW in wt_post else 'absent'})")

    # -- tiers
    def scenarios(self):
        quick = self.MODE == "quick"
        out = [("tierA", {"kind": "tierA", "all_cwds": not quick, "subcommands": list(SUBCOMMANDS)})]
        for prof in (("busy_clean_box",) if quick else PROFILES):
            for mode in ("cli", "driver"):
                out.append((f"box-{prof}-{mode}", {"kind": "box", "profile": prof, "mode": mode}))
        if not quick:
            out += [("crash", {"kind": "crash"}), ("extended", {"kind": "extended"}), ("tierC", {"kind": "tierC"})]
        only = os.environ.get("WT_GOLDEN_ONLY", "")
        if only:
            out = [s for s in out if re.search(only, s[0])]
            if not out:
                self.fail_with(f"ONLY={only!r} matches no {self.MODE} scenario, so nothing would be compared")
        return out

    def place(self, tree):
        code = os.path.join(self.B, "code")
        if os.path.isdir(code):
            shutil.rmtree(code)
        shutil.copytree(tree, code, symlinks=True)

    def run_sandboxed(self, sid, plan, tag):
        S = os.path.join(self.B, "run", sid)
        for d in ("home", "workspace", "var-tmp"):
            m = os.path.join(S, "mnt", d)
            if os.path.isdir(m):
                subprocess.run(["chmod", "-R", "u+rwx", m], capture_output=True)
                shutil.rmtree(m)
            os.makedirs(m)
            with open(os.path.join(m, ".golden-sentinel"), "w"):
                pass
        os.makedirs(os.path.join(S, "x"), exist_ok=True)
        plan = dict(plan, scratch=f"/tmp/run/{sid}", out=f"/tmp/out/{tag}-{sid}.json", tree="/tmp/code", sealed=True)
        with open(os.path.join(self.B, "plans", f"{tag}-{sid}.json"), "w") as f:
            json.dump(plan, f)
        p = subprocess.run(["unshare", "-rmn", "--propagation", "private", "/bin/bash", "-c", INNER, "golden", self.B, S,
                            f"/tmp/plans/{tag}-{sid}.json", self.py], capture_output=True, env={"PATH": "/usr/bin:/bin"}, timeout=3600)
        if p.returncode:
            self.fail_with(f"{sid} ({tag}): the sandbox run failed with {p.returncode}"
                           f"{' (a scratch mount is missing)' if p.returncode == 97 else ''}: {p.stderr.decode('utf-8', 'replace')[-1500:]}")
        with open(os.path.join(self.B, "out", f"{tag}-{sid}.json")) as f:
            return json.load(f)

    def test_1_tiers(self):
        if not self.sandbox:
            self.say("FAILED: no tier ran; nothing was compared")
            self.fail_with("unshare -rmn is unavailable (or Python lives under a folder the sandbox replaces): every tier needs the "
                           "sealed sandbox (tiers B and C read the computer's state), so nothing was compared")
        problems, used_cal, used_post = [], {}, {}
        enabled = {"N1", "N2", "N3", "N4", "N5", "N6", "N9"}
        needed = set()
        compared = 0
        hits, hits_by, sids, expected_items = {}, {}, [], 0
        for sid, plan in self.scenarios():
            res = {}
            sid_hits = hits_by.setdefault(sid, {})   # round 3 (4): what each entry took in this scenario alone
            for tag, tree in (("pre1", self.pre), ("pre2", self.pre), ("post", self.post)):
                self.place(tree)
                res[tag] = self.run_sandboxed(sid, plan, tag)["items"]
            crash = sid == "crash"
            a, b, c = res["pre1"], res["pre2"], res["post"]
            # calibration: pre against pre. Whatever differs must be covered by a rule; a rule is needed when the runs differ
            # without it, and only the rules calibration needs are applied to post.
            na, nb = norm_items(a, enabled), norm_items(b, enabled)
            bad_cal = differing(na, nb)
            for k in bad_cal:
                problems.append(f"[{sid}] calibration: pre differs from pre in {k!r} after normalization:\n"
                                f"{short_diff(na.get(k, '<missing>'), nb.get(k, '<missing>'))}")
            for r in sorted(enabled):
                extra = len(differing(norm_items(a, enabled - {r}), norm_items(b, enabled - {r}))) - len(bad_cal)
                if extra > 0:
                    needed.add(r)
                    used_cal[r] = used_cal.get(r, 0) + extra
            # N4 (durations) is always applied to post: two calibration runs can show the same tenths of a second by chance (after
            # S5, both pre runs timed pip-audit at 0.3 s and post at 0.4 s), so calibration can't be what turns it on.
            apply = needed | ALWAYS
            pa, pc = norm_items(a, apply, crash), norm_items(c, apply, crash)
            diff_post = differing(pa, pc)
            for k in diff_post:
                if self.expect is None:
                    problems.append(f"[{sid}] post differs from pre in {k!r}:\n{short_diff(pa.get(k, '<missing>'), pc.get(k, '<missing>'))}")
                    continue
                bad = unexpected_lines(sid, k, pa.get(k), pc.get(k), self.expect, sid_hits)
                if bad:
                    problems.append(f"[{sid}] post differs from pre in {k!r} by {len(bad)} line(s) no enabled entry expects:\n"
                                    + "\n".join("    | " + x[:220] for x in bad[:60]) + ("\n    | ..." if len(bad) > 60 else ""))
                else:
                    expected_items += 1
            sids.append(sid)
            for i, n in sid_hits.items():
                hits[i] = hits.get(i, 0) + n
            for r in sorted(apply | ({"N8"} if crash else set())):
                extra = len(differing(norm_items(a, apply - {r}, crash and r != "N8"), norm_items(c, apply - {r}, crash and r != "N8"))) - len(diff_post)
                if extra > 0:
                    used_post[r] = used_post.get(r, 0) + extra
            if crash:
                for k in sorted(set(a) & set(c)):
                    if frames(a[k]) != frames(c[k]):
                        problems.append(f"[{sid}] the crash frames' function sequence differs in {k!r}: {frames(a[k])} vs {frames(c[k])}")
            compared += 1
            n_cmds = len([k for k in a if k.endswith(" :rc")])
            self.say(f"{sid}: {n_cmds} commands, {len(a)} items; calibration {'ok' if not bad_cal else f'{len(bad_cal)} uncovered'}; "
                     f"post {'identical' if not diff_post else f'{len(diff_post)} differing items'}")
        if self.sandbox and self.MODE != "quick":
            self.timing()
        self.say("normalizations needed by calibration (items): " + (", ".join(f"{r} ({n})" for r, n in sorted(used_cal.items())) or "none"))
        self.say("normalizations applied where pre and post differed raw (items; N4 is always on): " + (", ".join(f"{r} ({n})" for r, n in sorted(used_post.items())) or "none"))
        if self.expect is not None:
            for e, s in unmet(self.expect, hits_by, sids):
                problems.append(f"[{e['item']}] must_see entry {e['id']} matched nothing in {s} (the intended change didn't happen there): {e['why']}")
            per = {}
            for e in self.expect:
                n, k = per.get(e["item"], (0, 0))
                per[e["item"]] = (n + hits.get(e["id"], 0), k + (1 if hits.get(e["id"]) else 0))
            self.say(f"expected differences ({expected_items} items fully expected), lines matched per item: "
                     + (", ".join(f"{i} {per.get(i, (0, 0))[0]} lines by {per.get(i, (0, 0))[1]} entries" for i in self.ITEMS) or "no items enabled"))
        if problems:
            self.say(f"PROBLEMS ({len(problems)}), one line each:")
            for p in problems:
                self.say("  - " + p.split("\n", 1)[0][:240])
            for p in problems[:40 if self.expect is None else 400]:   # expect mode: the list an allowlist is written from
                self.say(p)
            self.fail_with(f"{len(problems)} problems")
        if not compared:
            self.say("FAILED: no scenario was compared")
            self.fail_with("no scenario was compared, so nothing shows post == pre")
        if self.expect is not None:
            self.say(f"RESULT: post == pre on every tier run except the expected differences of {','.join(self.ITEMS) or 'no item'} "
                     f"({compared} scenarios compared)")
            return
        self.say(f"RESULT: post == pre on every tier run ({compared} scenarios compared)")

    def timing(self):
        res =self.run_sandboxed("timing", {"kind": "timing", "timing_trees": ["/tmp/trees/pre", "/tmp/trees/post"]}, "both")["timing"]
        for what in ("--version", "--help"):
            pre, post = statistics.median(res[f"pre {what}"]), statistics.median(res[f"post {what}"])
            flag = " FLAG: post is more than 10% slower" if post > pre * 1.10 else ""
            self.say(f"startup {what}: median pre {pre:.3f} s, post {post:.3f} s ({(post / pre - 1) * 100:+.1f}%) over 10 runs each{flag}")


if __name__ == "__main__":
    unittest.main()
