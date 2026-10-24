"""isr.py split into isr_bot/isr_parts (no behavior change; D1/D2/D3): the guards that keep the split honest.

Each part is a slice of the old isr.py. isr.py runs it inside its own namespace (decision D1) with _isr_part, compiled from the
part's source bytes, in the order of the _isr_part("<name>") lines. These tests hold that design: one namespace (G1), every part
loaded once and only from the explicit list (G2, G13), tracked and in the manifest (G3), no part binding the names the header
owns (G4), definition-time order (G5), the 3.8 grammar and absence checks the older source tests apply to isr.py alone (G6),
paths (G7), `python3 -I` from a hostile folder (G8), the installed copy and its tamper cases (G9-G13), the reassembled source
(G14), doctor's crash frames (G15, decision D2: a crash inside a part names it), no module import (G16) and no stdlib name (G17). The D3 line for a missing or
odd part is G12."""
import ast, builtins, hashlib, importlib.util, json, os, re, shutil, stat, subprocess, sys, tempfile, unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
W = os.path.join(ROOT, "isr_bot")
ISR_PY = os.path.join(W, "isr.py")
PARTS = os.path.join(W, "isr_parts")
sys.path.insert(0, W)
import isr  # noqa: E402
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from golden_split import BANNER, CALL, lines_of, read  # noqa: E402  (the reassembly the golden check uses)
from golden_split import reassemble as _reassemble  # noqa: E402

LOADER_NAMES = {"_ISR_PARTS", "_isr_part"}
D3 =("SELF-CHECK FAILED - ISR Bot stopped before doing anything. Its own file isr_bot/isr_parts/{}.py is missing or not a"
      " plain file. Tell the owner now. Don't run ISR Bot again until they reinstall it from the release (setup skill, section 1).")
DUNDERS = {"__name__", "__file__", "__doc__", "__builtins__", "__spec__", "__loader__", "__package__", "__cached__", "__annotations__"}


def part_calls(src=None):
    """The part names isr.py loads, in order: its `_isr_part("<name>")` lines."""
    return [m.group(1).decode() for m in map(CALL.match, lines_of(read(ISR_PY) if src is None else src)) if m]


def part_files(parts_dir=PARTS):
    return sorted(f[:-3] for f in os.listdir(parts_dir) if f.endswith(".py")) if os.path.isdir(parts_dir) else []


def reassemble(isr_bytes, parts_dir=PARTS):
    return _reassemble(isr_bytes, parts_dir)


def label_of(where, lineno):
    return [lab for first, lab in where if first <= lineno][-1]


def bound_names(node, out=None, into_classes=False):
    """Names a statement binds in the scope it runs in (function bodies, lambdas and comprehensions excluded; class bodies only
    when into_classes, for the names a class body binds for itself)."""
    out = set() if out is None else out
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        out.add(node.name)
        return out
    if isinstance(node, ast.ClassDef):
        out.add(node.name)
        if not into_classes:
            return out
    if isinstance(node, (ast.Lambda, ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)) and not into_classes:
        return out
    if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
        out.add(node.id)
    elif isinstance(node, ast.alias):
        out.add(node.asname or node.name.split(".")[0])
    elif isinstance(node, ast.ExceptHandler) and node.name:
        out.add(node.name)
    for c in ast.iter_child_nodes(node):
        bound_names(c, out, into_classes)
    return out


def deftime_loads(node, out=None):
    """Names a top-level statement reads while it runs: everything but function and lambda bodies (their decorators,
    defaults and annotations are read at definition time)."""
    out = set() if out is None else out
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
        a = node.args
        for x in a.defaults + [d for d in a.kw_defaults if d is not None]:
            deftime_loads(x, out)
        if not isinstance(node, ast.Lambda):
            for x in node.decorator_list + [node.returns] + [g.annotation for g in a.posonlyargs + a.args + a.kwonlyargs + [a.vararg, a.kwarg] if g]:
                if x is not None:
                    deftime_loads(x, out)
        return out
    if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
        out.add(node.id)
    for c in ast.iter_child_nodes(node):
        deftime_loads(c, out)
    return out


def tracked():
    r = subprocess.run(["git", "-C", ROOT, "ls-files", "-z"], capture_output=True, timeout=60)
    return [x.decode() for x in r.stdout.split(b"\0") if x] if r.returncode == 0 else None


def copy_tracked(dst):
    """A copy of this checkout's tracked files (what install.sh clones), without MANIFEST.sha256; returns the manifest lines."""
    lines = []
    for rel in tracked() or []:
        src = os.path.join(ROOT, rel)
        if rel == "MANIFEST.sha256" or not os.path.isfile(src) or os.path.islink(src):
            continue
        os.makedirs(os.path.dirname(os.path.join(dst, rel)), exist_ok=True)
        shutil.copy2(src, os.path.join(dst, rel))
        lines.append(f"{hashlib.sha256(read(src)).hexdigest()}  {rel}")
    return sorted(lines, key=lambda l: l.split(None, 1)[1])


HAS_PARTS = bool(part_calls())


class _Tmp(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="isr-bot-split-guard-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.home = os.path.join(self.tmp, "isr_home")
        for d in ("home", "decoys", "t", "isr_home"):
            os.makedirs(os.path.join(self.tmp, d), exist_ok=True)
        # built from scratch, so no PYTHONDONTWRITEBYTECODE from the suite's own environment
        self.env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": os.path.join(self.tmp, "home"), "ISR_BOT_HOME": self.home,
                    "ISR_BOT_DECOY_ROOT": os.path.join(self.tmp, "decoys"), "TMPDIR": os.path.join(self.tmp, "t"), "LC_ALL": "C.UTF-8"}

    def run_py(self, script, *argv, isolated=True, cwd=None, timeout=60):
        cmd = [sys.executable] + (["-I"] if isolated else []) + [script, *argv]
        return subprocess.run(cmd, capture_output=True, text=True, env=self.env, cwd=cwd or self.tmp, timeout=timeout)

    def dev_copy(self):
        d = os.path.join(self.tmp, "dev")
        copy_tracked(d)
        return d

    def installed(self):
        """An installed copy as test_v068_hardening.SelfCheck.install makes one: tracked files, their manifest, a .git naming a
        commit, and the same commit recorded in state."""
        app = os.path.join(self.home, "app")
        lines = copy_tracked(app)
        with open(os.path.join(app, "MANIFEST.sha256"), "w") as f:
            f.write("\n".join(lines) + "\n")
        os.makedirs(os.path.join(app, ".git"))
        with open(os.path.join(app, ".git", "HEAD"), "w") as f:
            f.write("a" * 40 + "\n")
        os.makedirs(os.path.join(self.home, "state"), exist_ok=True)
        with open(os.path.join(self.home, "state", "installed_commit"), "w") as f:
            f.write("a" * 40 + "\n")
        return app

    def caches(self, top):
        return sorted(os.path.relpath(dp, top) for dp, dns, _ in os.walk(top) if os.path.basename(dp) == "__pycache__")


class G01SharedGlobals(unittest.TestCase):
    def test_every_function_runs_in_isr_py_namespace(self):
        """D1: a monkeypatch of isr.X, `isr.X = ...` and `global X` reach every caller only while every function and method from
        isr.py and its parts has vars(isr) as its globals."""
        g = vars(isr)
        files = {os.path.realpath(ISR_PY)} | {os.path.realpath(os.path.join(PARTS, n + ".py")) for n in part_files()}
        seen = {}
        for name, v in list(g.items()):
            for f in [v] + (list(vars(v).values()) if isinstance(v, type) else []):
                f = getattr(f, "__func__", f)
                code = getattr(f, "__code__", None)
                if code is not None and os.path.realpath(code.co_filename) in files:
                    self.assertIs(f.__globals__, g, f"{name}: {code.co_filename}")
                    seen[os.path.realpath(code.co_filename)] = seen.get(os.path.realpath(code.co_filename), 0) + 1
        for n in part_files():
            p = os.path.join(PARTS, n + ".py")
            if any(isinstance(s, (ast.FunctionDef, ast.ClassDef)) for s in ast.parse(read(p)).body):
                self.assertTrue(seen.get(os.path.realpath(p)), f"no function of {n}.py is in isr.py's namespace")
        self.assertTrue(seen.get(os.path.realpath(ISR_PY)))


class G02PartsList(unittest.TestCase):
    def test_the_list_is_the_files_and_each_is_loaded_once(self):
        calls = part_calls()
        self.assertEqual(len(calls), len(set(calls)), calls)
        self.assertEqual(sorted(calls), part_files())
        self.assertFalse(os.path.lexists(os.path.join(PARTS, "__init__.py")), "isr_parts is not a package")
        for n in part_files():
            self.assertTrue(read(os.path.join(PARTS, n + ".py")).startswith(BANNER), n)
        tree = ast.parse(read(ISR_PY))
        top = [s.value.args[0].value for s in tree.body if isinstance(s, ast.Expr) and isinstance(s.value, ast.Call)
               and getattr(s.value.func, "id", None) == "_isr_part"]
        self.assertEqual(top, calls)                                            # every call is a plain top-level line
        anywhere = [n for n in ast.walk(tree) if isinstance(n, ast.Call) and getattr(n.func, "id", None) == "_isr_part"]
        self.assertEqual(len(anywhere), len(calls))
        spy = ("import builtins, collections, json, sys\nseen = collections.Counter(); real = builtins.compile\n"
               "def spy(src, fn, *a, **k):\n    seen[fn] += 1\n    return real(src, fn, *a, **k)\n"
               "builtins.compile = spy\nsys.path.insert(0, sys.argv[1])\nimport isr\nbuiltins.compile = real\n"
               "print(json.dumps(seen))\n")
        p = subprocess.run([sys.executable, "-I", "-B", "-c", spy, W], capture_output=True, text=True, timeout=60)
        self.assertEqual(p.returncode, 0, p.stderr)
        seen = json.loads(p.stdout)
        for n in part_files():
            self.assertEqual(seen.get(os.path.join(PARTS, n + ".py")), 1, n)
        self.assertFalse([f for f in seen if "isr_parts" in f and os.path.basename(f)[:-3] not in calls], seen)


class G03TrackedAndListed(unittest.TestCase):
    def test_every_part_is_tracked_and_in_the_manifest(self):
        files = tracked()
        if files is None:
            self.skipTest("not a git checkout")
        man = {}
        for line in read(os.path.join(ROOT, "MANIFEST.sha256")).decode().splitlines():
            h, rel = line.split(None, 1)
            man[rel.strip()] = h
        self.assertTrue(part_files())
        for n in part_files():
            rel = f"isr_bot/isr_parts/{n}.py"
            self.assertIn(rel, files, f"{rel} is not tracked (git add it)")
            self.assertEqual(man.get(rel), hashlib.sha256(read(os.path.join(ROOT, rel))).hexdigest(), f"{rel}: run scripts/make-manifest.sh")
        stray = [f for f in os.listdir(PARTS) if not f.endswith(".py") and f != "__pycache__"] if os.path.isdir(PARTS) else []
        self.assertEqual(stray, [])


def publish_walker():
    """The VERSION walker publish.sh runs on isr_bot/isr.py, taken from publish.sh itself."""
    text = read(os.path.join(ROOT, "scripts", "publish.sh")).decode()
    return text.split("<<'PYEOF'", 1)[1].split("\n", 1)[1].split("\nPYEOF\n", 1)[0] + "\n"


class G04HeaderNames(unittest.TestCase):
    def test_no_name_is_bound_in_two_files(self):
        owner = {}
        for label, src in [("isr.py", read(ISR_PY))] + [(n + ".py", read(os.path.join(PARTS, n + ".py"))) for n in part_files()]:
            for s in ast.parse(src).body:
                for name in bound_names(s):
                    self.assertIn(owner.setdefault(name, label), (label,), f"{name} is bound in {owner[name]} and {label}")

    def test_parts_never_bind_the_header_names_or_read_file(self):
        walker = publish_walker()
        for n in part_files():
            p = os.path.join(PARTS, n + ".py")
            src = read(p)
            # the name, not the text: scanners.py builds the lock reader's own namespace with a "__file__" key
            self.assertFalse([x.lineno for x in ast.walk(ast.parse(src)) if isinstance(x, ast.Name) and x.id == "__file__"], n)
            names = set()
            for s in ast.parse(src).body:
                for x in ast.walk(s):
                    names |= bound_names(x, into_classes=True) if isinstance(x, ast.stmt) else set()
                    if isinstance(x, (ast.Global, ast.Nonlocal)):
                        names |= set(x.names)
            self.assertFalse(names & {"VERSION", "HERE", "SELF_ROOT", "__file__"}, n)
            r = subprocess.run([sys.executable, "-I", "-", p], input=walker, capture_output=True, text=True, timeout=30)
            self.assertEqual(r.stdout.strip(), "0", f"publish.sh counts VERSION in {n}.py")
        r = subprocess.run([sys.executable, "-I", "-", ISR_PY], input=walker, capture_output=True, text=True, timeout=30)
        self.assertEqual(r.stdout.strip(), f"1 {isr.VERSION}")


class G05DefinitionOrder(unittest.TestCase):
    def test_each_statement_reads_only_names_bound_before_it(self):
        src, where = reassemble(read(ISR_PY))
        have = set(dir(builtins)) | DUNDERS
        for s in ast.parse(src).body:
            missing = deftime_loads(s) - bound_names(s, into_classes=True) - have
            self.assertFalse(missing, f"{label_of(where, s.lineno)} (reassembled line {s.lineno}) reads {sorted(missing)} before they are bound")
            have |= bound_names(s)


SOURCE_ABSENT = ("wt-dry",                                     # test_dry_run_sandbox: no name-based skip for dry-run folders
                 "ships with no entries",                      # test_item8_churn: the lock header names the exception
                 "install semgrep for deeper analysis",        # test_batch3_selfcheck_docs: no unchecked semgrep advice
                 "Remove the three Ask-first rules")           # test_v068_hardening: uninstall keeps them
NEWER_API = ("removeprefix(", "removesuffix(", "zip(strict", "math.lcm", "tomllib", "ExceptionGroup", "from zoneinfo")   # test_profiles


class G06SourceChecksOnEveryPart(unittest.TestCase):
    def test_parts_keep_the_38_grammar_and_the_absence_checks(self):
        for n in part_files():
            src = read(os.path.join(PARTS, n + ".py")).decode("utf-8")
            ast.parse(src, feature_version=(3, 8))
            for s in NEWER_API + SOURCE_ABSENT:
                self.assertNotIn(s, src, f"{n}.py")


class G07Paths(unittest.TestCase):
    def test_paths_resolve_to_the_checkouts_own_files(self):
        probe = ("import json, os, sys\nsys.path.insert(0, sys.argv[1])\nimport isr\n"
                 "print(json.dumps({k: os.path.realpath(v) for k, v in {'file': isr.__file__, 'here': isr.HERE, 'root': isr.SELF_ROOT,"
                 " 'rules': isr.RULES_PATH, 'platform': isr.PLATFORM_LOCK, 'scanners': isr.SCANNER_LOCK, 'feeds': isr.FEEDS_PATH,"
                 " 'reader': os.path.join(isr.HERE, '..', isr.LOCK_READER_REL), 'parts': isr._ISR_PARTS}.items()}))\n")
        p = subprocess.run([sys.executable, "-I", "-B", "-c", probe, W], capture_output=True, text=True, timeout=60)
        self.assertEqual(p.returncode, 0, p.stderr)
        got = json.loads(p.stdout)
        r = os.path.realpath(ROOT)
        want = {"file": "isr_bot/isr.py", "here": "isr_bot", "root": "", "rules": "rules/text_rules.json",
                "platform": "rules/platform-release.lock", "scanners": "scripts/scanner-bins.lock", "feeds": "rules/feeds.json",
                "reader": "scripts/scanner_lock.py", "parts": "isr_bot/isr_parts"}
        self.assertEqual(got, {k: os.path.join(r, v) if v else r for k, v in want.items()})
        for k in ("file", "rules", "platform", "scanners", "feeds", "reader"):
            self.assertTrue(os.path.isfile(got[k]), k)


class G08HostileFolder(_Tmp):
    def test_python_I_from_a_folder_with_planted_modules(self):
        cwd = os.path.join(self.tmp, "cwd")
        marker = os.path.join(self.tmp, "MARKER")
        plant = f"open({marker!r}, 'a').write(__name__ + chr(10))\n"
        os.makedirs(os.path.join(cwd, "isr_parts"))
        for n in set(part_calls()) | {"state", "zz"}:
            with open(os.path.join(cwd, "isr_parts", n + ".py"), "w") as f:
                f.write(BANNER.decode() + plant)
        for n in ("json", "secrets", "re", os.path.splitext(os.path.basename(ISR_PY))[0], "isr_parts/__init__"):
            with open(os.path.join(cwd, n + ".py"), "w") as f:
                f.write(plant)
        self.env["PYTHONPATH"] = cwd                                            # -I ignores it
        p = self.run_py(ISR_PY, "--version", cwd=cwd)
        self.assertEqual((p.returncode, p.stdout, p.stderr), (0, isr.VERSION + "\n", ""))
        p = self.run_py(ISR_PY, "vet", os.path.join(ROOT, "tests", "fixtures", "clean", "meeting-notes", "SKILL.md"), "--json", cwd=cwd)
        self.assertNotIn("Traceback", p.stderr)
        json.loads(p.stdout)
        self.assertFalse(os.path.exists(marker), "a planted file ran")


@unittest.skipUnless(HAS_PARTS, "no parts yet")
class G09InstalledCopy(_Tmp):
    def test_a_clean_install_runs_and_writes_no_bytecode_cache(self):
        app = self.installed()
        for isolated in (False, True):
            p = self.run_py(os.path.join(app, "isr_bot", "isr.py"), "status", isolated=isolated)
            self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
            self.assertNotIn("SELF-CHECK FAILED", p.stdout + p.stderr)
            p = self.run_py(os.path.join(app, "isr_bot", "isr.py"), "--version", isolated=isolated)
            self.assertEqual((p.returncode, p.stdout), (0, isr.VERSION + "\n"))
        self.assertEqual(self.caches(app), [])


@unittest.skipUnless(HAS_PARTS, "no parts yet")
class G10TamperedPart(_Tmp):
    def test_a_changed_part_stops_every_run(self):
        app = self.installed()
        n = part_calls()[len(part_calls()) // 2]
        with open(os.path.join(app, "isr_bot", "isr_parts", n + ".py"), "a") as f:
            f.write("# changed after install\n")
        p = self.run_py(os.path.join(app, "isr_bot", "isr.py"), "--version")
        self.assertEqual(p.returncode, 4, p.stdout)
        self.assertIn("SELF-CHECK FAILED", p.stdout); self.assertIn("1 problem (", p.stdout)
        self.assertNotIn(isr.VERSION + "\n", p.stdout)
        p = self.run_py(os.path.join(app, "isr_bot", "isr.py"), "status")
        self.assertEqual(p.returncode, 4, p.stdout)
        self.assertIn(f"isr_bot/isr_parts/{n}.py changed since install", p.stdout)


def forged_pyc(src_path, marker):
    """A bytecode cache for src_path with the source's own mtime and size (so a normal import would trust it) whose code only
    writes marker (Codex, batch 3 round 2: test_batch3_fix_round2.CachedReader)."""
    code = compile(f"open({marker!r}, 'a').write('forged ' + __name__ + chr(10))\n", src_path, "exec")
    st = os.stat(src_path)
    cache = importlib.util.cache_from_source(src_path)
    os.makedirs(os.path.dirname(cache), exist_ok=True)
    with open(cache, "wb") as f:
        f.write(importlib._bootstrap_external._code_to_timestamp_pyc(code, int(st.st_mtime), st.st_size))
    return cache


@unittest.skipUnless(HAS_PARTS, "no parts yet")
class G11ForgedBytecode(_Tmp):
    def check(self, top, argvs):
        script = os.path.join(top, "isr_bot", "isr.py")
        clean = [self.run_py(script, *a, isolated=False) for a in argvs]
        marker = os.path.join(self.tmp, "FORGED")
        for n in part_calls():
            forged_pyc(os.path.join(top, "isr_bot", "isr_parts", n + ".py"), marker)
        again = [self.run_py(script, *a, isolated=False) for a in argvs]
        self.assertFalse(os.path.exists(marker), "a planted bytecode cache ran")
        self.assertEqual([(p.returncode, p.stdout, p.stderr) for p in again], [(p.returncode, p.stdout, p.stderr) for p in clean])

    def test_installed_copy(self):
        app = self.installed()
        self.check(app, (["--version"], ["status"]))
        p = self.run_py(os.path.join(app, "isr_bot", "isr.py"), "status")
        self.assertNotIn("SELF-CHECK FAILED", p.stdout)                        # self-check still skips __pycache__

    def test_developer_checkout(self):
        self.check(self.dev_copy(), (["--version"], ["status"], ["vet", os.path.join(ROOT, "tests", "fixtures", "bad", "exfil-helper", "SKILL.md"), "--json"]))


@unittest.skipUnless(HAS_PARTS, "no parts yet")
class G12MissingOrOddPart(_Tmp):
    def stops(self, dev, n, how):
        p = self.run_py(os.path.join(dev, "isr_bot", "isr.py"), "--version", timeout=30)
        self.assertEqual((p.returncode, p.stdout, p.stderr), (4, D3.format(n) + "\n", ""), how)

    def test_d3_line_for_each_kind(self):
        dev = self.dev_copy()
        calls = part_calls()
        for n in sorted({calls[0], calls[-1]}):
            p = os.path.join(dev, "isr_bot", "isr_parts", n + ".py")
            good = read(p)
            keep = os.path.join(self.tmp, n + ".good")
            with open(keep, "wb") as f:
                f.write(good)
            cases = {"deleted": lambda: os.remove(p), "a link to a good copy": lambda: (os.remove(p), os.symlink(keep, p)),
                     "a FIFO": lambda: (os.remove(p), os.mkfifo(p)), "a folder": lambda: (os.remove(p), os.mkdir(p)),
                     "garbage bytes": lambda: open(p, "wb").write(b"\x00\xff\xfe garbage (((\n")}
            for how, make in cases.items():
                make()
                try:
                    self.stops(dev, n, how)
                except subprocess.TimeoutExpired:
                    self.fail(f"{n}.py as {how}: the run hung")
                finally:
                    if os.path.isdir(p) and not os.path.islink(p):
                        os.rmdir(p)
                    elif os.path.lexists(p):
                        os.remove(p)
                    with open(p, "wb") as f:
                        f.write(good)
            p2 = self.run_py(os.path.join(dev, "isr_bot", "isr.py"), "--version")
            self.assertEqual(p2.stdout, isr.VERSION + "\n")


@unittest.skipUnless(HAS_PARTS, "no parts yet")
class G13RoguePart(_Tmp):
    def plant(self, top):
        marker = os.path.join(self.tmp, "ROGUE")
        with open(os.path.join(top, "isr_bot", "isr_parts", "zz.py"), "w") as f:
            f.write(BANNER.decode() + f"open({marker!r}, 'a').write('rogue' + chr(10))\n")
        return marker

    def test_an_extra_part_never_runs(self):
        dev = self.dev_copy()
        marker = self.plant(dev)
        for argv in (["--version"], ["status"]):
            p = self.run_py(os.path.join(dev, "isr_bot", "isr.py"), *argv)
            self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        app = self.installed()
        self.plant(app)
        p = self.run_py(os.path.join(app, "isr_bot", "isr.py"), "status")
        self.assertEqual(p.returncode, 4, p.stdout)
        self.assertIn("isr_bot/isr_parts/zz.py is not in the release", p.stdout)
        self.assertFalse(os.path.exists(marker), "the rogue part ran")


class G14Reassembly(unittest.TestCase):
    def test_reassembled_source_compiles_and_names_match_the_module(self):
        src, _ = reassemble(read(ISR_PY))
        tree = ast.parse(src)
        compile(src, "reassembled isr.py", "exec", dont_inherit=True)
        names = set()
        for s in tree.body:
            names |= bound_names(s)
        probe = "import json, sys\nsys.path.insert(0, sys.argv[1])\nimport isr\nprint(json.dumps(sorted(vars(isr))))\n"
        p = subprocess.run([sys.executable, "-I", "-B", "-c", probe, W], capture_output=True, text=True, timeout=60)
        self.assertEqual(p.returncode, 0, p.stderr)
        live = set(json.loads(p.stdout)) - DUNDERS
        self.assertEqual(live - LOADER_NAMES, names - DUNDERS)
        self.assertLessEqual(LOADER_NAMES, live)


class G15DoctorFrames(unittest.TestCase):
    """D2: doctor's last_error.where keeps Watchtower's own frames, from isr.py and from its parts, each labelled with a short
    name (never a path prefix); any other frame is dropped (it can carry private paths)."""

    def test_part_frames_are_kept_with_a_short_label(self):
        text = ("2026-10-18T10:00:00 isr.py audit (v0.7.1)\nTraceback (most recent call last):\n"
                '  File "/workspace/isr-bot/app/isr_bot/isr.py", line 120, in main\n    x()\n'
                '  File "/workspace/isr-bot/app/isr_bot/isr_parts/engines.py", line 5, in engine_findings\n    y()\n'
                '  File "/usr/lib/python3.13/json/__init__.py", line 293, in load\n    z()\n'
                '  File "/home/box/acme-payroll/helper.py", line 7, in salaries\n    w()\n'
                "RuntimeError: /home/box/acme-payroll/salaries-2026.csv\n")
        d = isr.shareable_error(text)
        self.assertEqual(d["where"], ["isr.py line 120 in main", "isr_parts/engines.py line 5 in engine_findings"])
        self.assertEqual(d["error_type"], "RuntimeError")
        self.assertNotIn("acme-payroll", json.dumps(d))
        self.assertNotIn("/isr_bot/", json.dumps(d["where"]))
        self.assertNotIn("/isr-bot/", json.dumps(d["where"]))

    def test_a_real_crash_inside_a_part(self):
        import traceback
        from unittest import mock

        def boom():
            raise RuntimeError("private /home/box/acme-payroll")
        with mock.patch.object(isr, "home", boom):
            try:
                isr.state_path("x")
            except RuntimeError:
                text = "2026-10-18T10:00:00 isr.py status (v0.7.1)\n" + traceback.format_exc()
        frame = [ln for ln in text.splitlines() if "isr_parts/state.py" in ln]
        self.assertEqual(len(frame), 1, text)
        n = re.search(r"line (\d+), in state_path", frame[0]).group(1)
        self.assertEqual(isr.shareable_error(text)["where"], [f"isr_parts/state.py line {n} in state_path"])


class G16NoModuleImport(unittest.TestCase):
    def test_parts_are_never_modules(self):
        self.assertEqual([m for m in sys.modules if "isr_parts" in m], [])
        probe = ("import json, sys\nsys.path.insert(0, sys.argv[1])\nimport isr\n"
                 "print(json.dumps([m for m in sys.modules if 'isr_parts' in m or m in sys.argv[2:]]))\n")
        p = subprocess.run([sys.executable, "-I", "-B", "-c", probe, W, *part_calls()], capture_output=True, text=True, timeout=60)
        self.assertEqual((p.returncode, json.loads(p.stdout or "null")), (0, []), p.stderr)


class G17NoStdlibName(unittest.TestCase):
    def test_no_part_is_named_like_a_module(self):
        std = set(getattr(sys, "stdlib_module_names", ()))
        for n in part_files():
            self.assertNotIn(n, std | {os.path.splitext(os.path.basename(ISR_PY))[0]})
            self.assertIsNone(importlib.util.find_spec(n), n)


if __name__ == "__main__":
    unittest.main()
