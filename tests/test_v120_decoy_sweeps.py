"""v1.2.0: benign sweeps never set off a decoy alarm (plan decoy-false-trips-20261112, sections 2 and 4).

Nov 11 14:01:07Z: a routine's recursive content sweep of /tmp, /workspace and /home/box read the /tmp decoy and not the /var/tmp
ones, and ISR-K001 critical fired. From v1.2.0 each decoy has chaff beside it and each decoy root a far sentinel: a read is a
sweep (ISR-K008, info) only when the chaff beside it was read within 5 s AND something far from it was read within 180 s.

Every test runs on a sandboxed computer (Sandbox): ISR_BOT_DECOY_ROOT is the test's own temp folder, which holds its own tmp,
var/tmp, workspace and home/box stand-ins, each filled with ordinary files read three days ago. The real /tmp and /var/tmp
decoys are never touched; every test asserts it. Decoy values are compared by hash only and never printed.

Tests whose name holds "replay" (and carry "# replay: fails on 7da4c44") fail on 7da4c44 at their assertion; the others guard
what must not change. gitleaks and TruffleHog run only when on PATH (the only other copy is the live install's, which tests may
not touch); otherwise those two tests are skipped with the reason, and a report of the same shape is checked by a guard test."""
import hashlib, json, os, re, shutil, subprocess, sys, time, unittest
from unittest import mock
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_boxes import Box  # noqa: E402  (test_boxes puts isr_bot on sys.path)
import isr  # noqa: E402

IOC = "c2-beacon-7f3a.invalid"   # what the sweep searches for; no sandbox file holds it
FILLER = 320                     # ordinary files per sandbox root (plan: 300 to 2,000)
DAY = 86400


def fill(root, n=FILLER, folders=16):
    """n ordinary files in `folders` folders under root, last written two days ago and last read three days ago."""
    old = time.time()
    for i in range(n):
        d = os.path.join(root, f"proj-{i % folders:02d}", "notes" if i % 3 else "docs")
        os.makedirs(d, exist_ok=True)
        p = os.path.join(d, f"file-{i:04d}.txt")
        with open(p, "w") as f:
            f.write(f"Ordinary file {i}. Meeting notes and a to-do list.\n")
        os.utime(p, (old - 3 * DAY, old - 2 * DAY))      # atime below mtime: the next read moves it, relatime or not


def text_of(p):
    with open(p, encoding="utf-8", errors="replace") as f:
        return f.read()


def value_of(p):
    """The 16-hex value inside a decoy file (any case). Kept in memory only; tests compare it by hash."""
    m = re.search(r"rk_live_([0-9a-f]{16})|AKIA([0-9A-F]{16})|,([0-9a-f]{16})@", text_of(p))
    return next(g for g in m.groups() if g).lower()


def digest(v):
    return hashlib.sha256(v.encode()).hexdigest()


def holds_value(text, value):
    """True when any 16-hex window of text (any case) hashes to the value's hash: the value is never compared in the clear."""
    want = digest(value)
    low = text.lower()
    return any(digest(low[i:i + 16]) == want for i in range(max(0, len(low) - 15)) if re.fullmatch(r"[0-9a-f]{16}", low[i:i + 16]))


class Sandbox(Box):
    """A Box whose decoy root is the box's own temp folder: <tmp>/tmp, <tmp>/var/tmp, <tmp>/workspace (the box's workspace)
    and <tmp>/home/box (the box's $HOME), each with FILLER ordinary files. Decoys are planted with `isr.py canary plant`."""

    def setUp(self):
        super().setUp()
        os.environ["ISR_BOT_DECOY_ROOT"] = self.tmp
        self.tmpd, self.vartmp = isr.decoy_path("/tmp"), isr.decoy_path("/var/tmp")
        for d in (self.tmpd, self.vartmp, self.ws, self.home):
            fill(d)
        code, o, e = self.run_cmd("canary", "plant")
        self.assertEqual(code, 0, e)
        self.reg = isr.load_json(isr.state_path("canaries.json"), {})
        self.assertEqual(len(self.reg), 3)
        self.assert_sandboxed()
        for folder in sorted({os.path.dirname(v["path"]) for v in self.reg.values()}):
            if isr.reads_recorded(folder) is not True:
                self.skipTest("this temp mount records no file reads (noatime): the sweep rule has nothing to judge here")
        time.sleep(0.2)                                   # coarse file clocks: every read below is stamped after the plant

    def assert_sandboxed(self):
        """Plan acceptance 4: every decoy place, the decoy roots, the workspace and $HOME are inside this test's temp folder."""
        top = os.path.realpath(self.tmp) + os.sep
        places = [isr.decoy_path(x) for x in ("/tmp", "/var/tmp", "/workspace")] + [os.path.expanduser("~"), os.environ["ISR_BOT_HOME"]]
        places += [v["path"] for v in isr.load_json(isr.state_path("canaries.json"), {}).values()]
        self.assertEqual([p for p in places if not os.path.realpath(p).startswith(top)], [])
        self.assertNotIn(isr.decoy_path("/tmp"), ("/tmp", "/tmp/"))
        self.assertEqual(isr.decoy_path("/workspace"), self.ws)

    def path_of(self, name):
        return self.reg[name]["path"]

    def tool(self, *argv, **kw):
        """Run a real tool against the sandbox only (its output is never printed: it may hold a decoy's contents)."""
        top = os.path.realpath(self.tmp)
        for a in argv[1:]:
            if a.startswith("/"):
                self.assertTrue(os.path.realpath(a) == top or os.path.realpath(a).startswith(top + os.sep), "a tool was pointed outside the sandbox")
        return subprocess.run(list(argv), capture_output=not ("stdout" in kw or "stderr" in kw), timeout=300, cwd=self.tmp, **kw)

    def judged(self):
        """The decoy findings of one recording check, as (rule, severity, where)."""
        return [(f["rule"], f["severity"], f["where"]) for f in isr.canary_findings()]

    def rules(self, fs):
        return sorted(r for r, _, _ in fs)


class SweepsAreK008(Sandbox):
    def test_replay_grep_r_of_tmp_workspace_and_home_is_one_k008_not_k001(self):   # replay: fails on 7da4c44
        # Nov 11: an IOC content sweep of /tmp, /workspace and /home/box (not /var/tmp)
        self.tool("grep", "-rI", IOC, self.tmpd, self.ws, self.home)
        got = self.judged()
        self.assertNotIn("ISR-K001", self.rules(got))
        self.assertEqual([(r, s) for r, s, _ in got], [("ISR-K008", "info")])
        self.assertIn(os.path.dirname(self.path_of("api-env")), got[0][2])

    def test_replay_rg_uu_is_k008_not_k001(self):   # replay: fails on 7da4c44
        if not shutil.which("rg"):
            self.skipTest("rg is not installed")
        self.tool("rg", "-uu", IOC, self.tmpd, self.ws, self.home)
        got = self.judged()
        self.assertNotIn("ISR-K001", self.rules(got))
        self.assertEqual([(r, s) for r, s, _ in got], [("ISR-K008", "info")])

    def test_replay_find_exec_cat_both_forms_are_k008_not_k001(self):   # replay: fails on 7da4c44
        for form in (["-type", "f", "-exec", "cat", "{}", "+"], ["-name", "*.env", "-exec", "cat", "{}", "+"]):
            with self.subTest(form=" ".join(form[:2])):
                self.tool("find", self.tmpd, self.ws, self.home, *form)
                got = self.judged()
                self.assertNotIn("ISR-K001", self.rules(got))
                self.assertEqual([(r, s) for r, s, _ in got], [("ISR-K008", "info")])

    def test_replay_content_indexer_reading_every_file_every_50ms_is_k008(self):   # replay: fails on 7da4c44
        # an indexer or antivirus stand-in: every file of the four sandbox roots, one every 50 ms, for 60 s at most
        t0 = time.monotonic()
        for root in (self.tmpd, self.vartmp, self.ws, self.home):
            for dp, dns, fns in os.walk(root):
                dns.sort()
                for fn in sorted(fns):
                    if time.monotonic() - t0 > 60:
                        break
                    try:
                        with open(os.path.join(dp, fn), "rb") as f:
                            f.read()
                    except OSError:
                        pass                              # the mode-000 witness: an ordinary user can't read it
                    time.sleep(0.05)
        got = self.judged()
        self.assertNotIn("ISR-K001", self.rules(got))
        self.assertNotIn("ISR-K004", self.rules(got))
        self.assertEqual([(r, s) for r, s, _ in got], [("ISR-K008", "info")])

    def test_replay_tar_and_cp_a_of_tmp_are_a_sweep_and_the_tree_copy_is_k009(self):   # replay: fails on 7da4c44
        out = os.path.join(self.ws, "copies"); os.makedirs(out)
        self.tool("tar", "czf", os.path.join(out, "tmp.tar.gz"), "-C", self.tmp, "tmp")
        self.tool("tar", "cf", os.path.join(out, "tmp.tar"), "-C", self.tmp, "tmp")
        self.tool("cp", "-a", self.tmpd, os.path.join(out, "copy-of-tmp"))
        self.audit()
        fs = self.snap()["findings"]
        rules = [f["rule"] for f in fs if f["rule"].startswith("ISR-K")]
        self.assertNotIn("ISR-K001", rules)
        self.assertNotIn("ISR-K003", rules)
        self.assertIn("ISR-K008", rules)
        k9 = [f for f in fs if f["rule"] == "ISR-K009"]
        self.assertEqual([(f["severity"], f["where"].startswith(os.path.join(out, "copy-of-tmp") + os.sep)) for f in k9], [("info", True)])

    def test_replay_gitleaks_report_is_k009_not_k003(self):   # replay: fails on 7da4c44
        exe = shutil.which("gitleaks")
        if not exe:
            self.skipTest("gitleaks is not on PATH; the only other copy is the live install's scanners folder, which tests may not touch")
        report = os.path.join(self.ws, "gitleaks-report.json")
        self.tool(exe, "detect", "--no-git", "--source", self.tmp, "--report-format", "json", "--report-path", report, "--exit-code", "0")
        self.audit()
        fs = self.snap()["findings"]
        self.assertNotIn("ISR-K001", [f["rule"] for f in fs])
        self.assertEqual([f["rule"] for f in fs if f["where"] == report and f["rule"].startswith("ISR-K")], ["ISR-K009"])

    def test_replay_trufflehog_report_is_k009_not_k003(self):   # replay: fails on 7da4c44
        exe = shutil.which("trufflehog")
        if not exe:
            self.skipTest("trufflehog is not on PATH; the only other copy is the live install's scanners folder, which tests may not touch")
        report = os.path.join(self.ws, "trufflehog.json")
        with open(report, "w") as f:
            self.tool(exe, "filesystem", self.tmp, "--json", "--no-verification", "--no-update", stdout=f)
        self.audit()
        fs = self.snap()["findings"]
        self.assertNotIn("ISR-K001", [f["rule"] for f in fs])
        self.assertEqual([f["rule"] for f in fs if f["where"] == report and f["rule"].startswith("ISR-K")], ["ISR-K009"])


class TargetedReadsStayCritical(Sandbox):
    def test_cat_of_one_decoy_alone_is_k001_critical(self):   # guard
        self.tool("cat", self.path_of("api-env"))
        self.assertEqual([(r, s) for r, s, _ in self.judged()], [("ISR-K001", "critical")])

    def test_cat_of_the_decoy_folder_with_its_chaff_but_nothing_far_is_k001_critical(self):   # guard
        folder = os.path.dirname(self.path_of("api-env"))
        self.tool("sh", "-c", 'cat "$1"/* 2>/dev/null; true', "sh", folder)
        self.assertTrue(isr.chaff_reads(isr.load_json(isr.state_path(isr.CHAFF_STATE), {})))   # the chaff was read with it
        self.assertEqual([(r, s) for r, s, _ in self.judged()], [("ISR-K001", "critical")])

    def test_a_chaff_or_sentinel_whose_read_time_was_set_by_hand_proves_nothing(self):   # guard
        p = self.path_of("api-env")
        self.tool("cat", p)
        now = time.time()
        for c in list(isr.chaff_paths()) + list(isr.sentinel_paths()):
            os.utime(c, (now, os.stat(c).st_mtime))         # `touch -a` on every chaff and sentinel: a new ctime
        self.assertEqual([(r, s) for r, s, _ in self.judged()], [("ISR-K001", "critical")])

    def test_two_decoys_cat_together_without_a_sweep_stay_k004_high(self):   # guard
        self.tool("cat", self.path_of("customers"), self.path_of("cloud-keys"))
        self.assertEqual([(r, s) for r, s, _ in self.judged()], [("ISR-K004", "high")])


class K008IsACalmDailyLine(Sandbox):
    def test_k008_is_one_updated_line_a_day_logged_never_scored_and_not_in_the_daily_alarms(self):   # guard
        self.skills(1); self.audit()
        for _ in range(2):
            self.tool("grep", "-rI", IOC, self.tmpd, self.ws, self.home)
            code, o, _ = self.run_cmd("daily", "--roots", *self.roots)
            self.assertNotIn("ISR-K008", json.dumps(json.loads(o).get("decoys", [])) if o.startswith("{") else o)
            time.sleep(1.2)
        k8 = [f for f in self.snap()["findings"] if f["rule"] == "ISR-K008"]
        self.assertEqual(len(k8), 1)
        self.assertEqual((k8[0]["severity"], k8[0]["label"]), ("info", isr.CONFIRMED))
        self.assertIn("2 sweeps that day", k8[0]["evidence"])
        self.assertEqual(isr.status_of(isr.scored([k8[0]])), "All good")
        self.assertEqual(isr.score(isr.scored([k8[0]])), (100, "A"))
        read = [json.loads(x) for x in text_of(isr.state_path("ledger.jsonl")).splitlines() if '"canary-read"' in x]
        self.assertEqual(len(read), 2)
        self.assertTrue(all(e["sweep"]["api-env"]["sweep"] and e["sweep"]["api-env"]["chaff"] >= 1 for e in read))
        self.assertIn("A file sweep passed over a decoy", isr.render_md(self.snap(), [], "t"))   # the weekly report shows it

    def test_session_logs_with_a_tool_call_near_the_read_are_named_by_path(self):   # guard
        def log(rel, at):
            p = os.path.join(self.home, ".claude", "projects", "-workspace", rel)
            os.makedirs(os.path.dirname(p), exist_ok=True)
            stamp = time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime(at))
            with open(p, "w") as f:
                f.write(json.dumps({"type": "assistant", "timestamp": stamp, "message": {"content": [
                    {"type": "tool_use", "name": "Bash", "input": {"command": "ls"}}]}}) + "\n")
            return p
        near, far = log("near.jsonl", time.time()), log("far.jsonl", time.time() - 3600)
        self.tool("cat", self.path_of("api-env"))
        f = isr.canary_findings()[0]
        self.assertEqual((f["rule"], f["sessions"]), ("ISR-K001", [near]))
        self.assertIn("near.jsonl", f["fix"])
        self.assertNotIn(far, json.dumps(f))
        self.tool("grep", "-rI", IOC, self.tmpd, self.ws, self.home)
        f = isr.canary_findings()[0]
        self.assertEqual((f["rule"], f["sessions"]), ("ISR-K008", [near]))


class ChaffNeverThroughALink(Sandbox):
    def test_a_link_where_a_chaff_file_or_a_sentinel_folder_goes_is_refused_as_k006(self):   # guard
        victim = os.path.join(self.home, "keep.txt")
        with open(victim, "w") as f:
            f.write("keep\n")
        victim_dir = os.path.join(self.home, "keep-dir"); os.makedirs(victim_dir)
        chaff = sorted(isr.chaff_paths())[0]
        os.remove(chaff); os.symlink(victim, chaff)
        top = os.path.dirname(os.path.dirname(sorted(p for p, b in isr.sentinel_paths().items() if b == "/tmp")[0]))
        shutil.rmtree(top); os.symlink(victim_dir, top)
        refused = []
        isr.plant_chaff(refused)
        self.assertEqual(text_of(victim), "keep\n")
        self.assertEqual(os.listdir(victim_dir), [])
        self.assertTrue(os.path.islink(chaff) and os.path.islink(top))   # the evidence is left as found
        self.assertEqual(sorted(f["rule"] for f in refused), ["ISR-K006", "ISR-K006"])
        self.assertEqual({f["severity"] for f in refused}, {"high"})
        self.assertIn("ISR-K006", {e["rule"] for e in isr.load_json(isr.state_path("events.json"), [])})
        self.assertFalse(any(isr.owned_path(p, "decoy", log=False) for p, b in isr.sentinel_paths().items() if b == "/tmp"))

    def test_chaff_and_sentinels_are_planted_armed_owned_and_removed_on_uninstall(self):   # guard
        chaff, far = isr.chaff_paths(), isr.sentinel_paths()
        self.assertEqual((len(chaff), len(far)), (6, 4))
        for p in list(chaff) + list(far):
            st = os.lstat(p)
            self.assertLess(st.st_atime, st.st_mtime - DAY + 2)   # armed: the next read moves its atime
            self.assertTrue(isr.owned_path(p, "decoy", log=False))
            self.assertFalse(re.search(r"(?i)key|secret|token|passw|AKIA|rk_live", text_of(p)))   # dull text only
        for p, b in far.items():
            rel = os.path.relpath(p, isr.decoy_path(b)).split(os.sep)
            self.assertEqual((len(rel), rel[0][0] != "."), (3, True))   # two plain folders down
        lay = isr.load_json(isr.state_path("decoy_layout.json"), {})
        self.assertEqual(sorted(lay["chaff"]), ["api-env", "cloud-keys", "customers"])
        code, o, _ = self.run_cmd("uninstall")
        self.assertEqual(len(json.loads(o)["this_command_removes"]["decoy_chaff_and_sentinels"]), 10)
        self.run_cmd("uninstall", "--apply")
        self.assertFalse([p for p in list(chaff) + list(far) + [v["path"] for v in self.reg.values()] if os.path.lexists(p)])
        self.assertFalse([p for p in far if os.path.lexists(os.path.dirname(os.path.dirname(p)))])
        self.assertEqual(len([n for n in os.listdir(self.tmpd) if n.startswith("proj-")]), 16)   # the box's own files stay


if __name__ == "__main__":
    unittest.main()
