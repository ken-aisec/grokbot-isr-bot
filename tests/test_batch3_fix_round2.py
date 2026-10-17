"""Hardening batch 3, Codex review round 2: replays for its findings. Each fails on fix round 1 (55a4290) unless its docstring
says it is a contrast. The publish.sh replay (finding 14) is test_scripts.Publish.test_batch3_round2_*. Finding 3 (ctime is
not vendor provenance) is not fixed here: making every unverified platform change a counted alert breaks DQ-042's routine
update (CHANGELOG, Known gaps).
"""
import hashlib, importlib.util, json, os, shutil, subprocess, sys, time, unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_boxes import Box, CRASH, wt  # noqa: E402
from test_batch3_scanners import _Scanners, arch  # noqa: E402
from test_batch3_platform import _Platform, CLEAN, put, add  # noqa: E402
from test_batch3_fix_round1 import chain_root_owned  # noqa: E402
from test_watchtower import fake_key  # noqa: E402
import test_dq042_vendor_skills as dq042  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
READER = os.path.join(ROOT, "scripts", "scanner_lock.py")


def reader():
    """scripts/scanner_lock.py from its source, without writing a bytecode cache into the checkout."""
    ns = {"__name__": "scanner_lock_t"}
    with open(READER, "rb") as f:
        exec(compile(f.read(), READER, "exec"), ns)
    return ns


def six_lines():
    return "".join(f"{hashlib.sha256(n.encode()).hexdigest()}  {n}  x86_64  v1\n" for n in sorted(wt.SCANNER_NAMES))


class CachedReader(_Scanners):
    def test_1_a_planted_bytecode_cache_never_replaces_the_lock_reader(self):
        """Finding 1: the reader was imported, so Python ran a scanner_lock.*.pyc with the source's mtime and size instead of the
        checked source, and its parse() decided which programs were scanners."""
        app = os.path.join(self.tmp, "app")
        os.makedirs(os.path.join(app, "watchtower")); os.makedirs(os.path.join(app, "scripts"))
        src = os.path.join(app, "scripts", "scanner_lock.py")
        shutil.copy(READER, src)
        forged = compile("def read_lock(p):\n    return '', None\n"
                         f"def parse(t):\n    return {{('gitleaks', 'any'): {{'{'f' * 64}'}}}}, []\n", src, "exec")
        st = os.stat(src)
        cache = importlib.util.cache_from_source(src)
        os.makedirs(os.path.dirname(cache))
        with open(cache, "wb") as f:
            f.write(importlib._bootstrap_external._code_to_timestamp_pyc(forged, int(st.st_mtime), st.st_size))
        self.lock_line("gitleaks", "a" * 64)
        wt._SCANNER_LOCK_CACHE.clear()
        try:
            with mock.patch.object(wt, "HERE", os.path.join(app, "watchtower")):
                lock = wt.scanner_lock()
        finally:
            wt._SCANNER_LOCK_CACHE.clear()
        self.assertNotIn(("gitleaks", "any"), lock)
        self.assertEqual(lock, {("gitleaks", arch()): {"a" * 64}})              # read by the checked source, from the lock file


class RunningInterpreter(_Scanners):
    @unittest.skipUnless(chain_root_owned(os.path.realpath("/bin/sh")), "needs a root-owned /bin/sh")
    def test_2_trust_follows_the_running_interpreter_not_its_launcher_name(self):
        """Finding 2: realpath(sys.executable) followed the link Watchtower was started through. With that link and the scanner
        Python link retargeted at another root-owned program, that program was the "pinned" Python."""
        other = os.path.realpath("/bin/sh")
        launcher = os.path.join(self.tmp, "venv-python")
        os.symlink(other, launcher)                                            # the launcher Watchtower started through, retargeted
        os.makedirs(self.bin, exist_ok=True)
        for n in ("python3", "python"):
            os.symlink(other, os.path.join(self.bin, n))
        with mock.patch.object(sys, "executable", launcher):
            self.assertIsNone(wt.trusted_interpreter(os.path.join(self.bin, "python3")))
            self.assertIsNone(wt.scanners_python())


class OneToOneMoves(Box):
    def removed_and_copied(self, dests):
        d = self.skills(1)[0]
        self.scanners(); self.audit()
        src = os.path.join(d, "SKILL.md")
        with open(src) as f:
            body = f.read()
        os.remove(src)
        for p in dests:
            put(p, body)
        self.audit()
        s = self.snap()
        return {f["where"] for f in s.get("findings", []) + s.get("suppressed", []) if f["rule"] == "WT-I002"}

    def test_4_one_missing_approved_file_accounts_for_one_copy_only(self):
        """Finding 4: one deleted approved SKILL.md let any number of new SKILL.md files with its bytes through as moved."""
        copies = [os.path.join(self.home, "sand-data", "workflows", f"copy{i}", "SKILL.md") for i in range(3)]
        new = self.removed_and_copied(copies)
        self.assertEqual(len([c for c in copies if c in new]), 2)

    def test_4_a_copy_across_a_trust_boundary_is_new_where_it_lands(self):
        dst = os.path.join(self.home, ".grok", "bundled", "skills", "skill000", "SKILL.md")
        self.assertIn(dst, self.removed_and_copied([dst]))


class PreviewChecksItsBytes(_Platform):
    def update(self):
        for n in ("alpha", "beta"):
            add(self.md(n), "Updated.\n")
        self.guide = os.path.join(self.root, "gamma", "references", "guide.md")
        put(self.guide, "# Guide\nMore detail.\n")

    def plan(self):
        return wt.load_json(wt.state_path("platform_plan.json"), {}).get("files", {})

    def test_5_bytes_changed_before_the_preview_are_checked_before_they_are_offered(self):
        """Finding 5: with no engines, the preview offered whatever the file held by then, never scanned, and the yes approved it."""
        self.start(all=None)                                                    # no engines: Watchtower's rules are the check
        self.update()
        self.daily(); self.audit()
        put(self.guide, dq042.BAD)                                              # after the audit, before the fix
        self.run_cmd("fix", "--roots", *self.roots)
        self.assertNotIn(self.guide, self.plan())
        self.run_cmd("fix", "--apply", "--owner-said-yes", "--roots", *self.roots)
        self.assertNotEqual(wt.load_baseline()[0].get(self.guide), wt.sha256_file(self.guide))

    def test_5_a_file_nothing_reads_is_never_offered(self):
        """Finding 5: with no engines, a non-text file in a skill was offered, though no rule and no engine ever read it."""
        self.start(all=None)
        self.update()
        blob = os.path.join(self.root, "alpha", "helper.bin")
        with open(blob, "wb") as f:
            f.write(b"\x7fELF" + bytes(range(256)))
        self.daily(); self.audit()
        self.run_cmd("fix", "--roots", *self.roots)
        self.assertNotIn(blob, self.plan())

    def test_5_edited_saved_findings_never_make_a_plant_part_of_an_update(self):
        """Finding 5 (what the owner is shown can't be steered by the Bot's files): with the plant's lone line deleted from the
        saved findings, a Tip naming it added, and the lone memory wiped, the plant was offered and approved."""
        self.start()
        p = os.path.join(self.root, "helper", "SKILL.md")
        put(p, CLEAN.format(n="helper"))
        self.daily(); self.audit()
        snap = self.snap()
        snap["findings"] = [f for f in snap["findings"] if not f.get("lone")]
        tip = wt.finding(wt.REFRESH_RULE, "Platform refresh: 1 of Grok Bot's own files changed (helper)", "info", ["AST07"],
                         "platform-refresh", "0 updated, 1 added, 0 removed", "Nothing to worry about.", ident="platform-refresh")
        tip["platform_files"] = [p]
        snap["findings"].append(tip)
        wt.save_json(wt.state_path("last_findings.json"), snap)
        os.remove(wt.state_path("platform_changes.json"))
        self.run_cmd("fix", "--roots", *self.roots)
        self.assertNotIn(p, self.plan())
        self.run_cmd("fix", "--apply", "--owner-said-yes", "--roots", *self.roots)
        self.assertNotIn(p, wt.load_baseline()[0])

    def test_5_contrast_a_clean_update_is_still_offered_and_approved(self):
        """Contrast: passes on 55a4290 too."""
        self.start()
        self.update()
        self.daily(); self.audit()
        out = json.loads(self.run_cmd("fix", "--roots", *self.roots)[1])
        self.assertEqual(out["platform_update"]["files"], 3)
        self.run_cmd("fix", "--apply", "--owner-said-yes", "--roots", *self.roots)
        self.assertEqual(wt.load_baseline()[0].get(self.guide), wt.sha256_file(self.guide))

    def test_6_a_timed_out_engine_answer_is_not_an_answer(self):
        """Finding 6: entry_current() takes a stuck (timed out) entry as current, so the preview offered that skill's files."""
        self.start()
        self.update()
        self.daily(); self.audit()
        cache = wt.load_json(wt.state_path("engine_cache.json"), {})
        d = os.path.join(self.root, "alpha")
        self.assertIn(d, cache)
        cache[d] = {"hash": cache[d]["hash"], "stuck": "SkillSpector", "at": wt.now(), "limit": 10 ** 6}   # what a time out leaves
        wt.save_json(wt.state_path("engine_cache.json"), cache)
        self.run_cmd("fix", "--roots", *self.roots)
        self.assertNotIn(self.md("alpha"), self.plan())

    def test_8_a_null_or_malformed_plan_digest_approves_nothing(self):
        """Finding 8: `now_ok.get(p) == None` matched a file platform_update didn't return, and null went into the baseline."""
        self.start()
        p = os.path.join(self.root, "helper", "SKILL.md")
        put(p, CLEAN.format(n="helper"))
        self.daily()
        wt.save_json(wt.state_path("platform_plan.json"), {"files": {p: None, self.md("alpha"): "not-a-sha256"}})
        self.run_cmd("fix", "--apply", "--owner-said-yes", "--roots", *self.roots)
        base = wt.load_baseline()[0]
        self.assertNotIn(p, base)
        self.assertTrue(all(isinstance(h, str) for h in base.values()))
        self.audit()                                                            # and the next audit runs (a null crashed it)


class PartialApproval(dq042._Learn, Box):
    REL = ".grok/bundled/skills"

    def test_7_an_update_is_never_approved_in_part(self):
        """Finding 7: the learn update's two clean siblings were approved without learn and its reference, which were then a
        group of two: lone, counted highs at the next daily (a routine DQ-042 update turned into an alarm)."""
        self.refresh(dq042.LEARN_V2, bundle=True, skillspector=dq042.skillspector(dq042.LEARN_ISSUES), husk=dq042.husk(dq042.LEARN_HUSK))
        self.run_cmd("fix", "--roots", *self.roots)
        self.run_cmd("fix", "--apply", "--owner-said-yes", "--roots", *self.roots)
        self.assertEqual(self.daily(), "NO_CHANGES")
        self.assertFalse([f for f in self.snap()["findings"] if f.get("lone")])
        recall = os.path.join(self.home, self.REL, "recall", "SKILL.md")
        self.assertNotEqual(wt.load_baseline()[0].get(recall), wt.sha256_file(recall))   # all of the update, or none of it


LEAKS = ('#!/usr/bin/env python3\nimport json, sys\na = sys.argv[1:]\nif a and a[0] == "version":\n    print("8.30.1"); sys.exit(0)\n'
         'src = a[a.index("--source") + 1]\n'
         'leaks = [{"File": p, "StartLine": 1, "RuleID": "github-pat"} for p in %r if p.startswith(src.rstrip("/") + "/")]\n'
         'open(a[a.index("--report-path") + 1], "w").write(json.dumps(leaks))\n')


class LiteralPath(Box):
    def test_9_a_file_named_like_the_config_stays_itself_after_it_is_gone(self):
        """Finding 9: gateway.json:3:1 (line 1 of a file named gateway.json:3) was the config again once that file was renamed
        or deleted, so a critical key became low and uncounted, in the finding kept from the last run too."""
        lit = os.path.join(self.home, "sand-data", "gateway.json:3")
        put(lit, '"token": "ghp_' + fake_key(36) + '"\n')
        self.scanners(gitleaks=LEAKS % [lit])
        self.audit()
        s = [f for f in self.snap()["findings"] if f["rule"] == "WT-S002" and f["where"] == lit + ":1"]
        self.assertEqual(len(s), 1)
        sev = s[0]["severity"]
        self.assertTrue(wt.counts(s[0]))
        os.remove(lit)                                                          # gone after the scan
        self.assertTrue(wt.counts(s[0]))
        self.assertEqual(wt.platform_owned([dict(s[0])])[0]["severity"], sev)
        self.scanners(gitleaks=CRASH)                                           # gitleaks fails next run: its last results are kept
        self.audit()
        kept = [f for f in self.snap()["findings"] if f["rule"] == "WT-S002" and f["where"] == lit + ":1"]
        self.assertEqual([(f["severity"], wt.counts(f)) for f in kept], [(sev, True)])


class BoundedTime(_Scanners):
    def test_10_one_slow_read_is_bounded(self):
        """Finding 10: the deadline was checked only between reads, so one slow read followed by EOF took as long as it took."""
        p = self.put("gitleaks", "", register=False)
        wt.SCANNER_LOCK_EXTRA["gitleaks"] = hashlib.sha256(b"").hexdigest()
        real, calls = os.read, []

        def slow(fd, n):
            if not calls:
                calls.append(1)
                time.sleep(3)
                return b""
            return real(fd, n)
        with mock.patch.object(wt, "SCANNER_HASH_SECONDS", 1), mock.patch.object(wt.os, "read", slow):
            t0 = time.monotonic()
            got = wt.tool("gitleaks")
            took = time.monotonic() - t0
        self.assertIsNone(got, p)
        self.assertLess(took, 2.5)
        self.assertIn("too long", wt.SCANNER_PROBLEMS["gitleaks"][1])

    def test_10_making_the_sealed_copy_counts_against_the_programs_time(self):
        """Finding 10: run() set the program's timeout before the copy was made, so copying plus running took longer."""
        p = self.put("gitleaks", "#!/bin/sh\nsleep 1.5\necho done\n")
        real = wt._sealed_copy

        def slow_copy(path):
            time.sleep(1.5)
            return real(path)
        with mock.patch.object(wt, "_sealed_copy", slow_copy):
            t0 = time.monotonic()
            code, _, _ = wt.run([p], 2)
            took = time.monotonic() - t0
        self.assertEqual(code, 124)
        self.assertLess(took, 2.8)


class LinearGrouping(Box):
    def test_11_grouping_thousands_of_pending_platform_files_is_not_quadratic(self):
        """Finding 11: every pending file was compared with every other one in its folder (8,000 took seconds)."""
        root = os.path.join(self.home, ".grok", "bundled", "skills")
        n = 8000
        ct = {os.path.join(root, f"s{i}", "SKILL.md"): 1000.0 + i * 0.01 for i in range(n)}
        fs = [{"rule": "WT-I002", "refresh": True, "where": p} for p in ct]
        real = os.lstat

        class St:
            def __init__(self, t):
                self.st_ctime = t

        def fake_lstat(p, *a, **k):
            return St(ct[p]) if p in ct else real(p, *a, **k)
        with mock.patch.object(wt.os, "lstat", fake_lstat), mock.patch.object(wt, "platform_group", lambda p: root):
            t0 = time.monotonic()
            out = wt.mark_lone_platform_changes(fs)
            took = time.monotonic() - t0
        self.assertFalse([f for f in out if f.get("lone")])
        self.assertLess(took, 1.0)


class SharedLockRules(_Scanners):
    def test_12_publication_refuses_a_lock_the_runtime_refuses(self):
        """Finding 12: publication read the lock without the runtime's 1,000,000-byte limit, so a complete lock padded with
        comments passed publish.sh while Watchtower listed no scanner at all."""
        with open(self.lock, "w") as f:
            f.write(six_lines() + ("#" + "x" * 999 + "\n") * 1001)
        wt._SCANNER_LOCK_CACHE.clear()
        self.assertEqual(wt.scanner_lock(), {})                                  # the runtime refuses it whole (already on 55a4290)
        r = subprocess.run([sys.executable, "-I", READER, self.lock], capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("is over 1000000 bytes", r.stdout)

    def test_13_semgrep_may_be_listed_and_is_not_required(self):
        """Finding 13: semgrep wasn't a name the reader accepted, so codescan's optional semgrep could never be enabled, and a
        line for it stopped publication."""
        mod = reader()
        semgrep = f"{'a' * 64}  semgrep  x86_64  v1\n"
        lock, problems = mod["parse"](six_lines() + semgrep)
        self.assertEqual(problems, [])
        self.assertIn(("semgrep", "x86_64"), lock)
        self.assertEqual(mod["release_problems"](six_lines() + semgrep), [])
        self.assertEqual(mod["release_problems"](six_lines()), [])                # still optional
        p = self.put("semgrep", "#!/bin/sh\necho '{\"results\": []}'\n", register=False)
        self.lock_line("semgrep", wt.scanner_digest(p))
        wt._SCANNER_LOCK_CACHE.clear()
        self.assertEqual(wt.tool("semgrep"), p)


class Accounting(unittest.TestCase):
    def test_15_replay_counts_and_contrast_labels_are_right(self):
        """Finding 15: round 1's line counted 29 + 3 replays (its file has 26 tests), and RoutineUpdate.test_3 said it passes on
        base, which it doesn't since an update needs the owner's yes."""
        import test_batch3_platform as plat
        self.assertNotIn("Contrast: passes on base", plat.RoutineUpdate.test_3_contrast_a_routine_update_is_one_platform_line.__doc__ or "")
        with open(os.path.join(ROOT, "CHANGELOG.md")) as f:
            log = f.read()
        self.assertIn("Codex review, round 2", log)
        self.assertNotIn("Replays in `tests/test_batch3_fix_round1.py` (29 tests", log)


if __name__ == "__main__":
    unittest.main()
