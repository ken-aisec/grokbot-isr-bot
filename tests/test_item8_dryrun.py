"""v0.7.1 item 8, sandboxed main-box dry run of Oct 13 on 15206a3 (score 89, 55 worth a look). Replays, anonymized.
Each class reproduces one gate failure. Real signal is kept: a key, a live removal, a real sign-in, a live skill change."""
import json, os, sys, unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_boxes import Box, wt  # noqa: E402

GOOD = "---\nname: n\ndescription: d\n---\nSummarize the notes. Ask before saving.\n"


def write(p, text):
    os.makedirs(os.path.dirname(p), exist_ok=True)
    open(p, "w").write(text)


class ArchiveAndCandidatesLeak(Box):
    """workflows/_archive/<date>/... snapshots raised WT-I002, and deleted /workspace/skill-hunt-*/candidates raised WT-I003."""
    def setUp(self):
        super().setUp()
        self.skills(1); self.scanners()
        self.wf = os.path.join(self.home, "sand-data", "workflows")
        self.cand = os.path.join(self.ws, "skill-hunt-2026-09-22", "candidates", "compress")
        write(os.path.join(self.cand, "SKILL.md"), GOOD)
        write(os.path.join(self.cand, "scripts", "cli.py"), "print('x')\n")

    def drift(self):
        return [f for f in self.snap()["findings"] if f["rule"] in ("WT-I001", "WT-I002", "WT-I003")]

    def test_archive_snapshot_raises_no_new_file_alarm(self):
        self.audit(); self.run_cmd("baseline", "--roots", *self.roots, "--owner-said-yes")
        write(os.path.join(self.wf, "_archive", "2026-10-13", "snapshot-2", "team-polish", "SKILL.md"), GOOD + "Every email gets a reply.\n")
        self.audit()
        fs = [f for f in self.snap()["findings"] if "_archive" in f["where"]]
        self.assertEqual(fs, [])
        i7 = [f for f in self.snap()["findings"] if f["rule"] == "WT-I007"]
        self.assertEqual(len(i7), 1); self.assertEqual(i7[0]["label"], wt.TIP)

    def test_removed_candidate_outside_live_places_is_not_a_removal(self):
        self.audit(); self.run_cmd("baseline", "--roots", *self.roots, "--owner-said-yes")
        base = wt.load_json(wt.state_path("baseline.json"), {})   # a baseline from before item 1 still lists the candidates
        for p in (os.path.join(self.cand, "SKILL.md"), os.path.join(self.cand, "scripts", "cli.py")):
            base[p] = wt.sha256_file(p)
        wt.save_json(wt.state_path("baseline.json"), base)
        import shutil; shutil.rmtree(self.cand)
        self.audit()
        self.assertEqual([f for f in self.drift() if "candidates" in f["where"]], [])

    def test_a_live_skill_removed_still_shows(self):
        self.audit(); self.run_cmd("baseline", "--roots", *self.roots, "--owner-said-yes")
        import shutil; shutil.rmtree(os.path.join(self.wf, "skill000"))
        self.audit()
        self.assertTrue([f for f in self.drift() if f["rule"] == "WT-I003" and "skill000" in f["where"]])

    def test_a_live_skill_in_a_folder_named_tests_still_counts(self):
        """DQ-028/029 unchanged: only archive-named folders are snapshots."""
        self.assertTrue(wt.is_live_skill_path(os.path.join(self.wf, "tests", "x", "SKILL.md")))
        self.assertFalse(wt.is_live_skill_path(os.path.join(self.wf, "_archive", "2026-10-13", "x", "SKILL.md")))

    def test_project_agents_skills_in_a_clone_is_not_live_but_home_one_is(self):
        self.assertFalse(wt.is_live_skill_path(os.path.join(self.ws, "kb-clone", ".agents", "skills", "3d-brain", "SKILL.md")))
        self.assertTrue(wt.is_live_skill_path(os.path.join(self.home, ".agents", "skills", "topic-digest", "SKILL.md")))


class ListenerWordingAlone(Box):
    """email.md:19 'every email' was Confirmed medium only because the file changed after approval (WT-I001)."""
    def test_every_email_in_a_changed_file_is_not_confirmed(self):
        self.scanners()
        d = os.path.join(self.home, "sand-data", "workflows", "outreach")
        write(os.path.join(d, "SKILL.md"), GOOD)
        write(os.path.join(d, "references", "email.md"), "# Email\nTone notes.\n")
        self.audit(); self.run_cmd("baseline", "--roots", *self.roots, "--owner-said-yes")
        write(os.path.join(d, "references", "email.md"), "# Email\nTone notes.\nFor every email, open with the hook.\n")
        self.audit()
        t14 = [f for f in self.snap()["findings"] if f["rule"] == "WT-T014"]
        self.assertTrue(t14)
        self.assertFalse([f for f in t14 if f["label"] == wt.CONFIRMED], t14)
        self.assertTrue([f for f in self.snap()["findings"] if f["rule"] == "WT-I001" and f["label"] == wt.CONFIRMED])


class PlainCookieJar(Box):
    def jar(self, cookies):
        write(os.path.join(self.home, "sand-data", "chrome-cookie-seed.json"), json.dumps(cookies))
        self.skills(1); self.scanners(); self.audit()
        return next(f for f in self.snap()["findings"] if f["rule"] == "WT-S004")

    def test_no_sensitive_sign_in_is_a_tip_not_confirmed_medium(self):
        f = self.jar([{"domain": f"site{i}.example", "name": "_ga", "value": "x"} for i in range(37)])
        self.assertIn("sensitive: none", f["evidence"])
        self.assertEqual(f["label"], wt.TIP)
        self.assertEqual(f["severity"], "info")

    def test_a_real_sensitive_sign_in_stays_confirmed_high(self):
        f = self.jar([{"domain": ".google.com", "name": "SID", "value": "FAKE-WT-COOKIE"}])
        self.assertEqual((f["label"], f["severity"]), (wt.CONFIRMED, "high"))


class RollCallOneLinePerRule(Box):
    """15 Bots with the same connectors gave 15 WT-L001 lines and 10 memories gave 10 WT-M010 lines (no roster saved)."""
    def test_worth_a_look_rollcall_findings_are_one_line_per_rule(self):
        self.skills(1); self.scanners()
        fs = []
        for i in range(15):
            fs.append(wt.finding("WT-L001", "Lethal trifecta: private data + untrusted input + a way out", "high", ["ASI01"], f"rollcall:Bot{i}", "Gmail X Slack", "x"))
        for i in range(10):
            fs.append(wt.finding("WT-M010", "Memory acts as a standing instruction", "medium", ["ASI06"], f"rollcall:Bot{i}:memory1", "note", "x"))
        wt.save_json(wt.state_path("rollcall_findings.json"), {"at": wt.now(), "masked": wt.VERSION, "bots": [f"Bot{i}" for i in range(15)], "findings": fs})
        r = self.audit()
        look = [f for f in self.snap()["findings"] if f.get("label") == wt.MAYBE_FINE and f["where"].startswith("rollcall:")]
        self.assertEqual(sorted(f["rule"] for f in look), ["WT-L001", "WT-M010"], look)
        l1 = next(f for f in look if f["rule"] == "WT-L001")
        self.assertEqual(l1["also_count"], 14)
        self.assertIn("15 Bots", l1["title"])
        self.assertTrue(any("No roster saved" in n for n in self.snap()["notes"]))


class ToolchainTestKeys(Box):
    """~/.local/go.prev-1.27.1 (a kept Go rollback) and the pnpm store gave 11 gitleaks lines from their own test vectors."""
    def test_toolchain_hits_are_not_listed_but_a_workspace_file_is(self):
        self.skills(1)
        files = [os.path.join(self.home, ".local", "go.prev-1.27.1", "src", "crypto", "x_test.go"),
                 os.path.join(self.home, ".local", "share", "pnpm", "store", "v11", "files", "27", "ab"),
                 os.path.join(self.ws, "notes", "keys.txt")]
        for p in files:
            write(p, "x\n")
        report = json.dumps([{"File": p, "StartLine": 1, "RuleID": "generic-api-key"} for p in files])
        gl = ('#!/usr/bin/env python3\nimport sys\na = sys.argv[1:]\nif a and a[0] == "version":\n    print("8.30.1"); sys.exit(0)\n'
              f'open(a[a.index("--report-path") + 1], "w").write({report!r})\n')
        self.scanners(gitleaks=gl)
        r = self.audit()
        s2 = [f["where"] for f in self.snap()["findings"] if f["rule"] == "WT-S002"]
        self.assertTrue(any("notes/keys.txt" in w for w in s2), s2)
        self.assertFalse([w for w in s2 if "go.prev" in w or "pnpm" in w], s2)


if __name__ == "__main__":
    unittest.main()
