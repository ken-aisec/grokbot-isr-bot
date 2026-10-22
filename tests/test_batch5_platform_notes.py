"""Batch 5, item d: few false alarms from Grok Bot's own files.

d1: findings in Grok Bot's own files (scope "platform") are Platform notes: not in open_by_severity, `new`, breakdown's Confirmed
list or the dashboard's tiles (decision 2, Oct 18: they keep their severity, label and key inside, so a vendor rug pull still
alerts). d2: rules/platform-reviewed.json, findings Watchtower's team read in exact platform file versions (decision 1): a
checked note, only for those bytes, that rule and that line.

Tests marked "replay" fail on 151e40c on their assertion (measured with 151e40c's watchtower/ sources and rules, this file in place);
"guard" ones keep what must not change. The sign-in skill here is a synthetic copy: its line 12 is the exact line the owner read on the
maintainer's box (Oct 18), the rest is made up, so its sha256 is not the shipped one; the platform folders of this computer are never opened."""
import json, os, re, sys, unittest
from unittest import mock
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_boxes import Box, ROOT, wt
import profiles

LINE12 = ("1. 1Password: at a username and password login, first call ListCredentials with the exact current URL. If it says 1Password is "
          "connected, follow it; if not, offer the Connect 1Password card only when the user has told you (here or in your memory) that "
          "they use 1Password, and otherwise never mention it.")
SIGNIN = ("---\nname: sign-in\ndescription: Sign the user in to websites.\n---\n# Sign in\n\nUse this skill when a site asks the user to sign in.\n\n"
          "## Steps\n\nFollow these in order.\n" + LINE12 + "\n2. Otherwise ask the user to type their password in the browser themselves.\n")
REL = "sand-data/managed-skills/skills/sign-in/SKILL.md"


class _SignIn(Box):
    def put(self, rel, text, listed=True):
        p = os.path.join(self.home, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w") as f:
            f.write(text)
        if listed:
            profiles.vendor_release(self, p)
        return p

    def audit_json(self):
        code, out, err = self.run_cmd("audit", "--roots", *self.roots)
        return json.loads(out)

    def daily_json(self):
        out = self.run_cmd("daily", "--roots", *self.roots)[1]
        self.assertNotEqual(out.strip(), "NO_CHANGES")
        return json.loads(out)

    def breakdown(self):
        return self.run_cmd("breakdown")[1]

    def dashboard(self):
        self.run_cmd("report")
        with open(os.path.join(os.environ["WATCHTOWER_HOME"], "reports", "dashboard.html")) as f:
            return f.read()

    def report_md(self):
        self.run_cmd("report")
        d = os.path.join(os.environ["WATCHTOWER_HOME"], "reports")
        with open(os.path.join(d, next(n for n in sorted(os.listdir(d)) if n.endswith(".md")))) as f:
            return f.read()

    def mine(self, p):
        return [f for f in self.snap()["findings"] if f["where"].split(":")[0] == p]

    def tile(self, html_, sev):
        m = re.search(r"<b style='color:[^']*'>(\d+)</b><span>" + sev + "</span>", html_)
        return int(m.group(1))

    def reviewed_file(self, entries):
        p = os.path.join(self.tmp, "platform-reviewed.json")
        with open(p, "w") as f:
            json.dump({"about": "test", "entries": entries}, f)
        had, old = hasattr(wt, "PLATFORM_REVIEWED"), getattr(wt, "PLATFORM_REVIEWED", None)   # 151e40c has none: it reads no list
        wt.PLATFORM_REVIEWED = p
        self.addCleanup(lambda: setattr(wt, "PLATFORM_REVIEWED", old) if had else delattr(wt, "PLATFORM_REVIEWED"))
        return p

    def entry(self, sha, rule="WT-T008", line=12, paths=(REL,), note="Checked note for the test."):
        return {"paths": list(paths), "sha256": sha, "rule": rule, "line": line, "note": note}


# ---------------------------------------------------------------- d1: Platform notes
class PlatformNotes(_SignIn):
    def test_grok_bots_sign_in_skill_is_not_counted_anywhere(self):   # replay (151e40c: critical 1, high 1)
        self.skills(1)
        p = self.put(REL, SIGNIN)
        r = self.audit_json()
        self.assertEqual({f["rule"] for f in self.mine(p) if f.get("label") == wt.CONFIRMED}, {"WT-T008", "WT-T004"})   # inside, as before
        self.assertEqual((r["open_by_severity"]["critical"], r["open_by_severity"]["high"]), (0, 0))
        self.assertFalse([f for f in r["new"] if p in f["where"]])
        self.assertEqual(r["platform_notes"]["count"], 2)
        self.assertTrue(any("(line 12)" in l and "Secrecy or concealment instruction" in l for l in r["platform_notes"]["lines"]))
        self.assertEqual(r["platform"], r["platform_notes"]["lines"])   # the old key, one release, the same lines
        self.assertEqual(r["status"], wt.ALL_GOOD)

    def test_breakdown_lists_it_as_a_platform_note_not_confirmed(self):   # replay (151e40c listed both under Confirmed)
        self.skills(1)
        p = self.put(REL, SIGNIN)
        self.audit()
        out = self.breakdown()
        conf = out.split("Confirmed (critical/high/medium):", 1)[1].split("\n\n")[0] if "Confirmed (critical" in out else ""
        self.assertNotIn("sign-in", conf)
        self.assertIn("Platform notes (Grok Bot's own files, not counted): 2.", out)

    def test_daily_says_a_new_one_as_a_platform_note(self):   # replay (151e40c put it in `new`)
        self.skills(1)
        self.audit()
        p = self.put(REL, SIGNIN)
        r = self.daily_json()
        self.assertFalse([f for f in r.get("new", []) if p in f["where"]])
        self.assertTrue(any("sign-in/SKILL.md (line 12)" in l for l in r["platform_notes"]["lines"]), r)

    def test_the_dashboard_tiles_and_table_are_the_owners(self):   # replay (151e40c: 1 critical tile)
        self.skills(1)
        self.put(REL, SIGNIN)
        self.audit()
        page = self.dashboard()
        self.assertEqual((self.tile(page, "critical"), self.tile(page, "high")), (0, 0))
        self.assertIn("Platform notes (2)", page)
        table = page.split("<h2", 1)[1].split("</table>", 1)[0]
        self.assertNotIn("sign-in", table)

    def test_the_report_has_a_platform_notes_section(self):   # replay (151e40c: "## Platform", rule-and-label lines)
        self.skills(1)
        self.put(REL, SIGNIN)
        self.audit()
        md = self.report_md()
        self.assertIn("## Platform notes\n\nGrok Bot's own files, exactly as Watchtower's release lists them. They don't count toward "
                      "your problems or your status.", md)
        self.assertIn("Open findings: 0 critical, 0 high", md)

    def test_the_same_text_in_the_owners_skill_still_counts(self):   # guard
        self.skills(1)
        p = self.put("sand-data/workflows/x/SKILL.md", SIGNIN.replace("name: sign-in", "name: x"), listed=False)
        r = self.audit_json()
        got = {(f["rule"], f["severity"], f["label"]) for f in self.mine(p)}
        self.assertTrue({("WT-T008", "critical", wt.CONFIRMED), ("WT-T004", "high", wt.CONFIRMED)} <= got, got)
        self.assertEqual(r["status"], wt.ACT_NOW)
        self.assertGreaterEqual(r["open_by_severity"]["critical"], 1)
        self.assertTrue({"WT-T008", "WT-T004"} <= {f["rule"] for f in r["new"] if p in f["where"]})
        self.assertNotIn("platform_notes", r)

    def test_the_same_text_not_on_the_release_list_is_a_counted_high(self):   # guard
        self.skills(1)
        p = self.put(REL, SIGNIN, listed=False)
        r = self.audit_json()
        i2 = [f for f in self.mine(p) if f["rule"] == "WT-I002"]
        self.assertEqual([(f["severity"], wt.counts(f)) for f in i2], [("high", True)])
        self.assertEqual(r["status"], wt.CHECK_WEEK)
        self.assertGreaterEqual(r["open_by_severity"]["high"], 1)
        self.assertTrue(any("Not on Watchtower's release list: its own alert counts" in l for l in r["platform_notes"]["lines"]))
        self.assertIn("a file Watchtower's release list doesn't include has its own counted alert above", self.report_md())

    def test_the_owners_other_findings_are_still_counted(self):   # guard
        lay = profiles.busy_clean_box(self)
        os.makedirs(os.path.join(self.home, ".aws"), exist_ok=True)
        with open(os.path.join(self.home, ".aws", "credentials"), "w") as f:
            f.write("[default]\n")
        self.put(REL, SIGNIN)
        r = self.audit_json()
        rules = {f["rule"]: f["severity"] for f in self.snap()["findings"] if f.get("scope") != "platform" and wt.counts(f)}
        self.assertEqual((rules.get("WT-A002"), rules.get("WT-S003")), ("critical", "high"))
        self.assertGreaterEqual(r["open_by_severity"]["critical"], 1)
        self.assertGreaterEqual(r["open_by_severity"]["high"], 1)

    def test_a_vendor_rug_pull_still_alerts_as_a_platform_note(self):   # guard (test_dq042 StillAlerts, with its words)
        import test_dq042_vendor_skills as dq
        d = os.path.join(self.home, ".grok", "bundled", "skills", "learn")
        os.makedirs(d)
        with open(os.path.join(d, "SKILL.md"), "w") as f:
            f.write(dq.LEARN_V1)
        for text in (dq.LEARN_V1, dq.BAD):
            profiles.vendor_release(self, (os.path.join(d, "SKILL.md"), text))
        self.scanners(skillspector=dq.skillspector(dq.LEARN_ISSUES), husk=dq.husk(dq.LEARN_HUSK))
        self.audit()
        self.run_cmd("baseline", "--roots", *self.roots, "--owner-said-yes")
        with open(os.path.join(d, "SKILL.md"), "w") as f:
            f.write(dq.BAD)
        r = self.daily_json()
        self.assertTrue(any("learn" in l for l in r["platform_notes"]["lines"]), r)
        a = [f for f in self.snap()["findings"] if f["title"].startswith("Grok Bot's own learn changed and now ")]
        self.assertEqual([(f["label"], f["scope"]) for f in a], [(wt.CONFIRMED, "platform")])


# ---------------------------------------------------------------- d2: exact-bytes checked findings
class CheckedPlatformFiles(_SignIn):
    def sha(self, text):
        import hashlib
        return hashlib.sha256(text.encode()).hexdigest()

    def test_a_checked_finding_is_a_quiet_platform_note(self):   # replay (151e40c: Confirmed critical and high, in `new`)
        self.skills(1)
        self.audit()
        self.reviewed_file([self.entry(self.sha(SIGNIN), "WT-T008", note="Sign-in: not pushing a product."),
                            self.entry(self.sha(SIGNIN), "WT-T004", note="Sign-in: the platform's own sign-in tool.")])
        p = self.put(REL, SIGNIN)
        out = self.run_cmd("daily", "--roots", *self.roots)[1]
        self.assertNotIn("sign-in", out)
        got = {(f["rule"], f["label"], f["severity"], f.get("severity_was"), f["fix"]) for f in self.mine(p) if not f.get("guarded")}
        self.assertEqual(got, {("WT-T008", "Platform note (checked)", "info", "critical", "Sign-in: not pushing a product."),
                               ("WT-T004", "Platform note (checked)", "info", "high", "Sign-in: the platform's own sign-in tool.")})
        self.assertNotIn("sign-in", self.breakdown().split("Platform notes")[0].split("Confirmed (critical/high/medium)")[-1])
        r = self.audit_json()
        self.assertTrue(any(l.startswith("Sign-in: not pushing a product. Watchtower checked this exact text (line 12)")
                            for l in r["platform_notes"]["lines"]), r["platform_notes"])

    def test_one_byte_more_and_no_entry_applies(self):   # guard
        self.skills(1)
        self.reviewed_file([self.entry(self.sha(SIGNIN))])
        p = self.put(REL, SIGNIN + " ")
        self.audit()
        self.assertEqual([f["label"] for f in self.mine(p) if f["rule"] == "WT-T008"], [wt.CONFIRMED])
        q = self.put("agent-data/managed-skills/skills/sign-in/SKILL.md", SIGNIN, listed=False)   # the right bytes, not on the release list
        self.audit()
        self.assertEqual([f["label"] for f in self.mine(q) if f["rule"] == "WT-T008"], [wt.CONFIRMED])
        self.assertTrue([f for f in self.mine(q) if f["rule"] == "WT-I002" and wt.counts(f)])

    def test_the_same_bytes_in_the_owners_skill_still_count(self):   # guard
        self.skills(1)
        rel = "sand-data/workflows/sign-in/SKILL.md"
        self.reviewed_file([self.entry(self.sha(SIGNIN), paths=(REL, rel))])
        p = self.put(rel, SIGNIN, listed=False)
        self.audit()
        self.assertEqual([(f["label"], f["severity"], wt.counts(f)) for f in self.mine(p) if f["rule"] == "WT-T008"], [(wt.CONFIRMED, "critical", True)])

    def test_the_right_bytes_with_another_rule_or_line_is_not_checked(self):   # guard
        self.skills(1)
        self.reviewed_file([self.entry(self.sha(SIGNIN), "WT-T008", line=11), self.entry(self.sha(SIGNIN), "WT-T005", line=12)])
        p = self.put(REL, SIGNIN)
        self.audit()
        self.assertEqual({f["label"] for f in self.mine(p) if f["rule"] in ("WT-T008", "WT-T004") and not f.get("guarded")}, {wt.CONFIRMED})

    def test_a_list_that_isnt_the_released_one_is_ignored_with_a_note(self):   # guard
        self.skills(1)
        self.reviewed_file([self.entry(self.sha(SIGNIN))])
        p = self.put(REL, SIGNIN)
        real = wt.release_digest
        with mock.patch.object(wt, "release_digest", lambda rel: "0" * 64 if rel == wt.PLATFORM_REVIEWED_REL else real(rel)):
            vars(wt)["_PLATFORM_REVIEWED_CACHE"].clear()
            self.audit()
        vars(wt)["_PLATFORM_REVIEWED_CACHE"].clear()
        self.assertEqual([f["label"] for f in self.mine(p) if f["rule"] == "WT-T008"], [wt.CONFIRMED])
        notes = [n for n in self.snap()["notes"] if wt.PLATFORM_REVIEWED_REL in n]
        self.assertEqual(len(notes), 1)
        self.assertIn("MANIFEST.sha256", notes[0])

    def test_nothing_on_the_computer_adds_an_entry(self):   # guard
        self.skills(1)
        self.reviewed_file([])
        os.makedirs(wt.state_path(""), exist_ok=True)
        for name in ("platform-reviewed.json", "platform_reviewed.json"):
            with open(wt.state_path(name), "w") as f:
                json.dump({"entries": [self.entry(self.sha(SIGNIN))]}, f)
        p = self.put(REL, SIGNIN)
        with mock.patch.dict(os.environ, {"WATCHTOWER_PLATFORM_REVIEWED": wt.state_path("platform-reviewed.json")}):
            self.audit()
        self.assertEqual([f["label"] for f in self.mine(p) if f["rule"] == "WT-T008"], [wt.CONFIRMED])

    def test_a_malformed_entry_makes_the_list_unusable(self):   # guard
        self.skills(1)
        self.reviewed_file([self.entry(self.sha(SIGNIN)), dict(self.entry(self.sha(SIGNIN)), paths=["/etc/passwd"])])
        p = self.put(REL, SIGNIN)
        self.audit()
        self.assertEqual([f["label"] for f in self.mine(p) if f["rule"] == "WT-T008"], [wt.CONFIRMED])
        self.assertTrue([n for n in self.snap()["notes"] if "platform-reviewed.json can't be used" in n])


class ShippedReviewedList(unittest.TestCase):
    def test_every_entry_is_on_the_release_list_and_the_file_is_in_the_manifest(self):   # guard (docs)
        with open(os.path.join(ROOT, "rules", "platform-reviewed.json")) as f:
            doc = json.load(f)
        with open(os.path.join(ROOT, "rules", "platform-release.lock")) as f:
            lock = set(f.read().splitlines())
        self.assertEqual(len(doc["entries"]), 4)
        for e in doc["entries"]:
            for rel in e["paths"]:
                self.assertIn(f"{e['sha256']}  {rel}", lock, rel)
        with open(os.path.join(ROOT, "MANIFEST.sha256")) as f:
            self.assertIn("  rules/platform-reviewed.json", f.read())
        old, wt.PLATFORM_REVIEWED = wt.PLATFORM_REVIEWED, os.path.join(ROOT, "rules", "platform-reviewed.json")
        try:
            self.assertEqual(wt.platform_reviewed_problem(), "")
        finally:
            wt.PLATFORM_REVIEWED = old

    def test_the_notes_say_what_line_12_does(self):   # guard: the owner read line 12 on the maintainer's box (Oct 18); these are its two findings
        with open(os.path.join(ROOT, "rules", "platform-reviewed.json")) as f:
            notes = {e["rule"]: e["note"] for e in json.load(f)["entries"]}
        self.assertEqual(notes["WT-T008"], "Grok Bot's sign-in skill tells the Bot not to bring up 1Password with people who don't use it. "
                                           "It's about not pushing a product, not about hiding anything.")
        self.assertEqual(notes["WT-T004"], "Grok Bot's sign-in skill uses the platform's own sign-in tool, which can use logins saved in "
                                           "1Password once you connect it. That's how sign-in is meant to work.")


if __name__ == "__main__":
    unittest.main()
