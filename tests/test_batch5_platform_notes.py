"""Batch 5, item d: few false alarms from Grok Bot's own files.

d1: findings in Grok Bot's own files (scope "platform") are Platform notes: not in open_by_severity, `new`, breakdown's Confirmed
list or the dashboard's tiles (decision 2, Oct 18: they keep their severity, label and key inside, so a vendor rug pull still
alerts). d2: rules/platform-reviewed.json, findings ISR Bot's team read in exact platform file versions (decision 1): a
checked note, only for those bytes, that rule and that line.

Tests marked "replay" fail on 151e40c on their assertion (measured with 151e40c's engine sources and rules, this file in place);
"guard" ones keep what must not change. The sign-in skill here is a synthetic copy: its line 12 is the exact line the owner read on the
maintainer's box (Oct 18), the rest is made up, so its sha256 is not the shipped one; the platform folders of this computer are never opened."""
import json, os, re, sys, unittest
from unittest import mock
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_boxes import Box, ROOT
import isr  # noqa: E402
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
        with open(os.path.join(os.environ["ISR_BOT_HOME"], "reports", "dashboard.html")) as f:
            return f.read()

    def report_md(self):
        self.run_cmd("report")
        d = os.path.join(os.environ["ISR_BOT_HOME"], "reports")
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
        had, old = hasattr(isr, "PLATFORM_REVIEWED"), getattr(isr, "PLATFORM_REVIEWED", None)   # 151e40c has none: it reads no list
        isr.PLATFORM_REVIEWED = p
        self.addCleanup(lambda: setattr(isr, "PLATFORM_REVIEWED", old) if had else delattr(isr, "PLATFORM_REVIEWED"))
        return p

    def entry(self, sha, rule="ISR-T008", line=12, paths=(REL,), note="Checked note for the test."):
        return {"paths": list(paths), "sha256": sha, "rule": rule, "line": line, "note": note}

    # v0.8.1 (PLAN §5b): the snapshot's scored findings, its vendor records, and the drift and vendor rows at one path
    def fs(self):
        return self.snap()["findings"]

    def vs(self):
        return self.snap().get("vendor", [])

    def drift(self, p):
        return [f for f in self.fs() + self.vs() if f["where"].split(":")[0] == p and f["rule"] in ("ISR-I001", "ISR-I002", "ISR-I003", "ISR-I011")]

    def vend(self, p):
        return [f for f in self.vs() if f["where"].split(":")[0] == p]

    def user(self, n, fn="SKILL.md"):
        return os.path.join(self.home, "sand-data", "workflows", n, fn)

    @property
    def u0(self):
        return self.user("skill000")                                           # the owner's skill self.skills(1) made


# ---------------------------------------------------------------- d1: Platform notes
class PlatformNotes(_SignIn):
    def setUp(self):
        super().setUp()
        self.owned()

    def test_grok_bots_sign_in_skill_is_not_counted_anywhere(self):   # replay (151e40c: critical 1, high 1)
        """v0.8.1 (decision, Oct 24): vendor folders are never scored; drift is tracked for the owner's files only."""
        self.skills(1)
        p = self.put(REL, SIGNIN)
        r = self.audit_json()
        self.assertEqual({v["rule"] for v in self.vend(p) if v["label"] == isr.CONFIRMED}, {"ISR-T008", "ISR-T004"})   # kept as vendor records
        self.assertEqual(self.mine(p), [])
        self.assertEqual((r["open_by_severity"]["critical"], r["open_by_severity"]["high"]), (0, 0))
        self.assertFalse([f for f in r["new"] if p in f["where"]])
        self.assertEqual(r["platform_notes"]["count"], 2)                       # the non-warning-text vendor records
        self.assertTrue(any(v["where"] == p + ":12" and "Secrecy or concealment instruction" in v["title"] for v in self.vend(p)))
        self.assertEqual(r["platform"], r["platform_notes"]["lines"])   # the old key, one release, the same lines
        self.assertEqual(r["status"], isr.ALL_GOOD)

    def test_breakdown_lists_it_as_a_platform_note_not_confirmed(self):   # replay (151e40c listed both under Confirmed)
        """v0.8.1 (decision, Oct 24): vendor folders are never scored; drift is tracked for the owner's files only."""
        self.skills(1)
        p = self.put(REL, SIGNIN)
        self.audit()
        out = self.breakdown()
        conf = out.split("Confirmed (critical/high/medium):", 1)[1].split("\n\n")[0] if "Confirmed (critical" in out else ""
        self.assertNotIn("sign-in", conf)
        self.assertIn("Platform notes", out)
        self.assertIn("sign-in/SKILL.md", out.split("Platform notes", 1)[1])

    def test_daily_says_a_new_one_as_a_platform_note(self):   # replay (151e40c put it in `new`)
        """v0.8.1 (decision, Oct 24): vendor folders are never scored; drift is tracked for the owner's files only. The vendor
        file alone is quiet; the same text over the owner's skill is new."""
        self.skills(1)
        self.audit()
        p = self.put(REL, SIGNIN)
        self.assertEqual(self.run_cmd("daily", "--roots", *self.roots)[1].strip(), "NO_CHANGES")
        q = self.put("sand-data/workflows/skill000/SKILL.md", SIGNIN, listed=False)
        r = self.daily_json()
        self.assertFalse([f for f in r.get("new", []) if p in f["where"]])
        self.assertTrue([f for f in r["new"] if q in f["where"] and f["rule"] == "ISR-T008"], r)
        self.assertTrue([v for v in self.vend(p) if v["where"] == p + ":12" and v["rule"] == "ISR-T008"])

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
        """v0.8.1 (decision, Oct 24): vendor folders are never scored; drift is tracked for the owner's files only."""
        self.skills(1)
        self.put(REL, SIGNIN)
        self.audit()
        md = self.report_md()
        self.assertIn("## Platform notes\n\n", md)
        self.assertNotIn("release list", md)
        self.assertIn("Open findings: 0 critical, 0 high", md)

    def test_the_same_text_in_the_owners_skill_still_counts(self):   # guard
        self.skills(1)
        p = self.put("sand-data/workflows/x/SKILL.md", SIGNIN.replace("name: sign-in", "name: x"), listed=False)
        r = self.audit_json()
        got = {(f["rule"], f["severity"], f["label"]) for f in self.mine(p)}
        self.assertTrue({("ISR-T008", "critical", isr.CONFIRMED), ("ISR-T004", "high", isr.CONFIRMED)} <= got, got)
        self.assertEqual(r["status"], isr.ACT_NOW)
        self.assertGreaterEqual(r["open_by_severity"]["critical"], 1)
        self.assertTrue({"ISR-T008", "ISR-T004"} <= {f["rule"] for f in r["new"] if p in f["where"]})
        self.assertNotIn("platform_notes", r)

    def test_the_same_text_not_on_the_release_list_is_a_counted_high(self):   # guard
        """v0.8.1 (decision, Oct 24): vendor folders are never scored; drift is tracked for the owner's files only. Off the
        release list, the vendor file is still only a platform note; the same text over the owner's skill is a counted high."""
        self.skills(1)
        p = self.put(REL, SIGNIN, listed=False)
        r = self.audit_json()
        self.assertEqual(self.drift(p), [])
        self.assertEqual(r["status"], isr.ALL_GOOD)
        self.assertEqual(r["open_by_severity"]["high"], 0)
        self.assertFalse([l for l in r["platform_notes"]["lines"] if "release list" in l])
        self.assertEqual(r["platform_notes"]["count"], 2)
        self.assertNotIn("release list", self.report_md())
        with open(self.u0, "w") as f:                                           # the control: the owner's baselined skill
            f.write(SIGNIN)
        r2 = self.audit_json()
        self.assertEqual([(f["severity"], isr.counts(f)) for f in self.mine(self.u0) if f["rule"] == "ISR-I001"], [("high", True)])
        self.assertEqual(r2["status"], isr.ACT_NOW)
        self.assertGreaterEqual(r2["open_by_severity"]["high"], 1)

    def test_the_owners_other_findings_are_still_counted(self):   # guard
        lay = profiles.busy_clean_box(self)
        os.makedirs(os.path.join(self.home, ".aws"), exist_ok=True)
        with open(os.path.join(self.home, ".aws", "credentials"), "w") as f:
            f.write("[default]\n")
        self.put(REL, SIGNIN)
        r = self.audit_json()
        rules = {f["rule"]: f["severity"] for f in self.snap()["findings"] if f.get("scope") != "platform" and isr.counts(f)}
        self.assertEqual((rules.get("ISR-A002"), rules.get("ISR-S003")), ("critical", "high"))
        self.assertGreaterEqual(r["open_by_severity"]["critical"], 1)
        self.assertGreaterEqual(r["open_by_severity"]["high"], 1)

    def test_a_vendor_rug_pull_still_alerts_as_a_platform_note(self):   # guard (test_dq042 StillAlerts, with its words)
        """v0.8.1 (decision, Oct 24): vendor folders are never scored; drift is tracked for the owner's files only. The vendor
        rug pull is a vendor record, never new; the same rug pull of the owner's learn skill is new and a counted high."""
        import test_dq042_vendor_skills as dq
        d = os.path.join(self.home, ".grok", "bundled", "skills", "learn")
        os.makedirs(d)
        with open(os.path.join(d, "SKILL.md"), "w") as f:
            f.write(dq.LEARN_V1)
        u = self.user("learn")                                                  # the control: the owner's learn skill
        os.makedirs(os.path.dirname(u))
        with open(u, "w") as f:
            f.write(dq.LEARN_V1)
        for text in (dq.LEARN_V1, dq.BAD):
            profiles.vendor_release(self, (os.path.join(d, "SKILL.md"), text))
        self.scanners(skillspector=dq.skillspector(dq.LEARN_ISSUES), husk=dq.husk(dq.LEARN_HUSK))
        self.audit()
        self.run_cmd("baseline", "--roots", *self.roots, "--owner-said-yes")
        for p in (os.path.join(d, "SKILL.md"), u):
            with open(p, "w") as f:
                f.write(dq.BAD)
        r = self.daily_json()
        self.assertTrue([f for f in r["new"] if f["where"].startswith(os.path.dirname(u))], r)
        self.assertFalse([f for f in r["new"] if f["where"].startswith(d)], r)
        self.assertFalse([f for f in self.fs() if f["title"].startswith("Grok Bot's own learn changed and now ")])
        self.assertEqual([v["label"] for v in self.vend(d) if v["rule"] == "ISR-X003"], [isr.CONFIRMED])
        self.assertEqual(self.drift(os.path.join(d, "SKILL.md")), [])
        self.assertIn(("ISR-I001", "high"), [(f["rule"], f["severity"]) for f in self.mine(u)])


# ---------------------------------------------------------------- d2: exact-bytes checked findings
class CheckedPlatformFiles(_SignIn):
    def setUp(self):
        super().setUp()
        self.owned()

    def sha(self, text):
        import hashlib
        return hashlib.sha256(text.encode()).hexdigest()

    def test_a_checked_finding_is_a_quiet_platform_note(self):   # replay (151e40c: Confirmed critical and high, in `new`)
        """v0.8.1 (decision, Oct 24): vendor folders are never scored; drift is tracked for the owner's files only. The
        reviewed list isn't read: both findings are plain vendor records."""
        self.skills(1)
        self.audit()
        self.reviewed_file([self.entry(self.sha(SIGNIN), "ISR-T008", note="Sign-in: not pushing a product."),
                            self.entry(self.sha(SIGNIN), "ISR-T004", note="Sign-in: the platform's own sign-in tool.")])
        p = self.put(REL, SIGNIN)
        out = self.run_cmd("daily", "--roots", *self.roots)[1]
        self.assertNotIn("sign-in", out)
        got = {(v["rule"], v["label"], v["severity"]) for v in self.vend(p) if v["rule"] in ("ISR-T008", "ISR-T004") and v["label"] != isr.GUARDED_LABEL}
        self.assertEqual(got, {("ISR-T008", isr.CONFIRMED, "critical"), ("ISR-T004", isr.CONFIRMED, "high")})
        self.assertNotIn("Platform note (checked)", json.dumps(self.snap()))
        self.assertNotIn("sign-in", self.breakdown().split("Platform notes")[0].split("Confirmed (critical/high/medium)")[-1])
        r = self.audit_json()
        self.assertFalse([l for l in r["platform_notes"]["lines"] if "checked this exact text" in l], r["platform_notes"])
        self.assertEqual(r["platform_notes"]["count"], 2)

    def test_one_byte_more_and_no_entry_applies(self):   # guard
        """v0.8.1 (decision, Oct 24): vendor folders are never scored; drift is tracked for the owner's files only."""
        self.skills(1)
        self.reviewed_file([self.entry(self.sha(SIGNIN))])
        p = self.put(REL, SIGNIN + " ")
        self.audit()
        self.assertEqual([f["label"] for f in self.vend(p) if f["rule"] == "ISR-T008"], [isr.CONFIRMED])
        q = self.put("agent-data/managed-skills/skills/sign-in/SKILL.md", SIGNIN, listed=False)   # the right bytes, not on the release list
        self.audit()
        self.assertEqual([f["label"] for f in self.vend(q) if f["rule"] == "ISR-T008"], [isr.CONFIRMED])
        self.assertEqual(self.drift(q), [])
        with open(self.u0, "w") as f:                                           # the control: the owner's baselined skill
            f.write(SIGNIN)
        self.audit()
        self.assertEqual([(f["severity"], isr.counts(f)) for f in self.mine(self.u0) if f["rule"] == "ISR-I001"], [("high", True)])

    def test_the_same_bytes_in_the_owners_skill_still_count(self):   # guard
        self.skills(1)
        rel = "sand-data/workflows/sign-in/SKILL.md"
        self.reviewed_file([self.entry(self.sha(SIGNIN), paths=(REL, rel))])
        p = self.put(rel, SIGNIN, listed=False)
        self.audit()
        self.assertEqual([(f["label"], f["severity"], isr.counts(f)) for f in self.mine(p) if f["rule"] == "ISR-T008"], [(isr.CONFIRMED, "critical", True)])

    def test_the_right_bytes_with_another_rule_or_line_is_not_checked(self):   # guard
        """v0.8.1 (decision, Oct 24): vendor folders are never scored; drift is tracked for the owner's files only."""
        self.skills(1)
        self.reviewed_file([self.entry(self.sha(SIGNIN), "ISR-T008", line=11), self.entry(self.sha(SIGNIN), "ISR-T005", line=12)])
        p = self.put(REL, SIGNIN)
        self.audit()
        self.assertEqual({f["label"] for f in self.vend(p) if f["rule"] in ("ISR-T008", "ISR-T004") and not f.get("guarded")}, {isr.CONFIRMED})
        self.assertEqual(self.mine(p), [])

    def test_a_list_that_isnt_the_released_one_is_ignored_with_a_note(self):   # guard
        """v0.8.1 (decision, Oct 24): vendor folders are never scored; drift is tracked for the owner's files only. The list
        isn't read, so the audit says nothing about it; the library still refuses it."""
        self.skills(1)
        self.reviewed_file([self.entry(self.sha(SIGNIN))])
        p = self.put(REL, SIGNIN)
        real = isr.release_digest
        with mock.patch.object(isr, "release_digest", lambda rel: "0" * 64 if rel == isr.PLATFORM_REVIEWED_REL else real(rel)):
            vars(isr)["_PLATFORM_REVIEWED_CACHE"].clear()
            self.audit()
            vars(isr)["_PLATFORM_REVIEWED_CACHE"].clear()
            problem = isr.platform_reviewed_problem()
        vars(isr)["_PLATFORM_REVIEWED_CACHE"].clear()
        self.assertEqual([f["label"] for f in self.vend(p) if f["rule"] == "ISR-T008"], [isr.CONFIRMED])
        notes = [n for n in self.snap()["notes"] if isr.PLATFORM_REVIEWED_REL in n]
        self.assertEqual(notes, [])
        self.assertIn("MANIFEST.sha256", problem)

    def test_nothing_on_the_computer_adds_an_entry(self):   # guard
        """v0.8.1 (decision, Oct 24): vendor folders are never scored; drift is tracked for the owner's files only."""
        self.skills(1)
        self.reviewed_file([])
        os.makedirs(isr.state_path(""), exist_ok=True)
        for name in ("platform-reviewed.json", "platform_reviewed.json"):
            with open(isr.state_path(name), "w") as f:
                json.dump({"entries": [self.entry(self.sha(SIGNIN))]}, f)
        p = self.put(REL, SIGNIN)
        with mock.patch.dict(os.environ, {"ISR_BOT_PLATFORM_REVIEWED": isr.state_path("platform-reviewed.json")}):
            self.audit()
        self.assertEqual([f["label"] for f in self.vend(p) if f["rule"] == "ISR-T008"], [isr.CONFIRMED])

    def test_a_malformed_entry_makes_the_list_unusable(self):   # guard
        """v0.8.1 (decision, Oct 24): vendor folders are never scored; drift is tracked for the owner's files only. The list
        isn't read, so the audit says nothing about it; the library still refuses it."""
        self.skills(1)
        self.reviewed_file([self.entry(self.sha(SIGNIN)), dict(self.entry(self.sha(SIGNIN)), paths=["/etc/passwd"])])
        p = self.put(REL, SIGNIN)
        self.audit()
        self.assertEqual([f["label"] for f in self.vend(p) if f["rule"] == "ISR-T008"], [isr.CONFIRMED])
        self.assertFalse([n for n in self.snap()["notes"] if "platform-reviewed.json" in n])
        self.assertIn("entry 2", isr.platform_reviewed_problem())


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
        old, isr.PLATFORM_REVIEWED = isr.PLATFORM_REVIEWED, os.path.join(ROOT, "rules", "platform-reviewed.json")
        try:
            self.assertEqual(isr.platform_reviewed_problem(), "")
        finally:
            isr.PLATFORM_REVIEWED = old

    def test_the_notes_say_what_line_12_does(self):   # guard: the owner read line 12 on the maintainer's box (Oct 18); these are its two findings
        with open(os.path.join(ROOT, "rules", "platform-reviewed.json")) as f:
            notes = {e["rule"]: e["note"] for e in json.load(f)["entries"]}
        self.assertEqual(notes["ISR-T008"], "Grok Bot's sign-in skill tells the Bot not to bring up 1Password with people who don't use it. "
                                           "It's about not pushing a product, not about hiding anything.")
        self.assertEqual(notes["ISR-T004"], "Grok Bot's sign-in skill uses the platform's own sign-in tool, which can use logins saved in "
                                           "1Password once you connect it. That's how sign-in is meant to work.")


if __name__ == "__main__":
    unittest.main()
