"""DQ-046(b) (decision, Oct 20: "Trust the new version and add it to the approved list"): Grok Bot's sign-in skill changed from
sha256 329d4f59 to b06512e7 on the live boxes (sand-data and agent-data, identical). The line the owner read on Oct 18 (old line 12) is
byte-identical and is now line 11, so the release lock lists the new bytes at both paths and rules/platform-reviewed.json has
the same two checked findings (ISR-T008, ISR-T004) for them at line 11. The 329d4f59 lines and entries stay: boxes not yet updated
still have those bytes. Exact bytes only, as before: no change to the matching (sha256 + rule + line).

Tests marked "replay" fail on c1bf625 on their assertion (measured with c1bf625's rules/ restored, this file in place); "guard"
ones keep what must not change. As in test_batch5_platform_notes, the skill here is a synthetic copy (only its reviewed line is
the real one), and the platform folders of this computer are never opened; the real version is pinned by digests only."""
import hashlib, json, os, sys, unittest
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_boxes import ROOT
import isr  # noqa: E402
from test_batch5_platform_notes import _SignIn, LINE12, SIGNIN, REL

OLD = "329d4f59c94da1e42737230253bbb671183546d2ce82e04af9c304a46e759071"
NEW = "b06512e770076a989724a0aac84961a993089aca44cbfc5e79774c4f16055724"
AGENT_REL = "agent-data/managed-skills/skills/sign-in/SKILL.md"
USER_REL = "sand-data/workflows/sign-in/SKILL.md"   # v0.8.1: the owner's copy, where a changed sign-in skill still counts
# sha256 of line 11 of the b06512e7 bytes with its line end (`sed -n 11p SKILL.md | sha256sum`, measured on the maintainer's copy, Oct 20)
NEW_LINE11 = "195407c010ae686c473a4c75fc353c88b1bbcdc9d7ea3a46799d9825a7d8a39b"
# the synthetic new version: one line fewer above the reviewed line, which is now line 11
SIGNIN11 = SIGNIN.replace("## Steps\n\nFollow these in order.\n", "## Steps\nFollow these in order.\n")


def sha(text):
    return hashlib.sha256(text.encode()).hexdigest()


def shipped_entries(digest):
    with open(os.path.join(ROOT, "rules", "platform-reviewed.json")) as f:
        return [e for e in json.load(f)["entries"] if e["sha256"] == digest]


class ShippedLists(unittest.TestCase):
    def test_the_shipped_lists_pin_b06512e7_at_line_11(self):   # replay (c1bf625: no b06512e7 lock line)
        with open(os.path.join(ROOT, "rules", "platform-release.lock")) as f:
            lock = set(f.read().splitlines())
        for rel in (REL, AGENT_REL):
            self.assertIn(f"{NEW}  {rel}", lock, rel)
            self.assertIn(f"{OLD}  {rel}", lock, rel)                     # boxes not yet updated keep theirs
        new, old = shipped_entries(NEW), shipped_entries(OLD)
        self.assertEqual(sorted((e["rule"], e["line"], tuple(e["paths"])) for e in new),
                         [("ISR-T004", 11, (REL, AGENT_REL)), ("ISR-T008", 11, (REL, AGENT_REL))])
        self.assertEqual({e["rule"]: e["note"] for e in new}, {e["rule"]: e["note"] for e in old})   # the same two notes
        self.assertEqual(sorted((e["rule"], e["line"]) for e in old), [("ISR-T004", 12), ("ISR-T008", 12)])
        self.assertEqual(hashlib.sha256((LINE12 + "\n").encode()).hexdigest(), NEW_LINE11)   # line 11 is the line the owner read

    def test_the_synthetic_copy_has_the_reviewed_line_at_line_11(self):   # guard (this file's own fixture)
        self.assertEqual(SIGNIN11.split("\n")[10], LINE12)
        self.assertEqual(SIGNIN.split("\n")[11], LINE12)


class NewVersion(_SignIn):
    """The shipped b06512e7 entries (rule, line, paths, note), bound to the synthetic copy's sha256 as the existing tests do."""

    def setUp(self):
        super().setUp()
        self.owned()
        self.skills(1)
        self.reviewed_file([dict(e, sha256=sha(SIGNIN)) for e in shipped_entries(OLD)]
                           + [dict(e, sha256=sha(SIGNIN11)) for e in shipped_entries(NEW)])

    def checks(self, p):
        return {f["rule"]: f for f in self.mine(p) if f["rule"] in ("ISR-T008", "ISR-T004") and not f.get("guarded")}

    def counted_change(self, p):
        return [f for f in self.mine(p) if f["rule"] in ("ISR-I001", "ISR-I002") and f["severity"] == "high" and isr.counts(f)]

    def vs(self):
        """v0.8.1: the snapshot's vendor records (never scored)."""
        return self.snap().get("vendor", [])

    def test_the_vendor_update_is_a_checked_platform_note_only(self):   # replay (c1bf625: both Confirmed, not checked)
        """v0.8.1 (decision, Oct 24): vendor folders are never scored; drift is tracked for the owner's files only. Both
        findings are platform notes at line 11, and no drift row is kept."""
        ps = [self.put(rel, SIGNIN) for rel in (REL, AGENT_REL)]
        self.audit()                                                     # the old version, baselined
        for rel in (REL, AGENT_REL):
            self.put(rel, SIGNIN11)                                      # the vendor update, on the release list
        r = self.audit_json()
        for p in ps:
            self.assertEqual({(f["rule"], f["where"].rsplit(":", 1)[1]) for f in self.vs()
                              if f["where"].split(":")[0] == p and f["rule"] in ("ISR-T008", "ISR-T004")},
                             {("ISR-T008", "11"), ("ISR-T004", "11")}, p)
            self.assertFalse([f for f in self.mine(p) if isr.counts(f)], p)
            self.assertFalse([f for f in self.snap()["findings"] + self.vs() if f["where"].split(":")[0] == p and f["rule"].startswith("ISR-I")], p)
            self.assertFalse([f for f in r["new"] if p in f["where"]], p)
        self.assertEqual((r["open_by_severity"]["critical"], r["open_by_severity"]["high"]), (0, 0))
        self.assertEqual(r["status"], isr.ALL_GOOD)

    def tampered_counts(self, p, text, line):
        """Not the reviewed bytes, so not on the release list: the change is the file's own counted high ISR-I001, and its
        ISR-T008/ISR-T004 are not checked notes: they keep their severity as Confirmed platform findings (batch 5 d1).
        v0.8.1 (decision, Oct 24): vendor folders are never scored; drift is tracked for the owner's files only. The same text in
        the owner's sign-in skill is where it counts; at p the two findings are platform notes."""
        self.put(REL, text, listed=False)
        u = self.put(USER_REL, text, listed=False)
        r = self.audit_json()
        got = self.checks(u)
        self.assertEqual({(k, f["label"], f["severity"], f["where"]) for k, f in got.items()},
                         {("ISR-T008", isr.CONFIRMED, "critical", f"{u}:{line}"), ("ISR-T004", isr.CONFIRMED, "high", f"{u}:{line}")})
        self.assertEqual({f["rule"] for f in self.vs() if f["where"].split(":")[0] == p and f["rule"] in ("ISR-T008", "ISR-T004")},
                         {"ISR-T008", "ISR-T004"})
        self.assertEqual([f["rule"] for f in self.counted_change(u)], ["ISR-I001"])
        self.assertFalse(self.counted_change(p))
        self.assertGreaterEqual(r["open_by_severity"]["high"], 1)
        self.assertNotEqual(r["status"], isr.ALL_GOOD)

    def test_one_byte_changed_anywhere_still_counts(self):   # guard
        """v0.8.1 (decision, Oct 24): vendor folders are never scored; drift is tracked for the owner's files only."""
        p = self.put(REL, SIGNIN11)
        self.put(USER_REL, SIGNIN11, listed=False)
        self.audit()                                                     # the reviewed version, baselined
        for old, new in (("Sign the user", "sign the user"), ("current URL.", "current URl."), ("themselves.\n", "themselves!\n")):
            with self.subTest(old):
                self.assertEqual(SIGNIN11.count(old), 1)
                bad = SIGNIN11.replace(old, new)
                self.assertEqual(len(bad.encode()), len(SIGNIN11.encode()))
                self.assertEqual(sum(a != b for a, b in zip(bad.encode(), SIGNIN11.encode())), 1)
                self.tampered_counts(p, bad, 11)

    def test_the_reviewed_line_moved_still_counts(self):   # guard
        """v0.8.1 (decision, Oct 24): vendor folders are never scored; drift is tracked for the owner's files only."""
        p = self.put(REL, SIGNIN11)
        self.put(USER_REL, SIGNIN11, listed=False)
        self.audit()
        lines = SIGNIN11.split("\n")
        lines[10], lines[11] = lines[11], lines[10]                      # the reviewed line is now line 12
        self.tampered_counts(p, "\n".join(lines), 12)


if __name__ == "__main__":
    unittest.main()
