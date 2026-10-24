"""DQ-040: fix --revet --only works on skills daily/audit already flagged as changed, without a fresh preview."""
import json, os, sys, unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_boxes import Box  # noqa: E402
import isr  # noqa: E402


class DQ040RevetOnlyWithoutFreshPreview(Box):
    def test_revet_only_reapproves_changed_skills_when_preview_is_stale(self):
        """Main box, Oct 13 (DQ-040): daily reported four skills as changed; owner approved re-approving them by name.
        `fix --revet --only <names>` with a stale/empty preview list re-approved nothing and said each 'isn't a skill
        with an open change'. Neutral names stand in for the real skill names."""
        ds = self.skills(4)
        self.scanners()
        self.run_cmd("baseline", "--roots", *self.roots)
        for d in ds:
            open(os.path.join(d, "SKILL.md"), "a").write("Also list the open tasks.\n")
        self.audit()
        # Stale preview from an earlier run that did not list these four (empty list = same failure mode).
        isr.save_json(isr.state_path("revet_plan.json"), {"at": "2026-10-01T00:00:00+00:00", "skills": []})
        names = ",".join(isr.skill_name(d) for d in ds)
        code, o, _ = self.run_cmd("fix", "--revet", "--only", names, "--roots", *self.roots)
        self.assertEqual(code, 0, o)
        done = json.loads(o)["done"]
        joined = " | ".join(done)
        self.assertNotIn("isn't a skill with an open change", joined, done)
        self.assertNotIn("not in the list you approved", joined, done)
        self.assertEqual(sum(1 for x in done if "re-approved" in x), 4, done)
        for d in ds:
            self.assertIn(f"Re-scanned {isr.skill_name(d)}", joined)

    def test_revet_without_only_still_respects_the_preview_list(self):
        """DQ-019 must still hold: full --revet (no --only) refuses skills that changed after the preview."""
        ds = self.skills(3)
        self.scanners()
        self.run_cmd("baseline", "--roots", *self.roots)
        for d in ds[:2]:
            open(os.path.join(d, "SKILL.md"), "a").write("Also list the open tasks.\n")
        self.audit()
        code, o, _ = self.run_cmd("fix", "--roots", *self.roots)
        self.assertEqual(code, 0)
        listed = isr.load_json(isr.state_path("revet_plan.json"), {})["skills"]
        self.assertEqual(len(listed), 2)
        open(os.path.join(ds[2], "SKILL.md"), "a").write("Changed later.\n")
        self.audit()
        code, o, _ = self.run_cmd("fix", "--revet", "--roots", *self.roots)
        done = json.loads(o)["done"]
        self.assertTrue(any("not in the list you approved" in x and "skill002" in x for x in done), done)
        self.assertEqual(sum(1 for x in done if "re-approved" in x), 2, done)

    def test_revet_only_still_refuses_a_name_with_no_open_change(self):
        ds = self.skills(2)
        self.scanners()
        self.run_cmd("baseline", "--roots", *self.roots)
        open(os.path.join(ds[0], "SKILL.md"), "a").write("Also list the open tasks.\n")
        self.audit()
        isr.save_json(isr.state_path("revet_plan.json"), {"at": "2026-10-01T00:00:00+00:00", "skills": []})
        code, o, _ = self.run_cmd("fix", "--revet", "--only", "skill000,skill001", "--roots", *self.roots)
        done = json.loads(o)["done"]
        joined = " | ".join(done)
        self.assertIn("skill000", joined)
        self.assertIn("re-approved", joined)
        self.assertIn("skill001: not re-scanned. It isn't a skill with an open change", joined)


if __name__ == "__main__":
    unittest.main()
