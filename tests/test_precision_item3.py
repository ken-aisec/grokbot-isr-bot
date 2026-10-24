"""v0.7.1 precision pass, item 3: evidence rules split the fact from the severity.

The fact stays listed; the severity is kept only when the thing is reachable. Oct 12 main box: a cloned old-site repo with an
old leftpad was a Confirmed high (ISR-D002) though nothing on the computer loads that project.
"""
import json, os, sys, unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_boxes import Box, OSV_DATA, wt  # noqa: E402


class PackageFacts(Box):
    def osv_at(self, project):
        lock = os.path.join(project, "package-lock.json")
        os.makedirs(project, exist_ok=True)
        open(lock, "w").write(json.dumps({"name": "x", "lockfileVersion": 3, "packages": {"node_modules/leftpad": {"version": "1.0.0"}}}))
        osv = json.dumps({"results": [{"source": {"path": lock}, "packages": OSV_DATA["results"][0]["packages"]}]})
        self.scanners(osv_scanner="#!/bin/sh\ncat <<'EOF'\n" + osv + "\nEOF\n")

    def d2(self):
        return [f for f in self.snap()["findings"] if f["rule"] == "ISR-D002"]

    def test_an_old_package_in_a_cloned_project_is_a_tip_not_a_confirmed_high(self):
        self.skills(1); self.osv_at(os.path.join(self.ws, "projects", "old-site"))
        r = self.audit()
        fs = self.d2()
        self.assertEqual([(f["class"], f["severity"], f["severity_was"]) for f in fs], [("tip", "info", "high")])
        self.assertIn("nothing on this computer loads", fs[0]["title"])
        self.assertIn("leftpad 1.0.0", fs[0]["title"])                       # the fact is still there, named
        self.assertGreaterEqual(r["score"], 90)

    def test_an_old_package_inside_a_live_skill_keeps_its_severity(self):
        d = self.skills(1)[0]; self.osv_at(d)
        self.audit()
        self.assertEqual([(f["label"], f["severity"]) for f in self.d2()], [(wt.CONFIRMED, "high")])

    def test_fixing_a_reachable_package_raises_the_score(self):
        d = self.skills(1)[0]; self.osv_at(d)
        before = self.audit()["score"]
        self.scanners(osv_scanner="#!/bin/sh\necho '{\"results\": []}'\n")
        r = self.audit()
        self.assertIn("ISR-D002", {f["rule"] for f in r["fixed"]})
        self.assertGreater(r["score"], before)

    def test_the_daily_check_keeps_the_tip_quiet(self):
        self.skills(1); self.osv_at(os.path.join(self.ws, "projects", "old-site"))
        self.audit()
        self.assertEqual(self.run_cmd("daily", "--roots", *self.roots)[1].strip(), "NO_CHANGES")
        self.assertEqual([f["class"] for f in self.d2()], ["tip"])            # carried over, not re-raised
        self.assertEqual(self.d2()[0]["title"].count("nothing on this computer loads"), 1)


if __name__ == "__main__":
    unittest.main()
