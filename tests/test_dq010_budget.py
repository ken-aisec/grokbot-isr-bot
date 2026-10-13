"""DQ-010 leftover, main box v0.6.7 audit of 2026-10-09: "SkillSpector and husk checked 7 of 41 new or changed skills in the
time budget; the other 34 are picked up by the next runs". The copies half was fixed in 98c0c6e. The other half: an owner who
wants every skill checked in one full audit had no way to get it, because `audit --budget N` was still cut off by the run
limit (about 8 minutes), so a bigger budget bought nothing.
"""
import os, sys, unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_boxes import Box, SCANNERS, wt  # noqa: E402

SLOW_SS = SCANNERS["skillspector"].replace("skills = []\n", "import time\ntime.sleep(1)\nskills = []\n")


class BiggerBudget(Box):
    def setUp(self):
        super().setUp()
        saved = (wt.RUN_LIMIT, wt.ENGINE_BUDGET, wt.ENGINE_CHUNK, wt.ENGINE_LAUNCH_BASE, wt.ENGINE_LAUNCH_PER_SKILL)
        self.addCleanup(lambda: setattr(wt, "RUN_LIMIT", saved[0]) or setattr(wt, "ENGINE_BUDGET", saved[1]) or setattr(wt, "ENGINE_CHUNK", saved[2])
                        or setattr(wt, "ENGINE_LAUNCH_BASE", saved[3]) or setattr(wt, "ENGINE_LAUNCH_PER_SKILL", saved[4]))
        # Scaled down: a 23-second run limit stands in for the real 540, and each scanner launch takes a second.
        wt.RUN_LIMIT, wt.ENGINE_BUDGET, wt.ENGINE_CHUNK, wt.ENGINE_LAUNCH_BASE, wt.ENGINE_LAUNCH_PER_SKILL = 23, 420, 1, 5, 0
        self.ds = self.skills(8)
        self.scanners(skillspector=SLOW_SS)

    def waiting(self):
        cache = wt.load_json(wt.state_path("engine_cache.json"), {})
        return [d for d in self.ds if not (cache.get(d) or {}).get("engines")]

    def test_the_run_limit_still_caps_a_normal_full_audit(self):
        r = self.audit()
        self.assertTrue(self.waiting())                                            # three seconds of scanner time: not all eight
        self.assertTrue(any("picked up by the next runs" in n for n in r["notes"]), r["notes"])

    def test_asking_for_more_scanner_time_checks_every_skill_in_one_run(self):
        r = self.audit("--budget", "30")                                           # v0.7.0: still cut off by the run limit
        self.assertEqual(self.waiting(), [], r["notes"])
        self.assertFalse(any("picked up by the next runs" in n for n in r["notes"]), r["notes"])

    def test_the_budget_has_a_ceiling_and_the_daily_check_keeps_its_limit(self):
        import argparse
        seen = {}
        real = wt.audit
        def spy(roots, exports, quick=False):
            seen[quick] = (wt.ENGINE_BUDGET, wt.DEADLINE - wt.time.monotonic())
            return [], {}
        wt.audit = spy
        self.addCleanup(setattr, wt, "audit", real)
        for quick in (False, True):
            try:
                wt.run_audit_locked(argparse.Namespace(roots=self.roots, exports=None, budget=99999, everything=False, live_only=False), quick)
            except Exception:
                pass
        self.assertEqual(seen[False][0], wt.MAX_BUDGET)                            # an hour at most
        self.assertGreater(seen[False][1], wt.MAX_BUDGET)                          # and the full audit runs long enough to use it
        self.assertLessEqual(seen[True][1], wt.DAILY_LIMIT + 1)                    # the daily check never runs longer


if __name__ == "__main__":
    unittest.main()
