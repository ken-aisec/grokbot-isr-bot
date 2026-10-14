"""DQ-041 replay (Oct 14 2026): a dry run copied the real canary registry but bound its own empty /tmp. An earlier attempt had
re-planted the decoy there at 13:09:01 (armed atime = Oct 13 13:09:01), so the second attempt saw atime > registry atime and
raised WT-K001 "read Oct 13 17:09Z" on a decoy nobody read. The real decoy's atime still equalled its registry value."""
import os, shutil, sys, tempfile, time, unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "watchtower"))
import wt  # noqa: E402


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.env = {k: os.environ.get(k) for k in ("WATCHTOWER_HOME", "WT_DECOY_ROOT")}
        os.environ["WATCHTOWER_HOME"] = os.path.join(self.tmp, "wt")
        os.environ["WT_DECOY_ROOT"] = os.path.join(self.tmp, "decoys")
        os.makedirs(wt.state_path(""), exist_ok=True)
        wt.plant_canaries()
        self.reg = wt.load_json(wt.state_path("canaries.json"), {})
        self.name, self.v = next(iter(self.reg.items()))
        self.p = self.v["path"]

    def tearDown(self):
        for k, v in self.env.items():
            os.environ.pop(k, None) if v is None else os.environ.__setitem__(k, v)
        shutil.rmtree(self.tmp, ignore_errors=True)

    def stale_copy(self):
        """Registry from 4 days ago (as copied into the dry run); file re-planted now by another run."""
        old = time.time() - 4 * 86400
        for v in self.reg.values():
            v.pop("mtime", None); v["planted_ts"] = old; v["atime"] = old - 86400
        wt.save_json(wt.state_path("canaries.json"), self.reg)

    def rules(self, record=False):
        return [f["rule"] for f in wt.canary_findings(record=record)]


class ReplayDryRunReplant(Base):
    def test_rewritten_unread_decoy_is_k007_not_k001(self):
        self.stale_copy()
        rules = self.rules()
        self.assertNotIn("WT-K001", rules)
        self.assertIn("WT-K007", rules)            # still reported, never silent

    def test_read_after_rewrite_is_still_a_read(self):
        self.stale_copy()
        st = os.stat(self.p)
        os.utime(self.p, (time.time() + 5, st.st_mtime))   # a real read after the rewrite
        self.assertTrue({"WT-K001", "WT-K004"} & set(self.rules()))
        self.assertNotIn("WT-K007", [f["rule"] for f in wt.canary_findings(record=False) if self.p in f["where"]])

    def test_untouched_real_decoy_is_quiet(self):
        self.assertEqual(self.rules(), [])

    def test_read_of_own_decoy_still_critical(self):
        st = os.stat(self.p)
        os.utime(self.p, (time.time(), st.st_mtime))
        fs = wt.canary_findings(record=False)
        self.assertTrue(any(f["rule"] == "WT-K001" and f["severity"] == "critical" for f in fs))

    def test_plant_records_mtime(self):
        self.assertAlmostEqual(self.v["mtime"], os.stat(self.p).st_mtime, delta=1)


if __name__ == "__main__":
    unittest.main()
