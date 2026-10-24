"""Deterministic order (before batch 1): a gitleaks folder finding (ISR-S002) names its first files and lines in one fixed
order, whatever order the folder was listed in or gitleaks reported its hits in. test_batch6b_codex_r2's
test_every_line_and_file_is_named failed on 0.7.3 (ab8c7e7) on a box whose folder listing changed after a restart: the
evidence followed gitleaks' report, which follows the listing. The hits are now sorted by path, then line as a number
(_leak_order) before they are named; which hits are found and counted is unchanged.

The listing the scan uses is the gitleaks stand-in's os.walk, in its own process, so it is reordered in the stand-in's text;
the report is reordered where Watchtower reads it (gitleaks_private). Tests marked "replay" fail on ab8c7e7 on their
assertion; "guard" ones pass there too, unless marked "new" (they call something ab8c7e7 doesn't have)."""
import json, os, random, sys, unittest
from unittest import mock
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import test_boxes  # noqa: E402
import isr  # noqa: E402
from test_batch6_example_keys import _Keys, FAKE_GITLEAKS

EXPECT = "6 hit(s): github-pat at fake0.md:1, fake0.md:2, fake1.md:1 and 3 more"   # test_every_line_and_file_is_named's
WALK = "files = [os.path.join(d, n) for d, _, ns in os.walk(src) for n in ns]"   # the stand-in's folder listing
SEED = 20261022


def shuffled(seed):
    def order(xs):
        xs = list(xs)
        random.Random(seed).shuffle(xs)
        return xs
    return order


ORDERS = {"as listed": list, "reversed": lambda xs: list(xs)[::-1], **{f"shuffled {i}": shuffled(SEED + i) for i in range(3)}}


class ListingOrder(_Keys):
    d = "sand-data/workflows/setup-dev-tools/examples"

    def build(self):
        """test_every_line_and_file_is_named's folder: a fake in each of 5 files, two in fake0.md."""
        for i in range(5):
            text = "".join(f"token: ghp_FAKE{i}{j}" + "y8" * 15 + "\n" for j in range(2 if i == 0 else 1))
            p = self.put(f"{self.d}/fake{i}.md", text)
            for j in range(2 if i == 0 else 1):
                self.leak(p, f"ghp_FAKE{i}{j}" + "y8" * 15, rule="github-pat")

    def scan_with(self, body=FAKE_GITLEAKS):
        """_Keys.scan with the gitleaks stand-in `body`: the ISR-S002 findings in the skill's folder."""
        cf = os.path.join(self.tmp, "cands.json")
        json.dump(self.cands, open(cf, "w"))
        self.scanners(gitleaks=body.replace("CANDS", repr(cf)), trufflehog=None)
        self.audit()
        return [f for f in self.keys(self.snap()["findings"], self.skill) if f["rule"] == "ISR-S002"]

    def reported(self, order):
        """Scan with gitleaks' report given to Watchtower in `order`; (the ISR-S002 findings, each report as given)."""
        orig, seen = isr.gitleaks_private, []

        def given(exe, source, priv, *a, **k):
            got, err = orig(exe, source, priv, *a, **k)
            if isinstance(got, list):
                got = order(got)
                seen.append(list(got))
            return got, err
        with mock.patch.object(isr, "gitleaks_private", given):
            return self.scan_with(), seen

    def test_scanner_report_order(self):   # replay: ab8c7e7 names the files in the report's order
        self.build()
        for name, order in ORDERS.items():
            with self.subTest(order=name):
                got, _ = self.reported(order)
                self.assertEqual([f["evidence"] for f in got], [EXPECT])

    def test_directory_listing_order(self):   # replay: ab8c7e7 names the files in the folder listing's order
        self.assertIn(WALK, FAKE_GITLEAKS)   # the stand-in still lists its folder this way, so the reorders below take effect
        self.build()
        walks = {"reversed": "\nfiles.reverse()", **{f"shuffled {i}": f"\nimport random\nrandom.Random({SEED + i}).shuffle(files)"
                                                     for i in range(2)}}
        for name, extra in walks.items():
            with self.subTest(listing=name):
                got = self.scan_with(FAKE_GITLEAKS.replace(WALK, WALK + extra))
                self.assertEqual([f["evidence"] for f in got], [EXPECT])

    def test_hits_and_places_are_unchanged(self):   # guard: the order changes nothing found or counted
        self.build()
        d = os.path.join(self.home, self.d)
        want = {("fake0.md", 1), ("fake0.md", 2), ("fake1.md", 1), ("fake2.md", 1), ("fake3.md", 1), ("fake4.md", 1)}
        for name, order in ORDERS.items():
            with self.subTest(order=name):
                got, seen = self.reported(order)
                mine = [l for l in seen[0] if str(l.get("File") or "").startswith(d + "/")]
                self.assertEqual(len(mine), 6)
                self.assertEqual({(os.path.relpath(l["File"], d), l["StartLine"]) for l in mine}, want)
                self.assertEqual([(f["where"], f["title"], f.get("severity_was") or f["severity"]) for f in got],
                                 [(d, "gitleaks: secrets in 5 files under examples", "critical")])
                self.assertTrue(got[0]["evidence"].startswith("6 hit(s): github-pat at "), got[0]["evidence"])


class LeakOrder(unittest.TestCase):
    def test_lines_sort_as_numbers(self):   # guard (new: ab8c7e7 has no _leak_order)
        hits = [{"File": "/d/b.md", "StartLine": 1}, {"File": "/d/a.md", "StartLine": 10},
                {"File": "/d/a.md", "StartLine": 2, "StartColumn": 9, "RuleID": "b"}, {"File": "/d/a.md", "StartLine": 2},
                {"File": "/d/a.md", "StartLine": 2, "StartColumn": 9, "RuleID": "a"}]
        got = sorted(hits, key=isr._leak_order)
        self.assertEqual([(h["File"], h["StartLine"], h.get("StartColumn"), h.get("RuleID")) for h in got],
                         [("/d/a.md", 2, None, None), ("/d/a.md", 2, 9, "a"), ("/d/a.md", 2, 9, "b"), ("/d/a.md", 10, None, None),
                          ("/d/b.md", 1, None, None)])

    def test_odd_fields_sort_without_failing(self):   # guard (new)
        hits = [{"File": None, "StartLine": None}, {"File": "/d/a.md", "StartLine": "7"}, {"File": "/d/a.md", "StartLine": True},
                {}, {"File": "/d/a.md", "StartLine": 3, "StartColumn": "x", "RuleID": None}]
        got = sorted(hits, key=isr._leak_order)
        self.assertEqual(sorted(map(id, got)), sorted(map(id, hits)))   # the same hits, none lost or added


if __name__ == "__main__":
    unittest.main()
