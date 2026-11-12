"""1.1.0: `isr.py artifacts`: this week's threat report and access map as two standalone Markdown files from one observation,
with a manifest (reports/artifacts-<week>.json), and the report recipe that attaches them or says why it can't.

Tests marked "replay" fail on fa0525f on their assertion (no artifacts part or command, the old recipe text); "guard" ones keep
what must not change. Every value is synthetic (tests/fixtures/access_v110); Bots are bot-001…."""
import hashlib, json, os, re, sys, unittest
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_boxes import ROOT
import isr  # noqa: E402
from test_v110_observe import _V110

FIX = os.path.join(ROOT, "tests", "fixtures", "access_v110")
TAG = "2026-W45"


def fixture(name):
    with open(os.path.join(FIX, name), encoding="utf-8") as f:
        return f.read() if name.endswith(".md") else json.load(f)


def read(*p):
    with open(os.path.join(ROOT, *p), encoding="utf-8") as f:
        return f.read()


class _Pages(_V110):
    def pages(self, brief=True):
        prev, cur = isr.obs_record(fixture("obs_prev.json")), isr.obs_record(fixture("obs_cur.json"))
        diff = isr.diff_observations(isr.pick_baseline([prev], cur), cur)
        facts, why = isr.platform_facts()
        return (isr.render_threat_report_md(cur, fixture("last_brief.json") if brief else None, fixture("snapshot.json"), TAG, facts, why, diff),
                isr.render_access_map_md(cur, diff, facts, why, TAG))

    def section(self, page, head):
        i = page.index(head)
        j = page.find("\n## ", i + len(head))
        return page[i:] if j < 0 else page[i:j]


class ThePages(_Pages):
    def test_a1_both_pages_match_their_goldens_byte_for_byte(self):   # replay (fa0525f: no renderers)
        threat, access = self.pages()
        self.assertEqual(threat, fixture("expected_threat_report.md"))
        self.assertEqual(access, fixture("expected_access_map.md"))

    def test_a2_one_header_and_one_unresolved_scope_in_both(self):   # replay (fa0525f: no renderers)
        threat, access = self.pages()
        for head in ("## Coverage", "## History limits", "## Platform context", "## Unresolved scope"):
            self.assertEqual(self.section(threat, head), self.section(access, head))
        self.assertEqual(threat.split("\n")[2], access.split("\n")[2])
        self.assertTrue(threat.split("\n")[2].startswith("Observation `obs-20261108T100000Z` · observed 2026-11-08T10:00:00+00:00 UTC (Nov 8 5:00 AM ET) · ISR Bot "))

    def test_a3_hostile_names_and_titles_are_inert(self):   # replay (fa0525f: no md_text)
        threat, access = self.pages()
        for page in (threat, access):
            for bad in ("](", "\u202e", "*bold*", "javascript:"):
                self.assertNotIn(bad, page)
            self.assertIsNone(re.search(r"(?<!\\)<img", page))
        self.assertIn("bot\\-003 \\*bold\\* \\[x\\]\\(\\[link\\]", access)
        self.assertIn("FAKE Feed \\| two", threat)
        self.assertEqual(isr.md_text("a\u200bb\u2066c\nd|e"), "abc d\\|e")
        self.assertEqual((isr.md_link("https://news.example.invalid/x"), isr.md_link("javascript:alert(1)"), isr.md_link("https://a/<b>")),
                         ("<https://news.example.invalid/x>", "", ""))

    def test_a4_keys_in_outside_text_are_masked(self):   # replay (fa0525f: no md_text)
        key = "ghp_" + "FAKE" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7"
        self.assertNotIn(key, isr.md_text(f"token {key} leaked"))
        self.assertNotIn(key[8:], isr.md_text(f"token {key} leaked", rollcall=False))

    def test_a5_no_brief_says_so_and_the_manifest_records_it(self):   # replay (fa0525f: no artifacts command)
        threat, _ = self.pages(brief=False)
        self.assertIn(f"- No threat brief for {TAG}.", threat)
        self.world(rollcall=False)
        code, man = self.artifacts()
        self.assertEqual(man["brief"], "missing")
        week = isr.dt.date.today().isocalendar()
        self.assertIn(f"- No threat brief for {week[0]}-W{week[1]:02d}.", self.files(man)["threat-report"])

    def test_a6_the_manifest_matches_the_files(self):   # replay (fa0525f: no artifacts command)
        self.world()
        code, man = self.artifacts()
        rdir = self.isr_home("reports")
        on_disk = json.loads(open(os.path.join(rdir, next(n for n in os.listdir(rdir) if n.startswith("artifacts-")))).read())
        self.assertEqual(on_disk, {k: man[k] for k in ("observation_id", "observed_at", "files", "unresolved_count", "brief")})
        self.assertEqual([f["kind"] for f in man["files"]], ["threat-report", "access-map"])
        for f in man["files"]:
            raw = open(f["path"], "rb").read()
            self.assertEqual((f["sha256"], f["bytes"]), (hashlib.sha256(raw).hexdigest(), len(raw)))
            self.assertEqual(os.path.dirname(f["path"]), rdir)
            page = raw.decode("utf-8")
            self.assertIn(f"Observation `{man['observation_id']}`", page)
            self.assertEqual(man["unresolved_count"], len([x for x in self.section(page, "## Unresolved scope").split("\n") if x.startswith("- ")]))
        self.assertTrue(os.path.isfile(os.path.join(self.obs_dir(), man["observation_id"] + ".json")))

    def test_a8_not_a_sandbox_platform_context_and_no_shared_browser_claim(self):   # replay (fa0525f: no renderers)
        for page in self.pages():
            self.assertIn(isr.NOT_A_SANDBOX, page)
            self.assertIn(isr.PLATFORM_LABEL + ": Real browser sessions are per\\-agent", page)
            self.assertIsNone(re.search(r"(?i)every bot can|shared browser", page))

    def test_a8_a_story_that_names_nothing_here_claims_no_reach(self):   # replay (cd67415: the brief's means_here in the report)
        prev, cur = isr.obs_record(fixture("obs_prev.json")), isr.obs_record(fixture("obs_cur.json"))
        diff = isr.diff_observations(isr.pick_baseline([prev], cur), cur)
        facts, why = isr.platform_facts()
        cats = ("mcp", "hijack", "supply", "creds", "browser", "platform")
        for half in (cats[:3], cats[3:]):
            brief = dict(fixture("last_brief.json"), kev=[], research=[
                {"id": f"g-{c}", "title": "A flaw in something new", "category": c, "category_label": c, "cves": [], "score": 9,
                 "tier": "act", "source": "FAKE Feed", "link": "https://news.example.invalid/x"} for c in half])
            page = isr.render_threat_report_md(cur, brief, fixture("snapshot.json"), TAG, facts, why, diff)
            here = [x for x in page.split("\n") if x.startswith("- Here (observed here ")]
            self.assertEqual(len(here), len(half))
            for line in here:
                self.assertIsNone(re.search(r"(?i)any bot can read any file|share one browser|every login|every bot|all your bots share", line), line)


class TheRecipe(unittest.TestCase):
    def test_a7_the_report_recipe_attaches_both_files_or_says_why_not(self):   # replay (fa0525f: the old step 3)
        rep, brief, routine = read("skills", "isr-bot-report", "SKILL.md"), read("skills", "isr-bot-brief", "SKILL.md"), read("routines", "weekly-audit.md")
        for want in ("isr.py artifacts --json", "SendToUser", "Attachments unavailable: <reason>", "Never present a path as delivered",
                     "observation_id", "Don't attach the HTML pages"):
            self.assertIn(want, rep)
        self.assertNotIn("Attach `dashboard.html`", rep)
        self.assertIn("The file that gets attached is the Markdown threat report `isr.py artifacts` writes", brief)
        self.assertIn("then run `isr.py artifacts --json`", routine)
        self.assertIn("attach the two files `artifacts` names, or say attachments are unavailable and why", routine)
        self.assertNotIn("End with where the two pages are", routine)


if __name__ == "__main__":
    unittest.main()
