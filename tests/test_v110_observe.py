"""1.1.0: the status-only observation behind `isr.py artifacts` (observe.py).

What it may do: build the access map now, lstat each known CLI sign-in file name, read the Bots' profile names, and keep the
record in a 0700 folder. What it never does: open a credential file, follow a link, run anything but the crontab listing, or
reach the network.

Tests marked "replay" fail on fa0525f on their assertion (no observe part, no artifacts command); "guard" ones keep what must
not change. Every planted value is FAKE…; the box is a temp folder, never this computer's own."""
import builtins, json, os, shutil, socket, stat, subprocess, sys, unittest
from unittest import mock
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_boxes import ROOT
import isr  # noqa: E402
from test_batch5_access_map import _Access, w, cookie_jar, SETTINGS, MCP

AGENT_1 = "1b2c3d4e-0000-4000-8000-000000000001"
FAKES = ("FAKEenvVALUE", "FAKEargVALUE", "FAKEheaderVALUE", "FAKEurlPATH", "FAKEurlQUERY", "FAKEmemoryTEXT", "FAKEauthFILE",
         "FAKEcookieVALUE", "FAKEprofileFIELD", "FAKEreplyTEXT", "FAKEportUSER", "FAKElinkTARGET")
BOT_1 = {"name": "bot-001", "connectors": ["Gmail"], "routines": [{"name": "FAKEreplyTEXT", "trigger": "schedule", "sends_or_posts": False, "asks_first": True}],
         "memories": {"count": 2, "loosen_permissions": 0, "from_outside_content": 0}, "memory_text": "FAKEreplyTEXT"}
BOT_2 = {"name": "bot-002", "connectors": ["Slack"], "routines": [], "memories": {"count": 0, "loosen_permissions": 0, "from_outside_content": 0}}


class _V110(_Access):
    def world(self, rollcall=True):
        h = self.home
        w(os.path.join(h, "agent-data", "settings.json"), SETTINGS)
        cookie_jar(h, [("mail.google.com", "SID", "FAKEcookieVALUE"), (".example.com", "_ga", "x")])
        os.chmod(w(os.path.join(h, ".codex", "auth.json"), {"token": "FAKEauthFILE"}), 0o600)
        os.chmod(w(os.path.join(h, ".npmrc"), "//registry.example.invalid/:_authToken=FAKEauthFILE\n"), 0o640)
        self.target = w(os.path.join(self.tmp, "elsewhere", "netrc-target"), "machine x login y password FAKElinkTARGET\n")
        os.symlink(self.target, os.path.join(h, ".netrc"))
        w(os.path.join(h, ".cursor", "mcp.json"), MCP)
        w(os.path.join(h, "agent-data", "agents", AGENT_1, "profile.json"), {"name": "bot-001", "notes": "FAKEprofileFIELD"})
        w(os.path.join(h, "agent-data", "agents", AGENT_1, "memories.json"), [{"text": "FAKEmemoryTEXT"}])
        w(self.isr_home("exports", "roster.json"), [{"name": n, "kind": "bot"} for n in ("bot-001", "bot-002")])
        if rollcall:
            self.rollcall(BOT_1, BOT_2)

    def artifacts(self):
        try:
            code, out, err = self.run_cmd("artifacts", "--json")
        except SystemExit as e:   # fa0525f has no such command: argparse exits 2
            return e.code, {}
        self.assertEqual(code, 0, err)
        return code, json.loads(out)

    def files(self, man):
        return {f["kind"]: open(f["path"]).read() for f in man.get("files", [])}

    def obs_dir(self):
        return self.isr_home("state", "observations")


class StatusOnly(_V110):
    def test_o1_no_fake_value_reaches_any_output(self):   # replay (fa0525f: no artifacts command)
        self.world()
        code, man = self.artifacts()
        self.assertEqual(code, 0)
        texts = list(self.files(man).values())
        r = self.isr_home("reports")
        texts.append(open(os.path.join(r, next(n for n in os.listdir(r) if n.startswith("artifacts-")))).read())
        texts += [open(os.path.join(self.obs_dir(), n)).read() for n in os.listdir(self.obs_dir())]
        texts.append(json.dumps(man))
        self.assertEqual(len(texts), 5)
        for t in texts:
            for fake in FAKES:
                self.assertNotIn(fake, t)

    def test_o2_no_credential_or_store_file_is_opened(self):   # replay (fa0525f: no cred_status)
        self.world()
        guarded = {os.path.realpath(os.path.join(self.home, rel)) for rel in isr.KNOWN_CRED_FILES} | {os.path.realpath(self.target)}
        guarded |= {os.path.realpath(p) for p in isr.secret_store_places()}

        def resolve(p, dir_fd=None):
            p = os.fsdecode(p) if isinstance(p, (str, bytes)) else None
            if p is None:
                return None
            if dir_fd is not None and not os.path.isabs(p):
                p = os.path.join(os.readlink(f"/proc/self/fd/{dir_fd}"), p)
            return os.path.realpath(p)

        real_os_open, real_open = os.open, builtins.open

        def os_open(p, flags, mode=0o777, *, dir_fd=None):
            if resolve(p, dir_fd) in guarded:
                raise AssertionError(f"opened {p}")
            return real_os_open(p, flags, mode, dir_fd=dir_fd)

        def b_open(p, *a, **k):
            if isinstance(p, (str, bytes)) and resolve(p) in guarded:
                raise AssertionError(f"opened {p}")
            return real_open(p, *a, **k)

        with mock.patch("os.open", os_open), mock.patch("builtins.open", b_open):
            creds = {c["file"]: c for c in isr.cred_status()}
            obs = isr.access_observation()
        self.assertEqual(creds["~/.codex/auth.json"]["state"], "present")
        self.assertEqual(creds["~/.codex/auth.json"]["mode"], "0600")
        self.assertEqual(creds["~/.npmrc"]["mode"], "0640")
        self.assertEqual(obs["coverage"]["cli_files"], "complete")
        self.assertEqual(isr.cred_words(creds["~/.npmrc"]), "present; mode 0640: mode bits permit group read; owned by ISR Bot's uid")

    def test_o3_only_the_crontab_listing_runs_and_nothing_reaches_the_network(self):   # replay (fa0525f: no artifacts command)
        self.world()
        ran, real_popen = [], subprocess.Popen

        class Spy(real_popen):
            def __init__(self, args, *a, **k):
                argv = [str(x) for x in (args if isinstance(args, (list, tuple)) else [args])]
                ran.append(argv)
                if any(bad in " ".join(argv) for bad in ("gh", "auth", "trufflehog", "gitleaks", "curl")):
                    raise AssertionError(f"ran {argv}")
                super().__init__(args, *a, **k)

        def no_net(*a, **k):
            raise AssertionError("socket opened")

        with mock.patch("subprocess.Popen", Spy), mock.patch("socket.socket", no_net), mock.patch("socket.create_connection", no_net):
            code, man = self.artifacts()
        self.assertEqual(code, 0)
        self.assertTrue(man.get("files"))
        self.assertEqual({tuple(a[-2:]) if len(a) >= 2 else tuple(a) for a in ran} - {("crontab", "-l")}, set(), ran)

    def test_o4_a_link_is_named_a_link_and_its_target_never_looked_at(self):   # replay (fa0525f: no cred_status)
        self.world()
        target = os.path.realpath(self.target)
        real_stat, real_open = os.stat, os.open

        def stat_(p, *a, **k):
            if isinstance(p, (str, bytes)) and os.path.realpath(os.fsdecode(p)) == target and k.get("follow_symlinks", True):
                raise AssertionError("stat on the link target")
            return real_stat(p, *a, **k)

        with mock.patch("os.stat", stat_):
            c = {c["file"]: c for c in isr.cred_status()}["~/.netrc"]
        self.assertEqual((c["state"], c["mode"]), ("link", None))
        self.assertTrue(isr.cred_words(c).startswith("a link (target not checked)"))
        code, man = self.artifacts()
        page = self.files(man)["access-map"]
        self.assertIn("~/\\.netrc (netrc logins): a link (target not checked)", page)
        self.assertNotIn("can read", page.replace("any Bot that can read", ""))
        self.assertIn(isr.REACH_UNDETERMINED, page)

    def test_o5_a_pseudonym_survives_a_rename_and_a_name_based_one_says_so(self):   # replay (fa0525f: no bot_pid)
        self.world()
        first = {b["name"]: b for b in isr.access_observation()["bots"]}
        self.assertEqual(first["bot-001"]["id_basis"], "uuid")
        self.assertEqual(first["bot-001"]["pid"], isr.bot_pid(AGENT_1))
        self.assertEqual((first["bot-002"]["id_basis"], first["bot-002"]["pid"]), ("name", isr.bot_pid("bot-002")))
        w(os.path.join(self.home, "agent-data", "agents", AGENT_1, "profile.json"), {"name": "bot-009"})
        again = {b["pid"]: b for b in isr.access_observation()["bots"]}
        self.assertEqual(again[isr.bot_pid(AGENT_1)]["name"], "bot-009")
        code, man = self.artifacts()
        self.assertIn("id from its name: a rename looks like a new Bot", self.files(man)["access-map"])

    def test_o6_an_incomplete_source_reads_incomplete_with_its_reason(self):   # replay (fa0525f: no access_observation)
        self.world()
        with mock.patch.object(isr, "_ax_jar_now", return_value=(None, False)):
            obs = isr.access_observation()
            code, man = self.artifacts()
        self.assertEqual(obs["coverage"]["browser"], "incomplete: something there couldn't be read")
        page = self.files(man)["access-map"]
        self.assertIn("| Browser cookie files | incomplete: something there couldn't be read |", page)
        self.assertIn("- Browser cookie files: incomplete: something there couldn't be read.", page.split("## Unresolved scope")[1])


class TheStore(_V110):
    def test_o7_modes_a_planted_link_and_tampered_platform_facts(self):   # replay (fa0525f: no artifacts command)
        self.world(rollcall=False)
        code, man = self.artifacts()
        self.assertEqual(man["history"], "saved")
        d = self.obs_dir()
        self.assertEqual(stat.S_IMODE(os.lstat(d).st_mode), 0o700)
        names = os.listdir(d)
        self.assertEqual(len(names), 1)
        self.assertEqual(stat.S_IMODE(os.lstat(os.path.join(d, names[0])).st_mode), 0o600)
        self.assertNotIn("platform context unavailable", self.files(man)["access-map"])
        shutil.rmtree(d)
        elsewhere = os.path.join(self.tmp, "planted")
        os.makedirs(elsewhere)
        os.symlink(elsewhere, d)
        code, man = self.artifacts()
        self.assertTrue(man["history"].startswith("not saved: the observations folder can't be used safely"), man["history"])
        self.assertEqual(os.listdir(elsewhere), [])
        bad = os.path.join(self.tmp, "platform_facts.json")
        open(bad, "w").write(open(isr.PLATFORM_FACTS).read().replace("per-agent", "shared"))
        with mock.patch.object(isr, "installed_root", return_value=os.path.dirname(ROOT)):   # held to MANIFEST.sha256 as installed
            self.assertEqual(isr.platform_facts()[1], "")
            with mock.patch.object(isr, "PLATFORM_FACTS", bad):
                facts, why = isr.platform_facts()
        self.assertEqual(facts, [])
        self.assertTrue(why)
        obs = isr.access_observation()
        diff = isr.diff_observations(None, obs)
        for page in (isr.render_access_map_md(obs, diff, facts, why, "2026-W45"),
                     isr.render_threat_report_md(obs, None, None, "2026-W45", facts, why, diff)):
            self.assertIn("- platform context unavailable (", page)
            self.assertNotIn(isr.PLATFORM_LABEL, page)

    def test_only_the_newest_twelve_are_kept(self):   # guard
        self.world(rollcall=False)
        obs = isr.access_observation()
        for i in range(14):
            isr.save_observation(dict(obs, observation_id=f"obs-202611{i + 1:02d}T000000Z"))
        self.assertEqual(sorted(os.listdir(self.obs_dir()))[0], "obs-20261103T000000Z.json")
        self.assertEqual(len(os.listdir(self.obs_dir())), isr.OBS_KEEP)


if __name__ == "__main__":
    unittest.main()
