"""Batch 6 PR3, KL5 (#16 high 1) and the error/link half of #16 medium 2: a lookup Watchtower couldn't make is never "there is none".

os.path.isdir, isfile and lexists say False both for a name that isn't there and for one Watchtower wasn't allowed to look at (a
folder on the way without search permission). The access map then said "none" for what it couldn't see: no cookie jar, no
command-line sign-in, 0 scheduled jobs, "found no Gmail". `_look` tells the two apart; every lookup the map rests on uses it.
The scheduled-job folders are listed without following a link and without raising (the audit stopped on a cron folder it
couldn't list).

Tests marked "replay" fail on 1aed58a on their assertion (measured with 1aed58a's watchtower/ sources, this file in place);
"guard" ones keep what must not change. Denied lookups are made in memory (os.stat/os.lstat refuse the paths, as a locked
folder on the way does), except where a real chmod or link is named. Every planted value is FAKE…; the box is a temp folder."""
import errno, json, os, sys, unittest
from unittest import mock
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_boxes import wt
from test_batch5_access_map import AGENT, w
from test_batch5_access_round2 import CANT, DAY, _Small

GMAIL_STORY = "Gmail flaw lets attackers steal session tokens"
UNREAD = "Chief Worry Bot couldn't check all of it this time (something there couldn't be read)."


class Denied:
    """os.stat and os.lstat refuse these paths and everything under them with PermissionError, as a folder on the way without
    search permission does. A call relative to a folder fd (dir_fd) is left alone."""

    def __init__(self, *paths):
        self.paths = [os.path.normpath(p) for p in paths]

    def hit(self, p, kw):
        if kw.get("dir_fd") is not None or not isinstance(p, (str, bytes, os.PathLike)):
            return False
        p = os.path.normpath(os.path.abspath(os.fsdecode(p)))
        return any(p == d or p.startswith(d + "/") for d in self.paths)

    def __enter__(self):
        def wrap(real):
            def f(p, *a, **kw):
                if self.hit(p, kw):
                    raise PermissionError(errno.EACCES, "Permission denied", os.fsdecode(p))
                return real(p, *a, **kw)
            return f
        self.patches = [mock.patch("os.stat", wrap(os.stat)), mock.patch("os.lstat", wrap(os.lstat))]
        for p in self.patches:
            p.start()
        return self

    def __exit__(self, *exc):
        for p in reversed(self.patches):
            p.stop()


class _Lookups(_Small):
    def setUp(self):
        super().setUp()
        real = wt.run   # no crontab on the box: `crontab -l` says so (the computer's own crontab is never read)
        self.cron = mock.patch.object(wt, "run", lambda cmd, *a, **k: (1, "", "no crontab for box") if list(cmd[:2]) == ["crontab", "-l"] else real(cmd, *a, **k))
        self.cron.start()
        self.addCleanup(self.cron.stop)

    def answered(self):
        self.said({"Golf": {"said_at": DAY.isoformat(), "connectors": [], "routines": []}})

    def denied_places(self):
        h = self.home
        return Denied(*[os.path.expanduser(j) for j in wt.BROWSER_JARS], os.path.join(h, "sand-data"), os.path.join(h, "agent-data", "cookies.json"),
                      os.path.join(h, ".aws", "credentials"), os.path.join(h, ".config", "systemd", "user"), wt.SYSTEM_CRON)

    def json_map(self):
        code, out = self.access("--json")
        self.assertEqual(code, 0)
        return json.loads(out)

    def lines(self, start):
        return [x for x in self.access()[1].splitlines() if x.startswith("- " + start)]


class DeniedIsNotAbsent(_Lookups):
    def test_the_map_built_now_lists_what_it_couldnt_look_at(self):   # replay (1aed58a: none incomplete, 0 jobs, "found no Gmail")
        self.small()
        self.answered()
        self.audit_json()
        with self.denied_places():
            d = self.json_map()
            here = self.here(GMAIL_STORY)
            cli = self.lines("Command-line sign-ins")
        self.assertEqual({k: d["incomplete"].get(k) for k in ("browser", "cli_logins", "scheduled")},
                         dict.fromkeys(("browser", "cli_logins", "scheduled"), "unreadable"))
        self.assertIsNone(d["shared"]["scheduled_jobs"])
        self.assertEqual(here, CANT.format("Gmail"))
        self.assertEqual(cli, ["- Command-line sign-ins: " + UNREAD])

    def test_the_audits_own_map_too(self):   # replay (1aed58a: the audit's map had them complete)
        self.small()
        self.answered()
        with self.denied_places():
            self.audit_json()
        inc = json.loads(self.map_file())["shared"]["incomplete"]
        self.assertEqual({k: inc.get(k) for k in ("browser", "cli_logins", "scheduled")}, dict.fromkeys(("browser", "cli_logins", "scheduled"), "unreadable"))

    def test_a_scan_root_it_couldnt_look_at_is_an_error(self):   # replay (1aed58a: skipped as if not there)
        errors = []
        with Denied(self.ws):
            self.assertEqual(list(wt.walk([self.ws], errors=errors)), [])
        self.assertEqual(len(errors), 1)

    def test_a_scan_root_it_couldnt_look_at_is_not_none_found(self):   # replay (1aed58a: "Tool connections (MCP): none found.")
        self.small()
        wt.ACCESS_WORKSPACE = os.path.join(self.tmp, "projects")   # a scanned folder apart from Watchtower's own (tearDown restores it)
        w(os.path.join(wt.ACCESS_WORKSPACE, "mcp.json"), {"mcpServers": {"slack": {"command": "npx"}}})
        self.audit_json()
        with Denied(wt.ACCESS_WORKSPACE):
            self.assertEqual(self.lines("Tool connections"), ["- Tool connections (MCP): " + UNREAD])

    def test_a_settings_file_it_couldnt_look_at_is_unreadable_not_missing(self):   # replay (1aed58a: "couldn't find")
        self.small()
        self.audit_json()
        with Denied(*[os.path.expanduser(p) for p in wt.NATIVE_SETTINGS]):
            d = self.json_map()
        self.assertEqual(d["shared"]["settings"], "unreadable")

    def test_a_hooks_file_it_couldnt_look_for_is_no_count(self):   # replay (1aed58a: hooks 0)
        self.small()
        self.audit_json()
        with Denied(os.path.join(self.home, ".cursor")):
            d = self.json_map()
        self.assertIsNone(d["shared"]["hooks"])
        self.assertEqual(d["incomplete"].get("hooks"), "unreadable")

    def test_a_profile_it_couldnt_look_for_is_counted(self):   # replay (1aed58a: 0 unreadable profiles)
        self.small()
        w(os.path.join(self.home, "agent-data", "agents", AGENT, "memories.json"), [])
        self.audit_json()
        with Denied(os.path.join(self.home, "agent-data", "agents", AGENT, "profile.json")):
            d = self.json_map()
        self.assertEqual(d["more"]["bot_profiles_unreadable"], 1)

    def test_a_default_folder_it_couldnt_look_at_is_not_out_of_scope_silently(self):   # replay (1aed58a: None, "not there")
        with Denied(self.ws):
            self.assertEqual(wt._ax_scope([self.home]), "unreadable")


class ScheduledFolders(_Lookups):
    def test_a_cron_folder_that_cant_be_listed_doesnt_stop_the_audit(self):   # replay (1aed58a: os.listdir raised; the audit failed)
        self.small()
        w(os.path.join(wt.SYSTEM_CRON, "backup"), "0 3 * * * root /usr/local/bin/backup\n")
        os.chmod(wt.SYSTEM_CRON, 0)   # (the box's tearDown opens it up again)
        try:
            code, out, err = self.run_cmd("audit", "--roots", *self.roots, "--budget", "0")
        except AssertionError as e:   # run_cmd refuses a traceback in the output
            self.fail(f"the audit failed: {e}")
        self.assertEqual(code, 0, err)
        self.assertEqual(json.loads(self.map_file())["shared"]["incomplete"].get("scheduled"), "unreadable")
        self.assertIn(wt.SYSTEM_CRON, getattr(wt, "PERSIST_UNKNOWN", set()))

    def test_a_linked_cron_folder_is_not_listed_through_the_link(self):   # replay (1aed58a: the audit counted 2 jobs through the link)
        self.small()
        real = os.path.join(self.tmp, "elsewhere", "cron.d")
        w(os.path.join(real, "a"), "* * * * * root true\n")
        w(os.path.join(real, "b"), "* * * * * root true\n")
        os.makedirs(os.path.dirname(wt.SYSTEM_CRON), exist_ok=True)
        os.symlink(real, wt.SYSTEM_CRON)
        self.audit_json()
        sh = json.loads(self.map_file())["shared"]
        self.assertEqual(sh["incomplete"].get("scheduled"), "unreadable")
        self.assertNotIn(wt.SYSTEM_CRON, wt.persistence_snapshot())

    def test_a_systemd_folder_it_couldnt_look_at_is_unknown(self):   # replay (1aed58a: not in the snapshot, "no units")
        d = os.path.join(self.home, ".config", "systemd", "user")
        with Denied(d):
            snap = wt.persistence_snapshot()
        self.assertNotIn(d, snap)
        self.assertIn(d, getattr(wt, "PERSIST_UNKNOWN", set()))

    def test_listed_folders_are_still_counted(self):   # guard
        self.small()
        w(os.path.join(wt.SYSTEM_CRON, "backup"), "0 3 * * * root /usr/local/bin/backup\n")
        w(os.path.join(self.home, ".config", "systemd", "user", "sync.timer"), "[Timer]\n")
        self.audit_json()
        self.assertEqual(json.loads(self.map_file())["shared"]["scheduled"], {"crontab": 0, "systemd": 1, "system": 1})
        self.assertEqual(self.json_map()["shared"]["scheduled_jobs"], 2)


class AbsentIsStillNone(_Lookups):
    def test_truly_absent_places_are_still_none(self):   # guard
        self.small()
        self.answered()
        self.audit_json()
        d = self.json_map()
        for k in ("browser", "cli_logins", "scheduled", "hooks"):
            self.assertNotIn(k, d["incomplete"])
        self.assertEqual(d["shared"]["scheduled_jobs"], 0)
        self.assertEqual(self.lines("Command-line sign-ins"), ["- Command-line sign-ins: none found."])
        self.assertTrue(self.here(GMAIL_STORY).startswith("This is about Gmail. Chief Worry Bot found no Gmail"))

    def test_a_sign_in_beside_one_it_couldnt_look_at_is_still_shown(self):   # guard (the line); replay (1aed58a: not incomplete)
        self.small()
        w(os.path.join(self.home, ".netrc"), "machine example.com login FAKEuser password FAKEpass\n")
        self.audit_json()
        with Denied(os.path.join(self.home, ".aws", "credentials")):
            self.assertEqual(self.lines("Command-line sign-ins"), ["- Command-line sign-ins: netrc logins."])
            self.assertEqual(self.json_map()["incomplete"].get("cli_logins"), "unreadable")

    def test_look_tells_absent_from_unknown(self):   # the new helper itself (1aed58a has none)
        f = w(os.path.join(self.tmp, "x", "file"), "x")
        self.assertTrue(wt._look(f))
        self.assertIs(wt._look(os.path.join(self.tmp, "x", "nothing")), False)
        self.assertIs(wt._look(os.path.join(f, "under-a-file")), False)
        with Denied(os.path.join(self.tmp, "x")):
            self.assertIsNone(wt._look(f))
            self.assertIsNone(wt._look(os.path.join(self.tmp, "x", "nothing")))


if __name__ == "__main__":
    unittest.main()
