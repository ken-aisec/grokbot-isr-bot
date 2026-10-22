"""Oct 11 batch: WT-S004 session origins, DQ-017..021. Replays are anonymized."""
import io, json, os, shutil, sqlite3, sys, time, unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_boxes import Box, wt, ROOT, SCANNERS  # noqa: E402

CHROME_EPOCH = 11644473600


def chrome_us(t):
    return int((t + CHROME_EPOCH) * 1_000_000)


class BrowserSessions(Box):
    """Main box, Oct 11: WT-S004 high, 63 domains. The cookie jar is restored by the platform after every box reset
    (chrome-cookie-seed.json, saved 01:08 ET; this box was created 01:14 ET) and holds sessions created on earlier boxes
    since Aug 19, including an interactive Google sign-in on Aug 28. Names and values below are made up."""

    def jar(self, rows):
        d = os.path.join(self.home, "chrome-profile", "Default"); os.makedirs(d, exist_ok=True)
        p = os.path.join(d, "Cookies")
        c = sqlite3.connect(p)
        c.execute("create table if not exists cookies (creation_utc integer, host_key text, name text, value text, encrypted_value blob, last_access_utc integer)")
        for host, created in rows:
            c.execute("insert into cookies values (?,?,?,?,?,?)", (chrome_us(created), host, "SID", "SECRET-VALUE-NEVER-READ", b"x", chrome_us(created)))
        c.commit(); c.close()
        seed = os.path.join(self.home, "sand-data"); os.makedirs(seed, exist_ok=True)
        json.dump({"version": 1, "savedAt": int(time.time() * 1000), "cookies": [{"domain": "." + h, "name": "SID", "value": "SECRET-VALUE-NEVER-READ"} for h, _ in rows]},
                  open(os.path.join(seed, "chrome-cookie-seed.json"), "w"))
        return p

    def test_sessions_are_described_by_age_and_a_new_sign_in_is_its_own_alarm(self):
        old = time.time() - 40 * 86400
        self.jar([("accounts.google.com", old), ("x.ai", old + 3600), ("vault.bitwarden.com", old + 7200), ("ads.example", old)])
        self.skills(1); self.scanners()
        r = self.audit()
        s4 = [f for f in self.snap()["findings"] if f["rule"] == "WT-S004"]
        self.assertEqual([f["severity"] for f in s4], ["high"])                     # the exposure is real, so the severity stays
        self.assertIn("bitwarden", s4[0]["evidence"])                              # a password vault session is sensitive
        self.assertNotIn("SECRET-VALUE", json.dumps(self.snap()))
        self.assertFalse([f for f in self.snap()["findings"] if f["rule"] == "WT-S005"])   # first look: a baseline, no alarm
        self.jar([("accounts.google.com", time.time() - 60), ("console.anthropic.com", time.time() - 30), ("news.example", time.time() - 20)])
        self.audit()
        s5 = [f for f in self.snap()["findings"] if f["rule"] == "WT-S005"]
        self.assertEqual(len(s5), 1, s5)
        self.assertEqual((s5[0]["severity"], s5[0]["label"]), ("high", wt.CONFIRMED))
        self.assertIn("console.anthropic.com", s5[0]["evidence"])
        self.assertNotIn("accounts.google.com", s5[0]["evidence"])                # a refreshed cookie on a known site isn't a new sign-in
        self.assertNotIn("news.example", s5[0]["evidence"])
        self.assertNotIn("SECRET-VALUE", json.dumps(self.snap()))
        self.audit()
        self.assertEqual(len([f for f in self.snap()["findings"] if f["rule"] == "WT-S005"]), 1)   # stays open until reviewed, not re-raised


class DQ017CatalogSync(Box):
    COMMIT = "4bf3e083c6dec126e254f96181b84a105b6e3e70"

    def cat_plugin(self, name, commit=None, market="cursor-public", scripts=False, local_mcp=False, mtime=None):
        root = os.path.join(self.home, "sand-data", "plugins", "cache", market, name, commit or self.COMMIT)
        os.makedirs(os.path.join(root, ".cursor-plugin"), exist_ok=True)
        open(os.path.join(root, ".cursor-plugin", "plugin.json"), "w").write(json.dumps({"name": name}))
        srv = {"command": "npx", "args": [name + "-mcp@1.0.0"]} if local_mcp else {"url": f"https://mcp.{name}.example/mcp"}
        open(os.path.join(root, "mcp.json"), "w").write(json.dumps({"mcpServers": {name: srv}}))
        open(os.path.join(root, "README.md"), "w").write(f"# {name}\n")
        if scripts:
            os.makedirs(os.path.join(root, "scripts"), exist_ok=True)
            p = os.path.join(root, "scripts", "run.sh"); open(p, "w").write("#!/bin/sh\necho hi\n"); os.chmod(p, 0o755)
        if mtime:
            for dp, dns, fns in os.walk(root):
                for x in dns + fns:
                    os.utime(os.path.join(dp, x), (mtime, mtime))
            os.utime(root, (mtime, mtime))
        return root

    def test_a_catalog_sync_is_a_note_not_six_new_installs(self):
        """Main box, Oct 11 00:42 ET: calendly, excalidraw, finance, gmail, google-calendar and tinyfish appeared under
        cursor-public at one catalog commit in the same minute; each was raised as WT-I004 "A new plugin was installed"."""
        self.skills(1); self.scanners()
        self.cat_plugin("notion-workspace", commit="cf1324609edba6d617164f1dec138aeb43f26735")
        self.audit()                                                                  # first run: what is there is known
        t = time.time()
        for n in ("calendly", "excalidraw", "finance", "gmail", "google-calendar", "tinyfish"):
            self.cat_plugin(n, mtime=t)
        self.cat_plugin("helper-kit", scripts=True, mtime=t)                       # same sync, but it brings scripts: still a new install
        self.cat_plugin("local-runner", local_mcp=True, mtime=t)                    # starts a local program: still a new install
        self.cat_plugin("side-load", commit="aaaa1111", market="someone-else", mtime=t)
        r = self.audit()
        fs = self.snap()["findings"]
        i4 = sorted(f["evidence"].split(":")[0] for f in fs if f["rule"] == "WT-I004")
        self.assertEqual(i4, ["helper-kit", "local-runner", "side-load"])
        i5 = [f for f in fs if f["rule"] == "WT-I005"]
        self.assertEqual(len(i5), 1)
        self.assertEqual(i5[0]["severity"], "info")
        for n in ("calendly", "excalidraw", "finance", "gmail", "google-calendar", "tinyfish"):
            self.assertIn(n, i5[0]["evidence"])
        self.assertNotIn("WT-I004", [d["rule"] for d in json.loads(self.run_cmd("fix", "--roots", *self.roots)[1])["decisions"]
                                     if "calendly" in json.dumps(d)])
        self.audit()
        self.assertEqual(sorted(f["evidence"].split(":")[0] for f in self.snap()["findings"] if f["rule"] == "WT-I004"), i4)

    def test_one_plugin_alone_is_still_a_new_install(self):
        self.skills(1); self.scanners()
        self.cat_plugin("notion-workspace", commit="cf13"); self.audit()
        self.cat_plugin("gmail")
        self.audit()
        self.assertEqual([f["evidence"].split(":")[0] for f in self.snap()["findings"] if f["rule"] == "WT-I004"], ["gmail"])


class DQ018RemovedBots(Box):
    def test_findings_for_removed_bots_leave_the_report(self):
        """Main box, Oct 11: 8 Bots were removed on Oct 10, but the Oct 9 roll-call kept their findings in the weekly report
        (22 Worth-a-look and Tip lines). Bot names are anonymized."""
        self.skills(1); self.scanners()
        when = "2026-10-09T12:55:10+00:00"
        mk = lambda bot, rule, sub="": wt.finding(rule, "t", "high", ["X"], f"rollcall:{bot}{sub}", "ev", "fix")
        fs = [mk("bot-a - Team", "WT-L001"), mk("bot-t - eggbot", "WT-L001"), mk("bot-t - eggbot", "WT-M010", ":memory3"),
              mk("bot-d", "WT-L001"), mk("bot-z", "WT-T013", ":routine:Brief")]
        with mock.patch.object(wt, "now", return_value=when):
            wt.save_json(wt.state_path("rollcall_findings.json"), {"at": when, "masked": wt.VERSION, "bots": ["bot-a - Team", "bot-d", "bot-t - eggbot", "bot-z"], "findings": fs})
        fresh = (wt.dt.datetime.now(wt.dt.timezone.utc) - wt.dt.timedelta(days=2)).isoformat()
        rc = wt.load_json(wt.state_path("rollcall_findings.json"), {}); rc["at"] = fresh; wt.save_json(wt.state_path("rollcall_findings.json"), rc)
        self.audit()
        self.assertEqual(len([f for f in self.snap()["findings"] if f["where"].startswith("rollcall:")]), 5)
        # the owner removed two Bots; the roster the Bot saves now lists who is left
        exp = os.path.join(os.environ["WATCHTOWER_HOME"], "exports"); os.makedirs(exp, exist_ok=True)
        json.dump([{"name": "bot-d", "kind": "bot"}, {"name": "bot-z", "kind": "bot"}, {"name": "room-o", "kind": "room"}], open(os.path.join(exp, "roster.json"), "w"))
        r = self.audit()
        left = sorted({f["where"].split(":")[1] for f in self.snap()["findings"] if f["where"].startswith("rollcall:")})
        self.assertEqual(left, ["bot-d", "bot-z"])
        self.assertTrue(any("2 Bots no longer on the roster" in n for n in r.get("notes", [])), r.get("notes"))
        md = wt.render_md(self.snap(), [], "2026-W41")
        self.assertNotIn("bot-t", md); self.assertNotIn("bot-a - Team", md)
        self.assertEqual(wt.load_json(wt.state_path("rollcall_findings.json"), {})["bots"], ["bot-d", "bot-z"])   # pruned at the source

    def test_old_roll_call_data_ages_out(self):
        self.skills(1); self.scanners()
        old = (wt.dt.datetime.now(wt.dt.timezone.utc) - wt.dt.timedelta(days=wt.ROLLCALL_MAX_DAYS + 1)).isoformat()
        wt.save_json(wt.state_path("rollcall_findings.json"), {"at": old, "masked": wt.VERSION, "bots": ["bot-d"],
                                                               "findings": [wt.finding("WT-L001", "t", "high", ["X"], "rollcall:bot-d", "ev", "fix")]})
        self.audit()
        self.assertFalse([f for f in self.snap()["findings"] if f["where"].startswith("rollcall:")])


class DQ019RevetMatchesPreview(Box):
    def test_revet_touches_only_what_the_preview_listed(self):
        """Main box, Oct 11: the preview listed 12 changed skills and --revet re-approved 17 (5 more had changed in between, or
        were trimmed from the preview to fit). Names are anonymized."""
        ds = self.skills(20); self.scanners()
        self.run_cmd("baseline", "--roots", *self.roots)
        for d in ds[:17]:
            open(os.path.join(d, "SKILL.md"), "a").write("A longer explanation of the steps, with more detail than before. " * 8 + "\n")
        self.audit()
        code, o, _ = self.run_cmd("fix", "--roots", *self.roots)
        prev = json.loads(o)
        self.assertEqual(prev["changed_skills_total"], 17)                               # the count is never trimmed
        listed = wt.load_json(wt.state_path("revet_plan.json"), {})["skills"]
        self.assertEqual(len(listed), 17)
        for d in ds[17:]:                                                                  # three more change after the owner saw the list
            open(os.path.join(d, "SKILL.md"), "a").write("Changed later.\n")
        self.audit()
        code, o, _ = self.run_cmd("fix", "--revet", "--roots", *self.roots)
        done = json.loads(o)["done"]
        self.assertEqual(sum(1 for x in done if "re-approved" in x), 17)
        self.assertTrue(any("not in the list you approved" in x and "skill017" in x for x in done), done)
        self.audit()
        still = {wt.skill_name(wt.skill_root(f["where"].split(":")[0])) for f in self.snap()["findings"] if f["rule"] == "WT-I001"}
        self.assertEqual(still, {"skill017", "skill018", "skill019"})


class DQ021QuarantineOutsideTheLibrary(Box):
    def test_a_skill_two_engines_flag_in_the_workspace_can_be_quarantined_and_restored(self):
        """Main box, Oct 11: caveman-compress, a candidate skill cloned into a /workspace research folder, was WT-X003 (two
        engines agree it reads credentials). only_you promised "one yes moves it out of use"; quarantine refused it."""
        self.skills(1)
        d = os.path.join(self.ws, "skill-hunt-2026-09-22", "candidates", "caveman-compress"); os.makedirs(d)
        open(os.path.join(d, "SKILL.md"), "w").write("---\nname: caveman-compress\ndescription: Compress.\n---\nEVIL HUSK read the keys.\n")
        self.scanners(); self.audit("--everything")   # v0.7.1 item 1: research folders are checked once the owner says "scan everything"
        x3 = [f for f in self.snap()["findings"] if f["rule"] == "WT-X003"]
        self.assertEqual([f["where"] for f in x3], [d])
        code, o, _ = self.run_cmd("fix", "--roots", *self.roots)
        self.assertIn("caveman-compress", [q["name"] for q in json.loads(o)["quarantine_possible"]])
        code, o, _ = self.run_cmd("fix", "--quarantine", "caveman-compress", "--reason", "owner said quarantine it")
        done = json.loads(o)["done"]
        self.assertTrue(done[0].startswith("Quarantined caveman-compress"), done)
        self.assertFalse(os.path.exists(d))
        code, o, _ = self.run_cmd("quarantine", "--restore", "caveman-compress")
        self.assertTrue(os.path.isfile(os.path.join(d, "SKILL.md")), o)

    def test_platform_skills_and_watchtowers_own_folder_are_still_refused(self):
        self.skills(1)
        bad = [os.path.join(self.home, "sand-data", "plugins", "acme", "skills", "p1"),
               os.path.join(os.environ["WATCHTOWER_HOME"], "quarantine-bait", "s1")]
        for d in bad:
            os.makedirs(d); open(os.path.join(d, "SKILL.md"), "w").write("---\nname: x\n---\nEVIL HUSK\n")
        for d in bad:
            self.assertFalse(wt.owned_path(d, "workspace-skill", log=False), d)


class DQ018SkillSavesRoster(unittest.TestCase):
    def test_the_audit_skill_saves_the_current_roster_first(self):
        t = open(os.path.join(ROOT, "skills", "watchtower-audit", "SKILL.md")).read()
        self.assertLess(t.index("exports/roster.json"), t.index("wt.py audit"))


FAKE_CARGO = r'''#!/usr/bin/env python3
import re, sys
a = sys.argv[1:]
if a[:1] == ["--version"]:
    print("cargo 1.90.0"); sys.exit(0)
if a[:1] == ["update"]:
    spec, want = a[a.index("-p") + 1], a[a.index("--precise") + 1]
    name, have = spec.split("@")
    if want.startswith("9."):
        print("error: failed to select a version for the requirement", file=sys.stderr); sys.exit(101)
    t = open("Cargo.lock").read()
    t2 = re.sub(r'(name = "%s"\nversion = )"%s"' % (re.escape(name), re.escape(have)), r'\1"%s"' % want, t)
    open("Cargo.lock", "w").write(t2); sys.exit(0)
sys.exit(2)
'''


class DQ020CargoUpgrade(Box):
    """Main box, Oct 11: two WT-D002 highs (pyo3 0.26.0, quick-xml 0.39.4) in a Rust repo cloned into a research-run folder;
    fix --upgrade and --upgrade-projects skipped crates.io. Fixed versions here are made up for the fixture."""

    def repo(self):
        d = os.path.join(self.ws, "research-runs", "x-run", "repo-x", "phoenix"); os.makedirs(d)
        lock = ('version = 4\n\n[[package]]\nname = "pyo3"\nversion = "0.26.0"\n\n[[package]]\nname = "quick-xml"\nversion = "0.39.4"\n\n'
                '[[package]]\nname = "serde"\nversion = "1.0.200"\n')
        open(os.path.join(d, "Cargo.lock"), "w").write(lock)
        open(os.path.join(d, "Cargo.toml"), "w").write('[package]\nname = "phoenix"\nversion = "0.1.0"\n')
        rng = lambda fixed: [{"ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": fixed}]}]}]
        osv = {"results": [{"source": {"path": os.path.join(d, "Cargo.lock")}, "packages": [
            {"package": {"name": "pyo3", "version": "0.26.0", "ecosystem": "crates.io"},
             "vulnerabilities": [{"id": "GHSA-aaaa-0001", "affected": [dict(package={"name": "pyo3", "ecosystem": "crates.io"}, **r) for r in rng("0.26.1")]},
                                 {"id": "RUSTSEC-2026-0001", "affected": [dict(package={"name": "pyo3", "ecosystem": "crates.io"}, **r) for r in rng("0.26.2")]}],
             "groups": [{"max_severity": "7.5"}]},
            {"package": {"name": "quick-xml", "version": "0.39.4", "ecosystem": "crates.io"},
             "vulnerabilities": [{"id": "RUSTSEC-2026-0002", "affected": [dict(package={"name": "quick-xml", "ecosystem": "crates.io"}, **r) for r in rng("0.39.5")]}],
             "groups": [{"max_severity": "7.5"}]}]}]}
        self.scanners(osv_scanner="#!/bin/sh\ncat <<'EOF'\n" + json.dumps(osv) + "\nEOF\n")
        return d

    def fake_cargo(self):
        p = os.path.join(self.tmp, "fake-cargo"); open(p, "w").write(FAKE_CARGO); os.chmod(p, 0o755)
        return p

    def test_vulnerable_crates_are_offered_and_fixed_only_on_the_separate_yes(self):
        self.skills(1); d = self.repo(); self.audit()
        self.assertEqual(len([f for f in self.snap()["findings"] if f["rule"] == "WT-D002"]), 2)
        lock = open(os.path.join(d, "Cargo.lock")).read()
        with mock.patch.object(wt, "cargo_exe", return_value=self.fake_cargo()):
            prev = json.loads(self.run_cmd("fix", "--roots", *self.roots)[1])
            cargo = prev["project_upgrades"]["cargo"]
            self.assertIn("phoenix: pyo3 0.26.0 → 0.26.2", cargo)
            self.assertIn("phoenix: quick-xml 0.39.4 → 0.39.5", cargo)
            self.assertIn("--upgrade-projects", prev["project_upgrades"]["ask"])
            self.run_cmd("fix", "--upgrade", "--roots", *self.roots)                     # the general yes never touches projects
            self.assertEqual(open(os.path.join(d, "Cargo.lock")).read(), lock)
            done = json.loads(self.run_cmd("fix", "--upgrade-projects", "--roots", *self.roots)[1])["done"]
        new = open(os.path.join(d, "Cargo.lock")).read()
        self.assertIn('name = "pyo3"\nversion = "0.26.2"', new)
        self.assertIn('name = "quick-xml"\nversion = "0.39.5"', new)
        self.assertIn('name = "serde"\nversion = "1.0.200"', new)
        self.assertTrue(any("pyo3 0.26.0 → 0.26.2" in x for x in done), done)
        self.assertTrue(any("undo copy" in x for x in done), done)

    def test_cargo_missing_fails_cleanly_and_says_how_to_install(self):
        self.skills(1); d = self.repo(); self.audit()
        lock = open(os.path.join(d, "Cargo.lock")).read()
        with mock.patch.object(wt, "cargo_exe", return_value=None):
            done = json.loads(self.run_cmd("fix", "--upgrade-projects", "--roots", *self.roots)[1])["done"]
        self.assertTrue(any("cargo isn't installed" in x and "rustup" in x for x in done), done)
        self.assertEqual(open(os.path.join(d, "Cargo.lock")).read(), lock)

    def test_a_fix_cargo_refuses_puts_the_lockfile_back(self):
        self.skills(1); d = self.repo()
        self.audit()
        st = wt.load_json(wt.state_path("osv_projects.json"), {})
        st["cargo"][d][0]["want"] = "9.0.0"                                               # needs a Cargo.toml change
        wt.save_json(wt.state_path("osv_projects.json"), st)
        lock = open(os.path.join(d, "Cargo.lock")).read()
        with mock.patch.object(wt, "cargo_exe", return_value=self.fake_cargo()):
            done = json.loads(self.run_cmd("fix", "--upgrade-projects", "--roots", *self.roots)[1])["done"]
        self.assertTrue(any("pyo3" in x and "left" in x for x in done), done)
        self.assertIn('name = "pyo3"\nversion = "0.26.0"', open(os.path.join(d, "Cargo.lock")).read())
        self.assertIn('version = "0.39.5"', open(os.path.join(d, "Cargo.lock")).read())   # the other crate still got its fix
