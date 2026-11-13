"""ISR-K003 and the upgrade backup (v0.8.5 dev). A manual whole-folder copy of ISR Bot's home (the upgrade runbook's, not
install.sh's, which makes no backup) put state/canaries.json into /workspace/backups, and the decoy-copy check fired critical
on it. scripts/backup.sh copies the home's own folders and leaves state/canaries* out of the copy. The K003 check itself is not
changed: a decoy value written into a backup folder still alarms.

Every test runs on a stand-in home under a temp folder with a FAKE decoy value; the real home and backups are never read.
The test marked "replay" fails on 660fa29 at its assertion (no scripts/backup.sh: the run exits non-zero); the "guard" tests
cover what must not change."""
import hashlib, json, os, re, shutil, stat, subprocess, sys, tempfile, unittest
from unittest import mock
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_boxes import ROOT  # noqa: E402  (test_boxes puts isr_bot on sys.path)
import isr  # noqa: E402

SCRIPT = os.path.join(ROOT, "scripts", "backup.sh")
TOKEN = "k3tok-0123456789abcdef"   # FAKE: a stand-in decoy value, never a real one
COPIED = ("app", "state", "exports", "vet", "reports", "install.sh")


def tree(root):
    """{relative path: bytes} for every file under root (links are not followed; a link is kept as its target text)."""
    out = {}
    for d, dirs, files in os.walk(root):
        for n in dirs + files:
            p = os.path.join(d, n)
            rel = os.path.relpath(p, root)
            if os.path.islink(p):
                out[rel] = ("link", os.readlink(p))
            elif n in files:
                with open(p, "rb") as f:
                    out[rel] = f.read()
    return out


def k003_hits(root):
    """{relative path: finding} for each file under root that the real decoy-copy check flags, each read as the audit reads it."""
    out = {}
    for d, _, files in os.walk(root):
        for n in files:
            p = os.path.join(d, n)
            t = isr.read_text(p, limit=300_000)
            f = isr.canary_copies(t, p) if t else None
            if f:
                out[os.path.relpath(p, root)] = f
    return out


class StandIn(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="k003-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.home = os.path.join(self.tmp, "isr-bot")
        decoy = os.path.join(self.tmp, "decoys", "var", "tmp", ".cache-0a1b2c", "customers-3d4e.csv")
        files = {
            "app/isr_bot/isr.py": "print('stand-in app')\n",
            "app/skills/isr-bot-setup/SKILL.md": "# setup\n\nStand-in skill text.\n",
            "app/MANIFEST.sha256": "0" * 64 + "  isr_bot/isr.py\n",
            "state/canaries.json": json.dumps({"customers": {"path": decoy, "token": TOKEN, "atime": 1.0, "mtime": 2.0}}),
            "state/baseline.json": '{"files": {"a.md": "abc"}}\n',
            "state/ledger.jsonl": '{"event": "audit", "at": "2026-11-01T09:00:00+00:00"}\n',
            "exports/roster.json": "[]\n",
            "reports/2026-W44.md": "# Weekly report\n",
            "scanners/bin/gitleaks": "#!/bin/sh\necho stand-in\n",
            "backups/older.txt": "an older copy\n",
            ".stage.abc/app/x.py": "x = 1\n",
            "install.sh": "#!/usr/bin/env bash\necho stand-in installer\n",
        }
        for rel, text in files.items():
            p = os.path.join(self.home, rel)
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "w") as f:
                f.write(text)
        p = mock.patch.dict(os.environ, {"ISR_BOT_HOME": self.home})   # state_path reads the stand-in's registry
        p.start(); self.addCleanup(p.stop)

    def backup(self, dest, home=None):
        env = dict(os.environ, ISR_BOT_HOME=home or self.home)
        return subprocess.run(["bash", SCRIPT, dest], env=env, capture_output=True, text=True, timeout=60)


class BackupLeavesTheDecoysOut(StandIn):
    def test_a_manual_copy_trips_k003_and_the_backup_script_does_not(self):   # replay
        # (a) what the runbook's manual copy did: the whole folder, decoy registry included
        manual = os.path.join(self.tmp, "backups", "isr-bot-manual-copy")
        shutil.copytree(self.home, manual, symlinks=True)
        with open(os.path.join(manual, "state", "canaries.json")) as f:
            self.assertIn(TOKEN, f.read())
        hits = k003_hits(manual)
        self.assertEqual(sorted(hits), ["state/canaries.json"])
        self.assertEqual((hits["state/canaries.json"]["rule"], hits["state/canaries.json"]["severity"]), ("ISR-K003", "critical"))
        # (b) scripts/backup.sh: no copied file holds the decoy value, and the check finds nothing in any of them
        dest = os.path.join(self.tmp, "backups", "isr-bot-pre-upgrade-20261102-0900")
        r = self.backup(dest)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        got = tree(dest)
        self.assertIn("state/baseline.json", got)
        self.assertEqual([rel for rel, b in got.items() if isinstance(b, bytes) and TOKEN.encode() in b], [])
        self.assertEqual(k003_hits(dest), {})


class BackupCopiesTheRest(StandIn):
    def test_state_and_app_files_are_copied_byte_for_byte_and_the_source_is_unchanged(self):   # guard
        before = tree(self.home)
        dest = os.path.join(self.tmp, "out", "b1")
        r = self.backup(dest)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        want = {rel: b for rel, b in before.items() if rel.split(os.sep)[0] in COPIED and not rel.startswith("state/canaries")}
        self.assertEqual(tree(dest), want)
        self.assertEqual(sorted(os.listdir(dest)), ["app", "exports", "install.sh", "reports", "state"])
        for gone in ("scanners", "backups", ".stage.abc", "state/canaries.json"):
            self.assertFalse(os.path.lexists(os.path.join(dest, gone)), gone)
        self.assertEqual(stat.S_IMODE(os.lstat(dest).st_mode), 0o700)
        self.assertEqual(tree(self.home), before)
        self.assertTrue(os.path.isfile(os.path.join(self.home, "state", "canaries.json")))

    def test_it_says_where_what_was_left_out_and_how_to_plant_again_without_contents(self):   # guard
        dest = os.path.join(self.tmp, "out", "b2")
        r = self.backup(dest)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn(dest, r.stdout)
        self.assertIn("state/canaries*", r.stdout)
        self.assertIn("ISR-K003", r.stdout)
        self.assertIn("isr_bot/isr.py canary plant", r.stdout)
        for text in (TOKEN, "stand-in", "Weekly report", '"files"'):
            self.assertNotIn(text, r.stdout + r.stderr)


class BackupRefuses(StandIn):
    def test_an_existing_dest_a_dest_inside_the_home_and_a_missing_home_are_refused(self):   # guard
        before = tree(self.home)
        dest = os.path.join(self.tmp, "taken")
        os.makedirs(dest)
        with open(os.path.join(dest, "keep.txt"), "w") as f:
            f.write("already here\n")
        r = self.backup(dest)
        self.assertNotEqual(r.returncode, 0)
        self.assertEqual(tree(dest), {"keep.txt": b"already here\n"})
        os.symlink(self.home, os.path.join(self.tmp, "via-link"))
        for inside in (os.path.join(self.home, "backups", "new"), os.path.join(self.home, "app", "..", "new"),
                       os.path.join(self.tmp, "via-link", "new"), self.home):
            with self.subTest(dest=inside):
                r = self.backup(inside)
                self.assertNotEqual(r.returncode, 0)
                self.assertEqual(tree(self.home), before)
        missing = os.path.join(self.tmp, "no-home-here")
        out = os.path.join(self.tmp, "fresh-parent", "b3")
        r = self.backup(out, home=missing)
        self.assertNotEqual(r.returncode, 0)
        self.assertFalse(os.path.lexists(os.path.join(self.tmp, "fresh-parent")))
        self.assertFalse(os.path.lexists(missing))


class K003StillAlarms(StandIn):
    def test_a_decoy_value_written_into_a_backup_folder_is_still_critical(self):   # guard
        leak = os.path.join(self.tmp, "backups", "isr-bot-pre-upgrade-20261102-0900", "notes.txt")
        os.makedirs(os.path.dirname(leak))
        with open(leak, "w") as f:
            f.write(f"copied from a decoy: {TOKEN}\n")
        f = isr.canary_copies(isr.read_text(leak, limit=300_000), leak)
        self.assertEqual((f or {}).get("rule"), "ISR-K003")
        self.assertEqual(f["severity"], "critical")


class V120RegistryHoldsNoValue(unittest.TestCase):
    """v1.2.0: the registry keeps each decoy value's salted hash, never the value, so no copy of ISR Bot's home (by scripts/backup.sh
    or by hand, state/canaries* included) holds a decoy value or trips ISR-K003. Real decoys are planted under this test's own
    decoy root; the values are compared by hash only."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="k003-v120-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.home = os.path.join(self.tmp, "isr-bot")
        p = mock.patch.dict(os.environ, {"ISR_BOT_HOME": self.home, "ISR_BOT_DECOY_ROOT": os.path.join(self.tmp, "decoys"),
                                         "HOME": os.path.join(self.tmp, "home")})
        p.start(); self.addCleanup(p.stop)
        for rel, text in (("app/isr_bot/isr.py", "print('stand-in app')\n"), ("reports/2026-W46.md", "# Weekly report\n")):
            os.makedirs(os.path.dirname(os.path.join(self.home, rel)), exist_ok=True)
            with open(os.path.join(self.home, rel), "w") as f:
                f.write(text)
        isr.plant_canaries()
        reg = isr.load_json(isr.state_path("canaries.json"), {})
        self.assertTrue(reg and all(v["path"].startswith(os.path.join(self.tmp, "decoys") + os.sep) for v in reg.values()))   # sandboxed
        self.digests = set()
        for v in reg.values():
            with open(v["path"]) as f:
                m = re.search(r"rk_live_([0-9a-f]{16})|AKIA([0-9A-F]{16})|,([0-9a-f]{16})@", f.read())
            self.digests.add(hashlib.sha256(next(g for g in m.groups() if g).lower().encode()).hexdigest())

    def holds_a_value(self, root):
        """The relative paths under root with a 16-hex window (any case) whose hash is a decoy value's."""
        out = []
        for rel, b in tree(root).items():
            low = b.decode("utf-8", "replace").lower() if isinstance(b, bytes) else ""
            if any(hashlib.sha256(w.encode()).hexdigest() in self.digests for w in re.findall(r"(?=([0-9a-f]{16}))", low)):
                out.append(rel)
        return out

    def test_a_manual_copy_and_the_backup_script_of_a_v120_home_trip_no_k003(self):   # guard
        manual = os.path.join(self.tmp, "backups", "isr-bot-manual-copy")
        shutil.copytree(self.home, manual, symlinks=True)
        self.assertTrue(os.path.isfile(os.path.join(manual, "state", "canaries.json")))
        self.assertEqual(self.holds_a_value(manual), [])
        self.assertEqual(k003_hits(manual), {})
        dest = os.path.join(self.tmp, "backups", "isr-bot-pre-upgrade-20261112-1200")
        r = subprocess.run(["bash", SCRIPT, dest], env=dict(os.environ), capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("state/decoy_layout.json", tree(dest))
        self.assertEqual(self.holds_a_value(dest), [])
        self.assertEqual(k003_hits(dest), {})


class ScriptText(unittest.TestCase):
    def test_no_tar_and_no_file_contents_printed(self):   # guard
        with open(SCRIPT) as f:
            text = f.read()
        self.assertIn("set -euo pipefail", text)
        self.assertEqual([l for l in text.splitlines() if re.search(r"\btar\b", l)], [])
        self.assertNotIn("cat ", text)


if __name__ == "__main__":
    unittest.main()
