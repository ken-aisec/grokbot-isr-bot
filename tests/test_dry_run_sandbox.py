"""Claude via bridge, Oct 15: the release dry run left full sandbox copies in /workspace/isr-bot-dry-*, and the daily watch rightly
raised seven critical decoy alarms on their planted decoys and canary registry copies. scripts/dry-run.sh now writes only inside
its own /tmp sandbox and leaves the workspace exactly as it was. No name-based skip was added to the scanner.

These run the real script against a stand-in workspace (outside /tmp, so the sandbox's /tmp can't hide it) and a stand-in dev
build whose isr.py tries to write everywhere a real audit might."""
import hashlib, os, shutil, subprocess, tempfile, unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SCRIPT = os.path.join(ROOT, "scripts", "dry-run.sh")
GIT_ENV = {"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.invalid", "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.invalid",
           "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_NOSYSTEM": "1", "GIT_TERMINAL_PROMPT": "0"}

STUB = r'''
import json, os, sys
home = os.environ["ISR_BOT_HOME"]; ws = os.environ["STUB_WS"]
res = {}
def attempt(name, path, body="x"):
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        open(path, "w").write(body); res[name] = "wrote"
    except OSError as e:
        res[name] = e.strerror
attempt("state", os.path.join(home, "state", "canaries.json"), '{"api-env": "copied"}')
attempt("state_new", os.path.join(home, "state", "last_findings.json"), "[]")
attempt("install", os.path.join(home, "reports", "new.json"))
attempt("workspace", os.path.join(ws, "isr-bot-dry-leftover", "canaries.json"))
attempt("decoy", "/tmp/.sync-abcdef/prod-1234.env", "STRIPE_SECRET_KEY=rk_live_x")
res["state_seen"] = open(os.path.join(home, "state", "seed.json")).read()
res["args"] = sys.argv[1:]
print(json.dumps(res))
'''


def snapshot(top):
    out = {}
    for d, dirs, files in os.walk(top):
        for n in dirs + files:
            p = os.path.join(d, n); st = os.lstat(p)
            h = hashlib.sha256(open(p, "rb").read()).hexdigest() if os.path.isfile(p) and not os.path.islink(p) else ""
            out[os.path.relpath(p, top)] = (st.st_mode, st.st_size, st.st_mtime_ns, h)
    return out


def can_sandbox():
    try:
        return subprocess.run(["unshare", "-rm", "true"], capture_output=True, timeout=20).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


@unittest.skipUnless(can_sandbox(), "needs unprivileged mount namespaces (unshare -rm)")
class DryRunLeavesWorkspaceAlone(unittest.TestCase):
    def setUp(self):
        base = "/var/tmp" if os.access("/var/tmp", os.W_OK) else os.path.expanduser("~")
        self.ws = tempfile.mkdtemp(prefix="isr-bot-test-ws-", dir=base)
        self.tmproot = tempfile.mkdtemp(prefix="isr-bot-test-sbx-")          # under /tmp
        self.addCleanup(shutil.rmtree, self.ws, True); self.addCleanup(shutil.rmtree, self.tmproot, True)
        self.install = os.path.join(self.ws, "isr-bot")
        os.makedirs(os.path.join(self.install, "state")); os.makedirs(os.path.join(self.install, "reports"))
        open(os.path.join(self.install, "state", "seed.json"), "w").write('{"live": true}')
        open(os.path.join(self.install, "state", "canaries.json"), "w").write('{"api-env": "live registry"}')
        open(os.path.join(self.ws, "notes.md"), "w").write("owner file\n")
        # the dev build: a throwaway git repo holding the real script and a stub isr.py
        self.dev = os.path.join(self.ws, "isr-bot-dev")
        os.makedirs(os.path.join(self.dev, "scripts")); os.makedirs(os.path.join(self.dev, "isr_bot"))
        shutil.copy(SCRIPT, os.path.join(self.dev, "scripts", "dry-run.sh"))
        open(os.path.join(self.dev, "isr_bot", "isr.py"), "w").write(STUB)
        env = {**os.environ, **GIT_ENV}
        for c in (["init", "-q"], ["add", "-A"], ["commit", "-qm", "stub"]):
            subprocess.run(["git", "-C", self.dev] + c, check=True, env=env, capture_output=True)
        self.real_ws_before = self.real_workspace()

    @staticmethod
    def real_workspace():
        return sorted(n for n in os.listdir("/workspace") if n.startswith("isr-bot-dry")) if os.path.isdir("/workspace") else None

    def run_dry(self, **extra):
        env = {**os.environ, "ISR_DRY_WORKSPACE": self.ws, "ISR_DRY_INSTALL": self.install, "ISR_DRY_TMPROOT": self.tmproot,
               "ISR_DRY_RO": "", "STUB_WS": self.ws, **extra}
        return subprocess.run(["bash", os.path.join(self.dev, "scripts", "dry-run.sh"), "HEAD", "--", "audit"],
                              env=env, capture_output=True, text=True, timeout=120)

    def test_workspace_unchanged_and_only_the_report_is_kept(self):
        before = snapshot(self.ws)
        r = self.run_dry()
        self.assertEqual(r.returncode, 0, r.stderr + r.stdout)
        self.assertEqual(snapshot(self.ws), before, "the dry run changed the workspace")
        self.assertEqual(self.real_workspace(), self.real_ws_before, "a isr-bot-dry-* folder appeared in the real /workspace")
        left = os.listdir(self.tmproot)
        self.assertEqual(len(left), 1, left)                              # the sandbox itself is gone
        self.assertTrue(left[0].startswith("isr-bot-dry-report-"), left)
        rep = os.path.join(self.tmproot, left[0])
        self.assertEqual(sorted(os.listdir(rep)), ["audit.err", "audit.json"])
        import json
        res = json.load(open(os.path.join(rep, "audit.json")))
        self.assertEqual(res["state"], "wrote")                           # the audit could write its state copy
        self.assertEqual(res["state_seen"], '{"live": true}')             # ...which started from the real state
        self.assertEqual(res["workspace"], "Read-only file system")
        self.assertEqual(res["install"], "Read-only file system")
        self.assertEqual(res["decoy"], "wrote")                           # decoys land in the sandbox's /tmp, then go
        self.assertEqual(res["args"], ["audit"])
        self.assertFalse(any(os.path.exists(os.path.join(d, ".sync-abcdef")) for d in ("/tmp", self.tmproot)))

    def test_keep_leaves_the_sandbox_under_tmp_never_the_workspace(self):
        before = snapshot(self.ws)
        r = self.run_dry(ISR_DRY_KEEP="1")
        self.assertEqual(r.returncode, 0, r.stderr + r.stdout)
        self.assertEqual(snapshot(self.ws), before)
        kept = [n for n in os.listdir(self.tmproot) if n.startswith("isr-bot-dry.")]
        self.assertEqual(len(kept), 1)
        self.assertTrue(os.path.exists(os.path.join(self.tmproot, kept[0], ".sync-abcdef", "prod-1234.env")))
        self.assertEqual(open(os.path.join(self.tmproot, kept[0], "state", "canaries.json")).read(), '{"api-env": "copied"}')
        self.assertEqual(open(os.path.join(self.install, "state", "canaries.json")).read(), '{"api-env": "live registry"}')

    def test_refuses_a_sandbox_or_report_inside_the_workspace(self):
        before = snapshot(self.ws)
        r = self.run_dry(ISR_DRY_TMPROOT=os.path.join(self.ws, "scratch"))
        self.assertEqual(r.returncode, 2); self.assertIn("inside", r.stderr)
        r = self.run_dry(ISR_DRY_OUT=os.path.join(self.ws, "isr-bot-dry-report"))
        self.assertEqual(r.returncode, 2); self.assertIn("inside", r.stderr)
        self.assertEqual(snapshot(self.ws), before)
        self.assertEqual(os.listdir(self.tmproot), [])


class NoNameBasedSkip(unittest.TestCase):
    def test_scanner_has_no_isr_bot_dry_exception(self):
        src = open(os.path.join(ROOT, "isr_bot", "isr.py")).read()
        self.assertNotIn("isr-bot-dry", src, "a name-based skip for dry-run folders would be a blind spot")


if __name__ == "__main__":
    unittest.main()
