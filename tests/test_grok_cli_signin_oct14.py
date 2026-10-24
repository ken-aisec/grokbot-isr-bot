"""Decision, Oct 14: ~/.grok/auth.json (the Grok CLI sign-in file) is expected: one ISR-I009 Platform note, never read, never scored.
Only that exact path. A key anywhere else, including other files under ~/.grok, still counts. Replays, anonymized."""
import base64, json, os, sys, unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_boxes import Box, SCANNERS, TH_DONE  # noqa: E402
import isr  # noqa: E402
from test_isr_bot import fake_key  # noqa: E402

KEY = "sk-ant-api03-" + fake_key(80)


def b64(d):
    return base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")


JWT = b64({"alg": "HS256", "typ": "JWT"}) + "." + b64({"sub": "user-" + fake_key(12), "iat": 1760000000}) + "." + fake_key(43)


def write(p, text, mode=None):
    os.makedirs(os.path.dirname(p), exist_ok=True)
    open(p, "w").write(text)
    if mode is not None:
        os.chmod(p, mode)


class GrokCliSignIn(Box):
    def setUp(self):
        super().setUp()
        self.skills(1); self.scanners()
        self.auth = os.path.join(self.home, ".grok", "auth.json")

    def gitleaks_sees(self, files):
        """gitleaks reports a JWT in each file, as it did for ~/.grok/auth.json on the main box (Oct 14)."""
        report = os.path.join(self.tmp, "leaks.json")
        json.dump([{"File": f, "StartLine": 1, "RuleID": "jwt", "Match": "REDACTED"} for f in files], open(report, "w"))
        stub = SCANNERS["gitleaks"].replace('open(a[a.index("--report-path") + 1], "w").write("[]")',
                                            f'open(a[a.index("--report-path") + 1], "w").write(open({report!r}).read() if a[a.index("--source") + 1] == {self.home!r} else "[]")')
        th = "#!/bin/sh\n" + "".join("echo '" + json.dumps({"SourceMetadata": {"Data": {"Filesystem": {"file": f, "line": 1}}},
                                                             "DetectorName": "JWT", "Verified": True}) + "'\n" for f in files) + "echo '" + TH_DONE + "' >&2\n"
        self.scanners(gitleaks=stub, trufflehog=th)

    def test_gitleaks_jwt_in_the_sign_in_file_is_platform_and_elsewhere_under_grok_is_critical_s002(self):
        other = os.path.join(self.home, ".grok", "cli", "session.json")
        write(self.auth, json.dumps({"access_token": JWT}), 0o600)
        write(other, json.dumps({"access_token": JWT}))
        self.gitleaks_sees([self.auth, other])
        self.audit()
        fs = self.snap()["findings"]
        mine = [f for f in fs if self.auth == f["where"].split(":")[0]]
        self.assertEqual([f["rule"] for f in mine], ["ISR-I009"], mine)
        s2 = [f for f in fs if f["rule"] == "ISR-S002" and other in f["where"] + f.get("evidence", "")]
        self.assertTrue(s2 and all(f["severity"] == "critical" and isr.counts(f) for f in s2), [f for f in fs if f["rule"].startswith("ISR-S")])
        self.assertNotIn(JWT[:30], json.dumps(self.snap()))

    def test_sign_in_file_is_a_platform_note_without_the_value(self):
        write(self.auth, json.dumps({"access_token": JWT, "api_key": KEY}), 0o600)
        self.audit()
        fs = [f for f in self.snap()["findings"] if self.auth in f["where"]]
        self.assertEqual([f["rule"] for f in fs], ["ISR-I009"], fs)
        self.assertEqual(fs[0]["label"], isr.PLATFORM)
        self.assertIn("Grok CLI", fs[0]["title"])
        self.assertFalse(isr.counts(fs[0]))
        dump = json.dumps(self.snap())
        self.assertNotIn(KEY[:20], dump)
        self.assertNotIn(JWT[:30], dump)

    def test_other_files_under_grok_still_count(self):
        write(self.auth, "{}", 0o600)
        for other in (os.path.join(self.home, ".grok", "auth-old.json"), os.path.join(self.home, ".grok", "cli", "auth.json")):
            write(other, json.dumps({"api_key": KEY, "access_token": JWT}))
        self.audit()
        for other in (os.path.join(self.home, ".grok", "auth-old.json"), os.path.join(self.home, ".grok", "cli", "auth.json")):
            hits = [f for f in self.snap()["findings"] if f["rule"] in isr.SECRET_RULES and other in f["where"]]
            self.assertTrue(hits and all(f.get("scope") != "platform" for f in hits), (other, hits))

    def test_an_auth_json_elsewhere_still_counts(self):
        stray = os.path.join(self.ws, "copy", ".grok", "auth.json")
        write(stray, json.dumps({"api_key": KEY}))
        self.audit()
        self.assertTrue([f for f in self.snap()["findings"] if f["rule"] in isr.SECRET_RULES and stray in f["where"]])

    def test_exact_path_only(self):
        self.assertTrue(isr.is_platform_secret_store(os.path.join(os.path.expanduser("~"), ".grok", "auth.json")))
        self.assertFalse(isr.is_platform_secret_store(os.path.join(os.path.expanduser("~"), ".grok", "other.json")))
        self.assertFalse(isr.is_platform_secret_store("/tmp/.grok/auth.json"))


if __name__ == "__main__":
    unittest.main()
