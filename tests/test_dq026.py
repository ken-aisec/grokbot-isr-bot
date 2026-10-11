"""DQ-026: WT-S004 counts a sensitive site as signed-in only with a session cookie (not visit/analytics)."""
import json, os, shutil, sys, tempfile, unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_boxes import Box, wt  # noqa: E402


# Visit/analytics names from a real Bitwarden visit (names only; values never used).
BITWARDEN_VISIT_NAMES = (
    "_gcl_au", "_fbp", "_ketch_consent_v1_", "_mpxl_sid", "_gd_session",
    "_mpxl_cid", "_uetsid", "_gd_visitor",
)


class SessionCookieAnalytics(unittest.TestCase):
    """Tracking names that fit the old pattern must not count as a sign-in."""

    def test_analytics_sid_and_session_names_are_not_logins(self):
        for name in ("_mpxl_sid", "_mpxl_sid_ts", "_gd_session", "_mpxl_cid", "_mpxl_guid"):
            self.assertFalse(wt.is_session_cookie(name), name)

    def test_real_session_names_still_count(self):
        for name in ("SID", "sessionKey", "__Secure-next-auth.session-token", "_gh_sess",
                     "token_v2", "ESTSAUTHPERSISTENT", "ssid", "HSID", "SAPISID"):
            self.assertTrue(wt.is_session_cookie(name), name)


class DQ026BrowserSessions(unittest.TestCase):
    """Sensitive domain with only visit cookies → not high / not in sensitive: list; with SID → still high."""

    def setUp(self):
        # browser_sessions() always looks in ~/sand-data and ~/agent-data first
        self.old_home = os.environ.get("HOME")
        self.tmp_home = tempfile.mkdtemp()
        os.environ["HOME"] = self.tmp_home

    def tearDown(self):
        if self.old_home is None:
            os.environ.pop("HOME", None)
        else:
            os.environ["HOME"] = self.old_home
        shutil.rmtree(self.tmp_home, ignore_errors=True)

    def _seed(self, cookies):
        d = tempfile.mkdtemp()
        json.dump(cookies, open(os.path.join(d, "chrome-cookie-seed.json"), "w"))
        return d

    def test_bitwarden_visit_only_is_not_signed_in_sensitive(self):
        d = self._seed([{"domain": ".bitwarden.com", "name": n, "value": "SECRET-VALUE-NEVER-READ"}
                        for n in BITWARDEN_VISIT_NAMES]
                       + [{"domain": "ads.example", "name": "id", "value": "x"}])
        try:
            fs = wt.browser_sessions([d])
            self.assertEqual(len(fs), 1, fs)
            f = fs[0]
            self.assertEqual(f["rule"], "WT-S004")
            self.assertEqual(f["severity"], "medium", f)
            self.assertIn("sensitive: none", f["evidence"])
            self.assertNotIn("bitwarden", f["evidence"].split("sensitive:")[-1])
            self.assertNotIn("SECRET-VALUE", json.dumps(fs))
            plain = wt.plain(f)
            self.assertNotIn("sensitive sites", plain["title"].lower())
        finally:
            shutil.rmtree(d)

    def test_bitwarden_with_session_cookie_still_high(self):
        d = self._seed([{"domain": ".bitwarden.com", "name": n, "value": "SECRET-VALUE-NEVER-READ"}
                        for n in BITWARDEN_VISIT_NAMES]
                       + [{"domain": ".bitwarden.com", "name": "SID", "value": "SECRET-VALUE-NEVER-READ"},
                          {"domain": "ads.example", "name": "id", "value": "x"}])
        try:
            fs = wt.browser_sessions([d])
            self.assertEqual(len(fs), 1, fs)
            f = fs[0]
            self.assertEqual(f["severity"], "high")
            self.assertIn("bitwarden", f["evidence"])
            self.assertIn("sensitive:", f["evidence"])
            self.assertNotIn("sensitive: none", f["evidence"])
            self.assertNotIn("SECRET-VALUE", json.dumps(fs))
            self.assertIn("sensitive sites", wt.plain(f)["title"].lower())
        finally:
            shutil.rmtree(d)

    def test_google_sid_still_high_and_domain_only_entry_does_not(self):
        d = self._seed([{"domain": ".google.com", "name": "SID", "value": "x" * 40},
                        {"domain": "bitwarden.com"}])  # domain present, no session name
        try:
            fs = wt.browser_sessions([d])
            self.assertEqual(len(fs), 1, fs)
            f = fs[0]
            self.assertEqual(f["severity"], "high")
            sens = f["evidence"].split("sensitive:")[-1]
            self.assertIn("google", sens)
            self.assertNotIn("bitwarden", sens)
        finally:
            shutil.rmtree(d)


class DQ026AccountContext(Box):
    def test_sites_count_uses_signed_in_sensitive_only(self):
        seed = os.path.join(self.home, "sand-data")
        os.makedirs(seed, exist_ok=True)
        json.dump([{"domain": ".bitwarden.com", "name": n, "value": "SECRET-VALUE-NEVER-READ"}
                   for n in BITWARDEN_VISIT_NAMES]
                  + [{"domain": ".google.com", "name": "SID", "value": "SECRET-VALUE-NEVER-READ"}],
                  open(os.path.join(seed, "chrome-cookie-seed.json"), "w"))
        self.skills(1); self.scanners()
        self.audit()
        s4 = next(f for f in self.snap()["findings"] if f["rule"] == "WT-S004")
        self.assertEqual(s4["severity"], "high")
        self.assertIn("google", s4["evidence"])
        self.assertNotIn("bitwarden", s4["evidence"].split("sensitive:")[-1])
        ctx = wt.account_context()
        self.assertEqual(ctx["sites"], 1)  # google only, not bitwarden visit
        self.assertNotIn("SECRET-VALUE", json.dumps(self.snap()))


if __name__ == "__main__":
    unittest.main()
