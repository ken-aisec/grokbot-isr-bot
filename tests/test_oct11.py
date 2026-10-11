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
