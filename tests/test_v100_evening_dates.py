"""1.0 (U2): after 7 PM ET (midnight UTC) the access map, the report and the brief said the last audit and the roll-call were a
day ahead.

The red v0.8.5 suite line is from a run at 2026-11-03T01:32:16+00:00, which is Nov 2 8:32 PM ET: ISR Bot printed "Nov 3"
because _ax_date kept the UTC day of a stored time (the last audit's, the roll-call's) and the roll-call kept each answer's day
as now()[:10]. Every other time ISR Bot shows is US Eastern ("Oct 26 8:38 PM ET", et_time). Now those days are the Eastern day
too (et_date), and a day already kept as a bare YYYY-MM-DD stays as it is, so it is never shifted twice.

One frozen clock: the parts run in one namespace and read the time through isr.dt, so the tests swap isr.dt for a stand-in
whose datetime.now() is that evening (in the zone asked for, or local time without one) and whose date, timedelta and timezone
are the real ones. That freezes now(), the audit's and the access map's roll-call freshness checks (ROLLCALL_MAX_DAYS) and the
roll-call round, so the tests hold on any day. The fixture times the map reads (the cookie jar's creation times, the roster's
mtime) come from the frozen time too. Each test puts TZ back (time.tzset) when it ends.

Tests marked "replay" fail on bc91ed7 (1.0 batch 2, whose date code is 56ed018's, v0.8.5) at their assertion, in any time
zone ("Nov 3", "2026-11-03"). "guard" ones keep what must not change; the three-zone guard fails there too ("Nov 3" in every
zone), and the et_date guard errors there (no et_date). Every planted value is FAKE; the box is a temp folder.

Codex review of batch 3: two more shown days were the UTC day, the audit's roster warning ("... older than the roll-call from
2026-11-03") and the weekly brief's headline ("3 Nov 2026"). The evening replay and the three-zone guard check both now; on
f76851f (1.0 batch 4) they fail at those assertions, in any time zone."""
import datetime as dt, json, os, sqlite3, sys, time, types, unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import test_batch5_access_map as b5  # noqa: E402  (module access: the access-map harness; its tests don't run twice)
import test_batch5_brief_access as b5b  # noqa: E402  (module access: its brief harness, on top of the access-map one)
import isr  # noqa: E402

AT = dt.datetime(2026, 11, 3, 1, 32, 16, tzinfo=dt.timezone.utc)   # Nov 2 8:32 PM ET, the red run in the v0.8.5 suite log
ZONES = {"UTC": 0, "America/New_York": -5 * 3600, "Pacific/Kiritimati": 14 * 3600}   # each zone's UTC offset at AT
LAST_AUDIT = "(from the last audit, Nov 2)"
ROLLCALL = "roll-call on Nov 2"
ROSTER_NOTE = ("The saved roster (exports/roster.json) is older than the roll-call from 2026-11-02, so removed Bots are not dropped. "
               "Save the current roster and they drop out on the next run.")
BRIEF_DAY = "weekly report</span><span>2 Nov 2026</span>"   # the brief's headline date


class _Frozen(dt.datetime):
    """dt.datetime with now() stopped at AT: in `tz`, or local time without a zone (as datetime.now)."""
    @classmethod
    def now(cls, tz=None):
        return AT.astimezone(tz) if tz is not None else AT.astimezone().replace(tzinfo=None)


FROZEN = types.SimpleNamespace(datetime=_Frozen, date=dt.date, timedelta=dt.timedelta, timezone=dt.timezone)


def put_tz_back(old):
    if old is None:
        os.environ.pop("TZ", None)
    else:
        os.environ["TZ"] = old
    time.tzset()


class _Evening(b5b._Brief):
    def setUp(self):
        super().setUp()
        self.addCleanup(put_tz_back, os.environ.get("TZ"))
        time.tzset()   # the zone this run was started in, until a test sets another (zone)
        p = mock.patch.object(isr, "dt", FROZEN); p.start(); self.addCleanup(p.stop)

    def zone(self, name):
        """The rest of this test runs with TZ=name; False when this computer has no time zone data for it."""
        os.environ["TZ"] = name
        time.tzset()
        return time.localtime(AT.timestamp()).tm_gmtoff == ZONES[name]

    def box(self):
        """test_batch5_access_map's box without its roll-call: the cookie jar's creation times 3 days before the frozen clock,
        and the roster saved a minute before it (as a roster saved before the roll-call)."""
        self.build(rollcall=False)
        c = sqlite3.connect(os.path.join(self.home, "chrome-profile", "Default", "Cookies"))
        c.execute("update cookies set creation_utc = ?", (int((AT.timestamp() - 3 * 86400 + isr.CHROME_EPOCH) * 1_000_000),))
        c.commit(); c.close()
        os.utime(self.isr_home("exports", "roster.json"), (AT.timestamp() - 60, AT.timestamp() - 60))

    def evening(self):
        """A roll-call, an audit and `isr.py access` on the frozen evening: the access command's output."""
        self.rollcall(b5.BOT_F, b5.ECHO)
        self.audit_json()
        code, out = self.access()
        self.assertEqual(code, 0)
        return out

    def other_days(self):
        """The two other days the evening shows (Codex, batch 3 review): the audit's roster warning and, from a brief run then,
        its headline. The roster was saved before the roll-call, so the audit warns about it."""
        self.assertEqual([n for n in self.snap()["notes"] if "exports/roster.json" in n], [ROSTER_NOTE])
        self.assertIn(BRIEF_DAY, self.brief([])[2])


class AnEveningAudit(_Evening):
    def test_an_evening_audit_is_the_eastern_day(self):   # replay (bc91ed7: "Nov 3"; f76851f: "2026-11-03", "3 Nov 2026")
        self.box()
        out = self.evening()
        self.assertIn(LAST_AUDIT, out)
        self.assertIn(ROLLCALL, out)
        m = json.loads(self.map_file())   # the days the audit kept in state/access_map.json
        self.assertEqual((m["rollcall"]["at"], [b["said_at"] for b in m["bots"]]), ("2026-11-02", ["2026-11-02", "2026-11-02"]))
        self.other_days()

    def test_rollcall_said_at_is_the_eastern_day(self):   # replay (bc91ed7: "2026-11-03")
        self.box()
        self.rollcall(b5.BOT_F, b5.ECHO)
        acc = json.load(open(isr.state_path("rollcall_findings.json")))["access"]
        self.assertEqual({b: a["said_at"] for b, a in acc.items()}, {"bot-f": "2026-11-02", "bot-e": "2026-11-02"})

    def test_the_same_in_three_time_zones(self):   # guard (the box's own time zone never moves the day)
        self.box()
        for name in ZONES:
            with self.subTest(name):
                if not self.zone(name):
                    self.skipTest(f"no time zone data for {name} on this computer")
                out = self.evening()
                self.assertIn(LAST_AUDIT, out)
                self.assertIn(ROLLCALL, out)
                self.other_days()


class TheDayOfAStoredTime(unittest.TestCase):
    def test_ax_date_reads_a_time_as_the_eastern_day(self):   # replay (bc91ed7: "2026-11-03")
        self.assertEqual(isr._ax_date("2026-11-03T01:32:16+00:00"), "2026-11-02")
        self.assertEqual(isr._ax_date("2026-11-03"), "2026-11-03")   # guard: a day already kept is never shifted twice

    def test_et_date_on_both_sides_of_the_clock_change(self):   # guard (et_date is new: errors on the base)
        for at, want in (("2026-11-01T05:59:00+00:00", "2026-11-01"), ("2026-11-01T06:01:00+00:00", "2026-11-01"),
                         ("2026-03-08T06:59:00+00:00", "2026-03-08"), ("2026-03-08T07:01:00+00:00", "2026-03-08"),
                         # an evening hour where the 4- or 5-hour offset decides the day, just after each change
                         ("2026-11-02T04:30:00+00:00", "2026-11-01"), ("2026-03-09T04:30:00+00:00", "2026-03-09"),
                         (AT.isoformat(), "2026-11-02"), ("not a time", None)):
            with self.subTest(at):
                self.assertEqual(isr.et_date(at), want)
                if want:   # the day et_time shows
                    self.assertEqual(isr.et_time(at, day=True), f"{dt.date.fromisoformat(want):%b} {dt.date.fromisoformat(want).day}")


if __name__ == "__main__":
    unittest.main()
