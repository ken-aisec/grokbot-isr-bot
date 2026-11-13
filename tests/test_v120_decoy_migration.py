"""v1.2.0 migration (plan decoy-false-trips-20261112, section 5) and the noatime case.

The first v1.2.0 daily or audit plants chaff and far sentinels beside the decoys already there, without touching the decoys'
paths, files or values, rewrites state/canaries.json once to keep salted hashes only, and logs canary-migrate. A read made
before the chaff existed is judged by the old rules. Stored events are never re-judged. On a mount that doesn't record reads
there is no sweep to judge, and the copy and use checks still fire.

Every test runs on the Sandbox computer of test_v120_decoy_sweeps (its own tmp, var/tmp, workspace and $HOME under the test's
temp folder; asserted in setUp). Decoy values are compared by hash only. The test whose name holds "replay" fails on 7da4c44 at
its assertion; the others are guards."""
import hashlib, json, os, shutil, sys, unittest
from unittest import mock
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_v120_decoy_sweeps import IOC, Sandbox, holds_value, text_of, value_of  # noqa: E402
import isr  # noqa: E402

V120_KEYS = ("token_sha256", "token_prefix", "salt", "token_path", "past_tokens")


class Base(Sandbox):
    def setUp(self):
        super().setUp()
        self.values = {n: value_of(v["path"]) for n, v in self.reg.items()}   # in memory only
        isr.rearm_canaries()                              # reading them was a read: armed again before the test reads anything

    def registry_text(self):
        return text_of(isr.state_path("canaries.json"))

    def make_v111(self):
        """This install as v1.1.1 left it: raw values in the registry, no chaff, no far sentinels, no salt in the layout."""
        for p in list(isr.chaff_paths()) + list(isr.sentinel_paths()):
            os.remove(p)
        for top in {os.path.dirname(os.path.dirname(p)) for p in isr.sentinel_paths()}:
            shutil.rmtree(top)
        os.remove(isr.state_path(isr.CHAFF_STATE))
        lay = isr.load_json(isr.state_path("decoy_layout.json"), {})
        isr.save_json(isr.state_path("decoy_layout.json"), {n: lay[n] for n in self.reg})
        reg = isr.load_json(isr.state_path("canaries.json"), {})
        for n, v in reg.items():
            for k in V120_KEYS:
                v.pop(k, None)
            v["token"] = self.values[n]
        isr.save_json(isr.state_path("canaries.json"), reg)

    def decoy_bytes(self):
        out = {}
        for v in self.reg.values():
            with open(v["path"], "rb") as f:
                out[v["path"]] = hashlib.sha256(f.read()).hexdigest()
        return out

    def ledger(self, event):
        return [json.loads(x) for x in text_of(isr.state_path("ledger.jsonl")).splitlines() if f'"event": "{event}"' in x]


class RegistryHoldsNoValue(Base):
    def test_replay_registry_holds_no_raw_value_after_plant_and_after_migration(self):   # replay: fails on 7da4c44
        self.assertEqual([n for n, x in self.values.items() if holds_value(self.registry_text(), x)], [])   # after `canary plant`
        self.make_v111()
        self.assertEqual(sorted(n for n, x in self.values.items() if holds_value(self.registry_text(), x)), sorted(self.values))
        self.audit()
        self.assertEqual([n for n, x in self.values.items() if holds_value(self.registry_text(), x)], [])   # after the first run


class FirstRunMigrates(Base):
    def test_an_old_registry_is_hashed_once_and_the_decoys_and_stored_events_are_untouched(self):   # guard
        self.make_v111()
        before, reg_before = self.decoy_bytes(), isr.load_json(isr.state_path("canaries.json"), {})
        old = isr.finding("ISR-K001", "Something opened a decoy file", "critical", ["ASI03", "ASI10"], self.path_of("api-env"),
                          "api-env read at 2026-11-11T14:01+00:00", "Tell ISR Bot \"incident check\".")
        isr.remember_events([old])                        # the open Nov 11 alarm, as v1.1.1 stored it
        stored = [e for e in isr.load_json(isr.state_path("events.json"), []) if e["key"] == old["key"]]
        self.audit()
        reg = isr.load_json(isr.state_path("canaries.json"), {})
        self.assertEqual({n: v["path"] for n, v in reg.items()}, {n: v["path"] for n, v in reg_before.items()})
        self.assertEqual(self.decoy_bytes(), before)       # paths, files and values in them as they were
        self.assertFalse([n for n, v in reg.items() if "token" in v])
        self.assertEqual({n: isr.value_hash(v["salt"], self.values[n]) == v["token_sha256"] for n, v in reg.items()},
                         {n: True for n in reg})          # the hash of the value each decoy already held
        self.assertEqual([e for e in isr.load_json(isr.state_path("events.json"), []) if e["key"] == old["key"]], stored)
        self.assertIn(old["key"], {f["key"] for f in self.snap()["findings"]})
        self.assertEqual([{k: e[k] for k in ("chaff", "sentinels")} for e in self.ledger("canary-migrate")], [{"chaff": 6, "sentinels": 2}])
        self.assertTrue(all(os.path.isfile(p) for p in list(isr.chaff_paths()) + list(isr.sentinel_paths())))
        self.audit()
        self.assertEqual(len(self.ledger("canary-migrate")), 1)   # once
        self.assertEqual(isr.SCORE_ERA, "s6")

    def test_a_read_pending_at_the_upgrade_is_judged_by_the_old_rules(self):   # guard
        self.make_v111()
        self.tool("grep", "-rI", IOC, self.tmpd, self.ws, self.home)   # read before any chaff existed
        self.audit()
        k = [(f["rule"], f["severity"]) for f in self.snap()["findings"] if f["rule"].startswith("ISR-K")]
        self.assertEqual(k, [("ISR-K001", "critical")])   # no evidence, so no downgrade
        self.tool("grep", "-rI", IOC, self.tmpd, self.ws, self.home)   # the next sweep has chaff to read
        self.assertEqual([(r, s) for r, s, _ in self.judged()], [("ISR-K008", "info")])

    def test_a_replanted_decoy_gets_a_new_value_and_its_old_one_is_still_recognised(self):   # guard
        p = self.path_of("api-env")
        old_key = "rk_live_" + self.values["api-env"] * 2
        os.remove(p)
        isr.plant_canaries(only={"api-env"})
        v = isr.load_json(isr.state_path("canaries.json"), {})["api-env"]
        self.assertNotEqual(isr.value_hash(v["salt"], self.values["api-env"]), v["token_sha256"])
        self.assertEqual([isr.value_hash(x["salt"], self.values["api-env"]) == x["token_sha256"] for x in v["past_tokens"]], [True])
        leak = os.path.join(self.ws, "old-copy.txt")
        with open(leak, "w") as f:
            f.write(f"key: {old_key}\n")
        self.audit()
        self.assertEqual([(f["rule"], f["severity"]) for f in self.snap()["findings"] if f["where"] == leak], [("ISR-K003", "critical")])


class NoReadsRecorded(Base):
    def test_noatime_means_no_sweep_rule_and_copy_and_use_still_fire(self):   # guard
        with mock.patch.object(isr, "reads_recorded", return_value=False):
            self.tool("grep", "-rI", IOC, self.tmpd, self.ws, self.home)
            self.assertEqual([(r, s) for r, s, _ in self.judged()], [("ISR-K001", "critical")])   # judged as before
            key = "rk_live_" + self.values["api-env"] * 2
            copy = os.path.join(self.ws, "x.txt")
            with open(copy, "w") as f:
                f.write(key + "\n")
            hist = os.path.join(self.home, ".bash_history")
            with open(hist, "w") as f:
                f.write(f"curl -u {key}: https://example.invalid/\n")
            self.audit()
        k3 = sorted((f["title"], f["severity"], f["where"]) for f in self.snap()["findings"] if f["rule"] == "ISR-K003")
        self.assertEqual(k3, sorted([("Canary value copied into another file", "critical", copy),
                                     ("Decoy value used in a command", "critical", hist)]))
        self.assertNotIn("ISR-K008", [f["rule"] for f in self.snap()["findings"]])


if __name__ == "__main__":
    unittest.main()
