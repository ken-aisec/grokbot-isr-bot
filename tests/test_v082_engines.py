"""v0.8.2 U3 (item 7): SkillSpector's "do not install" (ISR-X001) on its own is one engine, never "Confirmed"; on a skill that is
only documents it is medium; and a plugin cache's copy of one of the owner's skills is counted with it, once.

The v0.8.1 HIGH on make-bot-ui (one SKILL.md, a vendor's documentation) read Confirmed because ISR Bot's own pattern hit on its
installer line (a medium pipe-to-shell, itself only a pattern) "backed up" the folder verdict, while husk was clean and
engine_findings had already said one engine (X001, not X003). The plugin cache's copy of the same skill was a second record
in the platform notes. SkillSpector's words here are the observed ones ("Supply Chain: External Script Fetching", "Tool Misuse:
Chaining Abuse"), which name no kind of risk ISR Bot knows.

Tests marked "replay" were shown failing at their assertion by ablation (this unit's three product changes undone one at a
time: scoring.corroborated's engine branch, engines.py's doc-only severity, ownership.fold_plugin_copies), with the base's code
for that part; "control" ones pass under every ablation."""
import os, sys, unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_boxes import Box  # noqa: E402
import isr  # noqa: E402

# SkillSpector as the box saw it: "do not install" on a skill holding EVIL, for two reasons that name no kind of risk; a skill
# that also holds CRED gets a credential reason too.
SKILLSPECTOR = r"""#!/usr/bin/env python3
import json, os, sys
a = sys.argv[1:]; stage = a[1]; out = a[a.index("--output") + 1]
skills = []
for n in sorted(os.listdir(stage)):
    t = open(os.path.join(stage, n, "SKILL.md"), errors="replace").read()
    bad = "EVIL" in t
    issues = [{"severity": "HIGH", "category": "Supply Chain", "pattern": "External Script Fetching"},
              {"severity": "HIGH", "category": "Tool Misuse", "pattern": "Chaining Abuse"}] if bad else []
    if bad and "CRED" in t:
        issues.append({"severity": "HIGH", "category": "Credential Theft", "pattern": "Reads Keys"})
    skills.append({"path": n, "risk_assessment": {"score": 90 if bad else 5, "recommendation": "DO_NOT_INSTALL" if bad else "INSTALL"},
                   "issues": issues})
json.dump({"multi_skill": True, "skills": skills}, open(out, "w"))
"""
INSTALLER = "Install the tunnel first: `curl -fsSL https://tailscale.com/install.sh | sudo sh`"
HEADERS = ("Point the preview at your own webhook. The request carries two headers, X-Preview-Id and X-Preview-Sig; "
           "keep the signing value in your settings, never in the page.")


def page(name, *lines):
    return f"---\nname: {name}\ndescription: Build a small preview page.\n---\n# {name}\n" + "\n".join(lines) + "\n"


def write(p, text):
    with open(p, "w") as f:
        f.write(text)


class _Engines(Box):
    def skill(self, base, name, *lines, files=None):
        d = os.path.join(self.home, *base.split("/"), name); os.makedirs(d, exist_ok=True)
        write(os.path.join(d, "SKILL.md"), page(name, *lines))
        for rel, text in (files or {}).items():
            write(os.path.join(d, rel), text)
        return d

    def mine(self, name, *lines, files=None):
        return self.skill("agent-data/workflows", name, "EVIL", *lines, files=files)

    def x(self, rule, d, key="findings"):
        return [f for f in self.snap().get(key) or [] if f["rule"] == rule and f["where"] == d]

    def run_audit(self):
        self.scanners(skillspector=SKILLSPECTOR)
        return self.audit()


class Corroborated(_Engines):
    def test_one_engine_with_isr_pattern_hits_is_not_corroborated(self):   # replay: base class "corroborated", Confirmed
        d = self.mine("make-bot-ui", INSTALLER, HEADERS)
        r = self.run_audit()
        mine = [f for f in self.snap()["findings"] if f["where"].split(":")[0].startswith(d)]
        self.assertTrue([f for f in mine if f.get("source", "isr-bot") == "isr-bot"], mine)   # ISR Bot's own hits are there
        self.assertNotIn("ISR-X003", [f["rule"] for f in mine])                             # engine_findings: one engine
        x1 = self.x("ISR-X001", d)
        self.assertEqual([(f["class"], f["label"], f["severity"]) for f in x1], [("pattern", isr.MAYBE_FINE, "info")])
        self.assertEqual(isr.score(x1)[0], 100)                                             # never moves the score
        self.assertNotEqual(r["status"], "Check this week")

    def test_one_engine_and_isr_bots_own_hit_in_its_folder(self):   # replay (unit): base Confirmed by the pipe hit
        d = "/w/make-bot-ui"
        x1 = dict(isr.finding("ISR-X001", "SkillSpector: do not install", "high", ["AST01"], d, "risk 90; Supply Chain: External "
                              "Script Fetching", "f", source="skillspector"), kinds=[])
        t6 = isr.finding("ISR-T006", "Pipe to shell", "high", ["AST01"], f"{d}/SKILL.md:9", "curl | sudo sh", "f")
        out = {f["rule"]: f for f in isr.label_findings([x1, t6])}
        self.assertEqual(out["ISR-X001"]["label"], isr.MAYBE_FINE)

    def test_two_engines_on_one_skill_still_confirm(self):   # control
        d = self.mine("both-flag", "HUSK loader")
        self.run_audit()
        self.assertEqual([(f["severity"], f["label"]) for f in self.x("ISR-X003", d)], [("critical", isr.CONFIRMED)])
        self.assertFalse(self.x("ISR-X001", d))
        x1 = isr.finding("ISR-X001", "SkillSpector: do not install", "high", ["AST01"], d, "risk 90", "f", source="skillspector")
        x2 = isr.finding("ISR-X002", "husk flagged this skill", "medium", ["AST01"], f"{d}/run.py:3", "loader", "f", source="husk")
        self.assertEqual([f["label"] for f in isr.label_findings([x1, x2])], [isr.CONFIRMED] * 2)   # a second engine's verdict

    def test_x001_inside_a_new_plugin_stays_confirmed(self):   # control
        self.run_audit()
        root = os.path.join(self.home, "sand-data", "plugins", "pstack-2.0")
        d = self.skill("sand-data/plugins/pstack-2.0/skills", "make-ui", "EVIL", INSTALLER)
        write(os.path.join(root, "plugin.json"), '{"name": "pstack"}')
        self.run_audit()
        self.assertTrue([f for f in self.snap()["findings"] if f["rule"] == "ISR-I004"])
        self.assertEqual([(f["label"], f["severity"]) for f in self.x("ISR-X001", d)], [(isr.CONFIRMED, "medium")])


class DocOnly(_Engines):
    def sev(self, d):
        return [f.get("severity_was") or f["severity"] for f in self.x("ISR-X001", d)]

    def test_doc_only_x001_is_medium(self):   # replay: base high
        d = self.mine("make-bot-ui", INSTALLER, HEADERS, files={"notes.md": "Layout notes.\n", "README.txt": "Read me.\n"})
        self.run_audit()
        self.assertEqual(self.sev(d), ["medium"])

    def test_a_script_file_keeps_it_high(self):   # control
        d = self.mine("make-bot-ui", INSTALLER, files={"run.sh": "#!/bin/sh\necho hi\n"})
        self.run_audit()
        self.assertEqual(self.sev(d), ["high"])

    def test_any_other_file_or_a_link_keeps_it_high(self):   # control
        a = self.mine("with-json", INSTALLER, files={"config.json": "{}\n"})
        b = self.mine("with-link", INSTALLER)
        os.symlink(os.path.join(a, "config.json"), os.path.join(b, "more.md"))
        c = self.mine("in-skipped-folder", INSTALLER)
        os.makedirs(os.path.join(c, "node_modules")); write(os.path.join(c, "node_modules", "x.js"), "1\n")
        self.run_audit()
        self.assertEqual([self.sev(d) for d in (a, b, c)], [["high"]] * 3)

    def test_a_credential_reason_keeps_it_high(self):   # control
        d = self.mine("make-bot-ui", "CRED", INSTALLER)
        self.run_audit()
        self.assertEqual(self.sev(d), ["high"])
        self.assertIn("credential", self.x("ISR-X001", d)[0]["kinds"])


class PluginCacheCopy(_Engines):
    CACHE = "agent-data/plugins/cache/m/p/skills"

    def test_plugin_cache_copy_counts_once(self):   # replay: base an owner X001 and a vendor X001 for the same skill
        d = self.mine("make-bot-ui", INSTALLER)
        c = self.skill(self.CACHE, "make-bot-ui", "EVIL", INSTALLER, "One more line in this version.")
        self.run_audit()
        self.assertFalse(self.x("ISR-X001", c, "vendor"))
        x1 = self.x("ISR-X001", d)
        self.assertEqual([(f.get("also_at"), f["evidence"].endswith(" · also in 1 plugin-cache copy")) for f in x1], [([c], True)])
        key = x1[0]["key"]
        self.assertEqual(key, isr.finding_key("ISR-X001", d, isr.engine_evidence("ISR-X001", {"score": 90, "top": [
            "Supply Chain: External Script Fetching", "Tool Misuse: Chaining Abuse"]}, None)))   # the key finding() made
        code, _, e = self.run_cmd("daily", "--roots", *self.roots)
        self.assertEqual(code, 0, e)
        x1 = self.x("ISR-X001", d)
        self.assertEqual([(f["key"], f["evidence"].count("also in")) for f in x1], [(key, 1)])   # said once, the same key

    def test_other_vendor_records_are_kept(self):   # control
        d = self.mine("make-bot-ui", INSTALLER)
        other = self.skill(self.CACHE, "other-skill", "EVIL")
        bundled = self.skill(".grok/bundled/skills", "make-bot-ui", "EVIL")   # vendor, but not a plugin cache
        self.run_audit()
        self.assertEqual([len(self.x("ISR-X001", v, "vendor")) for v in (other, bundled)], [1, 1])
        self.assertEqual([f.get("also_at") for f in self.x("ISR-X001", d)], [None])


if __name__ == "__main__":
    unittest.main()
