"""Simulated environment profiles (v0.6.9). Each builder lays out a computer under a Box test's temp folders."""
import json, os

EMOJI_SKILLS = ("📰-ニュース", "résumé-helper", "новости-дайджест", "助手 skill", "🤖bot-tools")


def empty_account(box):
    """A brand-new account: no skills, no plugins, no exports, no history."""
    return []


def power_user(box, skills=120, bots=24):
    """20+ Bots and 100+ skills, spread over the folders a heavy user ends up with, plus a roster and roll-call replies."""
    out = box.skills(skills // 2) + box.skills(skills - skills // 2, where="projects/agent-skills")
    exp = os.path.join(box.ws, "watchtower", "exports"); os.makedirs(os.path.join(exp, "rollcall"), exist_ok=True)
    roster = [{"name": f"Bot{i:02d}", "kind": "bot"} for i in range(bots)] + [{"name": "Ops room", "kind": "room"}]
    json.dump(roster, open(os.path.join(exp, "roster.json"), "w"))
    for i in range(bots):
        json.dump({"name": f"Bot{i:02d}", "description": "Helps with work.", "connectors": ["Gmail", "Slack"],
                   "routines": [{"name": "Morning", "schedule": "daily 7am", "instructions": "Draft a summary. Ask before sending."}],
                   "memories": [f"(2026-09-{i % 28 + 1:02d}) [log] prefers short replies"]},
                  open(os.path.join(exp, "rollcall", f"bot{i:02d}.json"), "w"))
    return out


def odd_layout(box):
    """Unreadable folders, a link loop, a skill that is a link to outside, odd file names, a binary SKILL.md."""
    base = os.path.join(box.home, "sand-data", "workflows"); os.makedirs(base, exist_ok=True)
    locked = os.path.join(base, "locked-skill"); os.makedirs(locked)
    open(os.path.join(locked, "SKILL.md"), "w").write("---\nname: locked\n---\nx\n")
    os.chmod(locked, 0)
    os.symlink(base, os.path.join(base, "loop"))
    outside = os.path.join(box.tmp, "outside-skill"); os.makedirs(outside)
    open(os.path.join(outside, "SKILL.md"), "w").write("---\nname: outside\n---\nSummarize.\n")
    os.symlink(outside, os.path.join(base, "linked-skill"))
    weird = os.path.join(base, "weird name\nwith newline"); os.makedirs(weird)
    open(os.path.join(weird, "SKILL.md"), "w").write("---\nname: weird\n---\nok\n")
    binary = os.path.join(base, "binary-skill"); os.makedirs(binary)
    open(os.path.join(binary, "SKILL.md"), "wb").write(bytes(range(256)) * 50)
    noperm = os.path.join(base, "noread-file"); os.makedirs(noperm)
    p = os.path.join(noperm, "SKILL.md"); open(p, "w").write("---\nname: noread\n---\nx\n"); os.chmod(p, 0)
    return [locked, outside, weird, binary, noperm]


def strict_auto_review(box):
    """Every consequential action is Ask first; nothing is allowed automatically."""
    exp = os.path.join(box.ws, "watchtower", "exports"); os.makedirs(exp, exist_ok=True)
    open(os.path.join(exp, "auto-review.txt"), "w").write(
        "Ask first: sending email or messages\nAsk first: publishing or posting\nAsk first: purchases or payments\n"
        "Ask first: deleting data\nAsk first: changing permissions, settings, routines or connectors\nAsk first: every shell command\n")
    d = box.skills(1, text="Send the weekly digest to the team.")[0]
    return [d]


def emoji_names(box):
    """Skills, Bots and an owner whose names are emoji or not English."""
    base = os.path.join(box.home, "sand-data", "workflows"); os.makedirs(base, exist_ok=True)
    out = []
    for n in EMOJI_SKILLS:
        d = os.path.join(base, n); os.makedirs(d)
        open(os.path.join(d, "SKILL.md"), "w").write(f"---\nname: {n}\ndescription: Résumé — 要約 📰\n---\nResume las notas. Pregunta antes de enviar.\n")
        out.append(d)
    exp = os.path.join(box.ws, "watchtower", "exports"); os.makedirs(os.path.join(exp, "rollcall"), exist_ok=True)
    json.dump([{"name": "Ïris 🤖", "kind": "bot"}, {"name": "Танго", "kind": "bot"}], open(os.path.join(exp, "roster.json"), "w"))
    json.dump({"name": "Ïris 🤖", "memories": ["Prefiere respuestas cortas 🙂"]}, open(os.path.join(exp, "rollcall", "ïris.json"), "w"))
    open(os.path.join(exp, "names.txt"), "w").write("José\n")
    return out
