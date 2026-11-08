# Part of isr.py: runs inside isr.py's namespace (loaded by _isr_part); not a module on its own.
# ---------------------------------------------------------------- changes between two observations (pure: no files, no clock)
DIFF_GAP_HOURS = 12
OBS_AREA_WORDS = {"browser": "Browser cookie files", "cli_logins": "Command-line sign-ins", "settings": "Allowed without asking",
                  "mcp": "Tool connections (MCP)", "plugins": "Plugins", "webhooks": "Chat webhooks", "scheduled": "Scheduled jobs",
                  "hooks": "Hooks", "key_files": "Files with live-looking keys", "cli_files": "CLI sign-in file names (lstat)",
                  "bots": "Roll-call answers", "bot_list": "Bot list (roster and agent profiles)"}


def _obs_time(r):
    return dt.datetime.fromisoformat(r["observed_at"].replace("Z", "+00:00"))


def pick_baseline(records, cur):
    """The newest kept observation at least DIFF_GAP_HOURS older than `cur`, or None."""
    cut = _obs_time(cur) - dt.timedelta(hours=DIFF_GAP_HOURS)
    old = [r for r in records if r["observation_id"] != cur["observation_id"] and _obs_time(r) <= cut]
    return max(old, key=lambda r: (r["observed_at"], r["observation_id"])) if old else None


def obs_items(r, area):
    """The things an observation saw in one area, as short plain strings (sorted)."""
    sh = r["map"]["shared"]
    if area == "browser":
        b = sh["browser"] or {"sites": 0, "sensitive": []}
        return sorted({f"signed in to {h}" for h in b["sensitive"]} | {f"{b['sites']} sites in all"})
    if area == "cli_logins":
        return sorted({c["tool"] for c in sh["cli_logins"]} | set(sh["platform_logins"]))
    if area == "settings":
        return sorted({f"{ACCESS_AREA_WORDS.get(a['area'], a['area'])}: {a['says']}" for a in sh["auto_allow"]}
                      | {f"running programs: {sh['runs_programs']}"})
    if area == "mcp":
        return sorted({t["name"] for t in sh["mcp"]["tools"]} | {f"{sh['mcp']['count']} tools in all"})
    if area == "plugins":
        return sorted(set(sh["plugins"]["names"]) | {f"{sh['plugins']['added']} added plugins in all"})
    if area == "webhooks":
        return sorted({f"{w['service']} webhook in {w['skill']}" for w in sh["webhooks"]})
    if area == "scheduled":
        return sorted(f"{k}: {v}" for k, v in sh["scheduled"].items())
    if area == "hooks":
        return sorted(f"{k} hooks: {v}" for k, v in sh["hooks"].items())
    if area == "key_files":
        return [f"{sh['key_files']} files"]
    if area == "cli_files":
        return sorted(f"{c['file']}: {cred_words(c)}" for c in r["creds"] if c["state"] != "missing")
    return []


def _record_line(r):
    return f"prior record `{r['observation_id']}`, written {r['written_at']} by ISR Bot {r['written_by_version']}"


def _bot_said(b):
    s = b["said"]
    if not s:
        return set()
    return set(s["connectors"]) | ({f"{s['connectors_other']} other connectors"} if s["connectors_other"] else set()) | \
        {f"{s['routines']} routines ({s['routines_sending']} send without asking)"}


def diff_observations(prev, cur):
    """What changed from `prev` (pick_baseline's record, or None) to `cur`: {"baseline", "areas", "bots"}. An area is compared
    only when both records saw it whole; what is missing from an incomplete one is "not seen this time", never gone. A Bot that
    didn't answer is "not heard from"; "no longer listed" needs both records' complete Bot lists to leave it out. What a Bot
    said stays under that Bot, unverified."""
    if prev is None:
        return {"baseline": None, "lines": ["No earlier record at least %d hours older: no earlier record to compare with." % DIFF_GAP_HOURS],
                "areas": [], "bots": []}
    areas = []
    for a in OBS_AREAS:
        if a in ("bots", "bot_list"):
            continue
        was, now_ = obs_items(prev, a), obs_items(cur, a)
        pc, cc = prev["coverage"][a], cur["coverage"][a]
        if pc == "complete" and cc == "complete":
            new, gone = [x for x in now_ if x not in was], [x for x in was if x not in now_]
            if new or gone:
                areas.append({"area": a, "state": "changed", "new": new, "gone": gone})
        else:
            why = cc if cc != "complete" else "in the prior record: " + pc
            areas.append({"area": a, "state": "not comparable", "why": why,
                          "not_seen": [x for x in was if x not in now_] if cc != "complete" else []})
    pb, cb = {b["pid"]: b for b in prev["bots"]}, {b["pid"]: b for b in cur["bots"]}
    lists_whole = prev["coverage"]["bot_list"] == "complete" and cur["coverage"]["bot_list"] == "complete"
    bots = []
    for pid in sorted(set(pb) | set(cb)):
        p, c = pb.get(pid), cb.get(pid)
        if p is None:
            bots.append({"pid": pid, "name": c["name"], "change": "new in this record", "id_basis": c["id_basis"]})
            continue
        if c is None:
            if lists_whole and p["listed"]:
                change = "no longer listed (not in the roster or any agent profile, both lists read whole both times)"
            else:
                change = "not seen this time (the Bot list wasn't read whole in both records)"
            bots.append({"pid": pid, "name": p["name"], "change": change, "id_basis": p["id_basis"]})
            continue
        notes = []
        if p["name"] != c["name"]:
            notes.append(f"renamed from {p['name']} to {c['name']}")
        if p["said"] and not c["said"]:
            notes.append("not heard from since " + (_ax_day(p["said"]["said_at"]) if p["said"]["said_at"] else "the prior record"))
        elif c["said"] and p["said"] and cur["coverage"]["bots"] == "complete":
            new, gone = sorted(_bot_said(c) - _bot_said(p)), sorted(_bot_said(p) - _bot_said(c))
            if new or gone:
                notes.append("said " + "; ".join([f"now: {', '.join(new)}"] * bool(new) + [f"no longer: {', '.join(gone)}"] * bool(gone))
                             + f" (said by {pid}, not checked; sender not verified)")
        if notes:
            bots.append({"pid": pid, "name": c["name"], "change": "; ".join(notes), "id_basis": c["id_basis"]})
    return {"baseline": {k: prev[k] for k in ("observation_id", "observed_at", "written_at", "written_by_version")},
            "lines": [f"Compared with the {_record_line(prev)}."], "areas": areas, "bots": bots}


def diff_lines(d):
    """The diff as plain lines (each a data line: artifacts escapes them)."""
    out = list(d["lines"])
    for a in d["areas"]:
        w = OBS_AREA_WORDS[a["area"]]
        if a["state"] == "changed":
            out += [f"{w}: new: {x}" for x in a["new"]] + [f"{w}: gone: {x}" for x in a["gone"]]
        else:
            out.append(f"{w}: not comparable ({a['why']})")
            out += [f"{w}: not seen this time: {x}" for x in a["not_seen"]]
    for b in d["bots"]:
        out.append(f"{b['pid']} ({b['name']}): {b['change']}")
    if d["baseline"] is not None and len(out) == 1:
        out.append("No change in the areas both records saw whole.")
    return out
