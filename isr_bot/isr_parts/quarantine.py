# Part of isr.py: runs inside isr.py's namespace (loaded by _isr_part); not a module on its own.
# ---------------------------------------------------------------- quarantine: take a dangerous skill out of use without deleting it
def PLATFORM_SKILL_DIRS():
    return [os.path.join(b, x) for b in (os.path.expanduser("~"), "/home/box") for x in ("sand-data", "agent-data", ".grok", ".cursor", ".agents")]


def quarantinable(f):
    """The skill folder a finding lets the fix take out of use, or None: the owner's own skills with a critical finding, and
    (DQ-021) a skill copy in the workspace that two engines agree is dangerous (ISR-X003). Plugins and built-in skills are removed
    in the app, not here."""
    w = f["where"].split(":")[0]
    d = skill_root(w) if os.path.exists(w) else None
    if not d:
        return None
    if f["severity"] == "critical" and skill_tier(d + "/") == "user":
        return os.path.normpath(d)
    if f["rule"] == "ISR-X003" and owned_path(d, "workspace-skill", log=False):
        return os.path.normpath(d)
    return None


def restorable_to_workspace(p):
    """Restore target for a workspace skill: the folder is gone (it was moved out), its parent is in the workspace, outside
    ISR Bot's own folder and the platform's folders, and not reached through a link."""
    n = os.path.normpath(os.path.abspath(str(p)))
    par = os.path.dirname(n)
    ws, h = os.path.realpath(os.path.dirname(home())), os.path.realpath(home())
    return (not os.path.exists(n) and os.path.realpath(par) == par and _under(n, {ws}, strict=True) and not _under(n, {h})
            and not _under(n, {os.path.realpath(x) for x in PLATFORM_SKILL_DIRS()}))


def quarantine_candidates(findings):
    """The skills the fix can take out of use (see quarantinable)."""
    out = {}
    for f in findings:
        d = quarantinable(f)
        if d:
            out.setdefault(d, []).append(plain(f)["title"])
    return [{"name": skill_name(d), "why": "; ".join(sorted(set(v))[:3])} for d, v in sorted(out.items())]


def quarantine(names, reason=""):
    snap = load_snapshot({"findings": []})
    dirs = {d for d in map(quarantinable, snap.get("findings", [])) if d}   # exactly what quarantine_candidates offers
    reg, done = load_json(state_path("quarantine.json"), []), []
    for name in names:
        cand = os.path.normpath(name)
        if os.path.isfile(os.path.join(cand, "SKILL.md")):
            d = cand if cand in dirs else None        # by path: only a skill the fix would have offered
        else:
            d = find_skill(name, dirs)
        if not d:
            done.append(f"{name}: not quarantined. It isn't one of your own skills with an open critical finding (plugins and built-in skills are removed in the app).")
            continue
        dst = os.path.join(home(), "quarantine", f"{skill_name(d)}-{dt.datetime.now().strftime('%Y%m%d-%H%M%S')}")
        if not ((owned_path(d, "skill", log=False) or owned_path(d, "workspace-skill")) and owned_path(dst, "quarantine")):
            done.append(f"{name}: not quarantined. {d} is not inside your own skill folders. Nothing changed.")
            continue
        try:
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            shutil.move(d, dst)
            md = os.path.join(dst, "SKILL.md")
            if os.path.isfile(md):
                os.replace(md, md + ".quarantined")   # nothing can load it as a skill from here
        except OSError as e:
            done.append(f"{name}: could not be moved ({e.strerror}). Nothing changed.")
            continue
        reg.append({"name": skill_name(d), "from": d, "to": dst, "at": now(), "reason": reason[:200]})
        ledger({"event": "quarantine", "skill": skill_name(d), "from": d, "to": dst})
        done.append(f"Quarantined {skill_name(d)}: moved out of use to {dst}. Nothing was deleted; `isr.py quarantine --restore {skill_name(d)}` puts it back.")
    save_json(state_path("quarantine.json"), reg)
    return done


def cmd_quarantine(args):
    reg = load_json(state_path("quarantine.json"), [])
    if args.restore:
        hit = [e for e in reg if e["name"] == args.restore and os.path.isdir(e["to"])]
        if not hit:
            print(f"Nothing named “{args.restore}” is in quarantine.")
            return 1
        e_ = hit[-1]
        if not (owned_path(e_["to"], "quarantine") and (owned_path(e_["from"], "skill", log=False) or restorable_to_workspace(e_["from"])
                                                       or owned_path(e_["from"], "skill"))):   # the last call only writes the refusal
            print(f"Not restored: the quarantine record for {args.restore} points outside ISR Bot's quarantine folder or your own "
                  "skill folders. Nothing was moved; the refusal is in the ledger.")
            return 1
        if os.path.exists(e_["from"]):
            print(f"Not restored: {e_['from']} exists again. Move it away first.")
            return 1
        q = os.path.join(e_["to"], "SKILL.md.quarantined")
        if os.path.isfile(q):
            os.replace(q, os.path.join(e_["to"], "SKILL.md"))
        os.makedirs(os.path.dirname(e_["from"]), exist_ok=True)
        shutil.move(e_["to"], e_["from"])
        save_json(state_path("quarantine.json"), [x for x in reg if x is not e_])
        ledger({"event": "quarantine-restore", "skill": e_["name"], "to": e_["from"]})
        print(f"Restored {e_['name']} to {e_['from']}. It will be scanned again on the next audit.")
        return 0
    if args.names:
        print("\n".join(quarantine([n.strip() for n in args.names.split(",") if n.strip()], args.reason or "")))
        return 0
    live = [e for e in reg if os.path.isdir(e["to"])]
    print("\n".join(f"{e['at'][:10]}  {e['name']:30} from {e['from']}" for e in live) or "Quarantine is empty.")
    return 0
