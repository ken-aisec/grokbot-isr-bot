# Part of isr.py: runs inside isr.py's namespace (loaded by _isr_part); not a module on its own.
# ---------------------------------------------------------------- plain language and the easy fix
SCRUB = re.compile(
    r"(AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|(?i:aws_secret_access_key)\s*[=:]\s*[A-Za-z0-9/+=]{40}"
    r"|\bsk-(proj|ant|svcacct|admin)-[A-Za-z0-9_-]{20,}|\bsk-[A-Za-z0-9]{40,}\b|\bxai-[A-Za-z0-9]{20,}"
    r"|\bgh[pousr]_[A-Za-z0-9]{36}|\bgithub_pat_[A-Za-z0-9_]{40,}|\bxox[baprs]-[A-Za-z0-9-]{10,}|\bglpat-[A-Za-z0-9_-]{20}"
    r"|\bsq0(atp|csp)-[0-9A-Za-z_-]{22,}|\bEAAA[A-Za-z0-9_+=-]{60}|\b[rs]k_live_[0-9A-Za-z]{24,}"
    r"|AIza[0-9A-Za-z_-]{35}|\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"
    r"|-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]{0,4000}?-----END [A-Z ]*PRIVATE KEY-----)")
SCRUB_DIRS = ("/agent-transcripts/",)
REDACTED = "[removed by ISR Bot]"

REVOKE = [  # gitleaks rule prefix → where the owner turns that key off
    ("aws", "AWS", "https://console.aws.amazon.com/iam/home#/security_credentials"),
    ("square", "Square", "https://developer.squareup.com/apps"),
    ("github", "GitHub", "https://github.com/settings/tokens"),
    ("slack", "Slack", "https://api.slack.com/apps"),
    ("openai", "OpenAI", "https://platform.openai.com/api-keys"),
    ("anthropic", "Anthropic", "https://console.anthropic.com/settings/keys"),
    ("gcp", "Google Cloud", "https://console.cloud.google.com/apis/credentials"),
    ("discord", "Discord", "https://discord.com/developers/applications"),
    ("stripe", "Stripe", "https://dashboard.stripe.com/apikeys"),
    ("gitlab", "GitLab", "https://gitlab.com/-/user_settings/personal_access_tokens"),
    ("notion", "Notion", "https://www.notion.so/profile/integrations"),
]

# rule → (plain title, why it matters, how to fix, who fixes it: "auto" = the fix handles it)
PLAIN = {
    "ISR-S001": ("Keys left in files", "Every Bot can read them and use them.", "Revoke the key at its provider, then delete the file.", "you"),
    "ISR-S002": ("Keys left in files", "Every Bot can read them and use them.", "Revoke the key at its provider; ISR Bot clears the copies.", "you"),
    "ISR-S003": ("A command-line login is stored on the Bot computer", "Any Bot can act as you with it.", "Tell ISR Bot \"fix it\": one yes keeps it, or sign out of that tool.", "you"),
    "ISR-S004": ("The shared browser is logged in to sensitive sites", "Every Bot uses the same logins.", "In the Bot browser, sign out of sites no Bot needs.", "you"),
    "ISR-A001": ("An auto-approve rule is too broad", "Bots can act without asking.", "Settings → General → Auto-review: change it to Ask first.", "you"),
    "ISR-A002": ("Sending or buying is auto-approved", "A tricked Bot could act on it.", "Settings → General → Auto-review: change it to Ask first.", "you"),
    "ISR-A003": ("Bots don't ask before sending or buying", "One bad web page could make a Bot act.", "Settings → General → Auto-review: add Ask-first rules.", "you"),
    "ISR-A004": ("Bots can create automations without asking", "A trick could keep running on a schedule.", "Settings → General → Auto-review: change it to Ask first.", "you"),
    "ISR-A005": ("No approval rules at all", "Nothing stops a Bot from acting.", "Settings → General → Auto-review: add Ask-first rules.", "you"),
    "ISR-C001": ("Bots can run code on your own computer", "Not just the cloud computer.", "Settings → General → Bot → Local Computer: Never allow.", "you"),
    "ISR-C003": ("Auto-review is off", "Nothing checks Bot actions.", "Settings → General → Auto-review: turn it on.", "you"),
    # Hooks have their own ID. They first shared ISR-C004 with "Connector installed but unused", so a connector finding was described
    # as a hook and accepting one accepted the other. ISR-C004 has no entry here, as in v0.6.6: it shows its own title and fix.
    "ISR-C005": ("A hook runs a script from a shared temp folder", "Any Bot could plant that script.", "Check what added the hook; report the platform's own to the platform.", "you"),
    "ISR-X001": ("A skill looks risky to the scanner", "It may read secrets or run outside code.", "Tell ISR Bot \"fix it\" and say yes for the ones that are yours.", "you"),
    "ISR-X002": ("A skill looks risky to the scanner", "It may hide what it does.", "Tell ISR Bot \"fix it\" and say yes for the ones that are yours.", "you"),
    "ISR-X003": ("Two scanners agree a skill is dangerous", "This is rarely a false alarm.", "Tell ISR Bot \"fix it\": one yes moves it out of use, and nothing is deleted. If it is a security tool of yours, the fix can keep it for 30 days.", "you"),
    "ISR-W001": ("ISR Bot's own tools need an update", "They live only in ISR Bot's folder.", "Tell ISR Bot \"update yourself\".", "auto"),
    "ISR-X004": ("A scanner couldn't get through a skill", "ISR Bot's own rules still checked it.", "Nothing to do; ISR Bot retries it in a week.", "auto"),
    "ISR-X005": ("One of ISR Bot's scanners was swapped", "ISR Bot didn't run it, so its checks weren't done.",
                "Reinstall the scanners (install.sh --scanners). If it comes back, tell the owner: something is changing ISR Bot's files.", "you"),
    "ISR-I004": ("A new plugin was installed", "It brought its own skills, and nothing could vet them before it arrived.",
                "Tell ISR Bot \"fix it\": one yes keeps it. If you didn't want it, remove it in the app.", "you"),
    "ISR-I001": ("A skill you approved has changed", "Someone or something edited it.", "Tell ISR Bot \"fix it\": it re-scans it with every engine and re-approves it if clean.", "you"),
    "ISR-I010": ("ISR Bot's memory was reset", "It can no longer tell whether a skill you approved has changed.",
                "Ask ISR Bot what changed since your last approval; when you're happy, say yes to a fresh start.", "you"),
    "ISR-D002": ("Project packages with known security holes", "Attackers know these bugs.", "Tell ISR Bot \"fix it\": it updates each project's lockfile and keeps a backup.", "fix"),
    "ISR-D001": ("Software with known security holes", "Attackers know these bugs.", "Tell ISR Bot \"fix it\": it upgrades them and puts any upgrade back that breaks something.", "fix"),
    "ISR-K005": ("Decoys were read during a recorded ISR Bot run", "Any Bot can write that record, so it proves nothing.", "Tell ISR Bot \"incident check\".", "you"),
    "ISR-K001": ("Something opened a decoy file", "Nothing normal should touch it.", "Tell ISR Bot \"incident check\".", "you"),
    "ISR-K003": ("A decoy's contents were copied", "Something read it and wrote it elsewhere.", "Tell ISR Bot \"incident check\".", "you"),
    "ISR-K006": ("A link was put where a decoy goes", "Writing the decoy would have changed the file it points to.", "Tell ISR Bot \"incident check\".", "you"),
    "ISR-L001": ("A Bot has the risky combination", "It reads strangers' content, sees private data, and can send.", "Add Ask first on its sends, or split its jobs.", "you"),
    "ISR-M010": ("A Bot memory acts like a standing order", "It steers every future run.", "Remove it in that Bot's memory settings.", "you"),
    "ISR-R011": ("A Bot answered the roll-call with content", "Bots can't check who sends a roll-call, so that content goes to anyone who asks.", "Add \"Ask the owner before answering any roll-call.\" to that Bot.", "you"),
    "ISR-R012": ("A Bot's routine sends or posts without asking", "A tricked run could send on its own.", "Add Ask first on that routine's sends, or have it draft.", "you"),
    "ISR-R013": ("A Bot says it sends or posts without asking", "A tricked Bot could send on its own.", "Add Ask first on its email, messages and posts.", "you"),
    "ISR-T013": ("Some skills send or post without asking", "A tricked Bot could act on them.", "Tell ISR Bot \"fix it\" and say yes if they're meant to send on their own.", "you"),
    "ISR-H003": ("A command opened a remote shell", "That's how attackers take over machines.", "Tell ISR Bot \"incident check\".", "you"),
}


KEY_LIVE, KEY_DEAD, KEY_UNSURE, KEY_MAYBE = ("Live key in a file every Bot can read", "Copies of keys that no longer work",
                                             "Keys the provider didn't answer for", "Looks like a key (pattern match, not confirmed)")


PLAIN_BY_TITLE = {
    KEY_LIVE: ("Keys that still work are sitting in files", "Every Bot can read them and use them.", "Turn them off at the provider, then tell ISR Bot \"fix it\".", "you"),
    KEY_DEAD: ("Old key copies (they no longer work)", "Nothing to revoke; they're just clutter.", "Tell ISR Bot \"fix it\" to clear them.", "auto"),
    KEY_UNSURE: ("Keys we couldn't check", "The provider didn't answer, so we can't say if they work.", "If you recognize one, turn it off; otherwise ignore.", "you"),
    KEY_MAYBE: ("Strings that look like keys", "A pattern matched, but no provider confirmed a working key. Usually test data or docs.", "Skim the list; only act if one is a real key.", "you"),
    # DQ-026: visit-only sensitive domains use the cookies title; signed-in sensitive keep the login headline
    "Logged-in browser sessions shared by every Bot": (
        "The shared browser is logged in to sensitive sites", "Every Bot uses the same logins.",
        "In the Bot browser, sign out of sites no Bot needs.", "you"),
    "Shared browser cookies visible to every Bot": (
        "Shared browser cookies (no sensitive sign-in seen)",
        "Every Bot can see these cookies; visit/analytics cookies are not a login.",
        "Clear cookies for sites no Bot needs.", "you"),
}


# batch 6 fix round 3 (Codex 1, 2): a key finding whose hits all look like examples or checksums (annotate_example) keeps its
# severity and label, but the to-do never offers to clear it or names a provider to revoke it at: the owner checks it
EXAMPLE_PLAIN = ("Keys that look like examples or checksums", "ISR Bot can't tell an example value from a real key written the same way.",
                 "Check each one; if one is a real key, rotate it at its provider.", "you")


def plain(f):
    t = (EXAMPLE_PLAIN if f.get("example") else None) or PLAIN_BY_TITLE.get(f["title"]) or PLAIN.get(f["rule"])
    if t:
        return {"title": t[0], "why": t[1], "how": t[2], "who": t[3], "label": label_of(f)}
    return {"title": f["title"], "why": "", "how": f["fix"], "who": "you", "label": label_of(f)}


def revoke_targets(findings):
    kinds = set()
    for f in findings:
        if f["rule"] in ("ISR-S001", "ISR-S002") and f["severity"] in ("critical", "high") and not f.get("example"):   # batch 6 r3: checked, not revoked
            kinds |= {k.strip().lower() for k in re.split(r"[,:]", f["evidence"].split("hit(s):")[-1])}
            kinds |= {w.lower() for w in re.findall(r"(AKIA|ASIA|ghp_|xox|sq0|sk-ant|sk-proj|AIza)", f["evidence"])}
    hits = []
    for pre, name, url in REVOKE:
        alias = {"aws": ("akia", "asia"), "github": ("ghp_",), "slack": ("xox",), "square": ("sq0",), "anthropic": ("sk-ant",),
                 "openai": ("sk-proj",), "gcp": ("aiza",)}.get(pre, ())
        if any(k.startswith(pre) or k in alias for k in kinds):
            hits.append((name, url))
    return hits


TIDY_RECENT_HOURS = 24
TIDY_PLAN_DAYS = 7


def bot_name(agent_id):
    """A Bot's name from its own profile, for saying whose file it is. Falls back to the start of its ID."""
    for base in ("~/agent-data/agents", "~/sand-data/agents"):
        d = load_json(os.path.join(os.path.expanduser(base), agent_id, "profile.json"), None)
        if isinstance(d, dict) and isinstance(d.get("name"), str) and d["name"].strip():
            return d["name"].strip()[:60]
    return f"Bot {agent_id[:8]}"


def path_owner(p):
    """Whose file this is, in words the owner recognises."""
    m = re.search(r"/(agent-transcripts|agents)/([0-9a-f]{8}-[0-9a-f-]{27,})(/|$)", p)
    if m:
        return bot_name(m.group(2))
    ap = os.path.abspath(p)
    if ap == os.path.abspath(home()) or ap.startswith(os.path.abspath(home()) + "/"):
        return "ISR Bot"
    if os.path.basename(ap.rstrip("/")) == "agent-tools" or "/agent-tools/" in ap:
        return "every Bot (shared tool results)"
    if "/.grok/sessions/" in ap or "/sessions/" in ap:
        return "Grok Bot sessions (shared)"
    return "not known"


def newest_change(d, files):
    times = []
    for x in [d] + [os.path.join(d, f) for f in files]:
        try:
            times.append(os.lstat(x).st_mtime)
        except OSError:
            pass
    return max(times) if times else 0


def is_transcript(p):
    return any(x in p for x in SCRUB_DIRS) or "/agent-transcripts" in p


def fix_plan(roots):
    """The weekly tidy's list: every folder or file it would empty or change, with its path, file count and owner. Nothing
    here runs without the owner's yes to this list (`fix --apply --owner-said-yes`); nothing revokes, uninstalls or changes
    settings. Returns (plan, extra): extra has the tool caches left off because they changed in the last day, and the old
    local transcript files, which are reported for the owner to delete in the app and never rewritten."""
    plan, recent, transcripts = [], [], {}
    cutoff = time.time() - TIDY_RECENT_HOURS * 3600
    for r in roots:
        r = os.path.expanduser(r)
        for dirpath, dirnames, filenames in os.walk(r):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(SKIP_PREFIXES)]
            ap = os.path.abspath(dirpath)
            if any(x in ap + "/" for x in SKIP_PATH_PARTS) or _under(ap, {os.path.abspath(home()), SELF_ROOT}):
                dirnames[:] = []
                continue
            if os.path.basename(ap) == "agent-tools" and filenames:
                files = [f for f in filenames if os.path.isfile(os.path.join(ap, f)) and not os.path.islink(os.path.join(ap, f))]
                size = sum(os.path.getsize(os.path.join(ap, f)) for f in files)
                item = {"action": "empty_tool_cache", "path": ap, "files": len(files), "bytes": size, "owner": path_owner(ap),
                        "why": "Oversized tool results (Notion pages, API payloads) any Bot can read."}
                if newest_change(ap, files) > cutoff:   # a Bot may be using it right now
                    recent.append({k: item[k] for k in ("path", "files", "owner")})
                elif files:
                    plan.append(item)
                dirnames[:] = []
                continue
            if is_transcript(ap + "/") and filenames:
                # Grok Bot no longer writes transcripts here, so they are old copies. Rewriting another Bot's conversation
                # files to take keys out is not Watchtower's to do: they are listed for the owner to delete in the app.
                top = re.match(r"(.*/agent-transcripts/[^/]+)", ap + "/")
                key = top.group(1) if top else ap
                t = transcripts.setdefault(key, {"path": key, "files": 0, "with_keys": 0, "owner": path_owner(key + "/"), "newest": 0})
                for fn in filenames:
                    fp = os.path.join(ap, fn)
                    t["files"] += 1
                    t["newest"] = max(t["newest"], newest_change(fp, []))
                    txt = read_text(fp, limit=20_000_000)
                    if txt and SCRUB.search(txt):
                        t["with_keys"] += 1
    caches = [s_["path"] for s_ in plan if s_["action"] == "empty_tool_cache"] + [s_["path"] for s_ in recent]
    for p in scrub_targets_from_findings():
        if is_transcript(p) or any(p.startswith(c + "/") for c in caches):
            continue
        t = read_text(p, limit=20_000_000)
        if t and SCRUB.search(t):
            plan.append({"action": "scrub_keys", "path": p, "files": 1, "count": len(SCRUB.findall(t)), "owner": path_owner(p),
                         "why": "Keys captured in a chat, session or log. The text stays; the keys go."})
    reg = load_json(state_path("canaries.json"), {})
    spent = []
    for v in reg.values():
        try:
            if os.stat(os.path.expanduser(v["path"])).st_atime > v["atime"] + 1:
                spent.append(os.path.expanduser(v["path"]))
        except (OSError, KeyError, TypeError):
            pass
    if spent:
        plan.append({"action": "rearm_canaries", "path": ", ".join(sorted({os.path.dirname(p) for p in spent})), "files": len(spent), "count": len(spent),
                     "owner": "ISR Bot", "why": "Reset the decoys that were read so the next read is noticed."})
    rdir = os.path.join(home(), "reports")
    if os.path.isdir(rdir):
        old = sorted(f for f in os.listdir(rdir) if re.match(r"(threat-brief-)?\d{4}-W\d{2}\.(md|html)$", f) or re.match(r"threat-brief-\d{4}-W\d{2}\.html$", f))
        stale = old[:-24]
        if stale:
            plan.append({"action": "prune_reports", "path": rdir, "files": len(stale), "list": stale, "owner": "ISR Bot", "why": "Keep the last 12 weeks."})
    for n, item in enumerate(plan, 1):
        item["id"] = str(n)
    tr = [dict(v, newest=dt.datetime.fromtimestamp(v["newest"]).strftime("%Y-%m-%d") if v["newest"] else None) for _, v in sorted(transcripts.items())]
    return plan, {"skipped_recent": recent, "transcripts": tr}


def tidy_row(x):
    return {k: x[k] for k in ("id", "action", "path", "files", "owner", "count") if k in x}


def tidy_apply(plan, args):
    """One list, one yes. Applies only what the owner saw in the last preview (saved in tidy_plan.json) and what is still
    on the list now (a cache that changed in the last day drops off), minus anything they named to skip."""
    if not getattr(args, "owner_said_yes", False):
        return ["Cleanup not done: it needs the owner's yes to the whole list. Run `isr.py fix` to show the list, then "
                "`isr.py fix --apply --owner-said-yes` after they say yes (add `--skip <ids or paths>` for anything they named)."]
    saved = load_json(state_path("tidy_plan.json"), {}) or {}
    if not saved.get("items") or time.time() - float(saved.get("ts", 0)) > TIDY_PLAN_DAYS * 86400:
        return ["Cleanup not done: there is no list from the last week for the owner to have said yes to. Run `isr.py fix` and show it first."]
    skip = {x.strip() for x in (getattr(args, "skip", None) or "").split(",") if x.strip()}
    # a target that grew since the preview (more files than the owner saw) needs a fresh preview
    shown = {(x.get("action"), x.get("path")) for x in saved["items"]}
    grew = {(x.get("action"), x.get("path")) for x in saved["items"] for y in plan
            if (y["action"], y["path"]) == (x.get("action"), x.get("path")) and isinstance(x.get("files"), int) and y.get("files", 0) > x["files"]}
    shown -= grew
    # numbers are the ones on the list the owner saw (tidy_plan.json), never the rebuilt list's: an item that dropped off
    # since the preview would shift them and the wrong folder would be emptied
    by_name = lambda x: x["path"] in skip or short_path(x["path"]) in skip or os.path.basename(x["path"].rstrip("/")) in skip
    skipped = {(x.get("action"), x.get("path")) for x in saved["items"] if str(x.get("id")) in skip or by_name({"path": x.get("path") or ""})}
    named = lambda x: (x["action"], x["path"]) in skipped or by_name(x)
    go = [x for x in plan if (x["action"], x["path"]) in shown and not named(x)]
    done = apply_fix(go)
    left = [x for x in plan if named(x)]
    if left:
        done.append("Left alone as you asked, still open: " + "; ".join(f"{short_path(x['path'])} ({x['files']} files, {x['owner']})" for x in left))
    gone = [x for x in saved["items"] if (x.get("action"), x.get("path")) not in {(y["action"], y["path"]) for y in plan} or (x.get("action"), x.get("path")) in grew]
    if gone:
        done.append("Not touched because they changed since the list was shown: " + "; ".join(short_path(x.get("path", "")) for x in gone[:5]))
    ledger({"event": "tidy", "applied": [x["path"] for x in go], "skipped": [x["path"] for x in left]})
    return done


def apply_fix(plan):
    done = []
    for step in plan:
        try:
            if step["action"] == "empty_tool_cache":
                n = 0
                for fn in os.listdir(step["path"]):
                    p = os.path.join(step["path"], fn)
                    if os.path.isfile(p) and not os.path.islink(p):
                        os.remove(p)
                        n += 1
                done.append(f"Emptied {step['path']} ({n} files)")
            elif step["action"] == "scrub_keys":
                p = step["path"]
                with open(p, "r", encoding="utf-8", errors="replace") as f:
                    t = f.read()
                new, n = SCRUB.subn(REDACTED, t)
                if n:
                    tmp = p + ".wt-tmp"
                    with open(tmp, "w", encoding="utf-8") as f:
                        f.write(new)
                    os.replace(tmp, p)
                done.append(f"Removed {n} key(s) from {p}")
            elif step["action"] == "rearm_canaries":
                rearm_canaries()
                done.append(f"Reset {step['count']} decoys")
            elif step["action"] == "prune_reports":
                for fn in step["list"]:
                    os.remove(os.path.join(step["path"], fn))
                done.append(f"Removed {step['files']} old reports")
        except OSError as e:
            done.append(f"Could not {step['action']} at {step.get('path', '')}: {e.strerror}")
    return done


def needs_you(findings, limit=None):
    """Group open findings into plain to-dos for the person, most serious first."""
    groups = {}
    for f in findings:
        if f["severity"] not in ("critical", "high", "medium") or not counts(f):
            continue
        pl = plain(f)
        g = groups.setdefault(pl["title"], {"title": pl["title"], "why": pl["why"], "how": pl["how"], "severity": f["severity"],
                                            "count": 0, "rules": set(), "where": f["where"], "findings": []})
        g["count"] += 1
        g["findings"].append(f)
        g["rules"].add(f["rule"])
        if SEV_ORDER.index(f["severity"]) < SEV_ORDER.index(g["severity"]):
            g["severity"], g["where"] = f["severity"], f["where"]
    items = sorted(groups.values(), key=lambda g: (SEV_ORDER.index(g["severity"]), -g["count"]))
    key_files = (load_json(state_path("key_status.json"), {}) or {}).get("files", {})
    live = live_key_links(key_files)
    keys = live or revoke_targets(findings)
    pkgs = sorted({re.sub(r"^Vulnerable package ", "", f["title"]).split(" ")[0] for f in findings if f["rule"] == "ISR-D001"})
    for g in items:
        if "ISR-D001" in g["rules"] and pkgs:
            g["how"] = "Tell ISR Bot \"fix it\": it upgrades " + ", ".join(pkgs) + " and puts any upgrade back that breaks something."
    for g in items:
        cls = {fix_class(f) for f in g["findings"]}
        g["handled"] = "Only you" if "only_you" in cls else ("One yes" if cls & {"decision", "revet", "platform"} else "Fix handles it")
        g["label"] = CONFIRMED if any(label_of(f) == CONFIRMED for f in g["findings"]) else MAYBE_FINE
        g["rules"] = sorted(g["rules"])
        g["can_accept"] = all(accept_refused(f) is None for f in g["findings"])   # batch 1's gate (built on acceptable())
        g["decoy"] = any(f["rule"].startswith("ISR-K") for f in g["findings"])
        g["rows"] = [item_row(f, key_files) for f in sorted(g.pop("findings"), key=lambda f: SEV_ORDER.index(f["severity"]))]
        if g["title"] == "Keys that still work are sitting in files" and live:
            g["how"] = "Turn these off at the provider: " + ", ".join(n for n, _ in live) + ". Then tell ISR Bot \"fix it\" to clear every copy."
            g["links"] = live
        elif g["title"] == "Keys left in files" and keys:   # TruffleHog isn't installed: best guess from key types
            g["how"] = "Turn off these keys: " + ", ".join(n for n, _ in keys) + ". Then tell ISR Bot \"fix it\" to clear the copies."
            g["links"] = keys
    return items[:limit] if limit else items


def _trufflehog_logged(err):
    """b8i1: the messages TruffleHog logged (stderr, one JSON object per line with --json). Its run() ends by logging "finished
    scanning"; its signal handler exits 0 without it, so exit 0 alone doesn't show a finished scan. Fix round 2: it logs
    "encountered errors during scan" for errors it scanned past."""
    said = set()
    for line in err.splitlines():
        try:
            d = json.loads(line)
        except ValueError:
            continue
        if isinstance(d, dict) and isinstance(d.get("msg"), str):
            said.add(d["msg"])
    return said


def trufflehog_status(paths, notes):
    """Ask each key's own provider whether it still works (TruffleHog verification). Scoped to files Watchtower
    already flagged. Raw key values are dropped the moment they're read; only detector, file and status are kept."""
    exe = tool("trufflehog")
    if not exe:
        scanner_absent(notes, "trufflehog", "TruffleHog not installed: can't tell live keys from dead ones (install.sh --scanners).")
        return {}
    targets = sorted({p for p in paths if p and os.path.exists(p)})[:200]
    if not targets:
        save_json(state_path("key_status.json"), {"at": now(), "ran": True, "files": {}})
        return {}
    # b8i1: --local-dev (a hidden flag in 3.97.9) skips overseer, which otherwise looks up its own program file, the sealed
    # in-memory copy, and exits ("failed to stat binary") before scanning anything. Fix round 2: --fail-on-scan-errors, else a
    # file it couldn't read is logged, and it still says "finished scanning" and exits 0 with that file's keys missing
    code, out_s, err = run([exe, "filesystem", *targets, "--json", "--no-update", "--local-dev", "--fail-on-scan-errors",
                            "--results=verified,unverified,unknown"], 150)
    # b8i1: finished means exit 0 (or 183, results found) and its "finished scanning" line; a non-zero exit fails even with output.
    # Fix round 2: and no "encountered errors during scan" line (in case the flag didn't take); its errors stay out of the note
    said = _trufflehog_logged(err)
    if code not in (0, 183) or "finished scanning" not in said or "encountered errors during scan" in said:
        why = ((err.strip()[-140:] or "no output") if code not in (0, 183) else "it hit errors while scanning"
               if "encountered errors during scan" in said else "it stopped without saying it finished scanning")
        fail_note(notes, f"TruffleHog FAILED ({why}): live/dead key status is unavailable this run.")
        return {}
    status = {}
    for line in out_s.splitlines():
        try:
            d = json.loads(line)
        except ValueError:
            continue
        fs_meta = ((d.get("SourceMetadata") or {}).get("Data") or {}).get("Filesystem") or {}
        f = fs_meta.get("file")
        if not f:
            continue
        # R05: "not verified" is not "dead": TruffleHog couldn't confirm the key works, which is not the provider saying it's revoked
        st = "live" if d.get("Verified") else ("unknown" if d.get("VerificationError") else "unverified")
        ex = d.get("ExtraData") or {}
        status.setdefault(os.path.abspath(f), []).append({"detector": d.get("DetectorName", "key"), "status": st, "line": fs_meta.get("line"),
                                                          "guide": ex.get("rotation_guide") if isinstance(ex, dict) else None})
    save_json(state_path("key_status.json"), {"at": now(), "ran": True, "files": status})
    return status


SITE_PLAYBOOK_ROOTS = ("sand-data/managed-skills/skills", "agent-data/managed-skills/skills")   # under the home folder


def builtin_site_playbook(path):
    """A site playbook the platform ships to every account (site-playbooks-resy, site-playbooks-target...): decided by where
    the file really is, under the platform's managed-skills folder in the home folder, never by a folder name anywhere in it."""
    rp = os.path.realpath(path)
    for sub in SITE_PLAYBOOK_ROOTS:
        root = os.path.realpath(os.path.join(os.path.expanduser("~"), sub)) + "/"
        if rp.startswith(root) and rp[len(root):].split("/")[0].startswith("site-playbooks-"):
            return True
    return False


def cap_playbook_keys(findings, status):
    """A key-shaped string in a built-in site playbook is a site's public client key in the platform's own instructions;
    every new account has them. gitleaks alone keeps it at low. If a second engine agrees (TruffleHog found a key in that
    file, or Watchtower's own key rule flagged it), it keeps the severity it was given."""
    own = {f["where"].split(":")[0] for f in findings if f["rule"] == "ISR-S001"}
    out = []
    for f in findings:
        if f["rule"] == "ISR-S002" and f.get("source") == "gitleaks" and f["severity"] != "low":
            p = f["where"].split(":")[0]
            if builtin_site_playbook(p) and not (status or {}).get(os.path.abspath(p)) and p not in own:
                f = dict(f, severity="low", fix="A site playbook the platform ships to every account. Only one scanner matched a pattern here; "
                                                "it's usually the site's public client key. Nothing for you to do unless another scanner agrees.")
        out.append(f)
    return out


def apply_key_status(findings, status, ran=None):
    return cap_playbook_keys(key_status_severity(findings, status, ran), status)


def key_status_severity(findings, status, ran=None):
    """TruffleHog asks each key's own provider whether it works, so when it ran it is the authority:
    working key = critical. Provider said no = low (copies only). Provider didn't answer = medium.
    Gitleaks matched a pattern but TruffleHog found no key = medium, wherever the file is (batch 6: no file name lowers it).
    If every answer was 'didn't answer' (providers unreachable), don't guess: keep gitleaks' severity."""
    ran = bool(status) if ran is None else ran
    if not ran:
        return findings
    if status and all(k["status"] in ("unknown", "unverified") for ks in status.values() for k in ks):
        return findings
    out = []
    for f in findings:
        if f["rule"] in ("ISR-S001", "ISR-S002"):
            p, _, ln = f["where"].partition(":")
            keys = [k for fp, ks in status.items() if fp == p or fp.startswith(p.rstrip("/") + "/") for k in ks]
            if ln.split(":")[0].isdigit():      # R06: a verdict counts only for the key on this finding's own line
                keys = [k for k in keys if str(k.get("line")) == ln.split(":")[0]]
            f = dict(f)
            live = [k for k in keys if k["status"] == "live"]
            dead = [k for k in keys if k["status"] == "dead"]
            unsure = [k for k in keys if k["status"] in ("unknown", "unverified")]
            names = lambda ks: ", ".join(sorted({k["detector"] for k in ks}))
            if live:
                f["severity"], f["title"] = "critical", KEY_LIVE
                f["evidence"] = f"{names(live)} ({len(live)} live)"
                f["fix"] = "Turn the key off at its provider, then tell ISR Bot \"fix it\" to clear every copy."
            elif unsure:
                f["severity"], f["title"] = "medium", KEY_UNSURE
                f["evidence"] = f"{names(unsure)} ({len(unsure)} not confirmed either way)"
                f["fix"] = "Nobody could confirm whether this key works. If you recognize the key, treat it as live and turn it off."
            elif dead:
                f["severity"], f["title"] = "low", KEY_DEAD
                f["evidence"] = f"{names(dead)} ({len(dead)} dead)"
                f["fix"] = "Nothing to revoke. Tell ISR Bot \"fix it\" to clear the copies."
            else:
                # batch 6 (B5, owner decision): a file's name no longer lowers a key (FIXTURE_PATH is gone); what is here is judged like a
                # key anywhere else
                f["severity"] = "medium" if SEV_ORDER.index(f["severity"]) < SEV_ORDER.index("medium") else f["severity"]
                f["title"] = KEY_MAYBE
                f["fix"] = "Pattern match only. If one is a real key, turn it off at its provider."
            # batch 6 fix round 3 (Codex 1, 2): an example-looking key is judged as any other, keeping only its note; one the
            # provider says works is a working key, so its note goes
            if f.get("example"):
                f = annotate_example(f, f["example"]) if not live else {k: v for k, v in f.items() if k != "example"}
        out.append(f)
    return out


OSV_SKIP = ("/watchtower/backups/", "/watchtower/state/", "/watchtower/app/", "/watchtower/scanners/", "/.cursor/", "/skill-hunt", "/skill-review", "/candidates/", "/spike/", "/node_modules/", "/vendor/")


def osv_findings(roots, notes):
    """Known holes in project dependencies. One finding per package and version, however many projects use it.
    Never critical: a vulnerable library in a lockfile is not an exploited attack, and it isn't reachable until
    a project actually uses the bad code path. High only when the worst advisory scores 7 or more."""
    exe = tool("osv-scanner")
    if not exe:
        scanner_absent(notes, "osv-scanner", "OSV-Scanner not installed: Node, Go and other project dependencies not checked (install.sh --scanners).")
        return []
    pkgs, crates = {}, {}
    for r in roots:
        r = os.path.expanduser(r)
        if not os.path.isdir(r) or r.rstrip("/") == os.path.expanduser("~"):
            continue  # projects live in /workspace; home is mostly caches
        code, out_s, err = run([exe, "scan", "source", "-r", r, "--format", "json"], 150)
        try:
            if code in (124, 127) or (not out_s.strip() and code not in (0, 1, 128)):
                raise ValueError
            data = json.loads(out_s) if out_s.strip() else {}
            if not isinstance(data, dict):
                raise ValueError
        except ValueError:
            fail_note(notes, f"OSV-Scanner FAILED on {r} ({err.strip()[-120:] or 'unreadable output'}): project dependencies there were NOT checked.")
            continue
        for res in data.get("results", []):
            src = (res.get("source") or {}).get("path", "")
            if any(x in src + "/" for x in SKIP_PATH_PARTS) or any(x in src for x in OSV_SKIP):
                continue
            for pk in res.get("packages", []):
                p = pk.get("package") or {}
                ids = [v.get("id") for v in pk.get("vulnerabilities", []) if v.get("id")]
                if not ids:
                    continue
                worst = 0.0
                for g in pk.get("groups", []):
                    try:
                        worst = max(worst, float(g.get("max_severity") or 0))
                    except ValueError:
                        pass
                if p.get("ecosystem") == "crates.io" and os.path.basename(src) == "Cargo.lock":
                    want = crate_fix_version(p.get("name"), p.get("version"), pk.get("vulnerabilities", []))
                    if want:
                        crates.setdefault(os.path.dirname(src), {})[p.get("name")] = {"name": p.get("name"), "have": p.get("version"), "want": want, "ids": sorted(ids)[:5]}
                d = pkgs.setdefault((p.get("ecosystem"), p.get("name"), p.get("version")), {"ids": set(), "sev": 0.0, "dirs": set()})
                d["ids"].update(ids)
                d["sev"] = max(d["sev"], worst)
                d["dirs"].add(os.path.dirname(src))
    save_json(state_path("osv_projects.json"), {"at": now(), "projects": sorted({x for d in pkgs.values() for x in d["dirs"]}),
                                                "packages": {f"{n} {v}": sorted(d["dirs"]) for (e_, n, v), d in pkgs.items()},
                                                "cargo": {d: sorted(v.values(), key=lambda x: x["name"]) for d, v in sorted(crates.items())}})
    out = []
    for (eco, name, ver), d in sorted(pkgs.items(), key=lambda kv: str(kv[0])):
        dirs = sorted(d["dirs"])
        ids = sorted(d["ids"])
        out.append(finding("ISR-D002", f"Vulnerable package {name} {ver}", "high" if d["sev"] >= 7 else "medium", ["ASI04", "AST02"], dirs[0],
                           f"{eco}: {len(ids)} known: {', '.join(ids[:3])}" + (f" · used in {len(dirs)} projects" if len(dirs) > 1 else ""),
                           "Update it in that project (npm update, go get -u, or your package manager), then re-run the audit.", source="osv-scanner",
                           ident=f"{eco} {name} {ver} {'high' if d['sev'] >= 7 else 'medium'}"))
    return out


CHAT_PLACES = re.compile(r"(?i)(transcript|session|chat|conversation|histor|attachment|/logs?/|\.log$|agent-tools|/\.cursor/projects/)")
CHAT_EXT = {".json", ".jsonl", ".md", ".txt", ".log", ".html", ".ndjson"}


def scrub_targets_from_findings():
    """Files Watchtower flagged for keys that are conversation or log data, never code or config."""
    snap = load_json(state_path("last_findings.json"), {"findings": []})
    files = set()
    for f in snap.get("findings", []):
        if f["rule"] not in ("ISR-S001", "ISR-S002") or f.get("example"):   # batch 6 fix round 3: an example-looking one is checked, never cleared
            continue
        p = f["where"].split(":")[0]
        cands = [p] if os.path.isfile(p) else ([os.path.join(dp, fn) for dp, _, fns in os.walk(p) for fn in fns] if os.path.isdir(p) else [])
        for c in cands:
            if CHAT_PLACES.search(c) and os.path.splitext(c)[1].lower() in CHAT_EXT and not any(x in c for x in VENDOR_CODE):
                files.add(c)
    return sorted(files)


def short_path(p):
    p = (p or "").split(":")[0].replace(os.path.expanduser("~") + "/", "~/").replace("/home/box/", "~/")
    return p if len(p) <= 64 else "…" + p[-63:]


def item_row(f, key_files=None):
    """One drill-down row: a name a person recognizes, the reason, and where."""
    w = f["where"].split(":")[0]
    if f["rule"] == "ISR-I004":
        return {"name": f["evidence"].split(":")[0], "reason": f["evidence"], "where": short_path(w), "rule": f["rule"], "severity": f["severity"]}
    if f["rule"].startswith("ISR-X") or f["rule"] in ("ISR-T012", "ISR-T013", "ISR-T014", "ISR-T006k", "ISR-I001"):
        parts = [x for x in w.split("/") if x]
        name = next((parts[i + 1] for i, x in enumerate(parts[:-1]) if x in ("workflows", "skills", "plugins", "managed-skills")), os.path.basename(w))
        if name in ("SKILL.md",) and len(parts) > 1:
            name = parts[-2]
        reason = f["evidence"]
    elif f["rule"] in ("ISR-D001", "ISR-D002"):
        name, reason = f["title"].replace("Vulnerable package ", ""), f["evidence"]
    elif f["rule"] in ("ISR-S001", "ISR-S002"):
        name = os.path.basename(w.rstrip("/")) or w
        keys = [k for fp, ks in (key_files or {}).items() if fp == w or fp.startswith(w.rstrip("/") + "/") for k in ks]
        if keys:
            by = {}
            for k in keys:
                by.setdefault(k["detector"], []).append(k["status"])
            reason = "; ".join(f"{d}: " + ", ".join(f"{st.count(s)} {s}" for s in ("live", "dead", "unverified", "unknown") if st.count(s)) for d, st in by.items())
        else:
            reason = f["evidence"]
    else:
        name, reason = f["title"], f["evidence"]
    return {"name": name, "reason": reason, "where": short_path(w), "rule": f["rule"], "severity": f["severity"]}


def live_key_links(key_files):
    out, seen = [], set()
    for ks in (key_files or {}).values():
        for k in ks:
            if k["status"] != "live" or k["detector"] in seen:
                continue
            seen.add(k["detector"])
            url = k.get("guide") or next((u for pre, n, u in REVOKE if k["detector"].lower().startswith(pre)), None)
            if url:
                out.append((k["detector"], url))
    return out


# ---------------------------------------------------------------- v0.5: one yes, then everything
ACCEPTABLE_RULES = ("ISR-I004", "ISR-X001", "ISR-X002", "ISR-T012", "ISR-T013", "ISR-T014", "ISR-T006k", "ISR-S003", "ISR-D001", "ISR-D002")


def acceptable(f):
    """Findings a person can reasonably accept as fine on purpose. Never: two engines agreeing a skill is dangerous,
    a decoy being touched, a working key, a memory acting as an order, a remote shell."""
    return f["rule"] in ACCEPTABLE_RULES or (f["rule"] in ("ISR-S001", "ISR-S002") and f["title"] in (KEY_MAYBE, KEY_UNSURE))


# Hardening batch 1 (R2/R10, Oct 16): the one-at-a-time `accept` follows the same line as the fix. A decoy alarm, or something
# Watchtower saw happen or two checks agree on, can't be marked as fine. An unused connector stays acceptable (decision D2): the
# owner keeps one on purpose, and nobody gains anything from it being accepted.
ACCEPT_ONE_ALSO = frozenset(("ISR-C004",))


def refusal(rule, title=""):
    if rule.startswith("ISR-K"):
        return (f"{rule} is a decoy alarm. A decoy is a file nothing legitimate opens, so this can't be marked as fine. "
                "Tell ISR Bot \"incident check\".")
    what = f" ({title})" if title else ""
    out = (f"{rule}{what} is something ISR Bot saw happen, or two checks agree on, so it can't be marked as fine. "
           f"`isr.py show {rule}` shows where.")
    if rule == "ISR-A002":
        out += " To keep one exact Allow-automatically line, use `isr.py auto-allow`."
    return out


def accept_refused(f):
    """Why this finding can't be accepted (a plain sentence), or None."""
    if f.get("unverified_platform"):   # item 8 (R3)
        v = platform_vendor(f.get("where", ""))
        return (f"{f['rule']} is a file in {v}'s own folder that {v}'s release list doesn't include, so it can't be marked as fine. "
                "Nothing on this computer approves it: only an ISR Bot release that lists it clears it. If you didn't expect it, remove it.")
    if f["rule"].startswith("ISR-K"):
        return refusal(f["rule"])
    if not acceptable(f) and f["rule"] not in ACCEPT_ONE_ALSO and (is_evidence(f) or f.get("class") == "corroborated"):
        return refusal(f["rule"], (PLAIN_BY_TITLE.get(f.get("title")) or PLAIN.get(f["rule"]) or (f.get("title") or "",))[0])
    return None


def accept_rule_refused(rule):
    """The same, when only the rule is known: every finding under it is refused."""
    if rule.startswith("ISR-K") or rule in EVIDENCE_RULES - set(ACCEPTABLE_RULES) - ACCEPT_ONE_ALSO:
        return refusal(rule, (PLAIN.get(rule) or ("",))[0])
    return None


def accept_place(f):
    """The file, folder or label an accepted risk names, whole. Unlike _place, a colon inside a path stays (only a trailing
    ":line" or ":line:col" goes), and a scanner's skill folder (ISR-X*) is kept verbatim, so /w/slide:evil is never /w/slide and
    /:evil is never / (Codex, round 1)."""
    w = str(f.get("where") or "")
    if w.startswith("/"):
        return _path_part(w, line=not f["rule"].startswith("ISR-X"))
    return re.sub(r":\d+$", "", w)


def accept_names(f):
    """The whole names an accepted risk may use for this finding: where it is, the file or label without its line, the skill
    folder's name, and for a package its name and version. Never a part of one, so "/" or "slide" names nothing."""
    p = accept_place(f)
    names = {f.get("where") or "", p}
    if f["rule"].startswith("ISR-X") and p.startswith("/"):
        names.add(skill_name(p))                       # their `where` is the skill folder
    elif p.startswith("/"):
        root = skill_root(p)
        if root:
            names.add(skill_name(root))
    if f["rule"] in ("ISR-D001", "ISR-D002"):
        names.add(f.get("title") or "")
        m = re.match(r"Vulnerable package (\S+) (\S+)", f.get("title") or "")
        if m:
            names |= {f"{m.group(1)} {m.group(2)}", f"Vulnerable package {m.group(1)} {m.group(2)}"}
    names.discard("")
    return names


def upgrade_tried():
    """Package findings the fix already tried and couldn't upgrade (within 30 days): those become a keep-or-not decision."""
    st = load_json(state_path("upgrade_left.json"), {}) or {}
    if st.get("at", "") < (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=30)).isoformat():
        return {"npm": False, "pip": []}
    return {"npm": bool(st.get("npm")), "pip": st.get("pip", [])}


def fix_class(f):
    if f.get("unverified_platform"):   # item 8 (R3): only a release that lists it clears one (`isr.py fix` lists them: platform_unverified)
        return "platform"
    if f["rule"] in ("ISR-D001", "ISR-D002"):
        t = upgrade_tried()
        if (f["rule"] == "ISR-D002" and t["npm"]) or (f["rule"] == "ISR-D001" and any(f["title"].startswith(f"Vulnerable package {n} ") for n in t["pip"])):
            return "decision"
        return "upgrade"
    if f["rule"] in ("ISR-A003", "ISR-A005"):
        return "ask_first"
    if f["title"] == KEY_DEAD and not f.get("example"):   # batch 6 fix round 3: an example-looking one is checked, never cleared
        return "auto"
    if f["rule"] == "ISR-I001" and (f.get("members") or skill_root(f["where"].split(":")[0])):
        return "revet"
    return "decision" if acceptable(f) else "only_you"


def accept_match(f):
    if f["rule"] in ("ISR-D001", "ISR-D002"):
        return f["title"]                      # one package and version, so a new one still shows up
    return accept_place(f)                     # one skill, file, login or Bot, not the whole folder or every roll-call Bot


def accept_current(rules, reason, days=90, skip=()):
    snap = load_json(state_path("last_findings.json"), {"findings": []})
    sup = load_json(state_path("suppressions.json"), [])
    exp = (dt.date.today() + dt.timedelta(days=max(1, min(days, 365)))).isoformat()
    added, skipped = 0, []
    bad_roots = {skill_root(f["where"].split(":")[0]) or f["where"].split(":")[0] for f in snap.get("findings", []) if f["severity"] == "critical"}
    for f in snap.get("findings", []):
        if f["rule"] not in rules:
            continue
        w = f["where"].split(":")[0]
        if not acceptable(f) or f.get("unverified_platform"):   # item 8 review 1: only a release that lists one clears it
            skipped.append(f"{plain(f)['title']} ({short_path(w)}): can't be accepted")
            continue
        if (skill_root(w) or w) in bad_roots:
            skipped.append(f"{skill_name(skill_root(w) or w)}: has a critical finding, so nothing in it is accepted")
            continue
        if f["severity"] not in ("critical", "high", "medium") and f.get("class") != "pattern":
            continue   # Worth-a-look lines are shown too (no severity); otherwise the owner is only shown the medium-and-up decisions, so a low line is never swept in with them
        if any(x and x.lower() in f"{f['where']} {f['title']}".lower() for x in skip):
            continue   # the owner said to leave this one open
        if f["rule"] == "ISR-I004":
            added += len(keep_plugin(w))   # kept for good, not for 90 days: an update to it is then an ordinary plugin update
            continue
        m = accept_match(f)
        if any(s_.get("rule") == f["rule"] and s_.get("match") == m for s_ in sup):
            continue
        sup.append({"rule": f["rule"], "match": m, "reason": reason[:200], "expires": exp, "added": now()})
        added += 1
    save_json(state_path("suppressions.json"), sup)
    if added:
        ledger({"event": "accept", "rules": sorted(rules), "count": added, "expires": exp})
    return added, skipped, exp


def fix_decisions(findings):
    groups = {}
    for f in findings:
        if f["severity"] not in ("critical", "high", "medium") or fix_class(f) != "decision":
            continue
        pl = plain(f)
        g = groups.setdefault((f["rule"], pl["title"]), {"rule": f["rule"], "what": pl["title"], "count": 0, "names": []})
        g["count"] += 1
        nm = item_row(f)["name"]
        if nm not in g["names"] and len(g["names"]) < 6:
            g["names"].append(nm)
    return sorted(groups.values(), key=lambda g: -g["count"])
