# Part of wt.py: runs inside wt.py's namespace (loaded by _wt_part); not a module on its own.
SCORE_ERA = "s5"   # bump when the formula changes; older history is then hidden instead of compared
SCORE_BASE = {"critical": 12, "high": 5, "medium": 1.5, "low": 0.3}   # per kind of risk
SCORE_CAP = {"critical": 50, "high": 25, "medium": 12, "low": 3}      # per severity tier


# v0.6.8: a false alarm is never scary. "Evidence" rules report a fact Watchtower saw (a decoy was read, an approved skill
# changed, a provider said a key works, two engines agree, a setting is on). "Pattern" rules match wording or a key-shaped
# string, or are one engine alone: often right, sometimes fine. A pattern finding is at most medium unless something backs it up.
EVIDENCE_RULES = frozenset((
    "ISR-A001", "ISR-A002", "ISR-A003", "ISR-A004", "ISR-A005", "ISR-C001", "ISR-C003", "ISR-C004", "ISR-C005",
    "ISR-D001", "ISR-D002", "ISR-I001", "ISR-I002", "ISR-I003", "ISR-I004", "ISR-I005", "ISR-I006", "ISR-I010", "ISR-I011",
    # Shell history: commands that actually ran on this computer, not wording (decision, 2026-10-10). H007 is a file-mode fact.
    "ISR-H001", "ISR-H002", "ISR-H003", "ISR-H004", "ISR-H005", "ISR-H006", "ISR-H007", "ISR-H008", "ISR-H009",
    "ISR-K001", "ISR-K002", "ISR-K003", "ISR-K004", "ISR-K005", "ISR-K006", "ISR-M001", "ISR-P001", "ISR-R010",
    "ISR-S003", "ISR-S004", "ISR-S005", "ISR-W001", "ISR-W002", "ISR-X003", "ISR-X004",
    "ISR-X005"))   # batch 3 (R7): Watchtower's copy of a scanner isn't the one it installed
HISTORY_SHRANK = "Shell history shrank since last check"
NEW_SIGN_IN = "New sign-in in the shared browser"
CONFIRMED, MAYBE_FINE = "Confirmed", "Worth a look (might be fine)"
# v0.6.8 (decision, Oct 10, after Cloudflare's MIT-licensed security-audit skill): a "Worth a look" finding carries no severity and
# never moves the score; best-practice checks are Tips, also without severity or score.
TIP_RULES = frozenset(("ISR-R002", "ISR-R003"))   # pattern-class best practice only; no evidence rule is moved
SCOPE_RULES = frozenset(("ISR-I007", "ISR-I008"))   # v0.7.1 items 1 and 6: "Not scanned" and "Platform refresh" summaries are tips
TIP = "Tip"
# Batch 6 (B3, decision 8): a setting that is already safe, said as a Tip (no severity, never scored, never new). ISR-C002
# ("Ask every time" for running commands on this computer) left EVIDENCE_RULES for it; "Always allow" (ISR-C001) stays critical.
SETTING_TIPS = frozenset(("ISR-C002",))
VERB_AREA = (("sending email or messages", r"(?i)^(send|sends|sending|email|emails|message|messages|reply|replies|dm)$"),
             ("publishing or posting", r"(?i)^(post|posts|publish|publishes|tweet|tweets)$"),
             ("purchases or payments", r"(?i)^(buy|buys|pay|pays|purchase|purchases|transfer|transfers|submit|submits)$"),
             ("deleting data", r"(?i)^(delete|deletes|remove|removes)$"))


def is_evidence(f):
    """A key TruffleHog's provider check says works is a fact, whatever rule found the string."""
    if f["rule"] == "ISR-S005":
        return f.get("title") == NEW_SIGN_IN   # proven by a session cookie; new cookies alone are worth a look
    return f["rule"] in EVIDENCE_RULES or (f["rule"] in ("ISR-S001", "ISR-S002") and f.get("title") == KEY_LIVE)


def _place(f):
    """The file or folder a finding is about. A path loses its ":line"; a label like "rollcall:Bot:routine:name:1" keeps
    everything but the line, so two different Bots or routines are never the same place."""
    w = f.get("where") or ""
    if w.startswith("/"):   # Codex, batch 4 round 1: only a trailing :line (or :+line) goes; /review/skill:v1/ is a folder name
        # Round 2: exactly one, and only from a finding that has one. /fake/script:1:1 is line 1 of a file called "script:1",
        # never the same place as /fake/script:1; a folder verdict or a fact about a whole file names its place as it is.
        r = f.get("rule") or ""
        if r.startswith(PLACE_WHOLE) or r in PLACE_WHOLE_RULES or f.get("source") in ("engines", "skillspector", "husk"):
            return os.path.normpath(w)
        return os.path.normpath(re.sub(r":\+?\d+$", "", w))
    return re.sub(r":\d+$", "", w)


PLACE_WHOLE = ("ISR-X", "ISR-I", "ISR-D", "ISR-K")   # where is a folder or a whole file: no line to take off
PLACE_WHOLE_RULES = frozenset(("ISR-S003", "ISR-S004", "ISR-S005", "ISR-T001r", "ISR-R002", "ISR-R003", "ISR-H006", "ISR-P001"))


def _corrob_sig(g):
    """Everything corroborated() reads about a finding. Findings that share it give the same answer (Codex, batch 4 round 2)."""
    return (g["rule"], g.get("title") if g["rule"] in ("ISR-S001", "ISR-S002", "ISR-S005") else None, _place(g),
            g.get("source", "watchtower"), g["severity"], g.get("severity_was"), bool(g.get("guarded")), tuple(sorted(g.get("kinds") or ())))


def _covers(a, b):
    return bool(a) and bool(b) and (a == b or b.startswith(a.rstrip("/") + "/") or a.startswith(b.rstrip("/") + "/"))


def _skill_of(f):
    p = _place(f)
    return (skill_root(p) if p.startswith("/") and os.path.exists(p) else None) or p


NO_OPINION = frozenset(("ISR-X004", "ISR-R010"))   # "couldn't finish" / "didn't parse": facts about the run, not the content

# v0.7.1 precision item 2 (decision, Oct 12): Confirmed means dangerous and reachable. Two votes count only when they are about the
# same file and the same kind of risk; a wording hit alone is never Confirmed, it needs a behavior signal in the same file.
RISK_KIND = {"ISR-T004": "credential", "ISR-T011": "credential", "ISR-T011x": "credential", "ISR-S001": "credential", "ISR-S002": "credential", "ISR-K003": "credential",
             "ISR-T005": "exfil", "ISR-T017": "exfil", "ISR-T006": "pipe", "ISR-T006k": "pipe", "ISR-T002": "obfuscation",
             "ISR-T003": "obfuscation", "ISR-T012": "exec", "ISR-T008": "secrecy", "ISR-T016": "secrecy", "ISR-T001": "override",
             "ISR-T007": "override", "ISR-T018": "exfil"}
WORDING_RULES = frozenset(("ISR-T001", "ISR-T007", "ISR-T008", "ISR-T014", "ISR-T016"))   # T014 "every email": item 8 dry run, Oct 13                          # what a skill says
BEHAVIOR_RULES = frozenset(("ISR-T002", "ISR-T003", "ISR-T004", "ISR-T005", "ISR-T006", "ISR-T012", "ISR-T017", "ISR-T018"))   # what it does
WORDING_BACKERS = BEHAVIOR_RULES | {"ISR-T013"}
WEBHOOK_PAIR = {"ISR-T018": "ISR-T004", "ISR-T004": "ISR-T018"}   # batch 4: the one pair that confirms a chat webhook (see corroborated)
DRIFT_RULES = frozenset(("ISR-I001", "ISR-I002"))   # a live file that changed or appeared: a fact about reach, never about wording   # an email or post sent with no approval line is a send, even without curl
ENGINE_KIND_WORDS = (("credential", r"cred|secret|token|passw|api[ _-]?key|ssh|aws|keychain|cookie"),
                     ("exfil", r"exfil|upload|leak|send|webhook|network|outbound|data[ _-]?theft|post\b"),
                     ("pipe", r"pipe|curl|wget|remote[ _-]?(code|script)|download"),
                     ("obfuscation", r"obfusc|encod|base64|hidden|unicode|loader|packed|homoglyph"),
                     ("secrecy", r"conceal|secre|stealth|hide|hiding"),
                     ("override", r"inject|override|jailbreak|ignore (previous|prior|all)"),
                     ("exec", r"\bexec|eval|shell|command|subprocess"))


HUSK_SQL_RETURN = re.compile(r"SQL keyword.*\breturned from a function", re.I)
HUSK_AT = re.compile(r"^'([^']+)': Line (\d+):")
SQL_SHAPE = re.compile(r"\b(select\b.*\bfrom\b|insert\s+into\b|update\s+[\w.`\"'\[\]{}$%]+\s+set\b|delete\s+from\b|merge\s+into\b|"
                       r"(drop|create|alter|truncate)\s+(table|database|index|view|schema)\b|union\s+(all\s+)?select\b|"
                       r"where\s+[\w.`\"'{}$%]+\s*(=|like\b|in\b))", re.I)


def husk_messages_that_count(d, msgs):
    """DQ-011 (4): husk flags any f-string with a SQL keyword that a function returns, so a chat message such as
    `return f"topic-digest update: {topic}..."` came back as SQL injection. Such a message counts only when the line it names
    (or the two after it, for a query split over lines) has the shape of a SQL statement. A query passed to execute(), a
    message of any other kind, a message without a file and line, or a line Watchtower can't read are kept
    as before."""
    keep = []
    for m in msgs or ():
        at = HUSK_AT.match(str(m))
        if at and HUSK_SQL_RETURN.search(m):
            try:
                with open(os.path.join(d, at.group(1)), errors="replace") as fh:
                    lines = fh.read().splitlines()
                n = int(at.group(2))
                if 0 < n <= len(lines) and not SQL_SHAPE.search(" ".join(lines[n - 1:n + 2])):
                    continue
            except (OSError, ValueError):
                pass
        keep.append(m)
    return keep


def engine_kinds(texts):
    """The kinds of risk a scanner's own words name ("Exfil: Upload", "obfuscated loader"). Unknown wording names none."""
    t = " ".join(str(x) for x in texts or ()).lower()
    return {k for k, rx in ENGINE_KIND_WORDS if re.search(rx, t)}


RULE_ALIAS = {"ISR-T011x": "ISR-T011"}   # batch 6 fix round 3: ISR-T011's example-looking hits are ISR-T011 to every rule here


def same_rule(g, f):
    """True when g and f are hits of one rule (ISR-T011x counted as ISR-T011)."""
    return RULE_ALIAS.get(g["rule"], g["rule"]) == RULE_ALIAS.get(f["rule"], f["rule"])


def kinds_of(f):
    return set(f.get("kinds") or ()) or ({RISK_KIND[f["rule"]]} if f["rule"] in RISK_KIND else set())


CORROB_INDEX = True   # batch 5 (c5): False makes corroborated() read every finding again, as before (the tests' reference)


class CorrobIndex:
    """Batch 5 (Codex medium, c5): which findings could back up a finding, found without reading all of them. Every branch of
    corroborated() needs g at the same place, at a place that covers it or that it covers (_covers), or a skill folder related
    the same way (ISR-I004, the drift rules and the folder verdicts included), so candidates() is a superset of every g that can
    answer yes, and the loop over it gives the same answer as the loop over all. Places and skills are looked up with their
    trailing / taken off (_covers ignores it): the same one, each ancestor (cut at a /) and, by a sorted list, every
    descendant. _skill_of (a filesystem look) runs once per finding, and only once a skill is asked about."""
    def __init__(self, findings):
        import bisect
        self._bisect = bisect.bisect_left
        self.findings, self.skill_of, by_place, self.i004 = findings, {}, {}, []
        for g in findings:
            by_place.setdefault(_place(g).rstrip("/"), []).append(g)
            if g["rule"] == "ISR-I004":
                self.i004.append(g)
        self.by = [(by_place, sorted(by_place)), None]

    def _related(self, which, key):
        if self.by[which] is None:
            by_skill = {}
            for g in self.findings:
                by_skill.setdefault(self.skill(g).rstrip("/"), []).append(g)
            self.by[which] = (by_skill, sorted(by_skill))
        table, keys = self.by[which]
        k = key.rstrip("/")
        out = list(table.get(k, ()))
        for i, c in enumerate(key):
            if c == "/" and key[:i] != k:
                out += table.get(key[:i], ())
        pre = k + "/"
        j = self._bisect(keys, pre)
        while j < len(keys) and keys[j].startswith(pre):
            out += table[keys[j]]
            j += 1
        return out

    def candidates(self, here, skill=None):
        """Every finding at a place related to `here` or (unless None) whose skill is related to `skill`, and every ISR-I004."""
        seen, out = set(), []
        for g in self._related(0, here) + (self._related(1, skill) if skill is not None else []) + self.i004:
            if id(g) not in seen:
                seen.add(id(g))
                out.append(g)
        return out

    def skill(self, g):
        held = self.skill_of.get(id(g))
        if held is None:
            held = self.skill_of[id(g)] = (g, _skill_of(g))   # g is kept, so its id can't be reused while the index lives
        return held[1]


def corroborated(f, findings, index=None):
    """A pattern finding is backed up (v0.7.1 item 2: two votes about the same file and the same kind of risk) when
    - a wording hit (override, weaken approvals, secrecy, quiet action) has a behavior signal in the same file: a credential read,
      a send to an outside address, a pipe-to-shell, hidden Unicode, an encoded blob, dynamic code. Wording alone never is;
    - a behavior hit has, in the same file, an evidence finding or another engine's finding about the same kind of risk, or a
      second, different loud Watchtower rule (credential read plus a send out is the classic chain);
    - a behavior hit has a scanner's verdict on its skill folder that names the same kind of risk ("husk found something
      somewhere in the folder" is not a vote; SkillSpector's "Exfil" backs up a send to an outside address);
    - a rule with no kind of risk keeps the v0.6.8 test: evidence or another engine at the same place;
    - a behavior hit in a skill that changed after approval (ISR-I001/I002) is backed up by the change; wording is not;
    - anything inside a new plugin the owner hasn't kept yet (ISR-I004) counts until they decide, as before.
    A ISR-S005 cookie-only note stays Worth a look even when a real sign-in is at the same shared-browser place.
    Batch 6 fix round 3 (Codex 1, 2): an example-looking secret is read like any other (its note changes nothing here), and
    ISR-T011x is ISR-T011 (same_rule)."""
    if f["rule"] == "ISR-S005" and f.get("title") != NEW_SIGN_IN:
        return False
    here, src, skill = _place(f), f.get("source", "watchtower"), (index.skill(f) if index is not None else _skill_of(f))
    skill_of = index.skill if index is not None else _skill_of
    loud = lambda g: (g.get("severity_was") or g["severity"]) in ("critical", "high")
    if index is not None:   # c5: only those that can answer yes, so the same answer (CorrobIndex); the skill folder is asked
        # about only where its branch below can be reached: no kind of risk, not wording, and f loud
        findings = index.candidates(here, skill if not kinds_of(f) and f["rule"] not in WORDING_RULES and loud(f) else None)
    if f["rule"] in WEBHOOK_PAIR:   # batch 4 (FP1): a chat webhook and a credential read in one file back each other up
        pair, full = WEBHOOK_PAIR[f["rule"]], lambda g: SEV_ORDER.index(g.get("severity_was") or g["severity"]) <= SEV_ORDER.index("medium")
        if full(f) and any(g["rule"] == pair and not g.get("guarded") and _place(g) == here and full(g) for g in findings):
            return True
        if f["rule"] == "ISR-T018":
            return False   # nothing else confirms one: an engine's "webhook", a change or a folder verdict is the owner's own chat
    fk = kinds_of(f)
    for g in findings:
        if g is f or g["rule"] in NO_OPINION or g.get("guarded"):
            continue                            # a scanner that didn't finish says nothing about the content (DQ-014); defensive text backs up nothing
        gp, gk = _place(g), kinds_of(g)
        other = is_evidence(g) or g.get("source", "watchtower") != src
        if g["rule"] == "ISR-I004" and _covers(gp, here):
            return True                          # a new plugin nobody has vetted: what the scanners flag in it counts until the owner decides
        if f["rule"] in WORDING_RULES and not fk:   # T014 has no kind: wording still needs a behavior signal in the same file
            if gp == here and g["rule"] in WORDING_BACKERS:
                return True
            continue
        if not fk:                               # no kind of risk to match: the v0.6.8 rule, unchanged
            if _covers(here, gp) and other:
                return True
            if loud(f) and loud(g) and not same_rule(g, f) and not is_evidence(g) and _covers(skill, skill_of(g)):
                return True
            continue
        same_file = gp == here
        if f["rule"] in WORDING_RULES:
            if same_file and (g["rule"] in WORDING_BACKERS or (other and gk - {"secrecy", "override"})):
                return True
            continue
        if other and same_file and fk & gk:
            return True
        if other and gp != here and _covers(gp, here) and fk & gk:
            return True                          # a verdict on the folder this file is in, about the same kind of risk
        if is_evidence(g) and not gk and g["rule"] in DRIFT_RULES and _covers(gp, here):
            return True                          # the live skill changed after approval and now does this: reach plus behavior
        if not other and same_file and loud(f) and loud(g) and not same_rule(g, f) and g["rule"] in RISK_KIND:
            return True
    return False


def ask_first_covered(findings):
    """The Ask-first areas the account's own rules cover, judged from a full run's findings: every area a ISR-A003 doesn't name
    as missing. Only a full audit can say this (it always reports ISR-A003 when rules are missing or unseen)."""
    a3 = [f for f in findings if f["rule"] == "ISR-A003"]
    gaps = " ".join(f.get("evidence", "") for f in a3).lower()
    return {w for w, _ in ASK_AREAS if w not in gaps}


def covered_by_ask_first(f, covered):
    """A missing approval line (ISR-T013, ISR-PP07) is a tip, not a finding, when the account's Ask-first rules already make every
    Bot ask before that kind of action."""
    if f["rule"] not in ("ISR-T013",) or not covered:
        return False
    verb = (f.get("evidence") or "").strip().split(" ")[0]
    area = next((w for w, rx in VERB_AREA if re.match(rx, verb)), None)
    return bool(area) and area in covered


def _no_severity(f, cls, label):
    f["class"], f["label"] = cls, label
    if f["severity"] != "info":
        f["severity_was"], f["severity"] = f["severity"], "info"   # shown without a severity, never scored


# v0.7.1 precision item 3 (decision, Oct 12): evidence rules split the fact from the severity. The fact stays listed; the severity
# is only kept when the thing is reachable. ISR-S004 (DQ-026: high only with a session cookie for a sensitive site) and ISR-A001
# (DQ-027: critical only when broader than one pinned address) already do this where they are made; FACT_ONLY holds the rest.
FACT_NOTE = {"ISR-D002": ("in a project nothing on this computer loads",
                         "Nothing Grok Bot loads uses this project, so it isn't scored. If you still run or deploy it, update the package "
                         "there (`wt.py fix` offers the upgrade).")}


# Oct 12 ruling (Claude review Oct 13, F2): packages in a project count in full when a live skill, routine or hook uses that
# project. Each audit collects every absolute path a hook command, a routine (exports, crontab, systemd user units) or a live
# skill names; a project is used when one of those paths is inside it.
USED_PATHS = set()
_PATH_IN_TEXT = re.compile(r"(?<![\w:/.$~-])((?:~|\$HOME|\$\{HOME\})?/[A-Za-z0-9._@+\-/]+)")


def paths_named(text):
    out = set()
    for m in _PATH_IN_TEXT.finditer(text or ""):
        p = m.group(1).rstrip(".,;:")
        for pre in ("${HOME}", "$HOME", "~"):
            if p.startswith(pre + "/"):
                p = os.path.expanduser("~") + p[len(pre):]
                break
        if p.count("/") >= 2:   # a bare "/tmp" or "/" names no project
            out.add(os.path.normpath(p))
    return out


def project_users(roots, inv, exports):
    """Absolute paths that hooks, routines and live skills name (see USED_PATHS)."""
    used = set()
    for c in hook_commands(roots, inv):
        used |= paths_named(c)
    if exports and os.path.isdir(exports):
        for fn in sorted(os.listdir(exports)):
            if fn.lower().startswith("routine"):
                used |= paths_named(read_text(os.path.join(exports, fn)))
    code, out, _ = run(["crontab", "-l"], 10)
    if code == 0:
        used |= paths_named(out)
    units = os.path.expanduser("~/.config/systemd/user")
    if os.path.isdir(units):
        for fn in sorted(os.listdir(units)):
            if os.path.isfile(os.path.join(units, fn)):
                used |= paths_named(read_text(os.path.join(units, fn)))
    for skill in inv.get("skills", []):
        for p in skill_dir_files(skill):
            if os.path.splitext(p)[1].lower() in TEXT_EXT:
                used |= paths_named(read_text(p))
    return used


def package_reachable(f):
    """A vulnerable package is reachable when something the platform loads uses it: a lockfile inside a skill or plugin
    folder, or in a project that a hook, routine or live skill names a path inside (Oct 12 ruling)."""
    path = (f.get("where") or "").split(":")[0]
    if not path.startswith("/"):
        return True
    m = re.match(r"Vulnerable package (.+)$", f.get("title") or "")
    dirs = (load_json(state_path("osv_projects.json"), {}) or {}).get("packages", {}).get(m.group(1), []) if m else []
    projs = set()
    for d in [path] + [x for x in dirs if isinstance(x, str) and x.startswith("/")]:   # the finding names one project; it may sit in several
        if is_loadable_skill_location(d):
            return True
        d = os.path.normpath(d if not os.path.isfile(d) else os.path.dirname(d))
        projs.add(d)
        try:
            projs.add(os.path.realpath(d))
        except OSError:
            pass
    for u in USED_PATHS:
        cands = {u}
        try:
            cands.add(os.path.realpath(u))
        except OSError:
            pass
        if any(c == pr or c.startswith(pr + "/") for c in cands for pr in projs):
            return True
    return False


FACT_ONLY = {"ISR-D002": package_reachable}


def split_facts(fs):
    """Mark evidence findings whose fact is real but whose thing nothing reaches: shown as a Tip (no severity, never scored)."""
    for f in fs:
        test = FACT_ONLY.get(f["rule"])
        if test and not f.get("fact_only") and not test(f):
            note, fix = FACT_NOTE[f["rule"]]
            f.update(fact_only=True, title=f"{f['title']} ({note})", fix=fix)
    return fs


def plain_cookie_jar(f):
    """DQ-026 intent (item 8 dry run, Oct 13): a shared cookie jar with no sign-in on a sensitive site is advice, not a Confirmed
    medium. It stays listed as a Tip; one session cookie for a sensitive site makes it the high Confirmed finding again."""
    return f["rule"] == "ISR-S004" and str(f.get("evidence", "")).endswith("sensitive: none")


def label_findings(findings, covered=None):
    """Label every finding. Evidence and corroborated findings are Confirmed and keep their severity. Best-practice checks are Tips
    and an approval line the Ask-first rules already cover is a Tip; pattern findings nothing backs up are "Worth a look". Tips and
    Worth-a-look carry no severity and never move the score. `covered`: the Ask-first areas known to be covered (none assumed)."""
    covered = covered or set()
    out, memo, reps = [], {}, {}
    for g in findings:   # Codex, batch 4 round 2: each distinct finding is read once (vet's 5,000 matches were 25 million pairs)
        reps.setdefault(_corrob_sig(g), g)
    reps = list(reps.values())
    index = None   # batch 5 (c5): built on the first pattern finding that needs it, once per call

    def backed(f):
        nonlocal index
        s = _corrob_sig(f)
        if s not in memo:
            if CORROB_INDEX and index is None:
                index = CorrobIndex(reps)
            memo[s] = corroborated(f, reps, index)
        return memo[s]
    for f in findings:
        f = dict(f)
        if f.get("guarded"):   # batch 2 (R1): defensive wording, kept as a record with no severity; severity_was stays the rule's own
            f["class"], f["label"], f["severity"] = "guarded", GUARDED_LABEL, "info"
        elif (f["rule"] in TIP_RULES or f["rule"] in SCOPE_RULES or f["rule"] in SETTING_TIPS or f.get("fact_only")
                or covered_by_ask_first(f, covered) or plain_cookie_jar(f) or ask_first_unread(f)):
            _no_severity(f, "tip", TIP)
        elif is_evidence(f):
            f["class"], f["label"] = "evidence", CONFIRMED
        elif backed(f):
            f["class"], f["label"] = "corroborated", CONFIRMED
            if f["rule"] == "ISR-T018" and f["severity"] != "critical":   # batch 4: a credential read sent to a chat webhook is how token stealers work
                f["severity_raised_from"], f["severity"] = f["severity"], "critical"
        else:
            _no_severity(f, "pattern", MAYBE_FINE)
        out.append(f)
    return out


# v0.7.1 precision item 5 (decision, Oct 12): one finding per root cause. Within one skill, findings about the same kind of risk
# with the same label are one line; the other rules, files and engines are listed on it as "also flagged by". Keys, decoys,
# change alerts and evidence (two engines agreeing, a decoy read) are never folded: each one is its own fact.
GROUP_CLASSES = ("pattern", "tip", "corroborated", "platform")
ALSO_MAX = 12


def _groupable(f):
    w = f.get("where") or ""
    return (f.get("class") in GROUP_CLASSES and w.startswith("/") and f["rule"] not in SECRET_RULES
            and not f["rule"].startswith(("ISR-K", "ISR-I", "ISR-X")))


ROLLCALL_GROUPED = frozenset(("ISR-L001", "ISR-M010"))


def _rollcall_group(f):
    """Item 8 dry run (Oct 13): 15 Bots sharing one connector set were 15 lethal-trifecta lines, and 10 memories judged by an
    Oct 9 roll-call were 10. Worth-a-look roll-call findings of one rule on ROLLCALL_GROUP_MIN or more Bots are one line naming every Bot; Confirmed ones stay apart."""
    w = f.get("where") or ""
    return w.startswith("rollcall:") and f["rule"] in ROLLCALL_GROUPED and f.get("class") == "pattern"


ROLLCALL_GROUP_MIN = 4   # a few Bots stay one line each (DQ-018 replay); four or more with the same rule are one fleet-wide root cause


def group_root_causes(fs):
    out, primary = [], {}
    n_rc = {}
    for f in fs:
        if _rollcall_group(f):
            n_rc[f["rule"]] = n_rc.get(f["rule"], 0) + 1
    for f in sort_findings(fs):
        if _rollcall_group(f) and n_rc.get(f["rule"], 0) >= ROLLCALL_GROUP_MIN:
            k = ("rollcall", f["rule"])
            p = primary.get(k)
            if p is None:
                primary[k] = f = dict(f)
                out.append(f)
            else:
                p["also_count"] = p.get("also_count", 0) + 1
                if len(p.setdefault("also_flagged_by", [])) < 20:
                    p["also_flagged_by"].append({"rule": f["rule"], "where": f["where"], "source": f.get("source", "watchtower")})
            continue
        root = skill_root(f["where"].split(":")[0]) if _groupable(f) else None
        if not root:
            out.append(f)
            continue
        k = (root, f["class"], "+".join(sorted(kinds_of(f))) or f["rule"])
        p = primary.get(k)
        if p is None:
            primary[k] = f
            out.append(f)
            continue
        p["also_count"] = p.get("also_count", 0) + 1
        if len(p.setdefault("also_flagged_by", [])) < ALSO_MAX:
            p["also_flagged_by"].append({"rule": f["rule"], "where": f["where"], "source": f.get("source", "watchtower")})
    for k, p in primary.items():
        if k[0] == "rollcall" and p.get("also_count"):
            p["title"] = f"{p['title']} ({p['also_count'] + 1} Bots)"
    return out


CHANGED_GROUP_MIN = 2


def _changed_high(f):
    # the owner's own skills only: a platform or built-in change keeps its own line (dry run 53e1836: a Grok Bot built-in
    # led the group, so the owner's changes went unscored)
    return (f.get("rule") == "ISR-I001" and f.get("severity") == "high" and not f.get("refresh") and f.get("scope") not in ("platform", "builtin")
            and not f.get("unverified_platform"))   # item 8: a platform change without provenance keeps its own line and title


def group_changed_skills(fs):
    """Decision, Oct 14: several reviewed skills changed is one finding listing each skill, not one high per skill. Still high.
    Each skill keeps its own record (fix, re-vet, diff and approvals work per skill); all but the first are marked
    `grouped_into` and are neither scored nor shown as lines of their own."""
    for f in fs:
        f.pop("grouped_into", None)
    hits = [f for f in sort_findings(fs) if _changed_high(f)]
    names = sorted({skill_name(skill_root(f["where"].split(":")[0]) or os.path.dirname(f["where"].split(":")[0])) for f in hits})
    if len(names) < CHANGED_GROUP_MIN:
        return fs
    p = hits[0]
    p["title"] = f"{len(names)} reviewed skills changed"
    p["skills"] = names
    p["member_evidence"], p["evidence"] = p["evidence"], ", ".join(names)[:400]
    p["members"] = [f["where"] for f in hits]
    for f in hits[1:]:
        f["grouped_into"] = p["key"]
    return fs


def shown(fs):
    """Findings as lines: members of a grouped finding are inside their group's line."""
    return [f for f in fs or [] if not f.get("grouped_into")]


def expand_groups(fs):
    return list(fs or [])


def open_counts(fs):
    """Worth-a-look and Tip counts, shown next to the score everywhere so a perfect score never hides open items."""
    fs = shown(fs)
    return sum(1 for f in fs if f.get("class") == "pattern"), sum(1 for f in fs if f.get("class") == "tip")


def score_line(snap):
    """'100 · 7 worth a look · 3 tips'"""
    if not snap or snap.get("score") is None:
        return "–"
    look, tips = open_counts(snap.get("findings"))
    return f"{snap['score']} · {look} worth a look · {tips} tip{'' if tips == 1 else 's'}"


def label_of(f):
    return f.get("label") or (CONFIRMED if is_evidence(f) else MAYBE_FINE)


def score(findings):
    """Score the kinds of risk, not the number of files. Each rule counts once at its worst severity, a little
    more when it appears many times (up to x1.5), so one finding appearing or vanishing moves the score by at most
    12 points, not 20. 300 skills with the same style issue cost about 2; one live key about 12."""
    worst, count = {}, {}
    for f in findings:
        sev = f["severity"]
        if sev not in SCORE_BASE:
            continue
        r = f["rule"]
        count[r] = count.get(r, 0) + 1
        if r not in worst or SEV_ORDER.index(sev) < SEV_ORDER.index(worst[r]):
            worst[r] = sev
    tiers = {k: 0.0 for k in SCORE_BASE}
    for r, sev in worst.items():
        tiers[sev] += SCORE_BASE[sev] * (1 + 0.5 * min(1.0, math.log10(count[r])))
    penalty = sum(min(SCORE_CAP[k], v) for k, v in tiers.items())
    s = max(0, 100 - round(penalty))
    grade = "A" if s >= 90 else "B" if s >= 80 else "C" if s >= 65 else "D" if s >= 50 else "F"
    return s, cap_grade(grade, status_of(findings))   # batch 2 (R5): the grade says what to do; the number is the trend


def cap_grade(grade, st):
    """Act now is grade F; Check this week is at most C."""
    if st == ACT_NOW:
        return "F"
    return "C" if st == CHECK_WEEK and grade in ("A", "B") else grade


ACT_NOW, CHECK_WEEK, ALL_GOOD = "Act now", "Check this week", "All good"


def status_of(findings):
    """The headline (hardening batch 2, R5): one Confirmed critical is "Act now", one Confirmed high "Check this week", whatever
    the number says. Pass the scored findings (`scored(live)`): accepted, platform, roll-call and grouped ones are already out."""
    sev = {f["severity"] for f in findings if label_of(f) == CONFIRMED}
    return ACT_NOW if "critical" in sev else CHECK_WEEK if "high" in sev else ALL_GOOD


def snap_status(snap):
    """An older snapshot without a status gets one from its findings."""
    return snap.get("status") or status_of(scored(snap.get("findings") or []))


def snap_grade(snap):
    """The grade to show. An older snapshot (no status) kept the grade of its day, so the cap is applied when it is read; its
    number stays as it was."""
    g = (snap or {}).get("grade", "")
    return g if not snap or "status" in snap or not g else cap_grade(g, snap_status(snap))


def status_line(snap):
    """'Act now — 1 confirmed critical problem'"""
    st = snap_status(snap)
    sev = "critical" if st == ACT_NOW else "high" if st == CHECK_WEEK else None
    if not sev:
        return st
    n = sum(1 for f in scored(snap.get("findings") or []) if f["severity"] == sev and label_of(f) == CONFIRMED)
    return f"{st} — {n} confirmed {sev} problem{'' if n == 1 else 's'}" if n else st


def warned_danger(f):
    """A credential path, exfiltration host, pipe-to-shell or upload that a guard lowered: vet never says Install over it and
    revet never re-approves because of it."""
    return bool(f.get("guarded")) and f["rule"] in GUARD_CODE_RULES and f.get("severity_was") in ("critical", "high")


def verdict(findings):
    sev = {f["severity"] for f in findings}
    if "critical" in sev:
        return "Do not install"
    if "high" in sev or any(warned_danger(f) for f in findings):
        return "Install with changes"
    return "Install"


def vet_verdict(labelled):
    """Batch 4 (FP2): vet judges on the audit's labels, with one rule of its own. A dangerous behaviour match that is critical
    on its own (an exfiltration host, a pipe-to-shell) is still "Do not install": before install nothing can back it up.
    Wording on its own (T001, T008) and a chat webhook are "Install with changes". An exposed key (T011) is "Do not install"
    on its own, as on 857ab38: it ships with every copy of the template (Codex, round 1)."""
    raw = lambda f: f.get("severity_was") or f["severity"]
    live = [f for f in labelled if not f.get("guarded")]
    if any(f.get("label") == CONFIRMED and f["severity"] == "critical" for f in live) or \
            any((f["rule"] in BEHAVIOR_RULES or RULE_ALIAS.get(f["rule"], f["rule"]) == SECRET_RULE) and raw(f) == "critical" for f in live):
        return "Do not install"
    if (any(f.get("label") == CONFIRMED and f["severity"] == "high" for f in live) or any(warned_danger(f) for f in labelled)
            or any(f.get("class") == "pattern" and raw(f) in ("critical", "high") for f in live)
            or any(f["rule"] == "ISR-T018" for f in live)):
        return "Install with changes"
    return "Install"


def sort_findings(fs):
    return sorted(fs, key=lambda f: (SEV_ORDER.index(f["severity"]), f["rule"], f["where"]))
