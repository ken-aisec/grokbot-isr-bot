# Part of isr.py: runs inside isr.py's namespace (loaded by _isr_part); not a module on its own.
# ---------------------------------------------------------------- weekly artifacts: two standalone Markdown files from one observation
_MD_HIDDEN = re.compile("[\u00ad\u061c\u180e\u200b-\u200f\u202a-\u202e\u2060-\u2069\ufeff]")
_MD_SPECIAL = re.compile(r"([\\`*_{}\[\]()<>#+\-.!|])")
_MD_LINK = re.compile(r"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]{1,300}")
ARTIFACT_KINDS = ("threat-report", "access-map")


def md_text(v, n=300, rollcall=True):
    """Outside text as Markdown shows it, inert: no hidden or direction characters, one line, secrets and (with `rollcall`)
    roll-call details masked, every Markdown character escaped. rollcall=False is for times, ids, modes and CVE numbers,
    which mask_rollcall would turn into [number]."""
    t = _MD_HIDDEN.sub("", str(v if v is not None else ""))
    t = "".join(ch if ch.isprintable() else " " for ch in t)
    t = re.sub(r"\s+", " ", t).strip()
    t = mask_secrets(t)
    t = mask_rollcall(t, n) if rollcall else (t if len(t) <= n else t[:n - 1] + "…")
    return _MD_SPECIAL.sub(r"\\\1", t)


def md_link(u):
    """An http(s) link as a Markdown autolink, or "" for anything else."""
    u = mask_secrets(str(u or "").strip())
    return f"<{u}>" if _MD_LINK.fullmatch(u) and "<" not in u and ">" not in u else ""


def _obs_when(obs):
    return f"{obs['observed_at']} UTC ({et_time(obs['observed_at'])})"


def unresolved_lines(obs):
    """What this observation couldn't settle: the areas it didn't see whole, what ISR Bot never sees, and the reach it never
    determines. Only ISR Bot's own words and checked values, so they are shown as they are."""
    out = [f"{OBS_AREA_WORDS[a]}: {obs['coverage'][a]}." for a in OBS_AREAS if obs["coverage"][a] != "complete"]
    out += access_unknown_lines(obs["map"])
    out += [REACH_UNDETERMINED, "A connector a Bot names is not authorization: what it may do at its service isn't checked.", NOT_A_SANDBOX]
    return out


def header_block(obs, title, tag, diff, facts, facts_why):
    m = obs["map"]
    scope = ", ".join(m["shared"]["scope"]) or "unknown"
    lines = [f"# {title} {tag}", "",
             f"Observation `{obs['observation_id']}` · observed {_obs_when(obs)} · ISR Bot {VERSION} · scope: {md_text(scope, rollcall=False)}", "",
             "Both ISR Bot artifacts this week come from this one observation. Read-only: ISR Bot changed nothing.", "",
             "## Coverage", "", "| Area | This observation |", "| --- | --- |"]
    lines += [f"| {OBS_AREA_WORDS[a]} | {md_text(obs['coverage'][a], rollcall=False)} |" for a in OBS_AREAS]
    lines += ["", "## History limits", "", f"- {OBS_TAMPER}"]
    lines.append("- " + (f"Compared with the {_record_line(diff['baseline'])}." if diff["baseline"] else
                         f"No earlier record at least {DIFF_GAP_HOURS} hours older: no earlier record to compare with."))
    lines.append(f"- Kept: the newest {OBS_KEEP} observations.")
    lines += ["", "## Platform context", ""]
    if facts_why:
        lines.append(f"- platform context unavailable ({md_text(facts_why, rollcall=False)})")
    else:
        lines += [f"- {PLATFORM_LABEL}: {md_text(f['text'], rollcall=False)} ({md_text(f['source'], rollcall=False)}, {f['date']})" for f in facts]
    lines += ["", f"- {NOT_A_SANDBOX}", ""]
    return lines


def _bot_line(b):
    who = f"`{b['pid']}` ({md_text(b['name'], 60)}, " + ("id from its agent folder)" if b["id_basis"] == "uuid" else
                                                          "id from its name: a rename looks like a new Bot)")
    s = b["said"]
    if s is None:
        what = {"no-detail": "answered the roll-call before access was kept", "silent": "not heard from in the roll-call",
                "listed": "listed on this computer; no roll-call answer on record"}.get(b["status"], "no answer on record")
        return f"- {who}: {what}."
    con = (", ".join(md_text(x, 40) for x in s["connectors"]) or "none named") + (f" and {s['connectors_other']} other" if s["connectors_other"] else "")
    if s["connectors_unknown"]:
        con += " (didn't say all of them)" if s["connectors_unknown"] == "partial" else " (didn't say)"
    when = _ax_day(s["said_at"]) if s["said_at"] else "an unknown day"
    return (f"- {who}: said on {when}: connectors {con}; {s['routines']} routines ({s['routines_sending']} send without asking). "
            f"Said by {b['pid']}, not checked; sender not verified.")


def render_access_map_md(obs, diff, facts, facts_why, tag):
    m = obs["map"]
    lines = header_block(obs, "ISR Bot access map", tag, diff, facts, facts_why)
    lines += ["## On this computer's shared files", "",
              f"Observed here {et_time(obs['observed_at'])} (status only), except each line marked \"from the last audit\": From the last audit "
              f"{_ax_day(m['shared']['cached_at']) if m['shared'].get('cached_at') else '(date unknown)'}, not observed here.", "", ACCESS_LEAD, ""]
    lines += [f"- {md_text(x, 400)}" for x in access_shared_lines(m)]
    lines += ["", "## CLI sign-in files (status only)", "",
              f"Observed here {et_time(obs['observed_at'])} (status only): each known name was looked at with lstat; no file was opened "
              "and no link was followed.", ""]
    shown = [c for c in obs["creds"] if c["state"] != "missing"]
    lines += [f"- {md_text(c['file'], rollcall=False)} ({md_text(c['tool'], rollcall=False)}): {cred_words(c)}." for c in shown]
    gone = [c["file"] for c in obs["creds"] if c["state"] == "missing"]
    if gone:
        lines.append(f"- Not found: {md_text(', '.join(gone), 600, rollcall=False)}.")
    lines += [f"- {REACH_UNDETERMINED}", "", "## Each Bot", "",
              "Said by each Bot about itself in the roll-call, not checked; sender not verified. A Bot's claim is kept under that Bot only.", ""]
    lines += [_bot_line(b) for b in obs["bots"]] or ["- No Bot is listed on this computer or in the roll-call."]
    lines += ["", "## Changes since the last record", ""]
    lines += [f"- {md_text(x, 400, rollcall=False)}" for x in diff_lines(diff)]
    lines += ["", "## Unresolved scope", ""] + [f"- {x}" for x in unresolved_lines(obs)]
    return "\n".join(lines) + "\n"


def render_threat_report_md(obs, brief, snap, tag, facts, facts_why, diff):
    lines = header_block(obs, "ISR Bot threat report", tag, diff, facts, facts_why)
    lines += ["## Score", ""]
    if snap and snap.get("score") is not None:
        lines += [f"From the last audit {et_time(snap.get('at'), day=True) if snap.get('at') else 'unknown'}:", "",
                  f"- Score: {md_text(score_line(snap), rollcall=False)} (grade {md_text(snap_grade(snap), rollcall=False)})", f"- Status: {md_text(status_line(snap), rollcall=False)}"]
    else:
        lines.append("- Unknown: no audit yet.")
    lines += ["", "## Top stories", ""]
    ok = isinstance(brief, dict) and brief.get("tag") == tag and isinstance(brief.get("research"), list)
    if not ok:
        lines.append(f"- No threat brief for {tag}.")
    else:
        try:
            top, _ = split_stories(brief)
        except (KeyError, TypeError):
            top, ok = [], False
            lines.append(f"- No threat brief for {tag}.")
        ctx = account_context() if top else {}
        for i, s in enumerate(top, 1):
            link = md_link(s.get("link"))
            cves = ", ".join(md_text(c, 30, rollcall=False) for c in s.get("cves", [])[:6] if isinstance(c, str))
            lines += [f"### {i}. {md_text(s.get('title'), 200, rollcall=False)}", "",
                      f"- {md_text(s.get('tier'), 20, rollcall=False)} · {md_text(s.get('category_label'), 40, rollcall=False)} · {md_text(s.get('source'), 60, rollcall=False)}"
                      + (f" · {link}" if link else "") + (f" · {cves}" if cves else ""),
                      f"- Here (observed here {et_time(obs['observed_at'])}, status only): {md_text(story_here(s, obs['map'], ctx), 400)}", ""]
        if ok:
            kev = [f"{k.get('cve')} {k.get('vendor')} {k.get('product')}" for k in brief.get("kev", []) if isinstance(k, dict) and k.get("relevant")][:6]
            lines += ["## Known exploited (CISA KEV)", ""] + ([f"- {md_text(k, 120, rollcall=False)}" for k in kev] or ["- None relevant this week."]) + [""]
    lines += ["## Unresolved scope", ""] + [f"- {x}" for x in unresolved_lines(obs)]
    return "\n".join(lines) + "\n"


def _write_new(path, text):
    """Write a report file next to its place and swap it in: a link put where the file goes is replaced, never written through."""
    d = os.path.dirname(path)
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".artifact-")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(text.encode("utf-8"))
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        if os.path.lexists(tmp):
            os.unlink(tmp)
        raise


def write_artifacts(obs, diff, brief, snap, tag, facts, facts_why):
    """The two Markdown files and their manifest under reports/: {observation_id, observed_at, files, unresolved_count, brief}."""
    rdir = os.path.join(home(), "reports")
    os.makedirs(rdir, exist_ok=True)
    texts = {"threat-report": render_threat_report_md(obs, brief, snap, tag, facts, facts_why, diff),
             "access-map": render_access_map_md(obs, diff, facts, facts_why, tag)}
    files = []
    for kind in ARTIFACT_KINDS:
        p = os.path.join(rdir, f"{kind}-{tag}.md")
        _write_new(p, texts[kind])
        raw = texts[kind].encode("utf-8")
        files.append({"kind": kind, "path": p, "sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)})
    has_brief = isinstance(brief, dict) and brief.get("tag") == tag and isinstance(brief.get("research"), list)
    man = {"observation_id": obs["observation_id"], "observed_at": obs["observed_at"], "files": files,
           "unresolved_count": len(unresolved_lines(obs)), "brief": "ok" if has_brief else "missing"}
    _write_new(os.path.join(rdir, f"artifacts-{tag}.json"), json.dumps(man, indent=1) + "\n")
    return man


def cmd_artifacts(args):
    obs = access_observation("artifacts")
    prior, load_why = load_observations()
    diff = diff_observations(pick_baseline(prior, obs), obs)
    try:
        kept = save_observation(obs)
        obs = dict(obs, observation_id=kept)
        history = "saved"
    except ObservationStoreError as e:
        history = f"not saved: {e}"
        ledger({"event": "observation-not-saved", "why": str(e)[:200]})
    facts, facts_why = platform_facts()
    brief = load_json_regular(state_path("last_brief.json"), None)
    snap = load_snapshot(None)
    week = dt.date.today().isocalendar()
    tag = f"{week[0]}-W{week[1]:02d}"
    man = write_artifacts(obs, diff, brief, snap, tag, facts, facts_why)
    ledger({"event": "artifacts", "week": tag, "observation": obs["observation_id"], "brief": man["brief"]})
    out = dict(man, history=history + (f" (earlier records: {load_why})" if load_why else ""),
               next_step="Attach both files with SendToUser when this run has it, or say \"Attachments unavailable: <reason>\" and "
                         "name the files. A path alone is not delivered.")
    if getattr(args, "json", False):
        print(json.dumps(out, indent=1))
    else:
        print(f"Observation {man['observation_id']} ({et_time(man['observed_at'])}); threat brief: {man['brief']}; history: {out['history']}")
        for f in man["files"]:
            print(f"{f['kind']}: {f['path']} ({f['bytes']} bytes, sha256 {f['sha256']})")
        print(out["next_step"])
    return 0
