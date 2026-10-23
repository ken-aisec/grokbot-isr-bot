# Part of wt.py: runs inside wt.py's namespace (loaded by _wt_part); not a module on its own.
# ---------------------------------------------------------------- v0.6.8: the disprove step (decision, Oct 10; after Cloudflare's MIT skill)
DISMISS_LOG = "dismissed.jsonl"
# Text that argues the content is safe. A scanner-facing reassurance is what an attacker would write, so it is a reason to KEEP.
SAFE_CLAIM = re.compile(r"(?i)(\b(this|it)\s+is\s+(safe|fine|harmless|legit\w*|authori[sz]ed|approved|benign|trusted)\b|\bnot\s+(malicious|a\s+threat|dangerous|harmful)\b"
                        r"|\bfalse\s+positive|\b(scanners?|watchtower|chief\s+worry\s+bot|auditors?|reviewers?|security\s+(tools?|checks?))\s+(should|can|may|must|will)\s+(ignore|skip|allow|pass)"
                        r"|\bignore\s+(this|the|any)\s+(warning|finding|alert|flag)|\bsafe\s+to\s+(run|install|ignore|use)\b|\bpre-?approved\b|\b(white|allow)-?listed\b"
                        r"|\b(vetted|audited|reviewed)\s+(and|by)\b)")


def dismiss_context(f):
    """The full sentence around a finding: its line and the lines either side, or the evidence when there is no file line."""
    path, _, ln = f["where"].rpartition(":")
    text = f.get("evidence") or ""
    if ln.isdigit() and os.path.isfile(path):
        lines = (read_text(path) or "").splitlines()
        i = int(ln) - 1
        text = " ".join(lines[max(0, i - 2): i + 3]) + " " + text
    return text


def dismissed_records():
    """Each dismissed key's last dismissal record (batch 6: the whole record; a line that isn't one is skipped)."""
    out = {}
    for l in (read_text(state_path(DISMISS_LOG)) or "").splitlines():
        try:
            e_ = json.loads(l)
        except ValueError:
            continue
        if isinstance(e_, dict) and e_.get("action") == "dismissed" and isinstance(e_.get("key"), str):
            out[e_["key"]] = e_
    return out


def dismissed_keys():
    return {k: e_.get("reason", "") for k, e_ in dismissed_records().items()}


def dismiss(key, reason):
    """Drop a Worth-a-look finding the Bot has shown is a false alarm, and log why. Never an evidence or Confirmed finding; never
    when the content argues it is safe. Every decision, kept or dropped, goes to state/dismissed.jsonl."""
    snap = load_json(state_path("last_findings.json"), {}) or {}
    rc = load_json(state_path("rollcall_findings.json"), {}) or {}
    fs = snap.get("findings", []) + label_findings(rc.get("findings", []))
    f = next((x for x in fs if x.get("key") == key or x.get("key", "").startswith(key) and len(key) >= 8), None)
    entry = {"at": now(), "key": key, "reason": (reason or "")[:300]}
    if not f:
        ok, why = False, "no such finding in the last audit or roll-call"
    else:
        entry.update(key=f["key"], rule=f["rule"], where=f["where"], cls=f.get("class") or ("evidence" if is_evidence(f) else "pattern"))
        m = SAFE_CLAIM.search(dismiss_context(f))
        if f.get("unverified_platform"):   # item 8 review 1; decision, Oct 18: only a release that lists it clears one
            ok, why = False, "a platform file not on the vendor's release list: only a Chief Worry Bot release that lists it clears it"
        elif is_evidence(f) or entry["cls"] != "pattern":
            ok, why = False, f"{entry['cls']} finding: only Worth-a-look findings can be dropped"
        elif not (reason or "").strip():
            ok, why = False, "give the reason it is a false alarm"
        elif m:
            ok, why = False, f"the text argues it is safe ('{m.group(0)}'), which is a reason to keep it"
        else:
            ok, why = True, "dropped as a false alarm"
    entry.update(action="dismissed" if ok else "kept", why=why)
    os.makedirs(os.path.dirname(state_path(DISMISS_LOG)), exist_ok=True)
    with open(state_path(DISMISS_LOG), "a") as fh:
        fh.write(json.dumps(entry) + "\n")
    return ok, why


def dismissed_since(since):
    out = []
    for l in (read_text(state_path(DISMISS_LOG)) or "").splitlines():
        try:
            e_ = json.loads(l)
        except ValueError:
            continue
        if e_.get("action") == "dismissed" and e_.get("at", "") >= since:
            out.append({"rule": e_.get("rule"), "where": short_path(str(e_.get("where", "")).split(":")[0]) + (":" + e_["where"].rsplit(":", 1)[1] if re.search(r":\d+$", str(e_.get("where", ""))) else ""),
                        "reason": e_.get("reason", "")})
    return out


def cmd_dismiss(args):
    if args.list or not args.key:
        since = args.since or (dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=24)).isoformat()
        rows = dismissed_since(since)
        print(fit({"dismissed": rows}) if rows else "NONE_DISMISSED")
        return 0
    ok, why = dismiss(args.key, args.reason)
    print(("DISMISSED " if ok else "KEPT ") + why)
    return 0 if ok else 1


def cmd_show(args):
    snap = load_json(state_path("last_findings.json"), None)
    if not snap:
        print("ERROR no audit yet", file=sys.stderr)
        return 2
    print(f"score {score_line(snap)}")
    rows = [f for f in snap["findings"] if f["rule"] == args.rule][: args.limit]
    masked = {}   # Codex, batch 4 round 2: the file is masked as a whole, then cut, so no secret beside a finding is printed
    for f in rows:
        print(f"{f['severity']} {f['rule']} [{label_of(f)}] {f['where']}\n  evidence: {mask_secrets(str(f.get('evidence') or ''))}")
        path, _, ln = f["where"].rpartition(":")
        if args.rule in ("WT-T011", "WT-T011x", "WT-S001", "WT-S002", "WT-S003") or not ln.isdigit():
            continue
        if path not in masked:
            masked[path] = mask_lines(read_text(path) or "")
        lines = masked[path]
        i = int(ln) - 1
        ctx = " ".join(lines[max(0, i - 1): i + 2])[:300]
        print(f"  context: {ctx}")
    return 0


def by_sev(fs):
    c = {s: 0 for s in SEV_ORDER}
    for f in fs:
        c[f["severity"]] += 1
    return c


# Batch 5 (d1, decision 2, Oct 18): Grok Bot's own files (scope "platform") keep their severity, label and key inside, so a
# vendor rug pull still alerts and stays Confirmed, but they are never one of the owner's problems: not in open_by_severity, not
# in `new`, not in breakdown's Confirmed list, not in the report's counts or the dashboard's tiles. Each is one plain line in
# "Platform notes" instead. Unverified platform files (WT-I001/I002/I011) are never platform scope and still count.
# PR A, Codex round 1 (5, 7): a platform finding that counts (a real key outside Grok Bot's config: counts() keeps it) is the
# owner's, with its own fix, in every channel; and only a place Watchtower itself vouches for (a platform root, Grok Bot's
# config, its secret store, a system package, the platform's hook) makes a note. A plugin state/plugins.json files as "catalog"
# (the Bot can write that file) stays in the owner's lists, as on 151e40c.
def platform_scope(f):
    return f.get("scope") == "platform" and not f.get("guarded") and not counts(f) and platform_file(f, catalog=False)


def owners(fs):
    """The findings that are the owner's to deal with: everything but platform notes (and platform warning-text records)."""
    return [f for f in fs if not (platform_scope(f) or (f.get("scope") == "platform" and f.get("guarded")))]


def _platform_place(where):
    """(the path, under ~/ when it is in the home folder; the line or "")."""
    path, _, ln = (where or "").rpartition(":")
    if not (ln.isdigit() and path):
        path, ln = where or "", ""
    h = os.path.expanduser("~").rstrip("/") + "/"
    return ("~/" + path[len(h):] if path.startswith(h) else path), ln


def _unlisted(path, unlisted):
    """True when the platform file at `path`, or one inside the folder `path`, is one the release list doesn't include."""
    return path in unlisted or any(u.startswith(path.rstrip("/") + "/") for u in unlisted)


def _note_kind(f, unlisted=()):
    """Which line a platform note gets: "reviewed", "unlisted", "pattern" or "said" (Watchtower would call it <severity>)."""
    if f.get("reviewed"):
        return "reviewed"
    if _unlisted(f["where"].split(":")[0], unlisted):
        return "unlisted"
    if f.get("class") == "platform" and not f.get("platform_hook"):
        return "pattern"
    return "said"


def loud_note(f, unlisted=()):
    """A note whose line says Watchtower would call it critical or high: the ones the daily routine names (Codex round 1, 10)."""
    return _note_kind(f, unlisted) == "said" and (f.get("severity_was") or f["severity"]) in ("critical", "high")


def platform_note_line(f, unlisted=()):
    """One plain line for a platform note. `unlisted`: paths whose platform file the release list doesn't include."""
    short, ln = _platform_place(f.get("where", ""))
    line = f" (line {ln})" if ln else ""
    v = platform_vendor(f["where"].split(":")[0]) if str(f.get("where", "")).startswith("/") else "Grok Bot"
    kind = _note_kind(f, unlisted)
    if kind == "reviewed":   # d2: an exact-bytes entry of rules/platform-reviewed.json; its note is the fix
        return f"{f['fix']} Chief Worry Bot checked this exact text{' (line ' + ln + ')' if ln else ''}; nothing to do."
    if kind == "unlisted":
        return f"{v}'s own folder, {short}{line}: {f['title']}. Not on Chief Worry Bot's release list: its own alert counts, this line doesn't."
    if kind == "pattern":
        return f"{v}'s own file {short}{line}: {f['title']}. A pattern match nothing backs up; not counted."
    sev = f.get("severity_was") or f["severity"]
    said = f"would call {sev}" if sev in ("critical", "high", "medium", "low") else "would list"
    if metadata_hit_note(f):   # batch 6 (B2): a gitleaks hit in a metadata file verified by content (fix round 1: decided afresh)
        return (f"gitleaks {said.replace('would call', 'would call this')} in {v}'s own file {short}{line} ({f['title']}). "
                f"Chief Worry Bot checked that file against the released version: it's {v}'s list of what it loads, so it isn't counted.")
    return (f"{v}'s own file {short}{line}: has text Chief Worry Bot {said} in your own skill ({f['title']}). It isn't counted. "
            f"If it worries you, tell {v} support; Chief Worry Bot keeps it listed.")


def platform_notes(fs, limit):
    """{"count", "loud", "lines"} for the platform notes among `fs`, or None when there are none: `loud` counts those Watchtower
    would call critical or high, whose lines come first (Codex round 1, 10); `lines` holds at most `limit`. `loud` is for the
    caller, which says what it leaves out (notes_more) and never prints it."""
    unlisted, plat = platform_note_order(fs)
    if not plat:
        return None
    return {"count": len(plat), "loud": sum(1 for f in plat if loud_note(f, unlisted)),
            "lines": [platform_note_line(f, unlisted) for f in plat[:limit]]}


def platform_note_order(fs):
    """(the unlisted paths, the platform notes among `fs` in the order platform_notes gives their lines: the loud ones first)."""
    unlisted = {f["where"].split(":")[0] for f in fs if f.get("unverified_platform")}
    plat = [f for f in shown(fs) if platform_scope(f)]
    return unlisted, [f for f in plat if loud_note(f, unlisted)] + [f for f in plat if not loud_note(f, unlisted)]


PLATFORM_NOTES_MORE = "`wt.py breakdown` lists every one"


def notes_more(count, loud, shown_):
    """The `more` line of platform_notes when the first `shown_` of `count` lines (the `loud` ones first) are shown."""
    left, loud = count - shown_, max(0, loud - shown_)
    return (f"{left} more platform note{'' if left == 1 else 's'} not shown here"
            + (f", {loud} of them Chief Worry Bot would call critical or high" if loud else "") + f": {PLATFORM_NOTES_MORE}.")


# ---------------------------------------------------------------- report
def cmd_report(args):
    snap = load_json(state_path("last_findings.json"), None)
    if not snap:
        print("ERROR no audit yet: run `wt audit` first", file=sys.stderr)
        return 2
    hist = load_history()
    week = dt.date.today().isocalendar()
    tag = f"{week[0]}-W{week[1]:02d}"
    rdir = os.path.join(home(), "reports")
    os.makedirs(rdir, exist_ok=True)
    md = render_md(snap, hist, tag)
    with open(os.path.join(rdir, f"{tag}.md"), "w") as f:
        f.write(md)
    with open(os.path.join(rdir, "dashboard.html"), "w") as f:
        f.write(render_html(snap, hist, tag))
    ledger({"event": "report", "week": tag, "score": snap["score"]})
    try:
        print("\n".join(md.splitlines()[:14]))
    except BrokenPipeError:
        pass
    print(f"\nFull report: {rdir}/{tag}.md · Dashboard: {rdir}/dashboard.html")
    return 0


def trend(hist):
    weekly = hist[-1:] if hist else []
    if len(hist) >= 2:
        prev = [h for h in hist if h[0][:10] <= (dt.date.today() - dt.timedelta(days=6)).isoformat()]
        if prev:
            d = hist[-1][1] - prev[-1][1]
            return f"{'+' if d >= 0 else ''}{d} vs last week"
    return "first week"


def render_md(snap, hist, tag):
    warn = [f for f in shown(snap["findings"]) if f.get("guarded")]   # batch 2 (R1): one count line, never a finding
    plat = [f for f in shown(snap["findings"]) if platform_scope(f)]   # v0.7.1 item 4: their own section, never scored
    fs = [f for f in shown(snap["findings"]) if not platform_scope(f) and not f.get("guarded")]   # Codex round 1 (5): a counted one is here
    c = by_sev(fs)
    lines = [f"# Chief Worry Bot report {tag}", "", f"Status: {status_line(snap)}", "",
             f"Score {score_line(snap)} (grade {snap_grade(snap)}), {trend(hist)}. Open findings: "
             f"{c['critical']} critical, {c['high']} high, {c['medium']} medium, {c['low']} low.", "",
             "## Top fixes", ""]
    for i, f in enumerate(fs[:3], 1):
        lines.append(f"{i}. **{f['title']}** ({label_of(f)}; {f['severity']}, {', '.join(f['owasp'])}) at `{f['where']}`. {f['fix']}")
    if not fs:
        lines.append("Nothing to fix this week.")
    amap = load_access_map()
    if amap is not None:   # batch 5 (a): what every Bot can reach, and what each Bot said
        lines += access_md(amap)
    lines += ["", "## All open findings", "", "| Severity | Rule | Finding | Where | Evidence | OWASP |", "| --- | --- | --- | --- | --- | --- |"]
    lines.insert(-3, f"Confirmed: something Chief Worry Bot saw happen, or two checks agree. {MAYBE_FINE}: a wording or pattern match that is often harmless.")
    lines.insert(-3, "")
    lows = [f for f in fs if f["severity"] in ("low", "info")]
    for f in [f for f in fs if f["severity"] not in ("low", "info")]:
        ev = f["evidence"].replace("|", "\\|")
        lines.append(f"| {f['severity']} | {f['rule']} | {label_of(f)}: {f['title']} | `{f['where']}` | {ev} | {', '.join(f['owasp'])} |")
    look = [f for f in fs if f.get("class") == "pattern"]
    tips = [f for f in fs if f.get("class") == "tip"]
    lows = [f for f in lows if f.get("class") not in ("pattern", "tip")]
    if look:
        lines += ["", f"## {MAYBE_FINE}", "", "Pattern matches nothing else backs up. No severity, not in the score."]
        lines += [f"- {f['rule']} {f['title']} at `{f['where']}`: {f['evidence']}" for f in look[:40]]
    if tips:
        lines += ["", "## Tips", "", "Best practice, not problems. No severity, not in the score."]
        lines += [f"- {f['title']} at `{f['where']}`. {f['fix']}" for f in tips[:40]]
    if lows:
        by_rule = {}
        for f in lows:
            by_rule[(f["rule"], f["title"])] = by_rule.get((f["rule"], f["title"]), 0) + 1
        lines += ["", "Hygiene notes (low): " + "; ".join(f"{t} ×{n}" for (r, t), n in sorted(by_rule.items(), key=lambda x: -x[1]))]
    if warn:
        lines += ["", f"{GUARDED_LABEL}: {len(warn)} line{'' if len(warn) == 1 else 's'} that warn against a risky step or quote it as an "
                  "example. Not findings, not in the score. `wt.py breakdown` lists them."]
    if plat:   # batch 5 (d1): one plain line each, outside every count
        unlisted = {f["where"].split(":")[0] for f in snap["findings"] if f.get("unverified_platform")}
        lead = ("Grok Bot's own files, exactly as Chief Worry Bot's release lists them. They don't count toward your problems or your status."
                if not any(_unlisted(f["where"].split(":")[0], unlisted) for f in plat) else
                "Grok Bot's own files. They don't count toward your problems or your status; a file Chief Worry Bot's release list doesn't "
                "include has its own counted alert above.")
        notes = platform_notes(snap["findings"], 40)
        lines += ["", "## Platform notes", "", lead]
        lines += [f"- {l}" for l in notes["lines"]]
        if notes["count"] > len(notes["lines"]):
            lines.append(f"- {notes_more(notes['count'], notes['loud'], len(notes['lines']))}")
    inv = snap.get("inventory", {})
    lines += ["", "## Inventory", "", f"Skills on disk: {inv.get('skills', 0)} · plugin files: {inv.get('plugin_files', 0)} · MCP configs: {inv.get('mcp_configs', 0)}"]
    fyi = [f for f in shown(snap["findings"]) if not counts(f)]
    if fyi:
        lines += ["", "## Built-in plugins and skills (for your information, not counted in the score)", "",
                  f"{len(fyi)} notes about software the platform or a plugin shipped. Nothing here needs you. `wt.py breakdown` lists them."]
    if snap.get("stages_skipped"):
        lines += ["", "## Skipped this run", ""] + [f"- {x}: did not finish, so its last results were kept." for x in snap["stages_skipped"]]
    exc = exceptions_active(snap)
    if exc:
        lines += ["", "## Security-tool exceptions", ""] + [
            f"- ⚠ `{x['skill']}` is flagged by two scanners. You confirmed it is a security tool. Exception ends {x['until']} ({x['days_left']} days) or when the skill changes." for x in exc]
    if snap.get("suppressed"):
        lines += ["", "## Accepted risks", ""] + [f"- {f['rule']} {f['title']} at `{f['where']}`" for f in snap["suppressed"] if not f.get("exception")]
    lb = load_json(state_path("last_brief.json"), None)
    if lb and lb.get("tag") == tag:
        lines += ["", "## Threat brief", "", f"Open `{lb['path']}` in a browser: {len(lb.get('research', []))} research items, "
                  f"{sum(1 for k in lb.get('kev', []) if k.get('relevant'))} relevant exploited vulnerabilities."]
    if snap.get("notes"):
        lines += ["", "## Coverage notes", ""] + [f"- {n}" for n in snap["notes"]]
    lines += ["", f"_Chief Worry Bot {VERSION}, read-only. Scanners can be bypassed; this report is evidence, not proof._", ""]
    return "\n".join(lines)


def extra_sections(fs):
    """Worth a look and Tips: listed below the findings, with no severity."""
    out = ""
    for cls, head, note in (("pattern", MAYBE_FINE, "Pattern matches nothing else backs up. No severity, not in the score."),
                            ("tip", "Tips", "Best practice, not problems. No severity, not in the score."),
                            ("guarded", GUARDED_LABEL, "Lines that warn against a risky step or quote it as an example. Not findings, not in the score.")):
        items = [f for f in fs if f.get("class") == cls][:40]
        if items:
            out += (f"<details><summary>{html.escape(head)} ({len(items)})</summary><p class='mut'>{note}</p><ul>"
                    + "".join(f"<li>{html.escape(f['title'])} <code>{html.escape(f['where'])}</code></li>" for f in items) + "</ul></details>")
    return out


def platform_details(findings):
    """The dashboard's "Platform notes (n)": Grok Bot's own files, one plain line each, outside the tiles and the table."""
    notes = platform_notes(findings, 40)
    if not notes:
        return ""
    more = [notes_more(notes["count"], notes["loud"], len(notes["lines"]))] if notes["count"] > len(notes["lines"]) else []
    return (f"<details><summary>Platform notes ({notes['count']})</summary><p class='mut'>Grok Bot's own files. They don't count toward "
            "your problems or your status.</p><ul>" + "".join(f"<li>{html.escape(l)}</li>" for l in notes["lines"] + more) + "</ul></details>")


def render_html(snap, hist, tag):
    fs = owners(shown(snap["findings"]))   # batch 5 (d1): tiles and table are the owner's findings; platform notes below
    c = by_sev(fs)
    pts = hist[-12:] or [(snap["at"], snap["score"], len(fs))]
    w, h = 320, 70
    step = w / max(1, len(pts) - 1)
    poly = " ".join(f"{round(i * step, 1)},{round(h - p[1] / 100 * h, 1)}" for i, p in enumerate(pts))
    colors = {"critical": "#c0392b", "high": "#d35400", "medium": "#b7950b", "low": "#2e86c1", "info": "#7f8c8d"}
    rows = "".join(
        f"<tr><td><span class='sev' style='background:{colors[f['severity']]}'>{f['severity']}</span></td>"
        f"<td><small>{html.escape(label_of(f))}</small><br>{html.escape(f['title'])}</td><td><code>{html.escape(f['where'])}</code></td>"
        f"<td>{html.escape(', '.join(f['owasp']))}</td><td>{html.escape(f['fix'])}</td></tr>" for f in [x for x in fs if x["severity"] not in ("low", "info")][:60])
    tiles = "".join(f"<div class='tile'><b style='color:{colors[s]}'>{c[s]}</b><span>{s}</span></div>" for s in SEV_ORDER[:4])
    return f"""<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>
<title>Chief Worry Bot {tag}</title><style>
:root{{--bg:#fff;--fg:#1b1f24;--mut:#5b6470;--line:#e3e6ea}}@media(prefers-color-scheme:dark){{:root{{--bg:#111418;--fg:#e8eaed;--mut:#9aa3ad;--line:#2a3038}}}}
body{{font:15px/1.45 system-ui,-apple-system,Segoe UI,sans-serif;background:var(--bg);color:var(--fg);margin:0;padding:24px;max-width:1100px}}
h1{{font-size:20px;margin:0 0 4px}}.mut{{color:var(--mut)}}.row{{display:flex;gap:16px;flex-wrap:wrap;margin:20px 0}}
.card{{border:1px solid var(--line);border-radius:10px;padding:16px}}.big{{font-size:44px;font-weight:700}}
.tile{{border:1px solid var(--line);border-radius:10px;padding:12px 18px;text-align:center}}.tile b{{font-size:26px;display:block}}
table{{border-collapse:collapse;width:100%;font-size:13px}}td,th{{border-bottom:1px solid var(--line);padding:8px;text-align:left;vertical-align:top}}
.sev{{color:#fff;border-radius:4px;padding:2px 6px;font-size:11px;text-transform:uppercase}}.wrap{{overflow-x:auto}}code{{font-size:12px}}
</style></head><body><h1>Chief Worry Bot · {tag}</h1><div class='mut'>Generated {html.escape(snap['at'])} · read-only audit of this Grok Bot computer</div>
<div class='row'><div class='card'><div class='mut'>Status</div><div style='font-size:24px;font-weight:700'>{html.escape(status_line(snap))}</div><div class='mut'>Posture score</div><div class='big'>{snap['score']}<span class='mut' style='font-size:18px'>/100 · {snap_grade(snap)}</span></div><div class='mut'>{html.escape(score_line(snap))}</div><div class='mut'>{trend(hist)}</div></div>
<div class='card'><div class='mut'>Score, last {len(pts)} runs</div><svg width='{w}' height='{h}' viewBox='0 0 {w} {h}' role='img' aria-label='score trend'><polyline fill='none' stroke='#2e86c1' stroke-width='2' points='{poly}'/></svg></div>
{tiles}</div><h2 style='font-size:16px'>Open findings</h2><div class='wrap'><table><tr><th>Severity</th><th>Finding</th><th>Where</th><th>OWASP</th><th>Fix</th></tr>{rows or "<tr><td colspan=5>Nothing open.</td></tr>"}</table></div>
{access_card(load_access_map())}{extra_sections(fs)}{platform_details(snap["findings"])}
<p style='margin-top:16px'>{f"<a href='threat-brief-{tag}.html'>Open this week's threat brief →</a>" if os.path.exists(os.path.join(home(), "reports", f"threat-brief-{tag}.html")) else ""}</p>
<p class='mut' style='margin-top:20px'>Chief Worry Bot {VERSION}. Scanners can be bypassed; this is evidence, not proof.</p></body></html>"""
