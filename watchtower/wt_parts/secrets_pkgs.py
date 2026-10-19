# Part of wt.py: runs inside wt.py's namespace (loaded by _wt_part); not a module on its own.
GITLEAKS_CONFIG = r"""[extend]
useDefault = true

[[allowlists]]
description = "Watchtower: package caches, lockfiles, headers and its own state"
paths = [
  '''(^|/)(go/pkg|pkg/mod|\.local/go|node_modules|\.cache|\.npm|\.venv|site-packages|dist-packages)/''',
  '''(^|/)\.config/(google-chrome[^/]*|chromium[^/]*|BraveSoftware)/''',
  '''(^|/)scoped_dir[^/]*/''',
  '''(^|/)chrome-profile/''',
  '''(^|/)(\.codex/auth\.json|\.claude/\.credentials\.json|\.config/gh/hosts\.yml|\.aws/credentials|\.git-credentials|\.netrc|\.docker/config\.json|\.npmrc)$''',
  '''(^|/)watchtower/(state|reports|app|\.venv|scanners|bin)/''',
  '''chrome-cookie-seed\.json$''',
  '''\.h$''',
  '''(^|/)(package-lock\.json|pnpm-lock\.yaml|yarn\.lock|go\.sum|Cargo\.lock|marketplace\.json)$''',
]
regexTarget = "line"
regexes = [
  '''(?i)x-amz-(credential|signature|security-token)=''',
  '''(?i)[?&](AWSAccessKeyId|Signature|Expires)=''',
]

[[allowlists]]
description = "A bare 40-character hex string is a git commit, not a Sourcegraph token"
targetRules = ["sourcegraph-access-token"]
regexTarget = "secret"
regexes = ['''^[a-fA-F0-9]{40}$''']

[[allowlists]]
description = "A code name made of short lowercase words and version numbers (eapi-grok-4-3-internal, self.eapi_4_3_x_algo) is not a key"
targetRules = ["generic-api-key"]
regexTarget = "secret"
regexes = ['''^((([a-z]{1,12}|[0-9]{1,4})[._-])*[0-9]{1,4}([._-]([a-z]{1,12}|[0-9]{1,4}))+|(([a-z]{1,12}|[0-9]{1,4})[._-])+[0-9]{1,4})$''']

[[allowlists]]
description = "A paging cursor (next_token, nextPageToken, prev_cursor...) in an API result is not a key. Matched on the found text, not the line"
targetRules = ["generic-api-key"]
regexTarget = "match"
regexes = ['''(?i)^["']?(next|prev|previous|page|pagination|continuation)_?(page_?)?(token|cursor)\b''']
"""


# Batch 6 (B5, DQ-043/044): no name-based skips. The tests/, fixtures/ and *.test.* path skips and the line rule that hid a whole
# line next to "token" and a $VAR, <...> or xxxx (so token=$X api_key=<a real key> was hidden) are gone; each hit's own secret is
# judged by its content instead (gitleaks_example), the same check as Watchtower's own rule (secret_kind).
GITLEAKS_READ_LIMIT = 5_000_000   # gitleaks reads files up to --max-target-megabytes 5
GITLEAKS_ONE_PIECE = 10_000       # gitleaks reads a file 100 KB at a time; well before that, a line is never a piece's first


def _int_field(leak, k):
    v = leak.get(k)
    return v if isinstance(v, int) and not isinstance(v, bool) else None


def _fill(match, text):
    """The secret when `text` is gitleaks' Match with each REDACTED put back as one same secret; None otherwise. Both ends of
    text are fixed, so the secret's length, and the secret, follow from the length alone."""
    parts = match.split("REDACTED")
    k, rest = len(parts) - 1, len(text) - sum(len(p) for p in parts)
    if k < 1 or rest <= 0 or rest % k:
        return None
    s = text[len(parts[0]):len(parts[0]) + rest // k]
    return s if s.join(parts) == text else None


def gitleaks_secret(leak, data):
    """Fix round 1 (Codex 1): (secret, its whole source line, where it starts in that line) for one gitleaks hit, read from
    `data` (the file's bytes as Watchtower read them once) at exactly the place gitleaks reported: StartLine/StartColumn to
    EndLine/EndColumn, in bytes. gitleaks counts a column from 1 on the first line of what it read at once and from 2 on the
    lines after (it counts the line break before), and trims line breaks from the ends of its Match; where a line may be
    either, both counts are tried. The bytes there must be gitleaks' Match exactly (it runs with --redact: each REDACTED is the
    same secret, so the secret follows from the length) and the secret must have gitleaks' Entropy. None, and the hit is kept
    as it is, unless exactly one place fits: no field, no Entropy, another text there, bytes that aren't UTF-8, or two places
    that both fit. No other text on the line is ever picked."""
    match = leak.get("Match")
    sl, el, sc, ec = (_int_field(leak, k) for k in ("StartLine", "EndLine", "StartColumn", "EndColumn"))
    want = leak.get("Entropy")
    if (not isinstance(match, str) or "REDACTED" not in match or not isinstance(data, bytes) or None in (sl, el, sc, ec)
            or not isinstance(want, (int, float)) or isinstance(want, bool) or want < 0):
        return None
    starts = [0] + [m.end() for m in re.finditer(b"\n", data)]
    if not (1 <= sl <= el <= len(starts)):
        return None
    # (start, end) count: line 1 is the first line gitleaks read at once; a later line is, too, only where gitleaks may have
    # started a new piece of a long file (it reads 100 KB at a time; any line past GITLEAKS_ONE_PIECE is taken as maybe one)
    first = (1, 0 if sl == el else 1)
    counts = [first] if sl == 1 else [(2, 1)] + ([first] if starts[sl - 1] >= GITLEAKS_ONE_PIECE else [])
    found = set()
    for ds, de in counts:
        a, b = starts[sl - 1] + sc - ds, starts[el - 1] + ec - de
        if not (0 <= a < b <= len(data)):
            continue
        raw = data[a:b]
        lead = len(raw) - len(raw.lstrip(b"\n"))
        try:
            text = raw.strip(b"\n").decode("utf-8")
        except UnicodeDecodeError:
            continue
        secret = _fill(match, text)
        if secret is None or abs(shannon_entropy(secret) - float(want)) > 1e-5:   # gitleaks writes Entropy as a float32
            continue
        at = a + lead + len(match.split("REDACTED")[0].encode("utf-8"))
        found.add((at, at + len(secret.encode("utf-8"))))
    if len(found) != 1:
        return None
    s, e = found.pop()
    ls = data.rfind(b"\n", 0, s) + 1
    le = data.find(b"\n", e)
    try:
        line = data[ls:len(data) if le < 0 else le].decode("utf-8").rstrip("\r")
        return data[s:e].decode("utf-8"), line, len(data[ls:s].decode("utf-8"))
    except UnicodeDecodeError:
        return None


def shannon_entropy(s):
    """Shannon entropy of s per byte of UTF-8, as gitleaks computes its Entropy."""
    import math
    if not s:
        return 0.0
    counts, n = {}, len(s.encode("utf-8"))
    for c in s:
        counts[c] = counts.get(c, 0) + 1
    return -sum(k / n * math.log2(k / n) for k in counts.values())


def gitleaks_example(leak, datas):
    """True when a gitleaks hit's own secret, read at gitleaks' place in the file's bytes (gitleaks_secret), is an example
    value (secret_kind): a whole placeholder or environment-variable reference, a key block whose body isn't a key, a checksum
    by its line's format. The file's bytes are read once per run (`datas`: a plain file, never through a link, at most
    GITLEAKS_READ_LIMIT); anything that can't be read there is kept. gitleaks_findings then keeps the verdict only when gitleaks
    gives the same hit on those very bytes (example_bound)."""
    p = leak.get("File")
    if not isinstance(p, str) or not p:
        return False
    if p not in datas:
        datas[p] = _read_plain(p, GITLEAKS_READ_LIMIT)
    found = gitleaks_secret(leak, datas[p])
    if not found:
        return False
    secret, line, at = found
    return secret_kind(secret, line=line, at=at)[0] == "example"


def _leak_mark(leak):
    return json.dumps([leak.get(k) for k in _LEAK_FIELDS], sort_keys=True, default=str)


def example_bound(exe, cfg, pending, datas):
    """Fix round 1 (Codex 1): {file: marks} of the example hits (`pending`: file -> hits judged example) that gitleaks also
    gives, exactly (rule, lines, columns, Match, Entropy), on a private copy of the bytes they were judged on (scan_copies). A
    file changed between gitleaks' read and Watchtower's, or a copy gitleaks can't scan, binds nothing: its hits count."""
    files = [fp for fp in pending if isinstance(datas.get(fp), bytes)]
    leaks = scan_copies(exe, cfg, [(os.path.basename(fp), datas[fp]) for fp in files], "gitleaks-examples.json") if files else None
    if leaks is None:
        return {}
    return {fp: {_leak_mark(l) for l in mine} for fp, mine in zip(files, leaks)}


GROUPED_DIRS = ("/agent-transcripts", "/agent-tools", "/.cursor/projects")
TOOL_CACHE_DIRS = ("/agent-tools",)


VENDOR_CODE = ("/plugins/", "/plugin-cache/", "/managed-skills/", "/skills-library/", "/.agents/skills/", "/.codex/skills/", "/.grok/bundled/")


def secret_severity(path, generic):
    """Documentation-style hits in shipped plugin code are medium; real token types in tool caches are high
    (usually someone else's token inside an API response); anywhere else a real token type is critical."""
    if generic or vendor_root_path(path):   # item 8 (R3): a real vendor folder, never a name in the path
        return "medium"
    if any(x in path for x in TOOL_CACHE_DIRS):
        return "high"
    return "critical"


def group_dir(fpath):
    """Folders that fill up with machine output are grouped at their top, not per subfolder."""
    fpath = fpath or ""
    for g in GROUPED_DIRS:
        i = fpath.find(g + "/")
        if i >= 0:
            return fpath[:i + len(g)]
    return os.path.dirname(fpath)


def gitleaks_findings(roots, notes):
    exe = tool("gitleaks")
    if not exe:
        scanner_absent(notes, "gitleaks", "gitleaks not installed: secrets checked with Watchtower's rules only.")
        return []
    out = []
    cfg = state_path("gitleaks.toml")
    with open(cfg, "w") as f:
        f.write(GITLEAKS_CONFIG)
    tmp = state_path("gitleaks.json")
    for r in roots:
        r = os.path.expanduser(r)
        if not os.path.isdir(r):
            continue
        try:
            os.remove(tmp)
        except OSError:
            pass
        code, _, err = run([exe, "detect", "--source", r, "--no-git", "--redact", "--config", cfg, "--report-format", "json",
                            "--report-path", tmp, "--exit-code", "0", "--max-target-megabytes", "5"], 180)
        if code != 0 or not os.path.exists(tmp):
            reason = next((l for l in re.sub(r"\x1b\[[0-9;]*m", "", err).splitlines() if "FTL" in l or "error" in l.lower()), err.strip()[:160] or "no report written")
            fail_note(notes, f"gitleaks FAILED on {r} ({reason.strip()[-160:]}): secrets there were NOT checked by gitleaks.")
            continue
        per_file, all_hits, decoys, skipped_tool, examples, datas, order, pending = {}, {}, canary_paths(), 0, 0, {}, [], {}
        for leak in load_json(tmp, []) or []:
            if not isinstance(leak, dict):
                continue
            if os.path.abspath(str(leak.get("File") or "")) in decoys:
                continue
            if is_platform_secret_store(str(leak.get("File") or "")):
                continue                                  # Ken, Oct 13: the platform's masked-secret store is one Platform note (WT-I009)
            if in_toolchain_tree(str(leak.get("File") or "")):
                skipped_tool += 1
                continue                                  # item 8 dry run: test vectors in a language toolchain or package store                                  # Watchtower's own decoys (their names are this install's, not in this config)
            all_hits.setdefault(leak.get("File"), []).append(leak)   # metadata_bound compares every hit in the file, examples too
            ex = gitleaks_example(leak, datas)
            if ex:
                pending.setdefault(leak.get("File"), []).append(leak)
            order.append((leak, ex))
        # batch 6 (B5): example hits are left out before the per-file and folder grouping, so fakes never make a group; fix round
        # 1 (Codex 1): only those gitleaks gives again on the very bytes they were judged on
        bound_ex = example_bound(exe, cfg, pending, datas) if pending else {}
        datas.clear()
        for leak, ex in order:
            if ex and _leak_mark(leak) in bound_ex.get(leak.get("File"), ()):
                examples += 1
                continue
            per_file.setdefault(leak.get("File"), []).append(leak)
        by_dir = {}
        for fpath in per_file:
            by_dir.setdefault(group_dir(fpath), []).append(fpath)
        for d, files in by_dir.items():
            if len(files) >= 4 or any(x in d for x in GROUPED_DIRS):  # transcripts, tool output: one finding per folder
                leaks = [l for fp in files for l in per_file.pop(fp)]
                kinds = sorted({l.get("RuleID", "secret") for l in leaks})
                generic = all(k.startswith("generic") for k in kinds)
                cache = any(x in d for x in TOOL_CACHE_DIRS)
                sev = secret_severity(d + "/", generic)
                why = ("Tool-overflow cache: oversized API results (Notion pages, GitHub payloads) land here and any Bot can read them. "
                       "Hits are often third-party tokens inside those payloads. Check for any of yours, then clear the folder; it refills on its own."
                       if cache else "Check which of these tokens are still live and revoke them, then clear the folder or move it off "
                       "the shared computer. Transcripts and tool output often capture tokens by accident.")
                # name the files and lines: the folder alone sent the owner re-running gitleaks to find the hit. The files in
                # these folders come and go, so the finding keeps one name (ident) while its evidence changes
                locs = [f"{os.path.relpath(l.get('File') or d, d)}:{l.get('StartLine')}" for l in leaks]
                at = ", ".join(locs[:3]) + (f" and {len(locs) - 3} more" if len(locs) > 3 else "")
                out.append(finding("WT-S002", f"gitleaks: secrets in {len(files)} {'file' if len(files) == 1 else 'files'} under {os.path.basename(d)}", sev,
                                   ["ASI03", "LLM02"], d, f"{len(leaks)} hit(s): {', '.join(kinds)[:60]} at {at}", why, source="gitleaks",
                                   ident="gitleaks:" + ",".join(kinds)))
        # fix round 1 (Codex 2): hits gitleaks also gives on the verified bytes. The copy's scan has the example hits batch 6 (B5)
        # dropped above, so each file is compared with all of its hits; a file with only example hits is in neither list
        bound = metadata_bound(exe, cfg, {fp: all_hits[fp] for fp in per_file})
        for fpath, leaks in per_file.items():
            kinds = sorted({l.get("RuleID", "secret") for l in leaks})
            generic = all(k.startswith("generic") for k in kinds)
            out.append(finding("WT-S002", "gitleaks: secrets in file", secret_severity(fpath or "", generic), ["ASI03", "LLM02"],
                               f"{fpath}:{leaks[0].get('StartLine')}", f"{len(leaks)} hit(s): {', '.join(kinds)[:100]}",
                               "Check whether these are live credentials. Revoke live ones, then delete or scrub the file.", source="gitleaks",
                               path=fpath if isinstance(fpath, str) and fpath.startswith("/") else None))
            if fpath in bound:
                out[-1]["metadata_sha256"] = bound[fpath]   # what metadata_hit_note holds the file to; never enough on its own
        if examples:
            notes.append(f"gitleaks: {examples} hit(s) were example values (FAKE or placeholder text, an environment variable name, "
                         "a key block that isn't a real key, or a file's checksum), not listed.")
        if skipped_tool:
            notes.append(f"gitleaks: {skipped_tool} hit(s) in language toolchains and package stores (Go, pnpm, ...) not listed: "
                         "those are the tools' own test keys. A key TruffleHog proves live is still reported wherever it is.")
        try:
            os.remove(tmp)
        except OSError:
            pass
    return out


_LEAK_FIELDS = ("RuleID", "StartLine", "EndLine", "StartColumn", "EndColumn", "Match", "Secret", "Entropy")


def _leak_marks(leaks):
    """What gitleaks reported for each hit in one file, but the file's name, in an order two scans can be compared in."""
    return sorted(json.dumps([l.get(k) for k in _LEAK_FIELDS], sort_keys=True, default=str) for l in leaks)


def metadata_bound(exe, cfg, per_file):
    """Batch 6 fix round 1 (Codex 2): {file: sha256} for the files among `per_file` (gitleaks' hits by file, from the scan of
    the folders) that this run verified by content (VERIFIED_METADATA holds the bytes it verified) and on whose verified bytes
    gitleaks gives exactly the same hits. Verification happens before gitleaks reads the folders, so the file it scanned may
    not be the one verified; the hits are bound to the verified bytes only when a private copy of them, written from memory
    (a new 0700 folder, each file 0400, never through a link), gives the same ones and is unchanged after the scan (inode,
    change time, size, bytes). metadata_hit_note then also needs the file itself to have those bytes still. Anything else binds
    nothing, and the hit counts."""
    files = [(fp, VERIFIED_METADATA[os.path.normpath(fp)]) for fp in per_file
             if isinstance(fp, str) and fp.startswith("/") and os.path.normpath(fp) in VERIFIED_METADATA]
    if not files:
        return {}
    leaks = scan_copies(exe, cfg, [(os.path.basename(fp), data) for fp, data in files], "gitleaks-metadata.json")
    if leaks is None:
        return {}
    return {fp: hashlib.sha256(data).hexdigest() for (fp, data), mine in zip(files, leaks)
            if mine and _leak_marks(mine) == _leak_marks(per_file[fp])}


def scan_copies(exe, cfg, named, report_name):
    """gitleaks' hits on private copies of some bytes, one list per (name, bytes) in `named`, in order; None when anything
    is off. The copies are written from memory (a new 0700 folder, each file 0400 in its own folder under its name, never
    through a link) and must be unchanged after the scan (inode, change time, size, bytes). (metadata_bound's private scan,
    shared with example_bound in batch 6 fix round 1.)"""
    tmp, report = None, state_path(report_name)
    try:
        tmp = tempfile.mkdtemp(prefix="wt-metadata-")
        copies = []
        for i, (name, data) in enumerate(named):
            d = os.path.join(tmp, str(i))
            os.mkdir(d, 0o700)
            q = os.path.join(d, name)
            fd = os.open(q, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o400)
            try:
                view = memoryview(data)
                while view:
                    view = view[os.write(fd, view):]
            finally:
                os.close(fd)
            copies.append((data, q))

        def marks():
            return [(x, st.st_ino, st.st_dev, st.st_ctime_ns, st.st_mtime_ns, st.st_size, st.st_mode, st.st_nlink)
                    for x in [tmp] + [y for _, q in copies for y in (os.path.dirname(q), q)] for st in (os.lstat(x),)]
        before = marks()
        try:
            os.remove(report)
        except OSError:
            pass
        code, _, _ = run([exe, "detect", "--source", tmp, "--no-git", "--redact", "--config", cfg, "--report-format", "json",
                          "--report-path", report, "--exit-code", "0", "--max-target-megabytes", "5"], 180)
        leaks = load_json(report, None) if code == 0 else None
        if not isinstance(leaks, list) or marks() != before or any(_read_plain(q, len(data)) != data for data, q in copies):
            return None
        return [[l for l in leaks if isinstance(l, dict) and os.path.normpath(str(l.get("File") or "")) == q] for _, q in copies]
    except (OSError, ValueError):
        return None
    finally:
        try:
            os.remove(report)
        except OSError:
            pass
        if tmp:
            shutil.rmtree(tmp, ignore_errors=True)


TOOLCHAIN_TREE = re.compile(r"/\.local/go[^/]*/|/\.local/share/pnpm/|/go/pkg/mod/|/\.rustup/toolchains/|/\.cargo/registry/")


def in_toolchain_tree(p):
    """Item 8 dry run (Oct 13): a Go toolchain kept as a rollback (~/.local/go.prev-1.27.1) and the pnpm store gave 11 gitleaks
    lines from their own crypto test vectors. SKIP_PATH_PARTS already skipped ~/.local/go/ for the other stages."""
    return bool(TOOLCHAIN_TREE.search(os.path.normpath(os.path.abspath(p)) + "/"))


def installed_python_packages():
    """Packages in the computer's own Python, not Watchtower's venv."""
    py = "/usr/bin/python3" if os.path.exists("/usr/bin/python3") else (shutil.which("python3") or "python3")
    code, out_s, _ = run([py, "-m", "pip", "list", "--format", "json", "--disable-pip-version-check"], 60)
    try:
        return {p["name"]: p["version"] for p in json.loads(out_s)}
    except (ValueError, KeyError, TypeError):
        return {}


def user_python_packages():
    """Packages the user (or a Bot) installed themselves with pip. Everything else came with the computer."""
    py = "/usr/bin/python3" if os.path.exists("/usr/bin/python3") else (shutil.which("python3") or "python3")
    code, out_s, _ = run([py, "-m", "pip", "list", "--user", "--format", "json", "--disable-pip-version-check"], 60)
    try:
        return {p["name"].lower() for p in json.loads(out_s)}
    except (ValueError, KeyError, TypeError, AttributeError):
        return set()


def package_findings(notes):
    exe = tool("pip-audit")
    if not exe:
        scanner_absent(notes, "pip-audit", "pip-audit not installed: installed Python packages not checked for known vulnerabilities.")
        return []
    pkgs = installed_python_packages()
    if not pkgs:
        return []
    req = state_path("installed-requirements.txt")
    with open(req, "w") as f:
        f.write("\n".join(f"{n}=={v}" for n, v in sorted(pkgs.items())))
    code, out_s, err = run([exe, "-r", req, "--no-deps", "--disable-pip", "-f", "json", "--progress-spinner", "off"], 120)
    out = []
    try:
        data = json.loads(out_s)
        if not isinstance(data, dict):
            raise ValueError
    except ValueError:
        fail_note(notes, f"pip-audit FAILED ({(err.strip().splitlines() or ['no answer'])[-1][:120]}): installed Python packages were NOT checked this run.")
        return []
    mine = user_python_packages()
    for d in (data.get("dependencies", []) if isinstance(data, dict) else []):
        vulns = d.get("vulns", [])
        if not vulns:
            continue
        fixes = sorted({fv for v in vulns for fv in v.get("fix_versions", [])}, key=vtuple)
        ids = list(dict.fromkeys(v.get("id", "") for v in vulns))
        if str(d.get("name", "")).lower() not in mine:      # came with the computer: the platform's to update, not the user's
            out.append(finding("WT-D001", f"Built-in Python package {d.get('name')} {d.get('version')} has known holes", "low", ["ASI04", "AST02"],
                               f"system python package {d.get('name')}", f"{len(ids)} known: {', '.join(ids[:4])}{'…' if len(ids) > 4 else ''}",
                               "It came with the computer and every Bot shares it. The platform's updates fix it; Watchtower doesn't touch system packages.",
                               source="pip-audit", ident=f"{d.get('name')} {d.get('version')}"))
            continue
        out.append(finding("WT-D001", f"Vulnerable package {d.get('name')} {d.get('version')}", "high", ["ASI04", "AST02"],
                           f"python package {d.get('name')}", f"{len(ids)} known: {', '.join(ids[:4])}{'…' if len(ids) > 4 else ''}",
                           f"Upgrade to {fixes[-1]} or later." if fixes else "No fixed version yet; remove it if nothing needs it.",
                           source="pip-audit"))
    save_json(state_path("package_vulns.json"), {"at": now(), "packages": len(pkgs), "findings": out})
    return out


def scanners_python():
    """Watchtower's scanner venv Python (scanners/bin/python), only when it leads to the pinned, root-owned interpreter
    (trusted_interpreter). run() starts it as that interpreter, never through the link."""
    py = os.path.join(scanner_bin(), "python")
    return py if os.path.lexists(py) and trusted_interpreter(py) else None


def self_findings(notes):
    """Watchtower holds its own tools to the same standard: known holes in the scanners' packages, and whether they were
    installed from the checksum lock."""
    py, exe, out = scanners_python(), tool("pip-audit"), []
    update_notes(notes)
    if not py:
        # Codex, batch 3 round 1: a missing or refused scanner Python returned here with the stage marked finished, so last
        # run's WT-W001 lines read as fixed. When there is a Python that isn't trusted, or there were W001 results to keep,
        # this is "not checked", never "clean". A computer that never had the scanners stays a plain skip, as before.
        if os.path.lexists(os.path.join(scanner_bin(), "python")) or carry(("WT-W001",)):
            fail_note(notes, "Watchtower's own tools were NOT checked for known holes this run (its scanner Python is missing or "
                             "isn't the computer's own); the last results are kept.")
        return out
    if not os.path.isfile(os.path.join(os.path.dirname(os.path.dirname(py)), "LOCKED")):
        out.append(finding("WT-W002", "Watchtower's scanners were installed without the checksum lock", "low", ["ASI04", "AST02"], "watchtower scanners",
                           "no LOCKED marker", "Run `bash /workspace/watchtower/app/scripts/install.sh --scanners` again; it installs only from the lock, and stops and says why if this computer's Python doesn't fit it."))
    if not exe:
        if scanner_unavailable("pip-audit")[0]:   # batch 3: pip-audit's own line says why; this stage's last results are kept too
            fail_note(notes, "Watchtower's own tools were NOT checked for known holes this run (pip-audit didn't run); the last results are kept.")
        return out
    code, out_s, _ = run([py, "-m", "pip", "list", "--format", "json", "--disable-pip-version-check"], 60)
    try:
        pkgs = {p_["name"]: p_["version"] for p_ in json.loads(out_s)}
    except (ValueError, KeyError, TypeError):
        fail_note(notes, "Watchtower's own tools FAILED to list their packages: they were NOT checked this run.")
        return out
    req = state_path("scanner-requirements.txt")
    with open(req, "w") as f:
        f.write("\n".join(f"{n}=={v}" for n, v in sorted(pkgs.items()) if n.lower() != "skillspector"))
    code, out_s, err = run([exe, "-r", req, "--no-deps", "--disable-pip", "-f", "json", "--progress-spinner", "off"], 90)
    try:
        data = json.loads(out_s)
        deps = data.get("dependencies", [])
    except (ValueError, AttributeError):
        fail_note(notes, f"Watchtower's own tools FAILED their package check ({(err.strip().splitlines() or ['no answer'])[-1][:100]}): NOT checked this run.")
        return out
    for d in deps:
        if d.get("vulns"):
            ids = list(dict.fromkeys(v.get("id", "") for v in d["vulns"]))
            out.append(finding("WT-W001", f"Watchtower's own tool needs an update: {d.get('name')} {d.get('version')}", "low", ["ASI04", "AST02"],
                               "watchtower scanners", f"{len(ids)} known: {', '.join(ids[:3])}",
                               "Update Watchtower: each release carries newer pinned scanners. This package lives only in Watchtower's own folder.", source="pip-audit"))
    return out
