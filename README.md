# Watchtower — Security Watch for Grok Bot

Every Grok Bot on your account shares one cloud computer: the same browser logins, files and command-line credentials. xAI's own docs say not to treat separate Bots as a security boundary. When you add a template, its skills and routines run with everything your other Bots are signed into, and audit logs, network allowlists and the MCP allowlist are Enterprise-only.

Watchtower is a security officer for that setup. It is read-only until you say yes: it looks, reports and recommends, and changes something only after you approve it in the conversation. It vets templates before you install them, audits your computer and every Bot on it, sets tripwires, sends a weekly threat brief, and tells you the few fixes that matter.

## What it does

| Skill | What you get |
| --- | --- |
| `vet-template` | Install / Install with changes / Do not install for any template, skill or plugin, with a risk score, evidence, its autonomy level (L0 observe → L3 unattended), and the boundary line to paste into its description |
| `watchtower-audit` | A 0–100 posture score and the top three fixes across skills, plugins, MCP configs, Auto Review rules, local execution, logged-in browser sessions, CLI credentials, secrets, vulnerable packages, persistence, integrity drift, canaries and shell history |
| `watchtower-brief` | The weekly report, one page you can read in a minute: status, score, threat level, trend charts, a one-click fix, what needs you, and the three threats that matter to your setup |
| `watchtower-report` | Weekly Markdown report and a self-contained HTML dashboard |
| `watchtower-rollcall` | DMs every Bot one fixed question that asks only for counts, names and yes/no answers (never memory text: Bots can't verify who sends a roll-call), then flags risky memories, routines that send without asking and the lethal trifecta (private data + untrusted input + a way out) |
| `watchtower-prepublish` | PASS/FAIL before you share a Bot as a template: secrets, emails, phone numbers, private doc links, internal hosts, local paths, and a missing approval boundary |
| `watchtower-incident` | Evidence pack first (findings, canaries, changed files, history, processes, connections, jobs), then containment one approved step at a time |
| `watchtower-codescan` | OWASP Top 10 (2021) review of code your Bots write, plus semgrep if installed |
| `watchtower-fix` | The one-yes fix: cleans up, upgrades outdated Python packages, and npm lockfiles in your own projects only after a separate yes (each upgrade is backed up and undone automatically if it breaks something), moves your own dangerous skills into a quarantine folder (nothing is deleted, and each can be restored), and accepts findings that are fine on purpose, after asking you a single question |
| `watchtower-setup` | Pinned, checksummed install; scanners; canaries; first audit and report; routines |
| `watchtower-uninstall` | Removes Watchtower and everything it created (routines, decoys, scanners, caches, its folder) after one yes |

On a template install these are files the Bot reads, not slash commands: ask in plain words ("audit", "fix it", "roll-call", "vet this link", "uninstall").

| Routine | When | Cost |
| --- | --- | --- |
| Daily watch | 06:00 | Silent unless something changed. Scripts only; the model reads a delta under 4 KB. |
| Weekly audit and report | Sunday 05:00 | One audit, one report, one summary. |
| Weekly tidy | Sunday 06:00 | Lists every cache or file it would empty or change, with whose it is, and waits for one yes. |
| Monthly roll-call reminder | Off by default | Opt-in. Only reminds; each roll-call needs the owner's yes. Replies sit in a 0700 folder as 0600 files, are deleted as each is analyzed, and are never scored. |

Every finding carries a rule ID, severity, file and line (secrets masked), the fix, and a mapping to the [OWASP Top 10 for Agentic Applications](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) (ASI), the [OWASP Agentic Skills Top 10](https://owasp.org/www-project-agentic-skills-top-10/) (AST), or the OWASP Top 10 (2021) for code.

## Three engines, one verdict

Skills are checked by Watchtower's own rules, [NVIDIA SkillSpector](https://github.com/nvidia/skillspector) and [husk](https://github.com/ctrl-adam/Husk). A skill flagged by one engine is a lead. A skill flagged by two is a corroborated critical. Your own skills, and any skill that's new or changed, get all three every day; marketplace and first-party skills are checked for malicious indicators, not style. gitleaks finds keys left in files and TruffleHog checks which of them still work, so you only revoke the live ones. pip-audit and OSV-Scanner cover known holes in installed software and project dependencies. The weekly report says which scanners checked your setup.

## Tripwires

`wt.py canary plant` places three decoys (a fake customer export, fake cloud keys, a fake payments .env). Nothing legitimate reads them. If anything opens, deletes or copies one, the next daily run says so. Zero tokens, and the best early warning a non-Enterprise account can get.

## How it stays light

Scripts find, the model judges, you approve. Scanning is deterministic Python with no dependencies of its own. A daily run with nothing new prints `NO_CHANGES` and the Bot stops without reading anything.

## Install (in Grok Bot)

1. Add the Watchtower template from its x.ai link.
2. Say yes when Watchtower asks to set itself up.

Manual install on the cloud computer. First copy the release's full commit ID from the GitHub release page
(https://github.com/ken-aisec/grokbot-watchtower/releases), then use it for both the download and the install, so the
installer itself and everything it installs are pinned:

```bash
COMMIT=<full commit ID from the release page>
mkdir -p /workspace/watchtower && cd /workspace/watchtower
curl -fsSLO "https://raw.githubusercontent.com/ken-aisec/grokbot-watchtower/$COMMIT/scripts/install.sh"
head -40 install.sh && bash install.sh v0.7.1 "$COMMIT"
bash /workspace/watchtower/app/scripts/install.sh --scanners
python3 /workspace/watchtower/app/watchtower/wt.py audit
```

## Built to not break

Every computer is different, so Watchtower assumes things will go wrong and is tested against simulated computers before each release (`tests/test_boxes.py`): empty, very large, odd folder layouts, files that hang naive scanners, a restart mid-run, damaged state files, and scanners that hang, crash, print garbage or disappear.

- The audit has a hard time limit. Every scanner gets only the time that is left.
- A stage that fails is skipped with one line saying so, and its last results are kept. A failure never moves the score and never reports old findings as fixed.
- Only what you own counts toward the score. Built-in plugins and platform updates are listed for information; they count only when two scanners agree one is dangerous.
- One run at a time. No stack traces: one plain line, and `wt.py doctor --save` writes a snapshot you can send to the author.
- Watchtower holds its own tools to the same standard: scanners install from a lock file with a checksum for every package (`scripts/scanners.lock`), nothing is unpacked unless its checksum passes, and the audit checks Watchtower's own scanner packages for known holes.

## CLI

```
wt.py vet FILE|-              vet before installing (exit 1 = Do not install)
wt.py audit | daily           full or quick audit (compact JSON for the Bot)
wt.py report                  weekly report + dashboard.html
wt.py brief [--summary F]     weekly threat brief (HTML)
wt.py rollcall --save <Bot>      save one reply (stdin) as a 0600 file in the private 0700 roll-call folder
wt.py rollcall --owner-said-yes  analyze roll-call replies, keep masked findings, delete the replies
wt.py prepublish PATH         check a Bot before sharing it as a template
wt.py fix                      preview: the cleanup list (path, file count, whose) and everything else
wt.py fix --apply --owner-said-yes [--skip N,..] --upgrade --revet --accept RULES   everything in one pass (after your yes)
wt.py fix --upgrade-projects   npm lockfile fixes in your own projects (its own yes)
wt.py diff SKILL               what changed in a skill since you approved it
wt.py exception add SKILL --reason "..."   keep one named security-tool skill that two scanners flag (30 days)
wt.py accept RULE WHERE --reason "..."   accept one risk on purpose (90 days); WHERE is a whole name (the place, skill
                                         folder name, or "package version"); decoy alarms and Confirmed findings are refused
wt.py accept --all-current RULES         accept everything currently open for those rules
wt.py events list|clear        one-time detections
wt.py canary plant|status      plant the decoys; see what touched them
wt.py canary remove --owner-said-yes   remove the decoys (only after the owner's yes)
wt.py auto-allow [keep IDS --owner-said-yes]   list Allow-automatically lines on consequential actions; keep exact ones after the owner's yes
wt.py incident --note "..."   evidence pack + containment checklist
wt.py codescan PATH           OWASP Top 10 code review
wt.py status                  what a running audit is doing and how long each stage took
wt.py breakdown | show RULE   findings by rule; evidence with context
wt.py baseline [--owner-said-yes]   accept current skills as reviewed (the first one on a computer needs no flag)
wt.py doctor [--save]         a support snapshot of this computer, safe to share (no file contents, keys or skill names)
```

State lives in `$WATCHTOWER_HOME` (default `/workspace/watchtower`). `state/ledger.jsonl` is an append-only record of every run: the audit trail non-Enterprise accounts don't get.

Release drill, dev dry-run (precision plan item 8): before each release the dev build is run read-only against a real install and reports the score line plus every finding above info. Gotcha: don't just point `WATCHTOWER_HOME` at a copy of the state. The real install folder then looks foreign to the dev build (its quarantine and its own state files get flagged) and the score comes out falsely low (a false 41/F on Oct 12, against a real 94/A). Use the sandbox instead: `scripts/dry-run.sh [REF]` runs the dev build in a private mount namespace with `/workspace`, the home folder and `/var/tmp` read-only, a copy of the install's state over its own path (so paths match), and one fresh sandbox folder under `/tmp` as the namespace's `/tmp`. Everything the run writes (code, state copy, caches, planted decoys) lives in that folder and is removed afterwards; only `audit.json` and `audit.err` are kept, in `/tmp/wt-dry-report-<sha>-<time>/`. Never copy a sandbox into `/workspace`: its planted decoys and canary registry copy are real decoy alarms to the daily watch (Oct 15), and the scanner has no name-based skip for them.

## Limits, stated plainly

- It audits after the fact. It can't intercept another Bot's actions in real time; Auto Review is the inline control, and Watchtower checks how you've set it up.
- Static engines can be bypassed. Three independent engines, hash drift, tripwires and history review make that harder, and the reports say they're evidence, not proof.
- Roll-call relies on each Bot describing itself. A compromised Bot could lie, which is why the filesystem evidence comes first.
- Canary reads need a filesystem that records access times; setup tells you if yours doesn't.
- The self-check catches accidental or careless changes to Watchtower's own files, not a Bot that rewrites both the code and the manifest. Every Bot runs as the same user on the same computer, so nothing stops one from editing both.
- The decoy names are random per install, which stops generic snooping, not a targeted attacker who reads Watchtower's state first.
- Grok Bot is in beta and changes weekly. The brief watches xAI's security docs for changes.

## Tests

`make test` runs 220 tests: seeded malicious skills must be caught, clean and defensive text must not be flagged, hostile feed content must not execute in the brief, and every feature has its own test.

## License

Apache-2.0. See `THREAT_MODEL.md`, `EGRESS.md` and `SECURITY.md`.

## Accepted auto-allow lines (WT-A002)

An auto-allow on a consequential action (sending, posting, paying, deleting, an HTTP POST) is always a critical WT-A002.
An owner can accept one exact line on purpose: `wt.py auto-allow` lists the lines with an id (the line's whole sha256), and after the owner's yes
`wt.py auto-allow keep <id> --owner-said-yes` stores its sha256 fingerprint in `state/accepted_auto_allow.json` (this box
only; nothing is shipped, so a line one owner accepted is never accepted for anyone else). A matching line keeps its critical
severity but is filed under Accepted risks, shown in the report and not scored. Any new, edited or broader line has a
different fingerprint and fires.

If Watchtower ran on a computer before and its baseline is later missing, empty or unreadable, that is a high WT-I010
"Watchtower's memory was reset", never a quiet fresh start: nothing is re-approved until the owner says yes to
`wt.py baseline --owner-said-yes`.
Several reviewed skills that changed show as one high WT-I001 line naming every skill.
