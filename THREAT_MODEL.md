# Watchtower threat model

Watchtower runs on the same shared Grok Bot computer it audits, so it is held to the rules it enforces.

## What it defends
| Risk | OWASP | Check |
| --- | --- | --- |
| Malicious or trojaned template or skill | AST01, AST02, ASI04 | `vet`, text rules, optional SkillSpector/husk |
| Prompt injection in skills | AST05, LLM01 | WT-T001, T002, T008 |
| Over-privileged routines, missing approval lines | AST03, ASI02 | WT-T013, R002, R003, T014 |
| Broad Auto Review allow rules | ASI03, ASI09 | WT-A001–A003 |
| Local execution on Always allow | ASI03, ASI05 | WT-C001 |
| Secrets on the shared computer or in shareable configs | AST04, LLM02 | WT-T011, S001, S002 |
| Update drift after review | AST07 | WT-I001 |
| Persistence (cron, units, shell rc) | ASI10 | WT-P001 |
| Unpinned MCP servers, vulnerable packages | AST02, ASI04 | WT-M001, D001 |
| Memory poisoning | ASI06 | roll-call: WT-M010 from each Bot's own counts (no memory text is asked for or kept) |
| Roll-call sent by someone else | ASI03, ASI07 | the question asks only for counts, names and yes/no answers; replies 0600 in a 0700 folder, deleted as read; WT-R011 when a Bot answers with content |
| Lethal trifecta on one Bot | ASI01, ASI02 | WT-L001 |
| Data theft in progress | ASI03, ASI10 | canaries: WT-K001–K003 |
| Commands nobody meant to run | ASI05, ASI10 | shell history: WT-H001–H009 |
| Secrets or private links shipped in a template | AST04, LLM02 | pre-publish: WT-PP01–PP07 |
| Vulnerable code written by Bots | OWASP Top 10 (2021) | codescan: WT-WA01–WA10 |
| Evasion of a single scanner | AST08 | three engines; WT-X001–X003 |

## What it trusts
The pinned release verified against `MANIFEST.sha256`; Python's standard library; the user's answers during setup. A file in the platform's own skill folders (`.grok/bundled`, the managed skills, `.codex/skills/.system`, `.claude/plugins/synced`) is trusted when the release's `rules/platform-release.lock` lists its path and exact sha256, or (the middle path, an owner decision of Oct 22) when it is a new or changed file at a path that already exists (a release-list line with any hash, or a `baseline.json` line), or in a new platform skill folder that appears in an update run, that Watchtower's whole rule set finds nothing at medium or above in (exactly the bytes it fingerprinted, every decoded string value of a metadata file included), that no other finding at medium or above is on (a grouped finding counts for each file it stands for, and one that doesn't name them all, such as a line saved by an earlier version, holds every file under its folder until a scan that finishes names them), that no two scanners name a dangerous behavior in, and that is no link, no file with a colon in its path, no file outside the platform folder where the home folder really has it (checked again after the scanners, before the refresh line is made and the audit accepts anything, and right before the baseline is written: one that moved by then is a counted high and keeps its old baseline hash; a move after that last check is seen on the next run) and no file over 1 MB. It rolls into the baseline only when every check of it finished. A new skill folder already there when a baseline is taken without one to compare with (`wt.py baseline` included) stays a counted high. Never by the owner's yes, a record in Watchtower's state or the ledger.

## What it does not trust
Every file it scans, every web page and feed it reads, and every reply from another Bot. They are data. An instruction found in them is a finding.

## Known gaps
- The self-check holds the installed copy to its own `MANIFEST.sha256`, so it shows changes made after the install, not who made them. Watchtower runs as the Bot's user, and the Bot can write to `/workspace/watchtower`. A Bot that rewrites `MANIFEST.sha256` together with the files it lists before a run passes the self-check, and so do `scripts/scanner-bins.lock` and its reader (a scanner the Bot chose then counts as verified). The same Bot could rewrite `wt.py` itself. Inside one run, Watchtower uses the manifest it checked at the start and never reads it again. If the lock, its reader or the folder behind `app` changes after the self-check, every scanner is reported as changed (WT-X005). Only a reinstall from the pinned release (setup, section 1) restores the release. install.sh, the setup skill's version check, the daily and tidy routines and the audit skill start `wt.py` with `python3 -I`, so a module planted next to it (`watchtower/argparse.py`) can't run before the self-check. The other skills still start it without `-I`.
- The platform release list was filled on Oct 18 from the maintainer's Grok Bot box, after Bots had run on it (an owner decision): it vouches for the bytes that box had then, not for a clean vendor install. Since Oct 22 (the middle path) a vendor update at a path that already exists, or a new platform skill folder, is the quiet "Platform refresh" line and rolls into the baseline when Watchtower's checks pass; a loose file, a link, a flagged or oversized file stays a counted high until a release lists it.
- The middle path means a plant that reuses an existing platform path, or forms a new clean platform skill folder, and passes every check is quiet too. The quiet line still names every file it covers (its `files` list), in daily and in the full audit that accepts it, so the owner can see it.
- `baseline.json` is Bot-writable: a Bot that writes a baseline line for a path makes that path "already existing" for the middle path (accepted by the owner, Oct 22). `state/engine_cache.json` is Bot-writable too: a forged clean answer hides a scanner vote, but Watchtower's own rules still read the file's bytes in every run. So are `state/last_findings.json` and `state/platform_held.json`, which remember that a skill folder was already there on a first run (or when `wt.py baseline` took the first baseline): deleting both lets that folder look new on the next run.
- The release list is only as trustworthy as the release: anyone who can change a Watchtower release, or a Bot that rewrites both the lock and `MANIFEST.sha256` (the gap above), can list a file. A development checkout without `MANIFEST.sha256` uses the lock unchecked.

## Out of scope
Connector OAuth tokens (kept on Cursor's backend), other users' computers, model serving, and anything that requires Enterprise APIs.
