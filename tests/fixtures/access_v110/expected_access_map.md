# ISR Bot access map 2026-W45

Observation `obs-20261108T100000Z` · observed 2026-11-08T10:00:00+00:00 UTC (Nov 8 5:00 AM ET) · ISR Bot 1.1.0 · scope: ~

Both ISR Bot artifacts this week come from this one observation. Read-only: ISR Bot changed nothing.

## Coverage

| Area | This observation |
| --- | --- |
| Browser cookie files | complete |
| Command-line sign-ins | complete |
| Allowed without asking | complete |
| Tool connections (MCP) | incomplete: something there couldn't be read |
| Plugins | complete |
| Chat webhooks | from the last audit \(Nov 7\), not observed here |
| Scheduled jobs | complete |
| Hooks | complete |
| Files with live-looking keys | from the last audit \(Nov 7\), not observed here |
| CLI sign-in file names (lstat) | complete |
| Roll-call answers | complete |
| Bot list (roster and agent profiles) | complete |

## History limits

- Stored in a folder any process running as this user can write; not tamper-proof and not authenticated. Sanitizing bounds its shape, not its truth or completeness.
- Compared with the prior record `obs-20261101T100000Z`, written 2026-11-01T10:00:00+00:00 by ISR Bot 1.1.0.
- Kept: the newest 12 observations.

## Platform context

- Platform context supplied to ISR Bot's developer (not observed): Real browser sessions are per\-agent; the OS filesystem is shared\. (platform context supplied to ISR Bot's developer via the ISR Bot relay, 2026-11-08)

- Approval rules are review policy, not technical isolation; the policy layer is not a sandbox.

## On this computer's shared files

Observed here Nov 8 5:00 AM ET (status only), except each line marked "from the last audit": From the last audit Nov 7, not observed here.

Your Bots run on one computer and share its files. The first list is what ISR Bot found on those files; which Bot can actually use each item isn't checked. Each Bot's own browser sessions and connectors are separate.

- Browser cookie files on this computer: signed in to 3 sites, including mail\.google\.com \(whether any Bot's browser uses them isn't checked\)\.
- Command\-line sign\-ins: OpenAI Codex CLI login\.
- Allowed without asking: no Allow\-automatically rules\.
- Running programs: Bots ask you first \(Execution on Local Computer: Ask every time\)\.
- Tool connections \(MCP\): 1 tool in 1 file: github\.
- Plugins: none\.

## CLI sign-in files (status only)

Observed here Nov 8 5:00 AM ET (status only): each known name was looked at with lstat; no file was opened and no link was followed.

- ~/\.codex/auth\.json (OpenAI Codex CLI login): present; mode 0600: mode bits permit owner read only; owned by ISR Bot's uid.
- ~/\.netrc (netrc logins): a link (target not checked); the link is owned by ISR Bot's uid.
- ~/\.npmrc (npm token): present; mode 0640: mode bits permit group read; owned by ISR Bot's uid.
- Not found: ~/\.aws/credentials, ~/\.claude/\.credentials\.json, ~/\.config/gcloud/credentials\.db, ~/\.config/gh/hosts\.yml, ~/\.docker/config\.json, ~/\.git\-credentials.
- Effective readability by other Bots: not determined (their uids, ACLs, parent-folder permissions and link targets are not checked).

## Each Bot

Said by each Bot about itself in the roll-call, not checked; sender not verified. A Bot's claim is kept under that Bot only.

- `b-0dbd957052` (bot\-001, id from its agent folder): said on Nov 7: connectors Gmail; 1 routines (0 send without asking). Said by b-0dbd957052, not checked; sender not verified.
- `b-61e3eef9c2` (bot\-002, id from its name: a rename looks like a new Bot): said on Nov 7: connectors Gmail, Slack; 1 routines (0 send without asking). Said by b-61e3eef9c2, not checked; sender not verified.
- `b-6ee9098578` (bot\-003 \*bold\* \[x\]\(\[link\], id from its name: a rename looks like a new Bot): not heard from in the roll-call.

## Changes since the last record

- Compared with the prior record \`obs\-20261101T100000Z\`, written 2026\-11\-01T10:00:00\+00:00 by ISR Bot 1\.1\.0\.
- Tool connections \(MCP\): not comparable \(incomplete: something there couldn't be read\)
- Tool connections \(MCP\): not seen this time: 2 tools in all
- Tool connections \(MCP\): not seen this time: notion
- Chat webhooks: not comparable \(from the last audit \(Nov 7\), not observed here\)
- Files with live\-looking keys: not comparable \(from the last audit \(Nov 7\), not observed here\)
- CLI sign\-in file names \(lstat\): new: ~/\.netrc: a link \(target not checked\); the link is owned by ISR Bot's uid
- CLI sign\-in file names \(lstat\): new: ~/\.npmrc: present; mode 0640: mode bits permit group read; owned by ISR Bot's uid
- b\-61e3eef9c2 \(bot\-002\): said now: Slack \(said by b\-61e3eef9c2, not checked; sender not verified\)
- b\-6ee9098578 \(bot\-003 \*bold\* \[x\]\(\[link\]\): new in this record

## Unresolved scope

- Tool connections (MCP): incomplete: something there couldn't be read.
- Chat webhooks: from the last audit (Nov 7), not observed here.
- Files with live-looking keys: from the last audit (Nov 7), not observed here.
- Which connectors a Bot uses, except what it said in the roll-call. The Grok Bot app keeps that list, not this computer.
- Routines and when they run: the Grok Bot app keeps them, not this computer.
- What each sign-in or connector is allowed to do at its service (its permissions there).
- Which Bots can actually read each file: their OS users, ACLs and folder permissions aren't checked. Each Bot's browser sessions are its own (platform context, not observed).
- What's inside memories, messages or saved passwords. ISR Bot never reads them.
- Effective readability by other Bots: not determined (their uids, ACLs, parent-folder permissions and link targets are not checked).
- A connector a Bot names is not authorization: what it may do at its service isn't checked.
- Approval rules are review policy, not technical isolation; the policy layer is not a sandbox.
