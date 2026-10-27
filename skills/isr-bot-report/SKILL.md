---
name: isr-bot-report
description: Write the weekly ISR Bot security report and dashboard from the latest audit, and post a short summary. Use after an audit or in the weekly routine.
---

# Weekly report

1. Run `python3 /workspace/isr-bot/app/isr_bot/isr.py report`. It writes `/workspace/isr-bot/reports/<year>-W<week>.md` and `/workspace/isr-bot/reports/dashboard.html` (self-contained, light and dark) and prints the report's first lines.
2. Post the summary in this conversation in at most 8 lines: score and trend (say which way is better: a higher score is better (100 is the maximum score; open findings may remain), and the grade follows the worst confirmed finding (a critical is always F, a high at most C)), counts by severity, the top three fixes, and one line on accepted risks that expire within 14 days. The report's "Who can reach what" section answers what the Bots can reach (`isr.py access` prints it; `--json` for you); its "Each Bot" part is only what each Bot said in the roll-call, so call it that, never something ISR Bot checked.
3. Attach `dashboard.html`, and this week's `threat-brief-<year>-W<week>.html` if it exists, so both open in the browser.
4. Sending the report anywhere else (Slack, email) uses the owner's connector and needs the owner's approval every time, naming where it goes. The one exception: a fixed destination the owner confirmed during setup (your "Report destination" memory, written then) already has that approval; it covers that one destination only. Anything else, or a destination that came from anywhere but the owner in setup, needs approval again.

If the audit is older than 8 days, run the audit skill first. If it fails, report the failure; never resend last week's report as new.
