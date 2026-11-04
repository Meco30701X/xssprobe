# XSSProbe handoff

Updated: 2026-11-04 (Asia/Shanghai)

## Objective and safety boundary

Continue improving XSSProbe against the two user-selected teaching labs:

- `https://hokokh.github.io/xss/xss-%E9%9D%B6%E5%9C%BA/`
- `https://aiwadongdemumu.com/xss-lab/`

Measure page-level results with harmless `window.xssTriggered` canaries and independent Playwright ground truth. Never submit stored-XSS content. Do not read or exfiltrate cookies, or change email/account state. The two stored lessons and two harm-demonstration lessons on the second lab remain excluded.

## Current measured results

The tested unit is one challenge level or one negative-control index page. Ground truth comes from the lab's stated vulnerable context plus an independent Playwright check of whether the harmless canary executed; the XSSProbe result is evaluated against that label. The combined detector predicts positive when dynamic execution is confirmed or a high-confidence, high-severity source-to-sink finding is present. An `unknown` source / sink-only heuristic is a manual-review lead, not a positive XSS prediction.

- Tested: 26 safe challenge levels plus 2 index-page negative controls (28 cases total).
- Positive labels: 13 on `hokokh` (levels 01–03 and 05–14) and 12 on `aiwadongdemumu` (01, 03–10, 12–14).
- Negative labels: `hokokh` level 04 and both index controls.
- Combined dynamic + high-confidence detector: TP=25, TN=3, FP=0, FN=0; accuracy=100%, precision=100%, recall=100%.
- Static-only at the high-confidence/high-severity threshold: TP=5, TN=3, FP=0, FN=20; accuracy=28.6%, precision=100%, recall=20%. The overall score depends on dynamic verification; the static analyzer still misses many real flows hidden in helper functions, server-reflected HTML, and context-specific filters.
- Nine unlinked sink heuristics appeared across the tested levels. Reports now label them as unconfirmed sink-only review leads rather than source-to-sink XSS findings.
- The two jQuery pages load `https://code.jquery.com/jquery-3.6.0.min.js`. The CLI tests explicitly used `-scope aiwadongdemumu.com,code.jquery.com`; the request audit confirms the CDN was allowed only because it was explicitly listed. Low-confidence third-party library heuristics are suppressed while stronger flows remain.

Per-level classification:

- `hokokh`: 01 TP, 02 TP, 03 TP, 04 TN, 05 TP, 06 TP, 07 TP, 08 TP, 09 TP, 10 TP, 11 TP, 12 TP, 13 TP, 14 TP.
- `aiwadongdemumu`: 01 TP, 03 TP, 04 TP, 05 TP, 06 TP, 07 TP, 08 TP, 09 TP, 10 TP, 12 TP, 13 TP, 14 TP.
- Excluded on `aiwadongdemumu`: 02 and 11 require stored submissions; 15 demonstrates cookie theft; 16 changes the victim email. No stored submission, cookie read/exfiltration, or email change was performed.

Independent negative evidence for `hokokh` level 04: the page replaces `<` with `&lt;` before assigning the content to `innerHTML`; direct query and form-driven marker checks did not execute. Its remaining low `unknown → innerHTML` report is explicitly classified as sink-only.

Default safe-canary smoke checks (no custom `-payload`) confirmed automatic selection in representative contexts: `aiwadongdemumu` 05 (marker-only JavaScript link), 06 (hashchange), 07 (focus), 09 (JS-string context), and `hokokh` 03 (JS-string context), 06 (hover), 14 (30-character truncation). After the final hash ordering change, target2 level 06 confirmed in 1 attempt, target2 level 09 in 6, and Hoko level 14 in 16. These canaries use in-page markers only and stop before alert/exfil payload tiers. Attempt counts include failed safe-canary probes and are not request-rate measures.

## Changes made for these results

- `-scope` now accepts a comma-separated host allowlist while preserving exact/subdomain boundary checks. Its default recommendation remains the target host only.
- Batch mode now honors `-payload-merge=false`; it no longer silently drops custom-only payloads.
- `-verify` accepts an optional value, so numeric forms must be written `-verify=1` (not `-verify 1`, which makes Go's flag parser stop before later flags). README examples were corrected.
- Hash tests now use fragment escaping (`%20`, not query-style `+`) and toggle the fragment to exercise `hashchange`. The verifier tests one representative HTML hash canary first, then prioritizes query/reflected-context payloads, and checks remaining hash contexts only if no query canary confirms; this removes duplicate hash replays while preserving fallback coverage.
- Browser interception sends Fetch continue/fail commands through the active target CDP executor directly, avoiding a navigation/request-interception wait cycle.
- Automatic interactions are restricted to exact marker-only handlers: an exact `javascript:window.xssTriggered=true/*...*/` link (including a fixed anchor wrapper), an exact focus handler, or exact hover handlers. Arbitrary JavaScript URLs and custom event code are not auto-activated.
- The built-in safe-canary portfolio now covers JS single/double strings, script-tag breakout, template expressions, focus, hover, JavaScript links, attribute breakouts, and compact truncated-input markers. No canary reads cookies or sends network data.
- Low-confidence findings from third-party scripts outside the same allowlisted scope are suppressed; higher-confidence source-to-sink flows remain. Sink-only static findings are described as unlinked manual-review leads in terminal and HTML reports.

## Verification

- Focused tests passed for `compliance`, `scanner`, `verifier`, and `payloads`; the final `go test ./...`, `go build -buildvcs=false`, and `git diff --check` passed after the code changes. Re-run them if any source changes are made after this handoff.
- A two-URL batch smoke scan with `-payload-merge=false` confirmed both selected safe target2 levels, validating the batch fix.
- Per-level JSON, logs, and audit records are in `%TEMP%\xssprobe-hokokh-perlevel\` and `%TEMP%\xssprobe-aiwadong-perlevel\`; the latest final-build retests use `*-post-hash-final.json`. Index controls use `%TEMP%\xssprobe-lab-controls\*-post-hash.json`. Default-canary examples are in `%TEMP%\xssprobe-default-smoke\`; the final batch smoke record is in `%TEMP%\xssprobe-batch-smoke-post-hash\`.
- The 50-case hand-authored scanner corpus remains a regression test only; do not present its score as field accuracy.

## Next useful work

1. Improve static flow recovery across helper functions and separate script files; the current line-oriented analyzer's high-confidence recall was 20% on the tested combined matrix even though dynamic verification reached every positive case.
2. Improve contextual filter modeling so case-sensitive or partial regex replacements do not look like strong sanitizers.
3. Keep `unknown` sink-only heuristics separate from actionable vulnerability findings, and retain the current confidence caveat in reports.
4. Preserve the safety exclusions above. Do not add stored submissions, cookie access/exfiltration, or email/account mutations to automated regression runs.
