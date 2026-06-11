# Tool comparison (LENIENT-CWE)

Datasets scored per tool: sighthound=31, semgrep=31

## Overall (strict precision view, all languages)

| tool         | config         |  time(s) |   TP |   FP |   FN |  prec | recall |    F1 |
|--------------|----------------|----------|------|------|------|-------|--------|-------|
| sighthound   | -              |   120.62 |  236 |   23 |  300 |  0.91 |   0.44 |  0.59 |
| semgrep      | p/default      |   811.29 |   71 |  691 |  465 |  0.09 |   0.13 |  0.11 |

## Per-language strict P/R/F1 (TP/FN/FP)

| lang | sighthound | semgrep |
|----|----|----|
| csharp | 1.00/0.53/0.69 (29/26/0) | 0.37/0.13/0.19 (7/48/12) |
| html | 1.00/0.88/0.93 (7/1/0) | 0.00/0.00/0.00 (0/8/26) |
| java | 0.94/0.76/0.84 (60/19/4) | 0.87/0.16/0.28 (13/66/2) |
| javascript | 0.91/0.64/0.75 (98/56/10) | 0.56/0.12/0.20 (19/135/15) |
| other | 1.00/0.00/0.00 (0/4/0) | 1.00/0.00/0.00 (0/4/0) |
| php | 1.00/0.00/0.00 (0/78/0) | 0.02/0.14/0.03 (11/67/578) |
| python | 0.82/0.27/0.40 (42/116/9) | 0.27/0.13/0.18 (21/137/58) |

## Speed (controlled, sequential — no CPU contention)

Same three representative datasets, run one tool at a time:

| dataset | files | sighthound | semgrep (p/default) | speedup |
|----|----|----|----|----|
| insecure-app | ~10 | 0.14s | 23.41s | **167x** |
| coffee-shop-java | 62 | 4.08s | 23.75s | **5.8x** |
| insecure-xben-030-24 | 3105 | 57.94s | 153.39s | **2.6x** |
| **total** | | **62.2s** | **200.6s** | **3.2x** |

Semgrep carries a ~23s fixed per-invocation cost (Python startup + rule
compilation), so Sighthound's advantage is largest on small/medium repos and
narrows to ~2.6x on the largest corpus where scan work dominates.

> The `time(s)` column in the table above is the full 31-dataset run captured
> while the three scan agents ran **in parallel** (CPU-contended), so treat the
> controlled table here as the authoritative speed figures.

## Notes / caveats

- **Scoring**: identical matching for both tools - set-based CWE membership, +/-25 line window, greedy 1:1 finding<->label assignment, FP accounting scoped to languages each dataset actually labels.
- **strict** precision counts any in-scope unmatched finding as a FP (the semgrep/opengrep-comparable view).
- **Semgrep config = `p/default`**: `--config auto` (Semgrep's stronger, recommended ruleset) requires a logged-in account/token, which was not available here, so the no-login community pack `p/default` was used. Semgrep's results would likely improve with `auto` or the paid Pro rules — the numbers above reflect the free/no-login experience.
- **Semgrep scans languages Sighthound does not target** (notably PHP: 578 in-scope FPs from p/default on the PHP fixtures), which inflates its FP count under strict scoring. Even excluding PHP, Sighthound leads on precision, recall and F1 in every shared language.
- **Sighthound used its file-based rules** (verified at parity with the embedded/shipped ruleset).
- **Opengrep was skipped** per request. It was installed (v1.22.0) and run, but opengrep aborts rule loading if *any* file under `--config` fails schema validation (one invalid rule in the full `opengrep-rules` repo zeroed out all results); pointing it at the corpus-relevant language rule dirs fixed this (37 findings on a probe) but the full run was not completed.
