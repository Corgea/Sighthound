#!/usr/bin/env python3
"""Consolidate normalized findings from bench/run_bench.py for multiple tools
and produce a head-to-head comparison (speed, TP/FP/FN, precision, recall, F1).

Every tool is scored with the identical matching logic from bench/score.py
(set-based CWE membership, +/-25 line window, greedy 1:1 assignment,
in-scope FP gating) so the numbers are directly comparable.

Usage:
  python3 bench/compare.py bench/results/sighthound.json \
      bench/results/semgrep.json bench/results/opengrep.json \
      --report bench/COMPARISON.md
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from score import (  # noqa: E402
    Counts, Finding, LABELS, lang_of, norm_cwe, parse_labels,
    rel_to_fixture, score_findings,
)


def build_findings(fixture: str, raw_findings: list[dict]) -> list[Finding]:
    out: list[Finding] = []
    for f in raw_findings:
        rel = rel_to_fixture(f.get("file", ""), fixture)
        cwes = {norm_cwe(c) for c in (f.get("cwes") or []) if c}
        primary = next(iter(sorted(cwes)), "")
        out.append(Finding(rel, int(f.get("line", 0)), primary, lang_of(rel), f, cwes))
    return out


def score_tool(payload: dict, exact: bool):
    """Return (overall Counts, {lang: Counts}, total_seconds, n_datasets)."""
    overall = Counts()
    by_lang: dict[str, Counts] = {}
    total_time = 0.0
    datasets = payload.get("datasets", {})
    for fixture, d in datasets.items():
        toml_path = LABELS / f"{fixture}.toml"
        if not toml_path.exists():
            continue
        labels = parse_labels(toml_path, fixture)
        findings = build_findings(fixture, d.get("findings", []))
        res = score_findings(fixture, labels, findings, exact, float(d.get("elapsed", 0.0)))
        total_time += res.elapsed
        for lang, c in res.by_lang.items():
            overall.add(c)
            by_lang.setdefault(lang, Counts()).add(c)
    return overall, by_lang, total_time, len(datasets)


def fmt_metrics(c: Counts, strict: bool) -> str:
    m = c.metrics(strict)
    return f"{m['precision']:.2f}/{m['recall']:.2f}/{m['f1']:.2f}"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("results", nargs="+", help="normalized result JSON files")
    ap.add_argument("--exact", action="store_true", help="exact-CWE only")
    ap.add_argument("--report", help="write a markdown report to this path")
    ap.add_argument("--langs", nargs="*", help="restrict per-language table to these langs")
    args = ap.parse_args()

    tools = []
    for path in args.results:
        payload = json.loads(Path(path).read_text())
        overall, by_lang, total_time, n = score_tool(payload, args.exact)
        tools.append({
            "name": payload.get("tool", Path(path).stem),
            "config": payload.get("config", ""),
            "overall": overall,
            "by_lang": by_lang,
            "time": total_time,
            "datasets": n,
        })

    view = "EXACT-CWE" if args.exact else "LENIENT-CWE"
    all_langs = sorted({l for t in tools for l in t["by_lang"]})
    if args.langs:
        all_langs = [l for l in all_langs if l in args.langs]

    lines: list[str] = []

    def out(s: str = "") -> None:
        lines.append(s)
        print(s)

    out(f"# Tool comparison ({view})\n")
    out(f"Datasets scored per tool: " + ", ".join(f"{t['name']}={t['datasets']}" for t in tools))
    out("")
    out("## Overall (strict precision view, all languages)\n")
    hdr = f"| {'tool':<12} | {'config':<14} | {'time(s)':>8} | {'TP':>4} | {'FP':>4} | {'FN':>4} | {'prec':>5} | {'recall':>6} | {'F1':>5} |"
    sep = "|" + "|".join(["-" * w for w in (14, 16, 10, 6, 6, 6, 7, 8, 7)]) + "|"
    out(hdr)
    out(sep)
    for t in tools:
        c = t["overall"]
        m = c.metrics(strict=True)
        cfg = (t["config"] or "-")[:14]
        out(f"| {t['name']:<12} | {cfg:<14} | {t['time']:>8.2f} | {c.tp:>4} | {c.fp_strict:>4} | {c.fn:>4} | {m['precision']:>5.2f} | {m['recall']:>6.2f} | {m['f1']:>5.2f} |")

    out("\n## Per-language strict P/R/F1 (TP/FN/FP)\n")
    head = "| lang | " + " | ".join(t["name"] for t in tools) + " |"
    out(head)
    out("|" + "----|" * (len(tools) + 1))
    for lang in all_langs:
        cells = []
        for t in tools:
            c = t["by_lang"].get(lang)
            if c is None or (c.tp + c.fn + c.fp_strict) == 0:
                cells.append("-")
            else:
                cells.append(f"{fmt_metrics(c, True)} ({c.tp}/{c.fn}/{c.fp_strict})")
        out(f"| {lang} | " + " | ".join(cells) + " |")

    out("\n## Notes\n")
    out("- **Scoring**: identical matching for all tools - set-based CWE membership, "
        "+/-25 line window, greedy 1:1 finding<->label assignment, FP accounting "
        "scoped to languages each dataset actually labels.")
    out("- **strict** precision counts any in-scope unmatched finding as a FP "
        "(the semgrep/opengrep-comparable view).")
    out("- **time(s)** is summed per-dataset wall-clock (includes each tool's "
        "per-invocation startup cost).")

    if args.report:
        Path(args.report).write_text("\n".join(lines) + "\n")
        sys.stderr.write(f"\nreport written -> {args.report}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
