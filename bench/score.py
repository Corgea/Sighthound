#!/usr/bin/env python3
"""Score Sighthound against the fusion-benchmarks label TOMLs.

For each labeled dataset we run the release binary with file-based rules,
match findings to labeled vulnerabilities, and report per-language /
per-CWE precision, recall and F1 in two views:

  * strict   - any in-scope finding not matching a labeled [[finding]] is an FP
               (semgrep/opengrep-comparable).
  * bench    - only findings landing on a [[hard_negative]] / [[confirmed_fp]]
               count as FP (the lenient fusion-scoreboard style).

Usage:
  python3 bench/score.py [--lang LANG] [--exact] [--json] [--dataset STEM]
                         [--bin PATH] [--quiet]
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
DATASETS = REPO / "fusion-benchmarks" / "datasets"
LABELS = REPO / "fusion-benchmarks" / "labels" / "datasets"
DEFAULT_BIN = REPO / "target" / "release" / "sighthound"

LINE_WINDOW = 25  # mirrors fusion scoreboard span-aware distance

# Extension -> language bucket used for per-language aggregation.
EXT_LANG = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".java": "java",
    ".cs": "csharp",
    ".go": "go",
    ".rb": "ruby",
    ".php": "php",
    ".html": "html",
    ".htm": "html",
    ".twig": "php",
    ".c": "c",
    ".h": "c",
}


def lang_of(path: str) -> str:
    return EXT_LANG.get(Path(path).suffix.lower(), "other")


def norm_cwe(cwe: str | None) -> str:
    if not cwe:
        return ""
    return cwe.strip().upper().replace("CWE_", "CWE-")


def rel_to_fixture(path: str, fixture: str) -> str:
    """Return the path tail after the fixture-name segment.

    Label paths use prefixes like `insecure_k8/<fixture>/...` or
    `datasets/<fixture>/...`; finding paths are `fusion-benchmarks/datasets/
    <fixture>/...`. Splitting on `/<fixture>/` normalizes both sides.
    """
    needle = f"/{fixture}/"
    norm = path.replace("\\", "/")
    idx = norm.rfind(needle)
    if idx != -1:
        return norm[idx + len(needle):]
    # Fixture name may be the leading segment with no prefix.
    if norm.startswith(f"{fixture}/"):
        return norm[len(fixture) + 1:]
    return norm


@dataclass
class Label:
    path: str          # fixture-relative
    target_line: int
    line_lo: int
    line_hi: int
    cwes: set[str]
    lang: str
    kind: str          # "tp" | "neg"


@dataclass
class Finding:
    path: str          # fixture-relative
    line: int
    cwe: str           # primary CWE (for display / by-CWE bucketing)
    lang: str
    raw: dict
    cwes: set[str] = field(default_factory=set)  # all CWEs a finding carries

    def __post_init__(self) -> None:
        if not self.cwes and self.cwe:
            self.cwes = {self.cwe}


@dataclass
class Counts:
    tp: int = 0
    fn: int = 0
    fp_strict: int = 0
    fp_bench: int = 0

    def add(self, other: "Counts") -> None:
        self.tp += other.tp
        self.fn += other.fn
        self.fp_strict += other.fp_strict
        self.fp_bench += other.fp_bench

    def metrics(self, strict: bool) -> dict:
        fp = self.fp_strict if strict else self.fp_bench
        prec = self.tp / (self.tp + fp) if (self.tp + fp) else 1.0
        rec = self.tp / (self.tp + self.fn) if (self.tp + self.fn) else 1.0
        f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
        return {
            "tp": self.tp,
            "fn": self.fn,
            "fp": fp,
            "precision": round(prec, 4),
            "recall": round(rec, 4),
            "f1": round(f1, 4),
        }


def parse_labels(toml_path: Path, fixture: str) -> list[Label]:
    data = tomllib.loads(toml_path.read_text())
    labels: list[Label] = []

    def make(block: dict, kind: str) -> Label | None:
        path = block.get("path")
        if not path:
            return None
        rng = block.get("line_range") or []
        tline = int(block.get("target_line") or (rng[0] if rng else 0))
        lo = int(rng[0]) if rng else tline
        hi = int(rng[1]) if len(rng) > 1 else tline
        cwes: set[str] = set()
        if block.get("target_cwe"):
            cwes.add(norm_cwe(block["target_cwe"]))
        for c in block.get("acceptable_cwes") or []:
            cwes.add(norm_cwe(c))
        rel = rel_to_fixture(path, fixture)
        return Label(rel, tline, lo, hi, cwes, lang_of(rel), kind)

    for block in data.get("finding", []):
        lbl = make(block, "tp")
        if lbl:
            labels.append(lbl)
    for key in ("confirmed_fp", "hard_negative"):
        for block in data.get(key, []):
            lbl = make(block, "neg")
            if lbl:
                labels.append(lbl)
    return labels


def run_scanner(binpath: Path, fixture_dir: Path, quiet: bool) -> tuple[list[dict], float]:
    cmd = [str(binpath), str(fixture_dir), "--output-format", "json", "--use-file-rules"]
    start = time.perf_counter()
    proc = subprocess.run(cmd, capture_output=True, text=True)
    elapsed = time.perf_counter() - start
    out = proc.stdout.strip()
    if not out:
        if not quiet and proc.returncode != 0:
            sys.stderr.write(f"  scanner stderr: {proc.stderr[-400:]}\n")
        return [], elapsed
    try:
        return json.loads(out), elapsed
    except json.JSONDecodeError:
        # Binary may emit progress before JSON; grab the JSON array tail.
        brace = out.find("[")
        if brace != -1:
            try:
                return json.loads(out[brace:]), elapsed
            except json.JSONDecodeError:
                pass
        if not quiet:
            sys.stderr.write(f"  could not parse JSON for {fixture_dir.name}\n")
        return [], elapsed


def to_findings(raw: list[dict], fixture: str) -> list[Finding]:
    out: list[Finding] = []
    for f in raw:
        path = f.get("file", "")
        rel = rel_to_fixture(path, fixture)
        out.append(Finding(rel, int(f.get("line", 0)), norm_cwe(f.get("cwe_id")), lang_of(rel), f))
    return out


def cwe_match(finding_cwes: set[str], label_cwes: set[str], exact: bool) -> bool:
    if not label_cwes:
        return True
    if not finding_cwes:
        return False
    # A finding matches if any CWE it carries is in the label's accepted set.
    # `exact` and lenient behave the same here because labels already merge
    # target_cwe + acceptable_cwes into one set.
    return bool(finding_cwes & label_cwes)


def line_distance(finding_line: int, label: Label) -> int:
    if label.line_lo <= finding_line <= label.line_hi:
        return 0
    return min(abs(finding_line - label.line_lo), abs(finding_line - label.line_hi),
               abs(finding_line - label.target_line))


@dataclass
class DatasetResult:
    fixture: str
    elapsed: float
    by_lang: dict[str, Counts] = field(default_factory=dict)
    by_cwe: dict[str, Counts] = field(default_factory=dict)
    unmatched: list[Finding] = field(default_factory=list)
    missed: list[Label] = field(default_factory=list)


def score_dataset(fixture: str, binpath: Path, exact: bool, quiet: bool) -> DatasetResult | None:
    toml_path = LABELS / f"{fixture}.toml"
    fixture_dir = DATASETS / fixture
    if not toml_path.exists() or not fixture_dir.exists():
        return None

    labels = parse_labels(toml_path, fixture)
    raw, elapsed = run_scanner(binpath, fixture_dir, quiet)
    findings = to_findings(raw, fixture)
    return score_findings(fixture, labels, findings, exact, elapsed)


def score_findings(
    fixture: str,
    labels: list[Label],
    findings: list[Finding],
    exact: bool,
    elapsed: float,
) -> DatasetResult:
    """Match a tool's findings against labels and tally TP/FN/FP.

    Pure scoring step shared by Sighthound (score_dataset) and the external
    tool comparison (bench/compare.py); identical matching keeps the
    cross-tool numbers apples-to-apples.
    """
    res = DatasetResult(fixture=fixture, elapsed=elapsed)

    tp_labels = [l for l in labels if l.kind == "tp"]
    neg_labels = [l for l in labels if l.kind == "neg"]

    # Scope FP accounting to languages this dataset actually curates. A finding
    # in a language with no labels here (e.g. vendored/bundled JS shipped inside
    # a PHP challenge app) is out of scope and must not be chased as an FP —
    # this mirrors the fusion scoreboard's per-fixture gate.
    langs_in_scope = {l.lang for l in labels}

    # Build candidate edges (finding -> tp label) for greedy 1:1 assignment.
    edges: list[tuple[int, int, int]] = []  # (distance, finding_idx, label_idx)
    for fi, fnd in enumerate(findings):
        for li, lbl in enumerate(tp_labels):
            if fnd.path != lbl.path and not (
                fnd.path.endswith(lbl.path) or lbl.path.endswith(fnd.path)
            ):
                continue
            if not cwe_match(fnd.cwes, lbl.cwes, exact):
                continue
            dist = line_distance(fnd.line, lbl)
            if dist <= LINE_WINDOW:
                edges.append((dist, fi, li))

    edges.sort(key=lambda e: (e[0], e[1], e[2]))
    claimed_findings: set[int] = set()
    claimed_labels: set[int] = set()
    for dist, fi, li in edges:
        if fi in claimed_findings or li in claimed_labels:
            continue
        claimed_findings.add(fi)
        claimed_labels.add(li)

    def lang_counts(lang: str) -> Counts:
        return res.by_lang.setdefault(lang, Counts())

    def cwe_counts(cwe: str) -> Counts:
        return res.by_cwe.setdefault(cwe or "UNKNOWN", Counts())

    # TP and FN from labels.
    for li, lbl in enumerate(tp_labels):
        canon = next(iter(sorted(lbl.cwes)), "UNKNOWN")
        if li in claimed_labels:
            lang_counts(lbl.lang).tp += 1
            cwe_counts(canon).tp += 1
        else:
            lang_counts(lbl.lang).fn += 1
            cwe_counts(canon).fn += 1
            res.missed.append(lbl)

    # FP accounting for unclaimed findings.
    for fi, fnd in enumerate(findings):
        if fi in claimed_findings:
            continue
        if fnd.lang in ("other",) or fnd.lang not in langs_in_scope:
            continue
        # Does it land on a negative label? -> bench FP.
        on_neg = any(
            (fnd.path == nl.path or fnd.path.endswith(nl.path) or nl.path.endswith(fnd.path))
            and line_distance(fnd.line, nl) <= LINE_WINDOW
            for nl in neg_labels
        )
        lc = lang_counts(fnd.lang)
        lc.fp_strict += 1
        if on_neg:
            lc.fp_bench += 1
        canon = fnd.cwe or "UNKNOWN"
        cc = cwe_counts(canon)
        cc.fp_strict += 1
        if on_neg:
            cc.fp_bench += 1
        res.unmatched.append(fnd)

    return res


def aggregate(results: list[DatasetResult]) -> dict[str, Counts]:
    agg: dict[str, Counts] = {}
    for r in results:
        for lang, c in r.by_lang.items():
            agg.setdefault(lang, Counts()).add(c)
    return agg


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--lang", help="restrict reporting to one language bucket")
    ap.add_argument("--dataset", help="restrict to one dataset stem")
    ap.add_argument("--exact", action="store_true", help="exact-CWE only (no acceptable-CWE credit)")
    ap.add_argument("--json", action="store_true", help="emit JSON instead of a table")
    ap.add_argument("--bin", default=str(DEFAULT_BIN), help="path to sighthound binary")
    ap.add_argument("--quiet", action="store_true", help="suppress scanner stderr")
    ap.add_argument("--details", action="store_true", help="print missed/unmatched detail")
    args = ap.parse_args()

    binpath = Path(args.bin)
    if not binpath.exists():
        sys.stderr.write(f"binary not found: {binpath}\n  build with: cargo build --release\n")
        return 2

    stems = sorted(p.stem for p in LABELS.glob("*.toml"))
    if args.dataset:
        stems = [s for s in stems if s == args.dataset]
    elif args.lang:
        # Restrict to datasets that actually curate the target language so the
        # per-language loop stays fast and never scans irrelevant fixtures.
        relevant = []
        for s in stems:
            labels = parse_labels(LABELS / f"{s}.toml", s)
            if any(l.lang == args.lang and l.kind == "tp" for l in labels):
                relevant.append(s)
        stems = relevant

    results: list[DatasetResult] = []
    for stem in stems:
        r = score_dataset(stem, binpath, args.exact, args.quiet)
        if r is not None:
            results.append(r)

    agg = aggregate(results)
    if args.lang:
        agg = {k: v for k, v in agg.items() if k == args.lang}

    total_time = sum(r.elapsed for r in results)

    payload = {
        "exact": args.exact,
        "datasets_scored": [r.fixture for r in results],
        "total_scan_seconds": round(total_time, 3),
        "languages": {},
    }
    for lang in sorted(agg):
        payload["languages"][lang] = {
            "strict": agg[lang].metrics(strict=True),
            "bench": agg[lang].metrics(strict=False),
        }

    if args.json:
        print(json.dumps(payload, indent=2))
    else:
        view = "EXACT-CWE" if args.exact else "LENIENT-CWE"
        print(f"\nSighthound benchmark scoreboard ({view})  |  scan time {total_time:.2f}s")
        print(f"datasets: {', '.join(payload['datasets_scored'])}\n")
        hdr = f"{'lang':<11} | {'strict P/R/F1':<24} | {'bench P/R/F1':<24} | TP/FN/FPs/FPb"
        print(hdr)
        print("-" * len(hdr))
        for lang in sorted(agg):
            s = agg[lang].metrics(True)
            b = agg[lang].metrics(False)
            sc = f"{s['precision']:.2f}/{s['recall']:.2f}/{s['f1']:.2f}"
            bc = f"{b['precision']:.2f}/{b['recall']:.2f}/{b['f1']:.2f}"
            counts = f"{agg[lang].tp}/{agg[lang].fn}/{agg[lang].fp_strict}/{agg[lang].fp_bench}"
            print(f"{lang:<11} | {sc:<24} | {bc:<24} | {counts}")

    if args.details:
        for r in results:
            if not r.missed and not r.unmatched:
                continue
            print(f"\n### {r.fixture}  ({r.elapsed:.2f}s)")
            for m in r.missed:
                if args.lang and m.lang != args.lang:
                    continue
                print(f"  FN  {m.lang:<10} {sorted(m.cwes)}  {m.path}:{m.target_line}")
            for u in r.unmatched:
                if args.lang and u.lang != args.lang:
                    continue
                snip = (u.raw.get('snippet') or '').replace('\n', ' ')[:60]
                print(f"  FP  {u.lang:<10} {u.cwe or '-':<10} {u.path}:{u.line}  {snip}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
