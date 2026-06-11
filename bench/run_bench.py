#!/usr/bin/env python3
"""Run one scanner (sighthound | semgrep | opengrep) over every labeled
fusion-benchmark dataset and emit a normalized findings file.

The output schema is identical regardless of tool so bench/compare.py can
score all three with the *same* matching logic (bench/score.py):

  {
    "tool": "semgrep",
    "config": "auto",
    "datasets": {
      "<fixture>": {
        "elapsed": 12.34,            # wall-clock seconds for this dataset scan
        "findings": [
          {"file": "...", "line": 42, "cwes": ["CWE-79"], "rule": "..."},
          ...
        ]
      },
      ...
    }
  }

Usage:
  python3 bench/run_bench.py --tool sighthound --out bench/results/sighthound.json
  python3 bench/run_bench.py --tool semgrep   --config auto --out bench/results/semgrep.json
  python3 bench/run_bench.py --tool opengrep  --config /path/opengrep-rules \
        --bin opengrep --out bench/results/opengrep.json
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from score import DATASETS, LABELS, DEFAULT_BIN, norm_cwe, run_scanner  # noqa: E402

CWE_RE = re.compile(r"CWE[-_ ]?(\d+)", re.IGNORECASE)


def labeled_stems(subset: list[str] | None) -> list[str]:
    stems = sorted(p.stem for p in LABELS.glob("*.toml") if (DATASETS / p.stem).exists())
    if subset:
        stems = [s for s in stems if s in subset]
    return stems


def extract_cwes(meta_cwe) -> list[str]:
    """semgrep/opengrep store CWE under extra.metadata.cwe as a string or list
    of strings like 'CWE-79: Improper Neutralization ...'."""
    if meta_cwe is None:
        return []
    items = meta_cwe if isinstance(meta_cwe, list) else [meta_cwe]
    out: list[str] = []
    for item in items:
        for m in CWE_RE.findall(str(item)):
            out.append(f"CWE-{m}")
    return sorted(set(out))


def scan_semgrep_like(binpath: str, cfg: str, fixture_dir: Path, tool: str,
                      timeout: int) -> tuple[list[dict], float]:
    cmd = [binpath, "scan", "--json", "--quiet", "--config", cfg, "--no-git-ignore"]
    # semgrep sends anonymous telemetry by default; opengrep has no --metrics flag.
    if tool == "semgrep":
        cmd.append("--metrics=off")
    cmd.append(str(fixture_dir))
    start = time.perf_counter()
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        sys.stderr.write(f"  [{tool}] TIMEOUT on {fixture_dir.name}\n")
        return [], float(timeout)
    elapsed = time.perf_counter() - start
    out = proc.stdout.strip()
    if not out:
        if proc.returncode != 0:
            sys.stderr.write(f"  [{tool}] stderr {fixture_dir.name}: {proc.stderr[-300:]}\n")
        return [], elapsed
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        brace = out.find("{")
        data = json.loads(out[brace:]) if brace != -1 else {"results": []}
    findings = []
    for r in data.get("results", []):
        meta = (r.get("extra") or {}).get("metadata") or {}
        findings.append({
            "file": r.get("path", ""),
            "line": int((r.get("start") or {}).get("line", 0)),
            "cwes": extract_cwes(meta.get("cwe")),
            "rule": r.get("check_id", ""),
        })
    return findings, elapsed


def scan_sighthound(binpath: str, fixture_dir: Path, timeout: int) -> tuple[list[dict], float]:
    raw, elapsed = run_scanner(Path(binpath), fixture_dir, quiet=True)
    findings = []
    for f in raw:
        cwe = norm_cwe(f.get("cwe_id"))
        findings.append({
            "file": f.get("file", ""),
            "line": int(f.get("line", 0)),
            "cwes": [cwe] if cwe else [],
            "rule": f.get("rule_id") or f.get("finding_type", ""),
        })
    return findings, elapsed


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--tool", required=True, choices=["sighthound", "semgrep", "opengrep"])
    ap.add_argument("--bin", help="path/name of the tool binary (defaults per tool)")
    ap.add_argument("--config", help="rule config for semgrep/opengrep (e.g. auto or a path)")
    ap.add_argument("--out", required=True, help="output JSON path")
    ap.add_argument("--timeout", type=int, default=600, help="per-dataset timeout seconds")
    ap.add_argument("--datasets", nargs="*", help="optional subset of dataset stems")
    args = ap.parse_args()

    if args.tool == "sighthound":
        binpath = args.bin or str(DEFAULT_BIN)
        if not Path(binpath).exists():
            sys.stderr.write(f"sighthound binary missing: {binpath}\n")
            return 2
    else:
        binpath = args.bin or args.tool
        if not args.config:
            sys.stderr.write(f"--config is required for {args.tool}\n")
            return 2

    stems = labeled_stems(args.datasets)
    payload = {"tool": args.tool, "config": args.config or "", "datasets": {}}

    for stem in stems:
        fixture_dir = DATASETS / stem
        if args.tool == "sighthound":
            findings, elapsed = scan_sighthound(binpath, fixture_dir, args.timeout)
        else:
            findings, elapsed = scan_semgrep_like(binpath, args.config, fixture_dir,
                                                  args.tool, args.timeout)
        payload["datasets"][stem] = {"elapsed": round(elapsed, 3), "findings": findings}
        sys.stderr.write(f"  [{args.tool}] {stem:<28} {elapsed:7.2f}s  {len(findings)} findings\n")

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(payload, indent=2))
    total = sum(d["elapsed"] for d in payload["datasets"].values())
    nf = sum(len(d["findings"]) for d in payload["datasets"].values())
    sys.stderr.write(f"[{args.tool}] {len(stems)} datasets, {nf} findings, {total:.2f}s total -> {out_path}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
