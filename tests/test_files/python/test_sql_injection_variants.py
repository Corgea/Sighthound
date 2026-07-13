import json
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
FIXTURE = Path(__file__).resolve().parent / "fixtures" / "sql_injection_variants.py"
BINARY = REPO_ROOT / "target" / "debug" / "sighthound"

EXPECTED_LINES = {2, 6, 10, 14, 18, 22}


def _scan(path: Path) -> list[dict]:
    if not BINARY.exists():
        pytest.skip(f"missing binary {BINARY}; run cargo build first")

    result = subprocess.run(
        [
            str(BINARY),
            str(path),
            "python",
            "--output-format",
            "json",
            "--include-test-fixtures",
        ],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout, "expected JSON findings on stdout"
    return json.loads(result.stdout)


def test_sql_injection_variants_detected():
    findings = _scan(FIXTURE)
    sql_lines = {
        f["line"] for f in findings if f.get("finding_type") == "SQL Injection"
    }
    assert EXPECTED_LINES <= sql_lines, (
        f"missing expected SQL Injection lines; got {sorted(sql_lines)}"
    )
