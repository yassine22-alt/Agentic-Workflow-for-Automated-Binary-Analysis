from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

# Allow running this file directly from repository root.
project_root = Path(__file__).resolve().parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from src.agent.pipeline import (
    MAX_FILE_SIZE_BYTES,
    MAX_SAMPLE_TIMEOUT_SEC,
    run_linear_pipeline,
)
from src.synthesizer.report import write_outputs


EXPECTED_TOOL_ORDER = [
    "pe_elf_structural_summary",
    "extract_strings_with_context",
    "extract_iocs",
    "detect_packing_or_obfuscation",
    "extract_imports_and_suspicious_apis",
    "find_suspicious_syscalls",
    "extract_crypto_constants",
    "analyze_control_flow_anomalies",
]


def _pick_existing_binary() -> Path | None:
    candidates = [
        Path("C:/Windows/System32/notepad.exe"),
        Path("C:/Windows/System32/cmd.exe"),
        Path("/bin/ls"),
        Path("/usr/bin/cat"),
    ]
    for p in candidates:
        if p.exists() and p.is_file():
            return p
    return None


def _create_sparse_file(path: Path, size_bytes: int) -> None:
    with path.open("wb") as handle:
        handle.seek(size_bytes - 1)
        handle.write(b"\0")


def test_step6_e2e_outputs_exist() -> None:
    sample = _pick_existing_binary()
    if sample is None:
        print("No system binary found; skipping Step 6 E2E test.")
        return

    result = run_linear_pipeline(sample_path=sample, timeout_sec=60, continue_on_error=True)
    assert result["executed_tools"] == EXPECTED_TOOL_ORDER

    outdir = project_root / "output" / "step6_e2e"
    outputs = write_outputs(
        outdir=outdir,
        sample_meta=result["sample_meta"],
        tool_results=result["tool_results"],
    )

    assert outputs["report_json"].exists()
    assert outputs["report_md"].exists()

    report_json = json.loads(outputs["report_json"].read_text(encoding="utf-8"))
    assert report_json["pipeline"]["mode"] == "linear"
    assert report_json["pipeline"]["tools"] == EXPECTED_TOOL_ORDER
    for tool_name in EXPECTED_TOOL_ORDER:
        assert tool_name in report_json["tool_outputs"]


def test_step6_file_size_limit_enforced() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        too_big = Path(tmpdir) / "too_big.bin"
        _create_sparse_file(too_big, MAX_FILE_SIZE_BYTES + 1)

        result = run_linear_pipeline(sample_path=too_big, timeout_sec=60, continue_on_error=True)

        assert result["tool_results"] == []
        assert result["executed_tools"] == []
        assert len(result["pipeline_errors"]) == 1
        assert "max allowed size" in result["pipeline_errors"][0]["message"].lower()
        assert result["sample_meta"].get("limit_violation") == "max_file_size_exceeded"


def test_step6_timeout_normalization() -> None:
    sample = _pick_existing_binary()
    if sample is None:
        print("No system binary found; skipping Step 6 timeout test.")
        return

    result = run_linear_pipeline(sample_path=sample, timeout_sec=MAX_SAMPLE_TIMEOUT_SEC + 999)
    assert result["effective_timeout_sec"] == MAX_SAMPLE_TIMEOUT_SEC


if __name__ == "__main__":
    test_step6_e2e_outputs_exist()
    test_step6_file_size_limit_enforced()
    test_step6_timeout_normalization()
    print("Step 6 pipeline tests passed.")
