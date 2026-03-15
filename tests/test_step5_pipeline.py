from __future__ import annotations

import json
import sys
from pathlib import Path

# Allow running this file directly from repository root.
project_root = Path(__file__).resolve().parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from src.agent.pipeline import run_linear_pipeline
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


def test_step5_pipeline_contract() -> None:
    sample = _pick_existing_binary()
    if sample is None:
        print("No system binary found; skipping Step 5 contract test.")
        return

    result = run_linear_pipeline(sample_path=sample, timeout_sec=60, continue_on_error=True)

    assert "sample_meta" in result
    assert "tool_results" in result
    assert "pipeline_errors" in result
    assert "executed_tools" in result

    assert result["sample_meta"]["name"] == sample.name
    assert result["executed_tools"] == EXPECTED_TOOL_ORDER
    assert len(result["tool_results"]) == len(EXPECTED_TOOL_ORDER)

    first_tool_result = result["tool_results"][0]
    assert first_tool_result.get("tool_name") == "pe_elf_structural_summary"
    for idx, tool_name in enumerate(EXPECTED_TOOL_ORDER):
        assert result["tool_results"][idx].get("tool_name") == tool_name



def test_step5_pipeline_writes_report() -> None:
    sample = _pick_existing_binary()
    if sample is None:
        print("No system binary found; skipping Step 5 report test.")
        return

    result = run_linear_pipeline(sample_path=sample, timeout_sec=60, continue_on_error=True)

    outdir = project_root / "output" / "step5_test"
    outputs = write_outputs(
        outdir=outdir,
        sample_meta=result["sample_meta"],
        tool_results=result["tool_results"],
    )

    report_json_path = outputs["report_json"]
    assert report_json_path.exists()

    report_json = json.loads(report_json_path.read_text(encoding="utf-8"))

    assert report_json["pipeline"]["mode"] == "linear"
    assert report_json["pipeline"]["tools"] == EXPECTED_TOOL_ORDER
    for tool_name in EXPECTED_TOOL_ORDER:
        assert tool_name in report_json["tool_outputs"]


if __name__ == "__main__":
    test_step5_pipeline_contract()
    test_step5_pipeline_writes_report()
    print("Step 5 pipeline tests passed.")
