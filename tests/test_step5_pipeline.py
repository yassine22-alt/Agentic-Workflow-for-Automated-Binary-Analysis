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
    assert result["executed_tools"] == ["pe_elf_structural_summary"]
    assert len(result["tool_results"]) == 1

    tool_result = result["tool_results"][0]
    assert tool_result.get("tool_name") == "pe_elf_structural_summary"



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
    assert report_json["pipeline"]["tools"] == ["pe_elf_structural_summary"]
    assert "pe_elf_structural_summary" in report_json["tool_outputs"]


if __name__ == "__main__":
    test_step5_pipeline_contract()
    test_step5_pipeline_writes_report()
    print("Step 5 pipeline tests passed.")
