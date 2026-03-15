from __future__ import annotations

import json
import sys
from pathlib import Path

project_root = Path(__file__).resolve().parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from src.agent.llm import LLMConfig
from src.agent.pipeline import run_linear_pipeline
from src.synthesizer.report import write_outputs


SAFE_SAMPLE = project_root / "output" / "safe_samples" / "validation_pe.exe"


def test_safe_validation_sample_pipeline() -> None:
    if not SAFE_SAMPLE.exists():
        print("Safe validation sample not built; skipping.")
        return

    result = run_linear_pipeline(
        sample_path=SAFE_SAMPLE,
        timeout_sec=60,
        continue_on_error=True,
        llm_config=LLMConfig(enabled=False),
    )

    outdir = project_root / "output" / "safe_validation_report"
    outputs = write_outputs(
        outdir=outdir,
        sample_meta=result["sample_meta"],
        tool_results=result["tool_results"],
        llm_result=result.get("llm_result"),
    )

    report_json = json.loads(outputs["report_json"].read_text(encoding="utf-8"))
    tool_outputs = report_json["tool_outputs"]

    assert "extract_iocs" in tool_outputs
    assert "extract_imports_and_suspicious_apis" in tool_outputs
    assert "extract_crypto_constants" in tool_outputs

    iocs = tool_outputs["extract_iocs"]["artifacts"]
    imports = tool_outputs["extract_imports_and_suspicious_apis"]["artifacts"]
    crypto = tool_outputs["extract_crypto_constants"]["artifacts"]

    assert iocs["urls"]
    assert imports["suspicious"]["network"] or imports["suspicious"]["injection"]
    assert crypto["families"]


if __name__ == "__main__":
    test_safe_validation_sample_pipeline()
    print("Safe validation sample test passed.")
