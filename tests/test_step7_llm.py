from __future__ import annotations

import os
import json
import sys
from pathlib import Path

# Allow running this file directly from repository root.
project_root = Path(__file__).resolve().parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from src.agent.llm import LLMConfig
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


def test_llm_disabled_path() -> None:
    sample = _pick_existing_binary()
    if sample is None:
        print("No system binary found; skipping llm-disabled test.")
        return

    result = run_linear_pipeline(
        sample_path=sample,
        timeout_sec=60,
        continue_on_error=True,
        llm_config=LLMConfig(enabled=False),
    )

    llm_result = result.get("llm_result")
    assert llm_result is not None
    assert llm_result["enabled"] is False
    assert llm_result["ok"] is False
    assert llm_result["error"] == "LLM disabled"


def test_llm_enabled_without_key_is_failure_safe() -> None:
    sample = _pick_existing_binary()
    if sample is None:
        print("No system binary found; skipping llm-no-key test.")
        return

    # Force missing key regardless of developer shell environment.
    old_key = os.environ.pop("GEMINI_API_KEY", None)

    result = run_linear_pipeline(
        sample_path=sample,
        timeout_sec=60,
        continue_on_error=True,
        llm_config=LLMConfig(enabled=True, provider="gemini", model="gemini-3-flash-preview", api_key=None),
    )

    if old_key is not None:
        os.environ["GEMINI_API_KEY"] = old_key

    llm_result = result["llm_result"]
    assert llm_result["enabled"] is True
    assert llm_result["ok"] is False
    assert llm_result["error"]

    assert any(err["tool"] == "llm_synthesis" for err in result["pipeline_errors"])



def test_report_contains_llm_section() -> None:
    sample = _pick_existing_binary()
    if sample is None:
        print("No system binary found; skipping llm report test.")
        return

    result = run_linear_pipeline(sample_path=sample, llm_config=LLMConfig(enabled=False))

    outdir = project_root / "output" / "step7_llm"
    outputs = write_outputs(
        outdir=outdir,
        sample_meta=result["sample_meta"],
        tool_results=result["tool_results"],
        llm_result=result["llm_result"],
    )

    report_json = json.loads(outputs["report_json"].read_text(encoding="utf-8"))
    assert "llm" in report_json
    assert report_json["llm"]["enabled"] is False


if __name__ == "__main__":
    test_llm_disabled_path()
    test_llm_enabled_without_key_is_failure_safe()
    test_report_contains_llm_section()
    print("Step 7 LLM tests passed.")
