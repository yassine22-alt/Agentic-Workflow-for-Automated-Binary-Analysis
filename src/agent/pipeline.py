from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List

from src.common.sample import get_sample_metadata
from src.mcp.server import pe_elf_structural_summary


def _run_structural_summary(sample_path: Path, timeout_sec: int) -> Dict[str, Any]:
    """
    Execute the first tool in the fixed v1 linear order.

    We keep this as a tiny wrapper so future tools can follow the same shape
    and we can add per-tool timeouts/retries without changing the runner API.
    """
    return pe_elf_structural_summary(sample_path=str(sample_path), timeout_sec=timeout_sec)


def run_linear_pipeline(
    sample_path: Path,
    timeout_sec: int = 60,
    continue_on_error: bool = True,
) -> Dict[str, Any]:
    """
    Run the v1 deterministic pipeline and return orchestration outputs.

    Current Step 5 scope:
    - Collect sample metadata once
    - Execute the first tool in planned order (pe_elf_structural_summary)
    - Preserve best-effort behavior

    Returns a dict consumed by CLI/synthesizer:
    {
      "sample_meta": {...},
      "tool_results": [...],
      "pipeline_errors": [...],
      "executed_tools": [...],
    }
    """
    sample_meta = get_sample_metadata(sample_path)

    tool_results: List[Dict[str, Any]] = []
    pipeline_errors: List[Dict[str, str]] = []

    # v1 fixed order starts with structural summary.
    tool_name = "pe_elf_structural_summary"
    try:
        result = _run_structural_summary(sample_path=sample_path, timeout_sec=timeout_sec)
        tool_results.append(result)

        if not result.get("ok", False):
            pipeline_errors.append(
                {
                    "tool": tool_name,
                    "message": result.get("error", "Tool returned ok=false"),
                }
            )
            if not continue_on_error:
                return {
                    "sample_meta": sample_meta,
                    "tool_results": tool_results,
                    "pipeline_errors": pipeline_errors,
                    "executed_tools": [tool_name],
                }

    except Exception as exc:
        pipeline_errors.append({"tool": tool_name, "message": str(exc)})
        if not continue_on_error:
            raise

    return {
        "sample_meta": sample_meta,
        "tool_results": tool_results,
        "pipeline_errors": pipeline_errors,
        "executed_tools": [tool_name],
    }
