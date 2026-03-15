from __future__ import annotations

import time
from pathlib import Path
from typing import Any, Dict, List

from src.agent.llm import LLMConfig, run_llm_synthesis
from src.common.sample import get_sample_metadata
from src.mcp.server import (
    analyze_control_flow_anomalies,
    detect_packing_or_obfuscation,
    extract_crypto_constants,
    extract_imports_and_suspicious_apis,
    extract_iocs,
    extract_strings_with_context,
    find_suspicious_syscalls,
    pe_elf_structural_summary,
)


MAX_FILE_SIZE_BYTES = 100 * 1024 * 1024
MAX_SAMPLE_TIMEOUT_SEC = 180
DEFAULT_TOOL_TIMEOUT_SEC = 60


def _run_structural_summary(sample_path: Path, timeout_sec: int) -> Dict[str, Any]:
    """
    Execute the first tool in the fixed v1 linear order.

    We keep this as a tiny wrapper so future tools can follow the same shape
    and we can add per-tool timeouts/retries without changing the runner API.
    """
    return pe_elf_structural_summary(sample_path=str(sample_path), timeout_sec=timeout_sec)


def _run_strings_with_context(sample_path: Path, timeout_sec: int) -> Dict[str, Any]:
    return extract_strings_with_context(sample_path=str(sample_path), timeout_sec=timeout_sec)


def _run_extract_iocs(sample_path: Path, timeout_sec: int) -> Dict[str, Any]:
    return extract_iocs(sample_path=str(sample_path), timeout_sec=timeout_sec)


def _run_detect_packing(sample_path: Path, timeout_sec: int) -> Dict[str, Any]:
    return detect_packing_or_obfuscation(sample_path=str(sample_path), timeout_sec=timeout_sec)


def _run_imports_apis(sample_path: Path, timeout_sec: int) -> Dict[str, Any]:
    return extract_imports_and_suspicious_apis(sample_path=str(sample_path), timeout_sec=timeout_sec)


def _run_syscalls(sample_path: Path, timeout_sec: int) -> Dict[str, Any]:
    return find_suspicious_syscalls(sample_path=str(sample_path), timeout_sec=timeout_sec)


def _run_crypto(sample_path: Path, timeout_sec: int) -> Dict[str, Any]:
    return extract_crypto_constants(sample_path=str(sample_path), timeout_sec=timeout_sec)


def _run_cfg(sample_path: Path, timeout_sec: int) -> Dict[str, Any]:
    return analyze_control_flow_anomalies(sample_path=str(sample_path), timeout_sec=timeout_sec)


def run_linear_pipeline(
    sample_path: Path,
    timeout_sec: int = DEFAULT_TOOL_TIMEOUT_SEC,
    continue_on_error: bool = True,
    llm_config: LLMConfig | None = None,
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
    started_at = time.perf_counter()

    llm_config = llm_config or LLMConfig(enabled=False)

    # Normalize timeout to Step 6 policy.
    effective_timeout_sec = max(1, min(int(timeout_sec), MAX_SAMPLE_TIMEOUT_SEC))

    tool_results: List[Dict[str, Any]] = []
    pipeline_errors: List[Dict[str, str]] = []
    executed_tools: List[str] = []

    # Enforce file size cap before expensive processing.
    size_bytes = sample_path.stat().st_size
    if size_bytes > MAX_FILE_SIZE_BYTES:
        return {
            "sample_meta": {
                "path": str(sample_path),
                "name": sample_path.name,
                "size_bytes": size_bytes,
                "detected_kind": "unknown",
                "file_description": "",
                "sha256": None,
                "collected_at": None,
                "limit_violation": "max_file_size_exceeded",
            },
            "tool_results": tool_results,
            "pipeline_errors": [
                {
                    "tool": "pipeline",
                    "message": (
                        f"File exceeds max allowed size ({MAX_FILE_SIZE_BYTES} bytes): "
                        f"{size_bytes} bytes"
                    ),
                }
            ],
            "executed_tools": executed_tools,
            "effective_timeout_sec": effective_timeout_sec,
            "total_runtime_ms": int((time.perf_counter() - started_at) * 1000),
        }

    sample_meta = get_sample_metadata(sample_path)

    # v1 fixed linear order.
    ordered_tools = [
        ("pe_elf_structural_summary", _run_structural_summary),
        ("extract_strings_with_context", _run_strings_with_context),
        ("extract_iocs", _run_extract_iocs),
        ("detect_packing_or_obfuscation", _run_detect_packing),
        ("extract_imports_and_suspicious_apis", _run_imports_apis),
        ("find_suspicious_syscalls", _run_syscalls),
        ("extract_crypto_constants", _run_crypto),
        ("analyze_control_flow_anomalies", _run_cfg),
    ]

    for tool_name, runner in ordered_tools:
        try:
            result = runner(sample_path=sample_path, timeout_sec=effective_timeout_sec)
            executed_tools.append(tool_name)
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
                        "executed_tools": executed_tools,
                        "effective_timeout_sec": effective_timeout_sec,
                        "total_runtime_ms": int((time.perf_counter() - started_at) * 1000),
                    }

        except Exception as exc:
            pipeline_errors.append({"tool": tool_name, "message": str(exc)})
            if not continue_on_error:
                raise

    llm_result = run_llm_synthesis(
        sample_meta=sample_meta,
        tool_results=tool_results,
        pipeline_errors=pipeline_errors,
        config=llm_config,
    )
    if llm_result.get("enabled") and not llm_result.get("ok"):
        pipeline_errors.append(
            {
                "tool": "llm_synthesis",
                "message": llm_result.get("error", "LLM synthesis failed"),
            }
        )

    return {
        "sample_meta": sample_meta,
        "tool_results": tool_results,
        "llm_result": llm_result,
        "pipeline_errors": pipeline_errors,
        "executed_tools": executed_tools,
        "effective_timeout_sec": effective_timeout_sec,
        "total_runtime_ms": int((time.perf_counter() - started_at) * 1000),
    }
