from __future__ import annotations

import sys
from pathlib import Path

# Allow running this file directly from repository root.
project_root = Path(__file__).resolve().parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from src.agent.pipeline import run_linear_pipeline
from src.mcp.tools.analysis_tools import (
    analyze_control_flow_anomalies,
    detect_packing_or_obfuscation,
    extract_crypto_constants,
    extract_imports_and_suspicious_apis,
    extract_iocs,
    extract_strings_with_context,
    find_suspicious_syscalls,
)
from src.mcp.tools.structural_analyzer import analyze_pe_elf_structure


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


def _require_sample() -> Path | None:
    sample = _pick_existing_binary()
    if sample is None:
        print("No system binary found; skipping tool unit test.")
    return sample


def test_tool_structural_summary_unit() -> None:
    sample = _require_sample()
    if sample is None:
        return
    result = analyze_pe_elf_structure(sample, timeout_sec=60)
    assert "ok" in result
    assert "artifacts" in result
    assert "sections" in result["artifacts"]


def test_tool_strings_with_context_unit() -> None:
    sample = _require_sample()
    if sample is None:
        return
    result = extract_strings_with_context(sample, timeout_sec=60)
    assert "ok" in result
    assert "artifacts" in result
    assert "strings_count" in result["artifacts"]
    assert "r2" in result["artifacts"]
    assert "string_xrefs" in result["artifacts"]["r2"]


def test_tool_extract_iocs_unit() -> None:
    sample = _require_sample()
    if sample is None:
        return
    result = extract_iocs(sample, timeout_sec=60)
    assert "ok" in result
    assert "artifacts" in result
    for key in ["urls", "domains", "ips", "emails", "paths", "registry_keys"]:
        assert key in result["artifacts"]


def test_tool_detect_packing_unit() -> None:
    sample = _require_sample()
    if sample is None:
        return
    result = detect_packing_or_obfuscation(sample, timeout_sec=60)
    assert "ok" in result
    assert "artifacts" in result
    assert "overall_entropy" in result["artifacts"]


def test_tool_extract_imports_apis_unit() -> None:
    sample = _require_sample()
    if sample is None:
        return
    result = extract_imports_and_suspicious_apis(sample, timeout_sec=60)
    assert "ok" in result
    assert "artifacts" in result
    assert "imports" in result["artifacts"]
    assert "suspicious" in result["artifacts"]


def test_tool_find_suspicious_syscalls_unit() -> None:
    sample = _require_sample()
    if sample is None:
        return
    result = find_suspicious_syscalls(sample, timeout_sec=60)
    assert "ok" in result
    assert "artifacts" in result
    assert "r2" in result["artifacts"]
    assert "candidate_wrappers" in result["artifacts"]["r2"]
    assert "call_targets" in result["artifacts"]["r2"]


def test_tool_extract_crypto_constants_unit() -> None:
    sample = _require_sample()
    if sample is None:
        return
    result = extract_crypto_constants(sample, timeout_sec=60)
    assert "ok" in result
    assert "artifacts" in result
    assert "families" in result["artifacts"]
    assert "r2" in result["artifacts"]
    assert "matches" in result["artifacts"]["r2"]


def test_tool_cfg_anomalies_unit() -> None:
    sample = _require_sample()
    if sample is None:
        return
    result = analyze_control_flow_anomalies(sample, timeout_sec=60)
    assert "ok" in result
    assert "artifacts" in result
    assert "r2" in result["artifacts"]
    assert "basic_block_overview" in result["artifacts"]["r2"]
    assert "call_targets" in result["artifacts"]["r2"]


def test_pipeline_exposes_agno_orchestration_log() -> None:
    sample = _require_sample()
    if sample is None:
        return
    result = run_linear_pipeline(sample_path=sample, timeout_sec=60, continue_on_error=True)
    orchestration = result.get("orchestration") or {}
    assert orchestration.get("framework") == "agno"
    assert orchestration.get("mode") == "linear"
    assert isinstance(orchestration.get("log"), list)
    assert orchestration.get("log")
