"""
MCP Server for Binary Analysis Tools.

Architecture decision: Why MCP?
- Decouples tool implementation from agent orchestration
- Standardized protocol → can swap Agno for LangChain/AutoGen later
- Tools are server-side → agent is client (clean separation)

FastMCP simplifies MCP server creation (like FastAPI for REST):
- @mcp.tool() decorator generates JSON schemas automatically
- Handles input validation and error serialization
- Supports stdio transport (agent spawns process, communicates via stdin/stdout)
"""
from __future__ import annotations

import time
from pathlib import Path
from typing import Any, Callable, Dict

from fastmcp import FastMCP

from .tools.analysis_tools import (
    analyze_control_flow_anomalies as analyze_control_flow_anomalies_impl,
    detect_packing_or_obfuscation as detect_packing_or_obfuscation_impl,
    extract_crypto_constants as extract_crypto_constants_impl,
    extract_imports_and_suspicious_apis as extract_imports_and_suspicious_apis_impl,
    extract_iocs as extract_iocs_impl,
    extract_strings_with_context as extract_strings_with_context_impl,
    find_suspicious_syscalls as find_suspicious_syscalls_impl,
)
from .tools.structural_analyzer import analyze_pe_elf_structure


# Create MCP server instance
mcp = FastMCP("binary-analysis-tools")


def _timed_tool_call(
    tool_name: str,
    sample_path: str,
    timeout_sec: int,
    impl: Callable[[Path, int], Dict[str, Any]],
) -> Dict[str, Any]:
    start_time = time.perf_counter()
    try:
        result = impl(Path(sample_path), timeout_sec)
        result["duration_ms"] = int((time.perf_counter() - start_time) * 1000)
        result["tool_name"] = tool_name
        return result
    except Exception as exc:
        return {
            "tool_name": tool_name,
            "ok": False,
            "duration_ms": int((time.perf_counter() - start_time) * 1000),
            "summary": [f"Tool failed with exception: {type(exc).__name__}"],
            "signals": [],
            "artifacts": {},
            "evidence": [],
            "raw_refs": [],
            "error": str(exc),
        }


@mcp.tool()
def pe_elf_structural_summary(
    sample_path: str,
    timeout_sec: int = 60
) -> Dict[str, Any]:
    """
    Analyzes PE or ELF binary structure and detects anomalies.
    
    This is the TRIAGE tool - answers: "What kind of binary is this and are there red flags?"
    
    Returns structured analysis including:
    - Architecture, bitness, entrypoint
    - Section details (names, sizes, permissions, entropy)
    - Structural anomalies (packing indicators, suspicious sections)
    - Normalized signals for risk scoring
    
    Args:
        sample_path: Absolute path to binary (must exist)
        timeout_sec: Max execution time (not enforced in v1, reserved for future)
    
    Returns:
        dict with keys: tool_name, ok, duration_ms, summary, signals, 
                       artifacts, evidence, raw_refs, error (if ok=false)
    """
    return _timed_tool_call(
        tool_name="pe_elf_structural_summary",
        sample_path=sample_path,
        timeout_sec=timeout_sec,
        impl=analyze_pe_elf_structure,
    )


@mcp.tool()
def extract_strings_with_context(sample_path: str, timeout_sec: int = 60) -> Dict[str, Any]:
    return _timed_tool_call(
        tool_name="extract_strings_with_context",
        sample_path=sample_path,
        timeout_sec=timeout_sec,
        impl=extract_strings_with_context_impl,
    )


@mcp.tool()
def extract_iocs(sample_path: str, timeout_sec: int = 60) -> Dict[str, Any]:
    return _timed_tool_call(
        tool_name="extract_iocs",
        sample_path=sample_path,
        timeout_sec=timeout_sec,
        impl=extract_iocs_impl,
    )


@mcp.tool()
def detect_packing_or_obfuscation(sample_path: str, timeout_sec: int = 60) -> Dict[str, Any]:
    return _timed_tool_call(
        tool_name="detect_packing_or_obfuscation",
        sample_path=sample_path,
        timeout_sec=timeout_sec,
        impl=detect_packing_or_obfuscation_impl,
    )


@mcp.tool()
def extract_imports_and_suspicious_apis(sample_path: str, timeout_sec: int = 60) -> Dict[str, Any]:
    return _timed_tool_call(
        tool_name="extract_imports_and_suspicious_apis",
        sample_path=sample_path,
        timeout_sec=timeout_sec,
        impl=extract_imports_and_suspicious_apis_impl,
    )


@mcp.tool()
def find_suspicious_syscalls(sample_path: str, timeout_sec: int = 60) -> Dict[str, Any]:
    return _timed_tool_call(
        tool_name="find_suspicious_syscalls",
        sample_path=sample_path,
        timeout_sec=timeout_sec,
        impl=find_suspicious_syscalls_impl,
    )


@mcp.tool()
def extract_crypto_constants(sample_path: str, timeout_sec: int = 60) -> Dict[str, Any]:
    return _timed_tool_call(
        tool_name="extract_crypto_constants",
        sample_path=sample_path,
        timeout_sec=timeout_sec,
        impl=extract_crypto_constants_impl,
    )


@mcp.tool()
def analyze_control_flow_anomalies(sample_path: str, timeout_sec: int = 60) -> Dict[str, Any]:
    return _timed_tool_call(
        tool_name="analyze_control_flow_anomalies",
        sample_path=sample_path,
        timeout_sec=timeout_sec,
        impl=analyze_control_flow_anomalies_impl,
    )
