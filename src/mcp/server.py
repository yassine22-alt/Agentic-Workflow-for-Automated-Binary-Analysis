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
from typing import Any, Dict

from fastmcp import FastMCP

from .tools.structural_analyzer import analyze_pe_elf_structure


# Create MCP server instance
mcp = FastMCP("binary-analysis-tools")


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
    start_time = time.perf_counter()
    
    try:
        # Delegate to specialized analyzer
        result = analyze_pe_elf_structure(Path(sample_path), timeout_sec)
        
        duration_ms = int((time.perf_counter() - start_time) * 1000)
        result["duration_ms"] = duration_ms
        result["tool_name"] = "pe_elf_structural_summary"
        
        return result
        
    except Exception as exc:
        # Best-effort principle: even catastrophic failures return structured output
        duration_ms = int((time.perf_counter() - start_time) * 1000)
        return {
            "tool_name": "pe_elf_structural_summary",
            "ok": False,
            "duration_ms": duration_ms,
            "summary": [f"Tool failed with exception: {type(exc).__name__}"],
            "signals": [],
            "artifacts": {},
            "evidence": [],
            "raw_refs": [],
            "error": str(exc),
        }
