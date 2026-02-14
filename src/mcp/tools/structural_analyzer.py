"""
Structural analysis for PE and ELF binaries.

Architecture: Unified interface, branching implementation
- detect_kind() decides PE vs ELF
- Delegate to specialized analyzers
- Return normalized schema regardless of binary type
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List

from src.common.sample import detect_kind
from src.common.process import run_command


def analyze_pe_elf_structure(sample_path: Path, timeout_sec: int) -> Dict[str, Any]:
    """
    Main entry point: detect binary type and delegate to specialized analyzer.
    
    Why separate PE/ELF analyzers?
    - Different tools (pefile vs readelf/pyelftools)
    - Different header structures
    - Different anomaly patterns
    
    But we return UNIFIED schema for both.
    """
    # Detect binary kind using file command (same as sample.py logic)
    file_result = run_command(["file", "-b", str(sample_path)])
    kind = detect_kind(file_result.stdout if file_result.ok else "")
    
    if kind == "PE":
        from .pe_analyzer import analyze_pe_structure
        return analyze_pe_structure(sample_path, timeout_sec)
    elif kind == "ELF":
        from .elf_analyzer import analyze_elf_structure
        return analyze_elf_structure(sample_path, timeout_sec)
    else:
        # Unsupported type - still return structured output (best-effort)
        return {
            "ok": False,
            "summary": [f"Unsupported binary type: {kind}"],
            "signals": [],
            "artifacts": {"detected_kind": kind},
            "evidence": [],
            "raw_refs": [],
            "error": f"Binary type '{kind}' is not PE or ELF",
        }
