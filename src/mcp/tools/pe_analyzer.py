"""
PE (Portable Executable) binary analyzer.

Uses pefile library for parsing Windows executables.

Why pefile?
- Pure Python (no compilation needed in Docker)
- Battle-tested (used by VirusTotal, YARA, many analysis tools)
- Handles malformed PEs gracefully (important for malware samples)
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List

import pefile

from src.common.entropy import calculate_section_entropy


# Known suspicious section names (common packers/protectors)
SUSPICIOUS_SECTION_NAMES = {
    ".upx0", ".upx1", ".upx2",  # UPX packer
    ".aspack", ".adata",         # ASPack
    ".packed", ".pec",           # Generic packers
    ".themida", ".winlice",      # Themida/WinLicense
    "bss", "adata",              # Non-standard names (missing leading dot)
}

# High entropy threshold (7.0+ suggests encryption/compression)
HIGH_ENTROPY_THRESHOLD = 7.0


def analyze_pe_structure(sample_path: Path, timeout_sec: int) -> Dict[str, Any]:
    """
    Analyze PE binary structure using pefile.
    
    Extraction strategy:
    1. Load PE headers (DOS, NT, Optional, sections)
    2. Extract metadata (arch, entrypoint, imports count)
    3. Analyze sections (entropy, permissions, names)
    4. Detect anomalies (packing indicators, missing imports, etc.)
    5. Generate normalized signals
    """
    try:
        pe = pefile.PE(str(sample_path), fast_load=False)
        
        # Extract basic metadata
        architecture = "x86" if pe.FILE_HEADER.Machine == 0x14c else "x64"
        entrypoint_va = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        image_base = pe.OPTIONAL_HEADER.ImageBase
        
        # Analyze sections
        sections_data = []
        high_entropy_sections = []
        suspicious_names = []
        
        for section in pe.sections:
            section_name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
            section_size = section.SizeOfRawData
            section_offset = section.PointerToRawData
            
            # Calculate entropy for this section
            # Why? Packed/encrypted code has entropy ~7.5-8.0
            entropy = calculate_section_entropy(sample_path, section_offset, section_size)
            
            # Check for suspicious characteristics
            if entropy >= HIGH_ENTROPY_THRESHOLD:
                high_entropy_sections.append(section_name)
            
            if section_name.lower() in SUSPICIOUS_SECTION_NAMES:
                suspicious_names.append(section_name)
            
            sections_data.append({
                "name": section_name,
                "virtual_address": section.VirtualAddress,
                "virtual_size": section.Misc_VirtualSize,
                "raw_size": section_size,
                "raw_offset": section_offset,
                "entropy": round(entropy, 2),
                "characteristics": section.Characteristics,
                # Human-readable flags (executable, writable, readable)
                "executable": bool(section.Characteristics & 0x20000000),
                "writable": bool(section.Characteristics & 0x80000000),
                "readable": bool(section.Characteristics & 0x40000000),
            })
        
        # Check import table
        has_imports = hasattr(pe, 'DIRECTORY_ENTRY_IMPORT') and len(pe.DIRECTORY_ENTRY_IMPORT) > 0
        import_count = len(pe.DIRECTORY_ENTRY_IMPORT) if has_imports else 0
        
        # Detect anomalies
        anomalies = []
        if not has_imports:
            anomalies.append("No import table (could be packed or statically linked)")
        if high_entropy_sections:
            anomalies.append(f"{len(high_entropy_sections)} high-entropy sections detected")
        if suspicious_names:
            anomalies.append(f"Suspicious section names: {', '.join(suspicious_names)}")
        
        # Generate normalized signals (for risk scoring)
        signals = []
        
        if high_entropy_sections:
            signals.append({
                "type": "packing.high_entropy",
                "severity": "medium",
                "confidence": 0.7,
                "details": f"Sections with entropy ≥ {HIGH_ENTROPY_THRESHOLD}: {', '.join(high_entropy_sections)}"
            })
        
        if suspicious_names:
            signals.append({
                "type": "packing.suspicious_section_names",
                "severity": "medium",
                "confidence": 0.8,
                "details": f"Known packer section names: {', '.join(suspicious_names)}"
            })
        
        if not has_imports:
            signals.append({
                "type": "structure.missing_imports",
                "severity": "low",
                "confidence": 0.5,
                "details": "No import table found (packing or static linking)"
            })
        
        # Build summary bullets
        summary = [
            f"PE binary: {architecture}, {len(pe.sections)} sections",
            f"Entrypoint: 0x{entrypoint_va:x} (VA), ImageBase: 0x{image_base:x}",
            f"Imports: {import_count} DLLs" if has_imports else "No imports detected",
        ]
        if anomalies:
            summary.extend(anomalies)
        
        # Evidence: attach section info with offsets/VAs
        evidence = []
        for sec_data in sections_data:
            if sec_data["entropy"] >= HIGH_ENTROPY_THRESHOLD or sec_data["name"].lower() in SUSPICIOUS_SECTION_NAMES:
                evidence.append({
                    "source_tool": "pe_elf_structural_summary",
                    "artifact_type": "section",
                    "value": sec_data["name"],
                    "location": {
                        "offset": sec_data["raw_offset"],
                        "va": sec_data["virtual_address"],
                        "size": sec_data["raw_size"],
                    },
                    "reason": "High entropy or suspicious name"
                })
        
        pe.close()
        
        return {
            "ok": True,
            "summary": summary,
            "signals": signals,
            "artifacts": {
                "architecture": architecture,
                "entrypoint_va": entrypoint_va,
                "image_base": image_base,
                "sections": sections_data,
                "import_count": import_count,
                "anomalies": anomalies,
            },
            "evidence": evidence,
            "raw_refs": [],
        }
        
    except pefile.PEFormatError as exc:
        # Malformed PE - return partial data
        return {
            "ok": False,
            "summary": [f"PE parsing failed: {str(exc)}"],
            "signals": [{
                "type": "structure.malformed_pe",
                "severity": "high",
                "confidence": 0.9,
                "details": f"pefile library rejected binary: {str(exc)}"
            }],
            "artifacts": {},
            "evidence": [],
            "raw_refs": [],
            "error": str(exc),
        }
