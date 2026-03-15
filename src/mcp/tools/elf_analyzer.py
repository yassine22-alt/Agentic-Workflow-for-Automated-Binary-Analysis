"""
ELF (Executable and Linkable Format) binary analyzer.

Uses pyelftools library for parsing Linux/Unix executables.

Why pyelftools?
- Pure Python, well-maintained
- Used by industry tools (IDA, Binary Ninja plugins)
- Handles malformed ELFs gracefully
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List

from elftools.elf.elffile import ELFFile
from elftools.elf.constants import SH_FLAGS

from src.common.entropy import calculate_section_entropy


# High entropy threshold
HIGH_ENTROPY_THRESHOLD = 7.0

# Suspicious section names for ELF
SUSPICIOUS_SECTION_NAMES = {
    ".upx0", ".upx1",
    ".packed",
    # Non-standard names (most ELF sections start with .)
}


def analyze_elf_structure(sample_path: Path, timeout_sec: int) -> Dict[str, Any]:
    """
    Analyze ELF binary structure using pyelftools.
    
    Extraction strategy:
    1. Parse ELF headers (e_machine, e_entry, e_type)
    2. Extract sections (names, addresses, sizes, flags)
    3. Calculate per-section entropy
    4. Detect anomalies (stripped, suspicious sections, high entropy)
    5. Generate signals
    """
    try:
        with sample_path.open("rb") as f:
            elf = ELFFile(f)
            
            # Extract basic metadata
            header = elf.header
            e_machine = header['e_machine']  # Architecture (e.g., EM_X86_64, EM_386)
            e_entry = header['e_entry']      # Entrypoint virtual address
            e_type = header['e_type']        # ET_EXEC, ET_DYN, etc.
            
            # Map machine type to human-readable architecture
            arch_map = {
                'EM_386': 'x86',
                'EM_X86_64': 'x64',
                'EM_ARM': 'ARM',
                'EM_AARCH64': 'ARM64',
            }
            architecture = arch_map.get(e_machine, e_machine)
            
            # Analyze sections
            sections_data = []
            high_entropy_sections = []
            suspicious_names = []
            has_symbols = False
            
            for section in elf.iter_sections():
                section_name = section.name
                section_size = section['sh_size']
                section_offset = section['sh_offset']
                section_addr = section['sh_addr']
                
                # Check if this is a symbol table
                if section.name in ['.symtab', '.dynsym']:
                    has_symbols = True
                
                # Calculate entropy (skip empty sections)
                entropy = 0.0
                if section_size > 0:
                    entropy = calculate_section_entropy(sample_path, section_offset, section_size)
                    
                    if entropy >= HIGH_ENTROPY_THRESHOLD:
                        high_entropy_sections.append(section_name)
                
                if section_name.lower() in SUSPICIOUS_SECTION_NAMES:
                    suspicious_names.append(section_name)
                
                # Parse section flags
                flags = section['sh_flags']
                executable = bool(flags & SH_FLAGS.SHF_EXECINSTR)
                writable = bool(flags & SH_FLAGS.SHF_WRITE)
                allocatable = bool(flags & SH_FLAGS.SHF_ALLOC)
                
                sections_data.append({
                    "name": section_name,
                    "address": section_addr,
                    "size": section_size,
                    "offset": section_offset,
                    "entropy": round(entropy, 2),
                    "type": section['sh_type'],
                    "executable": executable,
                    "writable": writable,
                    "allocatable": allocatable,
                })
            
            # Detect anomalies
            anomalies = []
            if not has_symbols:
                anomalies.append("Binary is stripped (no symbol table)")
            if high_entropy_sections:
                anomalies.append(f"{len(high_entropy_sections)} high-entropy sections detected")
            if suspicious_names:
                anomalies.append(f"Suspicious section names: {', '.join(suspicious_names)}")
            
            # Generate signals
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
            
            if not has_symbols:
                signals.append({
                    "type": "structure.stripped_binary",
                    "severity": "low",
                    "confidence": 0.9,
                    "details": "Binary is stripped (analysis will be harder)"
                })
            
            # Build summary
            summary = [
                f"ELF binary: {architecture}, {len(sections_data)} sections",
                f"Entrypoint: 0x{e_entry:x}, Type: {e_type}",
                f"Symbols: {'present' if has_symbols else 'stripped'}",
            ]
            if anomalies:
                summary.extend(anomalies)
            
            # Evidence
            evidence = []
            for sec_data in sections_data:
                if sec_data["entropy"] >= HIGH_ENTROPY_THRESHOLD or sec_data["name"].lower() in SUSPICIOUS_SECTION_NAMES:
                    evidence.append({
                        "source_tool": "pe_elf_structural_summary",
                        "artifact_type": "section",
                        "value": sec_data["name"],
                        "location": {
                            "offset": sec_data["offset"],
                            "va": sec_data["address"],
                            "size": sec_data["size"],
                        },
                        "reason": "High entropy or suspicious name"
                    })
            
            return {
                "ok": True,
                "summary": summary,
                "signals": signals,
                "artifacts": {
                    "architecture": architecture,
                    "entrypoint": e_entry,
                    "elf_type": e_type,
                    "sections": sections_data,
                    "has_symbols": has_symbols,
                    "anomalies": anomalies,
                },
                "evidence": evidence,
                "raw_refs": [],
            }
        
    except Exception as exc:
        # Malformed ELF or parsing error
        return {
            "ok": False,
            "summary": [f"ELF parsing failed: {str(exc)}"],
            "signals": [{
                "type": "structure.malformed_elf",
                "severity": "high",
                "confidence": 0.9,
                "details": f"pyelftools library rejected binary: {str(exc)}"
            }],
            "artifacts": {},
            "evidence": [],
            "raw_refs": [],
            "error": str(exc),
        }
