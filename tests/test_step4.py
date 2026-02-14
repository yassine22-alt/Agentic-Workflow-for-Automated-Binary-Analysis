"""
Quick test for Step 4: pe_elf_structural_summary tool

This is NOT a comprehensive test suite - just a smoke test to verify:
1. Tool can be called
2. Returns expected structure
3. Handles basic PE/ELF samples

TODO for later:
- Add pytest fixtures
- Test edge cases (malformed binaries, empty files)
- Test all signal types
- Validate against golden outputs
"""
from pathlib import Path
import json
import tempfile

from src.mcp.server import pe_elf_structural_summary


def test_tool_structure():
    """Test that tool returns expected schema even for missing file."""
    result = pe_elf_structural_summary("/nonexistent/file")
    
    # Should fail gracefully
    assert result["ok"] == False
    assert "tool_name" in result
    assert "duration_ms" in result
    assert "error" in result
    assert "summary" in result
    assert "signals" in result
    assert "artifacts" in result
    assert "evidence" in result
    
    print("✓ Tool returns valid structure on error")


def test_with_system_binary():
    """Test with real binary (assumes Linux/Unix or WSL)."""
    # Try common system binaries
    test_paths = [
        "/bin/ls",          # Linux
        "/usr/bin/cat",     # Linux
        "/bin/bash",        # Linux/WSL
        "C:\\Windows\\System32\\notepad.exe",  # Windows
    ]
    
    found_binary = None
    for path_str in test_paths:
        path = Path(path_str)
        if path.exists():
            found_binary = path
            break
    
    if not found_binary:
        print("⚠ No system binary found for testing - skipping")
        return
    
    print(f"Testing with: {found_binary}")
    result = pe_elf_structural_summary(str(found_binary))
    
    print(f"Result: {json.dumps(result, indent=2)}")
    
    # Should succeed
    assert result["ok"] == True, f"Tool failed: {result.get('error')}"
    assert result["tool_name"] == "pe_elf_structural_summary"
    assert result["duration_ms"] > 0
    
    # Should have artifacts
    artifacts = result["artifacts"]
    assert "architecture" in artifacts
    assert "sections" in artifacts
    assert len(artifacts["sections"]) > 0
    
    # Check first section has required fields
    first_section = artifacts["sections"][0]
    assert "name" in first_section
    assert "entropy" in first_section
    
    print(f"✓ Analyzed {found_binary.name}: {len(artifacts['sections'])} sections")
    print(f"  Architecture: {artifacts['architecture']}")
    print(f"  Signals: {len(result['signals'])}")
    
    # Print signals
    if result["signals"]:
        print("  Detected signals:")
        for sig in result["signals"]:
            print(f"    - [{sig['severity'].upper()}] {sig['type']}: {sig['details']}")


if __name__ == "__main__":
    print("=== Step 4 Smoke Tests ===\n")
    
    test_tool_structure()
    test_with_system_binary()
    
    print("\n✓ All smoke tests passed!")
    print("\nNext: Install dependencies and run with real samples")
    print("  pip install -r requirements.txt")
    print("  python -m cli.main analyze --input /bin/ls --outdir ./output/test")
