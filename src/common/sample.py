from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

from .hashing import sha256_file
from .process import run_command


def detect_kind(file_description: str) -> str:
    if not file_description:
        return "unknown"

    desc = file_description.lower()
    if "elf" in desc:
        return "ELF"
    if "pe32" in desc or "pe32+" in desc or ("windows" in desc and "executable" in desc):
        return "PE"
    return "unknown"


def get_sample_metadata(sample_path: Path) -> Dict[str, Any]:
    size_bytes = sample_path.stat().st_size
    sha256 = sha256_file(sample_path)

    file_result = run_command(["file", "-b", str(sample_path)])
    file_description = file_result.stdout if file_result.ok else ""

    return {
        "path": str(sample_path),
        "name": sample_path.name,
        "size_bytes": size_bytes,
        "sha256": sha256,
        "file_description": file_description,
        "file_cmd_ok": file_result.ok,
        "file_cmd_error": file_result.stderr,
        "detected_kind": detect_kind(file_description),
        "collected_at": datetime.now(timezone.utc).isoformat(),
    }
