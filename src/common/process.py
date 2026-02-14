from __future__ import annotations

from dataclasses import dataclass
import subprocess
from typing import Sequence


@dataclass(frozen=True)
class CmdResult:
    ok: bool
    stdout: str
    stderr: str
    returncode: int


def run_command(cmd: Sequence[str]) -> CmdResult:
    try:
        completed = subprocess.run(
            list(cmd),
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError as exc:
        return CmdResult(False, "", str(exc), -1)

    return CmdResult(
        ok=completed.returncode == 0,
        stdout=completed.stdout.strip(),
        stderr=completed.stderr.strip(),
        returncode=completed.returncode,
    )
