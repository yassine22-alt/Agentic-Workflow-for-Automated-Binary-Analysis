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
    timed_out: bool = False


def run_command(cmd: Sequence[str], timeout_sec: int | None = None) -> CmdResult:
    try:
        completed = subprocess.run(
            list(cmd),
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout_sec,
        )
    except subprocess.TimeoutExpired as exc:
        return CmdResult(
            ok=False,
            stdout=(exc.stdout or "").strip() if isinstance(exc.stdout, str) else "",
            stderr=(exc.stderr or "").strip() if isinstance(exc.stderr, str) else "",
            returncode=-2,
            timed_out=True,
        )
    except OSError as exc:
        return CmdResult(False, "", str(exc), -1, False)

    return CmdResult(
        ok=completed.returncode == 0,
        stdout=completed.stdout.strip(),
        stderr=completed.stderr.strip(),
        returncode=completed.returncode,
        timed_out=False,
    )
