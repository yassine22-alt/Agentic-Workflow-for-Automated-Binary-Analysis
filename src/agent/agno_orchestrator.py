from __future__ import annotations

import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Tuple


class AgnoLinearOrchestrator:
    """Linear tool runner with Agno-flavored orchestration metadata.

    The project keeps fixed-order v1 execution semantics, but centralizes execution
    via this orchestration layer so future adaptive policies can be added here.
    """

    def __init__(self, continue_on_error: bool = True) -> None:
        self.continue_on_error = continue_on_error
        self.framework = "agno"
        self.agent_name = "linear-malware-triage-agent"
        self.agno_available = self._detect_agno()

    def _detect_agno(self) -> bool:
        try:
            import agno  # type: ignore # noqa: F401

            return True
        except Exception:
            return False

    def run(
        self,
        ordered_tools: List[Tuple[str, Callable[..., Dict[str, Any]]]],
        sample_path: Path,
        timeout_sec: int,
    ) -> Dict[str, Any]:
        tool_results: List[Dict[str, Any]] = []
        pipeline_errors: List[Dict[str, str]] = []
        executed_tools: List[str] = []
        orchestration_log: List[Dict[str, Any]] = []

        for step_index, (tool_name, runner) in enumerate(ordered_tools, start=1):
            step_started = time.perf_counter()
            orchestration_log.append(
                {
                    "step": step_index,
                    "event": "dispatch",
                    "tool": tool_name,
                    "framework": self.framework,
                    "agent": self.agent_name,
                }
            )

            try:
                result = runner(sample_path=sample_path, timeout_sec=timeout_sec)
                executed_tools.append(tool_name)
                tool_results.append(result)

                orchestration_log.append(
                    {
                        "step": step_index,
                        "event": "complete",
                        "tool": tool_name,
                        "ok": bool(result.get("ok", False)),
                        "duration_ms": int((time.perf_counter() - step_started) * 1000),
                    }
                )

                if not result.get("ok", False):
                    pipeline_errors.append(
                        {
                            "tool": tool_name,
                            "message": result.get("error", "Tool returned ok=false"),
                        }
                    )
                    if not self.continue_on_error:
                        break

            except Exception as exc:
                pipeline_errors.append({"tool": tool_name, "message": str(exc)})
                orchestration_log.append(
                    {
                        "step": step_index,
                        "event": "exception",
                        "tool": tool_name,
                        "message": str(exc),
                        "duration_ms": int((time.perf_counter() - step_started) * 1000),
                    }
                )
                if not self.continue_on_error:
                    raise

        return {
            "tool_results": tool_results,
            "pipeline_errors": pipeline_errors,
            "executed_tools": executed_tools,
            "orchestration": {
                "framework": self.framework,
                "mode": "linear",
                "agent": self.agent_name,
                "agno_available": self.agno_available,
                "log": orchestration_log,
            },
        }
