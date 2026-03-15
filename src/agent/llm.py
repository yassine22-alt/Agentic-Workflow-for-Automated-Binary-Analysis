from __future__ import annotations

import json
import os
import re
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Protocol

import requests
from dotenv import load_dotenv

load_dotenv()  # fallback: loads .env if not already loaded by the CLI entry point

__all__ = ["LLMConfig", "run_llm_synthesis"]


@dataclass(frozen=True)
class LLMConfig:
    enabled: bool = False
    provider: str = "gemini"
    model: str = "gemini-3-flash-preview"
    timeout_sec: int = 30
    api_key: str | None = None


class LLMClient(Protocol):
    def synthesize(
        self,
        sample_meta: Dict[str, Any],
        tool_results: List[Dict[str, Any]],
        pipeline_errors: List[Dict[str, str]],
    ) -> Dict[str, Any]:
        ...


class GeminiClient:
    """Gemini implementation behind a provider-agnostic interface."""

    def __init__(self, model: str, api_key: str, timeout_sec: int = 30) -> None:
        self.model = model
        self.api_key = api_key
        self.timeout_sec = timeout_sec

    def _build_prompt(
        self,
        sample_meta: Dict[str, Any],
        tool_results: List[Dict[str, Any]],
        pipeline_errors: List[Dict[str, str]],
    ) -> str:
        payload = {
            "sample": {
                "name": sample_meta.get("name"),
                "sha256": sample_meta.get("sha256"),
                "detected_kind": sample_meta.get("detected_kind"),
                "size_bytes": sample_meta.get("size_bytes"),
            },
            "tool_outputs": tool_results,
            "pipeline_errors": pipeline_errors,
        }

        return (
            "You are a malware triage assistant. Produce a balanced, evidence-backed synthesis only from provided data. "
            "Do not invent facts. Be specific enough to cover the main behaviors, IOCs, capabilities, constraints, and analyst-relevant context, "
            "but avoid filler, repetition, and speculation beyond the supplied evidence. Return valid JSON only with this exact schema: "
            "{\"executive_summary\": [str], \"top_findings\": [{\"title\": str, \"severity\": \"low|medium|high\", \"confidence\": float, \"rationale\": str}], "
            "\"recommendations\": [str], \"confidence_notes\": [str]}. "
            "Prefer 4-8 executive_summary bullets and 4-8 top_findings when the evidence supports it. "
            "Recommendations should be practical follow-up actions grounded in the observed indicators.\n\n"
            "Analysis input JSON:\n"
            f"{json.dumps(payload, ensure_ascii=False)}"
        )

    def _extract_json(self, text: str) -> Dict[str, Any]:
        text = text.strip()

        # Direct JSON fast path.
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass

        # Fallback: extract first JSON object block.
        match = re.search(r"\{[\s\S]*\}", text)
        if not match:
            raise ValueError("No JSON object found in LLM response")
        return json.loads(match.group(0))

    def synthesize(
        self,
        sample_meta: Dict[str, Any],
        tool_results: List[Dict[str, Any]],
        pipeline_errors: List[Dict[str, str]],
    ) -> Dict[str, Any]:
        started_at = time.perf_counter()
        prompt = self._build_prompt(sample_meta, tool_results, pipeline_errors)

        endpoint = (
            f"https://generativelanguage.googleapis.com/v1beta/models/{self.model}:generateContent"
            f"?key={self.api_key}"
        )
        body = {
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {
                "temperature": 0.2,
                "responseMimeType": "application/json",
            },
        }

        resp = requests.post(endpoint, json=body, timeout=self.timeout_sec)
        resp.raise_for_status()

        data = resp.json()
        text = (
            data.get("candidates", [{}])[0]
            .get("content", {})
            .get("parts", [{}])[0]
            .get("text", "")
        )

        parsed = self._extract_json(text)

        duration_ms = int((time.perf_counter() - started_at) * 1000)
        return {
            "enabled": True,
            "ok": True,
            "provider": "gemini",
            "model": self.model,
            "duration_ms": duration_ms,
            "result": {
                "executive_summary": parsed.get("executive_summary", []),
                "top_findings": parsed.get("top_findings", []),
                "recommendations": parsed.get("recommendations", []),
                "confidence_notes": parsed.get("confidence_notes", []),
            },
            "error": None,
        }


def _sanitize_api_key(raw: str | None) -> str:
    """Normalize API keys from env/CLI by removing accidental wrapping quotes."""
    if not raw:
        return ""
    value = raw.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"\"", "'"}:
        value = value[1:-1].strip()
    return value


def _get_client(config: LLMConfig) -> LLMClient:
    provider = (config.provider or "").lower().strip()
    if provider == "gemini":
        api_key = _sanitize_api_key(config.api_key or os.getenv("GEMINI_API_KEY"))
        if not api_key:
            raise ValueError("Missing GEMINI_API_KEY for Gemini provider")
        return GeminiClient(model=config.model, api_key=api_key, timeout_sec=config.timeout_sec)

    raise ValueError(f"Unsupported LLM provider: {config.provider}")


def run_llm_synthesis(
    sample_meta: Dict[str, Any],
    tool_results: List[Dict[str, Any]],
    pipeline_errors: List[Dict[str, str]],
    config: LLMConfig,
) -> Dict[str, Any]:
    """Failure-safe wrapper so LLM issues never break analysis output generation."""
    if not config.enabled:
        return {
            "enabled": False,
            "ok": False,
            "provider": config.provider,
            "model": config.model,
            "duration_ms": 0,
            "result": None,
            "error": "LLM disabled",
        }

    try:
        client = _get_client(config)
        return client.synthesize(sample_meta, tool_results, pipeline_errors)
    except Exception as exc:
        return {
            "enabled": True,
            "ok": False,
            "provider": config.provider,
            "model": config.model,
            "duration_ms": 0,
            "result": None,
            "error": str(exc),
        }
