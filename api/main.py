from __future__ import annotations

import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict
from uuid import uuid4

from dotenv import load_dotenv
from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.responses import JSONResponse

load_dotenv()

from src.agent.llm import LLMConfig
from src.agent.pipeline import run_linear_pipeline
from src.synthesizer.report import write_outputs

app = FastAPI(
    title="Binary Analysis API",
    description="Static analysis of PE and ELF binaries. Never executes samples.",
    version="1.0.0",
)


def _is_true(value: str | None, default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _sanitize_name(filename: str | None) -> str:
    if not filename:
        return "sample"
    safe = "".join(ch if ch.isalnum() or ch in {"-", "_", "."} else "_" for ch in filename)
    return safe[:80] or "sample"


@app.get("/health")
def health() -> Dict[str, str]:
    return {"status": "ok"}


@app.post("/analyze")
async def analyze(
    file: UploadFile = File(..., description="Binary sample to analyze (PE or ELF)."),
    use_llm: bool = Form(True, description="Enable LLM synthesis stage."),
    llm_provider: str = Form("gemini", description="LLM provider (e.g. gemini)."),
    llm_model: str = Form("gemini-3-flash-preview", description="Model name."),
    llm_timeout_sec: int = Form(30, description="LLM request timeout in seconds."),
    timeout_sec: int = Form(60, description="Per-tool timeout in seconds (1–180)."),
    persist_report: bool | None = Form(None, description="Persist report files on disk."),
) -> JSONResponse:
    """
    Upload a binary file for static analysis.

    Returns the full report.json content as JSON.
    The file is written to a temp directory that is deleted after analysis.
    """
    content = await file.read()
    if not content:
        raise HTTPException(status_code=422, detail="Uploaded file is empty.")

    default_persist = _is_true(os.getenv("API_PERSIST_REPORTS"), default=False)
    should_persist = default_persist if persist_report is None else persist_report
    output_root = Path(os.getenv("API_OUTPUT_DIR", "/output"))

    with tempfile.TemporaryDirectory() as tmpdir:
        sample_path = Path(tmpdir) / (file.filename or "sample.bin")
        sample_path.write_bytes(content)
        outdir = Path(tmpdir) / "report"

        try:
            pipeline_result = run_linear_pipeline(
                sample_path=sample_path,
                timeout_sec=timeout_sec,
                continue_on_error=True,
                llm_config=LLMConfig(
                    enabled=use_llm,
                    provider=llm_provider,
                    model=llm_model,
                    timeout_sec=llm_timeout_sec,
                ),
            )
        except Exception as exc:
            raise HTTPException(status_code=500, detail=str(exc))

        outputs = write_outputs(
            outdir=outdir,
            sample_meta=pipeline_result["sample_meta"],
            tool_results=pipeline_result["tool_results"],
            llm_result=pipeline_result.get("llm_result"),
        )

        report: Dict[str, Any] = json.loads(
            outputs["report_json"].read_text(encoding="utf-8")
        )

        if should_persist:
            run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            safe_name = _sanitize_name(file.filename)
            persist_dir = output_root / f"api_{run_id}_{safe_name}_{uuid4().hex[:8]}"
            persist_dir.mkdir(parents=True, exist_ok=True)
            (persist_dir / "report.json").write_text(
                outputs["report_json"].read_text(encoding="utf-8"),
                encoding="utf-8",
            )
            (persist_dir / "report.md").write_text(
                outputs["report_md"].read_text(encoding="utf-8"),
                encoding="utf-8",
            )
            report["persisted_report_dir"] = str(persist_dir)

    return JSONResponse(content=report)
