from __future__ import annotations

import json
import sys
from pathlib import Path

# Allow running this file directly from repository root.
project_root = Path(__file__).resolve().parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from src.agent.llm import LLMConfig
from src.agent.pipeline import run_linear_pipeline
from src.synthesizer.report import write_outputs


PROJECT_ROOT = Path(__file__).resolve().parent.parent
MANIFEST_PATH = PROJECT_ROOT / "tests" / "samples_manifest.json"


def _load_manifest() -> dict:
    if not MANIFEST_PATH.exists():
        return {"samples": []}
    return json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))


def test_e2e_manifest_corpus() -> None:
    manifest = _load_manifest()
    samples = manifest.get("samples", [])
    assert len(samples) >= 5, "Expected 5-10 samples in manifest"

    executed = 0
    skipped = 0
    for item in samples:
        sample_path = Path(item.get("local_path", ""))
        if not sample_path.exists() or not sample_path.is_file():
            skipped += 1
            continue

        result = run_linear_pipeline(
            sample_path=sample_path,
            timeout_sec=60,
            continue_on_error=True,
            llm_config=LLMConfig(enabled=False),
        )
        assert "sample_meta" in result
        assert "tool_results" in result
        assert len(result["tool_results"]) == 8

        outdir = PROJECT_ROOT / "output" / "corpus_matrix" / item.get("id", "sample")
        outputs = write_outputs(
            outdir=outdir,
            sample_meta=result["sample_meta"],
            tool_results=result["tool_results"],
            llm_result=result.get("llm_result"),
        )
        assert outputs["report_json"].exists()
        assert outputs["report_md"].exists()

        report_json = json.loads(outputs["report_json"].read_text(encoding="utf-8"))
        assert "tool_outputs" in report_json
        assert len(report_json["tool_outputs"]) == 8
        executed += 1

    assert executed >= 1, "No manifest sample was available locally; provide at least one sample path"
    print(f"Corpus matrix: executed={executed}, skipped={skipped}")
