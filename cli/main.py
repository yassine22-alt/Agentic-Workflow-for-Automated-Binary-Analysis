from __future__ import annotations

from pathlib import Path
import typer
from dotenv import load_dotenv

load_dotenv()  # loads .env from the project root before any env reads

from src.agent.llm import LLMConfig
from src.agent.pipeline import run_linear_pipeline
from src.synthesizer.report import write_outputs


app = typer.Typer(help="Agentic binary analysis CLI (v1 skeleton).")


@app.command()
def analyze(
    input: Path = typer.Option(..., "--input", "-i", help="Path to sample file."),
    outdir: Path = typer.Option(..., "--outdir", "-o", help="Output directory."),
    timeout_sec: int = typer.Option(
        60,
        "--timeout-sec",
        envvar="PIPELINE_TIMEOUT_SEC",
        help="Per-tool timeout in seconds (normalized to 1..180).",
    ),
    use_llm: bool = typer.Option(False, "--use-llm", help="Enable LLM synthesis stage."),
    llm_provider: str = typer.Option("gemini", "--llm-provider", envvar="LLM_PROVIDER", help="LLM provider name (e.g., gemini)."),
    llm_model: str = typer.Option("gemini-3-flash-preview", "--llm-model", envvar="LLM_MODEL", help="Model name for selected provider."),
    llm_timeout_sec: int = typer.Option(30, "--llm-timeout-sec", envvar="LLM_TIMEOUT_SEC", help="LLM request timeout in seconds."),
) -> None:
    """
    Analyze a binary sample and generate report.
    
    Current implementation (Step 5):
    - CLI delegates to orchestration runner
    - Runner executes fixed-order linear pipeline (v1)
    - Synthesizer writes report.json + report.md from pipeline outputs
    """
    if not input.exists():
        raise typer.BadParameter(f"Input file does not exist: {input}")
    if not input.is_file():
        raise typer.BadParameter(f"Input is not a file: {input}")

    typer.echo("[1/3] Running linear pipeline...")
    pipeline_result = run_linear_pipeline(
        sample_path=input.absolute(),
        timeout_sec=timeout_sec,
        continue_on_error=True,
        llm_config=LLMConfig(
            enabled=use_llm,
            provider=llm_provider,
            model=llm_model,
            timeout_sec=llm_timeout_sec,
        ),
    )

    sample_meta = pipeline_result["sample_meta"]
    tool_results = pipeline_result["tool_results"]
    llm_result = pipeline_result.get("llm_result")

    typer.echo("[2/3] Aggregating report...")
    outputs = write_outputs(outdir, sample_meta, tool_results=tool_results, llm_result=llm_result)

    typer.echo("[3/3] Finalizing output...")

    typer.echo(f"\n✓ Analysis complete!")
    typer.echo(f"  Report (JSON):   {outputs['report_json']}")
    typer.echo(f"  Report (MD):     {outputs['report_md']}")
    
    typer.echo(f"\n  Tools executed: {', '.join(pipeline_result['executed_tools'])}")
    typer.echo(f"  Effective timeout: {pipeline_result['effective_timeout_sec']}s")
    typer.echo(f"  Total runtime: {pipeline_result['total_runtime_ms']}ms")

    if pipeline_result["pipeline_errors"]:
        typer.echo("  Pipeline errors:", err=True)
        for err in pipeline_result["pipeline_errors"]:
            typer.echo(f"    - {err['tool']}: {err['message']}", err=True)

    if llm_result:
        if llm_result.get("enabled") and llm_result.get("ok"):
            typer.echo(
                f"  LLM synthesis: OK ({llm_result.get('provider')}/{llm_result.get('model')}, "
                f"{llm_result.get('duration_ms', 0)}ms)"
            )
        elif llm_result.get("enabled"):
            typer.echo(
                f"  LLM synthesis: FAILED ({llm_result.get('provider')}/{llm_result.get('model')}) - "
                f"{llm_result.get('error')}",
                err=True,
            )

    for tool_result in tool_results:
        name = tool_result.get("tool_name", "unknown")
        if tool_result.get("ok"):
            typer.echo(f"  {name}: OK ({tool_result.get('duration_ms', 0)}ms)")
            typer.echo(f"    Signals detected: {len(tool_result.get('signals', []))}")
        else:
            typer.echo(f"  {name}: FAILED - {tool_result.get('error')}", err=True)


def main() -> None:
    app()


if __name__ == "__main__":
    main()
