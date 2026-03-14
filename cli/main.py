from __future__ import annotations

from pathlib import Path
import typer

from src.agent.pipeline import run_linear_pipeline
from src.synthesizer.report import write_outputs


app = typer.Typer(help="Agentic binary analysis CLI (v1 skeleton).")


@app.command()
def analyze(
    input: Path = typer.Option(..., "--input", "-i", help="Path to sample file."),
    outdir: Path = typer.Option(..., "--outdir", "-o", help="Output directory."),
    timeout_sec: int = typer.Option(60, "--timeout-sec", help="Per-tool timeout in seconds."),
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
    )

    sample_meta = pipeline_result["sample_meta"]
    tool_results = pipeline_result["tool_results"]

    typer.echo("[2/3] Aggregating report...")
    outputs = write_outputs(outdir, sample_meta, tool_results=tool_results)

    typer.echo("[3/3] Finalizing output...")

    typer.echo(f"\n✓ Analysis complete!")
    typer.echo(f"  Sample metadata: {outputs['sample_meta']}")
    typer.echo(f"  Report (JSON):   {outputs['report_json']}")
    typer.echo(f"  Report (MD):     {outputs['report_md']}")
    
    typer.echo(f"\n  Tools executed: {', '.join(pipeline_result['executed_tools'])}")

    if pipeline_result["pipeline_errors"]:
        typer.echo("  Pipeline errors:", err=True)
        for err in pipeline_result["pipeline_errors"]:
            typer.echo(f"    - {err['tool']}: {err['message']}", err=True)

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
