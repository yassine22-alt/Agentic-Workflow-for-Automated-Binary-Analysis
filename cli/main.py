from __future__ import annotations

from pathlib import Path
import typer

from src.common.sample import get_sample_metadata
from src.synthesizer.report import write_outputs
from src.mcp.server import pe_elf_structural_summary


app = typer.Typer(help="Agentic binary analysis CLI (v1 skeleton).")


@app.command()
def analyze(
    input: Path = typer.Option(..., "--input", "-i", help="Path to sample file."),
    outdir: Path = typer.Option(..., "--outdir", "-o", help="Output directory."),
) -> None:
    """
    Analyze a binary sample and generate report.
    
    Current implementation (Step 4):
    - Collect sample metadata (hash, file type)
    - Call pe_elf_structural_summary tool directly (no agent yet)
    - Generate report.json + report.md
    
    Next steps:
    - Add agent orchestration (Agno)
    - Add remaining 7 tools
    - Implement linear pipeline
    """
    if not input.exists():
        raise typer.BadParameter(f"Input file does not exist: {input}")
    if not input.is_file():
        raise typer.BadParameter(f"Input is not a file: {input}")

    typer.echo(f"[1/3] Collecting sample metadata...")
    sample_meta = get_sample_metadata(input)
    
    typer.echo(f"[2/3] Running structural analysis tool...")
    # Call MCP tool directly (no agent orchestration yet)
    # In next iteration, this will be: agent.run(sample_path) → agent calls tools
    tool_result = pe_elf_structural_summary(sample_path=str(input.absolute()))
    
    typer.echo(f"[3/3] Writing outputs...")
    outputs = write_outputs(outdir, sample_meta, tool_results=[tool_result])

    typer.echo(f"\n✓ Analysis complete!")
    typer.echo(f"  Sample metadata: {outputs['sample_meta']}")
    typer.echo(f"  Report (JSON):   {outputs['report_json']}")
    typer.echo(f"  Report (MD):     {outputs['report_md']}")
    
    # Show risk summary
    if tool_result.get("ok"):
        typer.echo(f"\n  Tool status: OK ({tool_result.get('duration_ms')}ms)")
        typer.echo(f"  Signals detected: {len(tool_result.get('signals', []))}")
    else:
        typer.echo(f"\n  Tool status: FAILED - {tool_result.get('error')}", err=True)


def main() -> None:
    app()


if __name__ == "__main__":
    main()
