from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any, Dict, List, Optional


def build_minimal_report(
    sample_meta: Dict[str, Any], 
    tool_results: Optional[List[Dict[str, Any]]] = None,
    llm_result: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Build report from sample metadata and optional tool results.
    
    Why tool_results is a list:
    - Linear pipeline executes tools in order
    - Each tool returns structured dict (ok, summary, signals, artifacts, evidence)
    - We aggregate all results into unified report
    """
    tool_results = tool_results or []
    
    # Extract tool names and outputs
    tools_executed = []
    tool_outputs_map = {}
    all_signals = []
    all_errors = []
    
    for tool_result in tool_results:
        tool_name = tool_result.get("tool_name", "unknown")
        tools_executed.append(tool_name)
        tool_outputs_map[tool_name] = tool_result
        
        # Collect signals for risk scoring
        if tool_result.get("ok"):
            all_signals.extend(tool_result.get("signals", []))
        else:
            # Tool failed - record error
            error_msg = tool_result.get("error", "Unknown error")
            all_errors.append({
                "tool": tool_name,
                "message": error_msg,
            })
    
    # Calculate risk score from signals
    risk_score = calculate_risk_score(all_signals)
    risk_level = get_risk_level(risk_score)
    
    # Build summary from tool summaries
    summary_bullets = []
    if not tool_results:
        summary_bullets = [
            "No tools executed yet.",
            "Metadata collected from file and sha256 only.",
        ]
    else:
        summary_bullets.append(f"{len(tool_results)} tool(s) executed")
        summary_bullets.append(f"{len(all_signals)} signal(s) detected")
        if all_errors:
            summary_bullets.append(f"{len(all_errors)} tool(s) failed")
    
    return {
        "schema_version": "0.2.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "sample": {
            "name": sample_meta.get("name"),
            "path": sample_meta.get("path"),
            "size_bytes": sample_meta.get("size_bytes"),
            "sha256": sample_meta.get("sha256"),
            "file_description": sample_meta.get("file_description"),
            "detected_kind": sample_meta.get("detected_kind"),
        },
        "pipeline": {
            "mode": "linear",
            "tools": tools_executed,
        },
        "overview": {
            "risk_score": risk_score,
            "risk_level": risk_level,
            "summary": summary_bullets,
            "tags": extract_tags(all_signals),
        },
        "findings": [],  # TODO: convert signals to findings in next iteration
        "tool_outputs": tool_outputs_map,
        "llm": llm_result,
        "errors": all_errors,
    }


def calculate_risk_score(signals: List[Dict[str, Any]]) -> int:
    """
    Calculate risk score (0-100) from signals.
    
    Scoring strategy (from spec):
    - Packing: +20 (high entropy) / +25 (suspicious sections)
    - Each signal has severity (low/medium/high) and confidence (0.0-1.0)
    
    Formula: sum(signal_weight * confidence) then clamp to 0-100
    """
    if not signals:
        return 0
    
    # Weight map: severity -> base score
    severity_weights = {
        "low": 10,
        "medium": 20,
        "high": 30,
    }
    
    total_score = 0
    for signal in signals:
        severity = signal.get("severity", "low")
        confidence = signal.get("confidence", 0.5)
        weight = severity_weights.get(severity, 10)
        total_score += weight * confidence
    
    # Clamp to 0-100
    return min(100, max(0, int(total_score)))


def get_risk_level(score: int) -> str:
    """Map risk score to label (from spec)."""
    if score >= 67:
        return "high"
    elif score >= 34:
        return "medium"
    else:
        return "low"


def extract_tags(signals: List[Dict[str, Any]]) -> List[str]:
    """Extract unique signal types as tags."""
    tags = set()
    for signal in signals:
        signal_type = signal.get("type", "")
        if signal_type:
            # Extract prefix (e.g., "packing" from "packing.high_entropy")
            prefix = signal_type.split(".")[0]
            tags.add(prefix)
    return sorted(tags)


def write_report_json(outdir: Path, report: Dict[str, Any]) -> Path:
    report_path = outdir / "report.json"
    with report_path.open("w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2, ensure_ascii=False)
    return report_path


def write_report_md(outdir: Path, sample_meta: Dict[str, Any], report: Dict[str, Any]) -> Path:
    """
    Generate Markdown report from structured JSON.
    
    Why Markdown?
    - Human-readable for analysts
    - Can be viewed in GitHub/GitLab
    - Easy to convert to PDF/HTML for reporting
    """
    size_bytes = sample_meta.get("size_bytes")
    size_text = f"{size_bytes} bytes" if size_bytes is not None else "unknown"

    report_path = outdir / "report.md"
    lines = [
        "# Analysis Report",
        "",
        "## Sample",
        f"- Name: `{sample_meta.get('name')}`",
        f"- SHA256: `{sample_meta.get('sha256')}`",
        f"- Size: {size_text}",
        f"- File: {sample_meta.get('file_description')}",
        f"- Detected kind: **{sample_meta.get('detected_kind')}**",
        "",
        "## Overview",
        f"- Risk: **{report['overview']['risk_level'].upper()}** ({report['overview']['risk_score']}/100)",
        f"- Tags: {', '.join(report['overview']['tags']) if report['overview']['tags'] else 'none'}",
        "- Summary:",
    ]
    for bullet in report["overview"]["summary"]:
        lines.append(f"  - {bullet}")
    lines.append("")
    
    # Add tool outputs section
    if report["tool_outputs"]:
        lines.append("## Tool Outputs")
        lines.append("")
        for tool_name, tool_result in report["tool_outputs"].items():
            lines.append(f"### {tool_name}")
            lines.append(f"- Status: {'✓ OK' if tool_result.get('ok') else '✗ FAILED'}")
            lines.append(f"- Duration: {tool_result.get('duration_ms', 0)}ms")
            
            # Tool summary
            if tool_result.get("summary"):
                lines.append("- Summary:")
                for bullet in tool_result["summary"]:
                    lines.append(f"  - {bullet}")
            
            # Signals
            if tool_result.get("signals"):
                lines.append(f"- Signals: {len(tool_result['signals'])}")
                for signal in tool_result["signals"]:
                    severity = signal.get("severity", "low").upper()
                    signal_type = signal.get("type", "unknown")
                    details = signal.get("details", "")
                    lines.append(f"  - [{severity}] `{signal_type}`: {details}")
            
            lines.append("")
    
    # Add errors if any
    if report["errors"]:
        lines.append("## Errors")
        lines.append("")

    llm = report.get("llm")
    if llm:
        lines.append("## LLM Synthesis")
        lines.append("")
        lines.append(f"- Enabled: {llm.get('enabled')}")
        lines.append(f"- Status: {'OK' if llm.get('ok') else 'FAILED'}")
        lines.append(f"- Provider/Model: {llm.get('provider')}/{llm.get('model')}")
        lines.append(f"- Duration: {llm.get('duration_ms', 0)}ms")

        if llm.get("ok") and llm.get("result"):
            llm_data = llm["result"]
            lines.append("- Executive Summary:")
            for bullet in llm_data.get("executive_summary", []):
                lines.append(f"  - {bullet}")

            findings = llm_data.get("top_findings", [])
            if findings:
                lines.append("- Top Findings:")
                for finding in findings:
                    title = finding.get("title", "Untitled")
                    sev = finding.get("severity", "low").upper()
                    conf = finding.get("confidence", 0)
                    rationale = finding.get("rationale", "")
                    lines.append(f"  - [{sev}] {title} (confidence={conf}): {rationale}")

            recs = llm_data.get("recommendations", [])
            if recs:
                lines.append("- Recommendations:")
                for rec in recs:
                    lines.append(f"  - {rec}")
        else:
            lines.append(f"- Error: {llm.get('error')}")

        lines.append("")
        for error in report["errors"]:
            lines.append(f"- **{error['tool']}**: {error['message']}")
        lines.append("")

    report_path.write_text("\n".join(lines), encoding="utf-8")
    return report_path



def write_outputs(
    outdir: Path, 
    sample_meta: Dict[str, Any],
    tool_results: Optional[List[Dict[str, Any]]] = None,
    llm_result: Optional[Dict[str, Any]] = None,
) -> Dict[str, Path]:
    """
    Write all persisted outputs: report.json and report.md.
    
    Args:
        outdir: Output directory
        sample_meta: Sample metadata from get_sample_metadata()
        tool_results: Optional list of tool output dicts
    """
    outdir.mkdir(parents=True, exist_ok=True)

    report = build_minimal_report(sample_meta, tool_results, llm_result)
    report_json = write_report_json(outdir, report)
    report_md = write_report_md(outdir, sample_meta, report)

    return {
        "report_json": report_json,
        "report_md": report_md,
    }
