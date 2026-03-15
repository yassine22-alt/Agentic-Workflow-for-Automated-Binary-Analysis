# Agentic Binary Analysis

Automated **static** analysis of PE and ELF binaries using an 8-tool MCP pipeline with optional LLM synthesis. Never executes samples.

---

## Capabilities

| Area | Detail |
|---|---|
| Formats | PE (`.exe`, `.dll`) and ELF (Linux / IoT / ARM) |
| Pipeline | 8 sequential static-analysis tools (details below) |
| LLM synthesis | Optional Gemini stage — risk score, MITRE tags, findings |
| Output | `report.json` (structured) + `report.md` (readable) |

**Pipeline tools (fixed order):**
1. `pe_elf_structural_summary` — headers, sections, architecture
2. `extract_strings_with_context` — printable strings with entropy context
3. `extract_iocs` — IPs, domains, URLs, registry keys
4. `detect_packing_or_obfuscation` — entropy analysis, packer signatures
5. `extract_imports_and_suspicious_apis` — imported symbols and red-flag APIs
6. `find_suspicious_syscalls` — Linux/Windows suspicious system calls
7. `extract_crypto_constants` — crypto magic bytes and constants
8. `analyze_control_flow_anomalies` — entropy spikes, section anomalies

---

## Setup

```bash
python -m venv .venv
.venv\Scripts\activate        # Windows
# source .venv/bin/activate   # Linux / macOS
pip install -r requirements.txt
```

Copy the env template and fill in your values:

```bash
cp .env.example .env
# then edit .env
```

---

## Analyzing a File

```bash
# Static only (no LLM)
python -m cli.main analyze --input path/to/sample.exe --outdir output/run1

# With LLM synthesis (requires GEMINI_API_KEY (or other LLM) in .env)
python -m cli.main analyze --input path/to/sample.exe --outdir output/run1 --use-llm

# All options
python -m cli.main analyze \
  --input path/to/sample \
  --outdir output/run1 \
  --timeout-sec 90 \
  --use-llm \
  --llm-provider gemini \
  --llm-model gemini-3-flash-preview \
  --llm-timeout-sec 60
```

Results are written as `<outdir>/report.json` and `<outdir>/report.md`.

---

## Running Tests

```bash
pytest tests/
```

---

## Layout

```
cli/              Typer CLI entry point
src/agent/        Pipeline orchestration + LLM client
src/mcp/          FastMCP server + 8 analysis tool endpoints
src/synthesizer/  Report building and writing
src/common/       Shared utilities (hashing, sample metadata)
schema/           JSON schema for report.json
api/              FastAPI surface (not yet implemented)
tests/            Test suite
```

---

## Pending

- [ ] `api/` — FastAPI HTTP surface not implemented yet
- [ ] Support for additional LLM providers beyond Gemini
- [ ] `pytest` missing from `requirements.txt` (install manually for now)
