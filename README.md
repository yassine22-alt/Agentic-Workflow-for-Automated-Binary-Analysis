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

## API Server

```bash
# Start the server (local)
python -m cli.main serve

# Then call it
curl.exe -X POST http://localhost:8000/analyze \
  -F "file=@path/to/sample.elf" \
  -F "use_llm=true" \
  -o report.json
```

Interactive docs: `http://localhost:8000/docs`

---

## Docker Compose (simple run)

This is the easiest way to run the full project.

```bash
# 1) Put your key in .env
GEMINI_API_KEY=your_key_here

# 2) Build + start API
docker compose up -d --build

# 3) Test health
curl.exe http://localhost:8000/health

# 4) Analyze a file
curl.exe -X POST http://localhost:8000/analyze \
  -F "file=@C:/path/to/sample.elf" \
  -F "use_llm=true" \
  -F "persist_report=true" \
  -o api_report.json

# 5) Stop
docker compose down
```

API docs: `http://localhost:8000/docs`

If `persist_report=true` (or `API_PERSIST_REPORTS=true`), reports are also written to host `output/`:

```text
output/api_<timestamp>_<sample>_<id>/report.json
output/api_<timestamp>_<sample>_<id>/report.md
```

Use `--network=none` only for isolated one-shot CLI analysis, not for API server mode.

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
api/              FastAPI service (`/health`, `/analyze`)
tests/            Test suite
```

---

## Pending

- [ ] Async job API (`POST /analyze` → job_id, `GET /jobs/{id}` for polling)
- [ ] Support for additional LLM providers beyond Gemini
