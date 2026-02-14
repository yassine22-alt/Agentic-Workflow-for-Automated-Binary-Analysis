# Step 4 Complete: First MCP Tool Implementation

## What We Built

✅ **Entropy calculator** ([src/common/entropy.py](src/common/entropy.py))
- Shannon entropy calculation for detecting packed/encrypted sections
- Per-section analysis (why: localized packing detection)

✅ **MCP Server skeleton** ([src/mcp/server.py](src/mcp/server.py))
- FastMCP framework integration
- `pe_elf_structural_summary` tool endpoint
- Best-effort error handling

✅ **PE Analyzer** ([src/mcp/tools/pe_analyzer.py](src/mcp/tools/pe_analyzer.py))
- Uses `pefile` library for parsing Windows executables
- Extracts: architecture, entrypoint, sections, imports
- Detects: high entropy sections, suspicious names, missing imports
- Returns normalized signals

✅ **ELF Analyzer** ([src/mcp/tools/elf_analyzer.py](src/mcp/tools/elf_analyzer.py))
- Uses `pyelftools` for parsing Linux executables
- Extracts: architecture, entrypoint, sections, symbols
- Detects: stripped binaries, high entropy, packing indicators

✅ **Updated Synthesizer** ([src/synthesizer/report.py](src/synthesizer/report.py))
- Accepts tool results and integrates into report
- **Risk scoring algorithm**: severity-weighted signals with confidence
- Markdown report now includes tool outputs and signals

✅ **Updated CLI** ([cli/main.py](cli/main.py))
- Calls tool directly (agent orchestration comes next)
- Shows progress and results

## Testing Step 4

### 1. Install Dependencies (in Docker or local venv)

```bash
pip install -r requirements.txt
```

### 2. Test with a Sample Binary

**Option A: Test with a Linux binary (easiest)**
```bash
python -m cli.main analyze --input /bin/ls --outdir ./output/ls_test
```

**Option B: Create a minimal test ELF**
```bash
# Create tiny C program
echo 'int main() { return 0; }' > test.c
gcc test.c -o test_binary
python -m cli.main analyze --input ./test_binary --outdir ./output/test
```

### 3. Verify Outputs

Check `./output/test/`:
- `report.json` - structured JSON with tool outputs
- `report.md` - human-readable report
- `artifacts/metadata/sample.json` - sample metadata

### 4. Expected Results

For a normal binary (like `/bin/ls`):
- Risk level: LOW (0-33)
- Some sections might show medium entropy (~6.0)
- Should detect if binary is stripped

For a packed binary (if you have one):
- Risk level: MEDIUM or HIGH
- High entropy sections (>7.0)
- Suspicious section names (.upx0, etc.)

## Key Architectural Decisions Made

### 1. **Why separate PE/ELF analyzers?**
Different tools and data structures, but unified output schema for consistency.

### 2. **Why per-section entropy vs whole-file?**
A 10MB binary with 9.9MB of zeros + 100KB encrypted shellcode has LOW overall entropy but HIGH section entropy → catches localized packing.

### 3. **Why best-effort error handling?**
Even if a tool fails, we return structured output with `ok=false`. This allows pipeline to continue and produce partial results.

### 4. **Risk scoring formula**
```
score = Σ (severity_weight * confidence)
  where severity_weight = {low: 10, medium: 20, high: 30}
  then clamp to 0-100
```



## Next Step Preview: Agent Orchestration

Next we'll:
1. Add **Agno agent** that calls tools (instead of direct calls)
2. Implement **linear pipeline** mode (fixed order: structural → strings → IOCs → ...)
3. Add **MCP client** to communicate with MCP server

**Architecture shift**:
```
Current:  CLI → tool function → report
Next:     CLI → Agno Agent → MCP Server → tools → report
```

**Why this matters**: Agent can make decisions (which tool to call next, when to stop, how to interpret results).
