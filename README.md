# Agentic Workflow for Automated Binary Analysis (PE & ELF)

Early skeleton for the v1 pipeline.

## Layout
- src/agent: Agno orchestration
- src/mcp: FastMCP server + tools
- src/synthesizer: normalize, score, report writers
- src/common: schemas, models, utils
- api: FastAPI entrypoint
- cli: Typer entrypoint
- schema: report schema
- scripts: helper scripts
- tests: test suite
