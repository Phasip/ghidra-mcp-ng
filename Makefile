# ghidra-mcp-ng developer tasks
#
# Targets:
#   make tools-docs   — regenerate TOOLS.md from the live server's OpenAPI spec
#   make test         — run Java integration tests
#   make build        — build the Ghidra extension ZIP

GHIDRA_HOME ?= /opt/ghidra

# ---------------------------------------------------------------------------

.PHONY: tools-docs test build

## Generate TOOLS.md from the Java annotations — no running server required.
## Scans JAX-RS + OpenAPI annotations via Gradle, then renders TOOLS.md.
tools-docs:
	GHIDRA_HOME=$(GHIDRA_HOME) gradle generateOpenApiSpec --no-daemon -q
	python3 scripts/generate_tools_docs.py --spec build/openapi.json --output TOOLS.md
	@echo "TOOLS.md updated."

## Run the Java and Python integration test suites.
test:
	GHIDRA_HOME=$(GHIDRA_HOME) gradle test --no-daemon
	GHIDRA_HOME=$(GHIDRA_HOME) python3 -m pytest tests/ -v

## Build the Ghidra extension ZIP into dist/.
build:
	GHIDRA_HOME=$(GHIDRA_HOME) gradle buildExtension --no-daemon
