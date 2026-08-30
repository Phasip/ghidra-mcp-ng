# ghidra-mcp-ng developer tasks
#
# Targets:
#   make tools-docs   — regenerate TOOLS.md from the live server's OpenAPI spec
#   make test         — build the extension, then run the Java and Python suites
#   make test-serial  — the same on a single worker (use when debugging a failure)
#   make build        — build the Ghidra extension ZIP

GHIDRA_HOME ?= /opt/ghidra

# Ghidra servers to run side by side. Each worker starts its own server against its
# own copy of the project, so this is bounded by RAM and cores rather than by the
# tests; past ~4 the servers contend and the suite gets slower, not faster.
PYTEST_WORKERS ?= 4

# The pytest fixture installs the newest dist/*.zip and never builds one, so a test
# run that skipped the build silently exercises the previous build.
GRADLE = GHIDRA_HOME=$(GHIDRA_HOME) gradle

# ---------------------------------------------------------------------------

.PHONY: tools-docs test test-serial build

## Generate TOOLS.md from the Java annotations — no running server required.
## Scans JAX-RS + OpenAPI annotations via Gradle, then renders TOOLS.md.
tools-docs:
	$(GRADLE) generateOpenApiSpec -q
	python3 scripts/generate_tools_docs.py --spec build/openapi.json --output TOOLS.md
	@echo "TOOLS.md updated."

## Run the Java and Python integration test suites against a freshly built extension.
test: build
	$(GRADLE) test
	GHIDRA_HOME=$(GHIDRA_HOME) python3 -m pytest tests/ -n $(PYTEST_WORKERS) --dist loadscope

## Same, on one worker — parallel failures report only the worker's own output.
test-serial: build
	$(GRADLE) test
	GHIDRA_HOME=$(GHIDRA_HOME) python3 -m pytest tests/ -v

## Build the Ghidra extension ZIP into dist/.
build:
	$(GRADLE) buildExtension
