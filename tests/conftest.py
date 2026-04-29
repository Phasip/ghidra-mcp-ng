"""
conftest.py — session fixtures for ghidra-mcp-ng integration tests.

Self-contained: compiles a C test binary, installs the Ghidra extension (if
needed), creates a Ghidra project, and starts the HTTP server — all in a
temporary directory cleaned up at session end.

Optional environment variables
--------------------------------
GHIDRA_HOME      — Ghidra installation directory (required).
                   Tests are skipped if this directory does not exist.
GHIDRA_MCP_PORT  — HTTP port for the test server (default: 8199).
"""

from __future__ import annotations

import json
import os
import signal
import shutil
import subprocess
import tempfile
import time
import urllib.parse
import urllib.error
import urllib.request
from pathlib import Path
from typing import Generator

import pytest

# ---------------------------------------------------------------------------
# Paths and constants
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).resolve().parent.parent
FIXTURE_C = Path(__file__).resolve().parent / "fixture" / "test_target.c"
GHIDRA_HOME = Path(
    os.environ.get("GHIDRA_HOME", "/opt/ghidra")
)
TEST_PORT = int(os.environ.get("GHIDRA_MCP_PORT", "8199"))
PROG_NAME = "test_target"


# ---------------------------------------------------------------------------
# Extension helpers
# ---------------------------------------------------------------------------

def _ghidra_version() -> str:
    """Read 'VERSION_RELEASE' string from Ghidra's application.properties."""
    props = GHIDRA_HOME / "Ghidra" / "application.properties"
    ver = release = ""
    with open(props) as f:
        for line in f:
            if line.startswith("application.version="):
                ver = line.split("=", 1)[1].strip()
            elif line.startswith("application.release.name="):
                release = line.split("=", 1)[1].strip()
    return f"{ver}_{release}"


def _ext_install_dir() -> Path:
    """Return the XDG Ghidra user-extensions directory."""
    ver = _ghidra_version()
    xdg_base = Path(os.environ.get("XDG_CONFIG_HOME", str(Path.home() / ".config")))
    return xdg_base / "ghidra" / f"ghidra_{ver}" / "Extensions"


def _extension_installed() -> bool:
    return (_ext_install_dir() / "GhidraMcpNg" / "extension.properties").exists()


def _install_extension() -> None:
    zips = sorted((REPO_ROOT / "dist").glob("*.zip"))
    if not zips:
        raise RuntimeError(
            "No dist/*.zip found — run "
            "`GHIDRA_HOME=<path> gradle buildExtension` first"
        )
    zip_path = zips[-1]
    ext_dir = _ext_install_dir() / "GhidraMcpNg"
    shutil.rmtree(ext_dir, ignore_errors=True)
    ext_dir.mkdir(parents=True, exist_ok=True)

    # Unzip into a temp subdir, then flatten the single top-level directory
    tmp = ext_dir / "_unzip_tmp"
    tmp.mkdir(exist_ok=True)
    subprocess.run(
        ["unzip", "-q", "-o", str(zip_path), "-d", str(tmp)],
        check=True,
        capture_output=True,
    )
    # Find the one top-level directory the zip created and move its contents up
    subdirs = [p for p in tmp.iterdir() if p.is_dir()]
    if len(subdirs) == 1:
        for item in subdirs[0].iterdir():
            item.rename(ext_dir / item.name)
        subdirs[0].rmdir()
    else:
        # Zip has no wrapping dir — move everything directly
        for item in tmp.iterdir():
            item.rename(ext_dir / item.name)
    tmp.rmdir()


# ---------------------------------------------------------------------------
# HTTP client
# ---------------------------------------------------------------------------

class GhidraClient:
    """Thin HTTP wrapper for the ghidra-mcp-ng REST API."""

    def __init__(self, base_url: str) -> None:
        self.base_url = base_url.rstrip("/")
        self._schema_cache: dict[str, dict] | None = None

    def health(self) -> dict:
        with urllib.request.urlopen(f"{self.base_url}/health", timeout=5) as r:
            return json.loads(r.read())

    def tools(self) -> list:
        with urllib.request.urlopen(f"{self.base_url}/schema", timeout=10) as r:
            spec = json.loads(r.read())
        tools = []
        for path, operations in spec.get("paths", {}).items():
            if not path.startswith("/tool/"):
                continue
            for method, operation in operations.items():
                name = operation.get("operationId")
                if not name:
                    continue
                tools.append({
                    "name": name,
                    "httpMethod": method.upper(),
                    "path": path,
                })
        self._schema_cache = {item["name"]: item for item in tools}
        return tools

    def call(self, tool: str, arguments: dict | None = None) -> dict:
        """Call a direct tool endpoint and return its JSON envelope."""
        arguments = arguments or {}
        if self._schema_cache is None or tool not in self._schema_cache:
            self.tools()
        assert self._schema_cache is not None
        tool_info = self._schema_cache[tool]
        method = tool_info.get("httpMethod", "GET")
        path = tool_info.get("path", f"/{tool}")
        url = f"{self.base_url}{path}"

        if method == "GET":
            query = urllib.parse.urlencode(arguments, doseq=True)
            if query:
                url = f"{url}?{query}"
            req = urllib.request.Request(url, method="GET")
        else:
            body = json.dumps(arguments).encode()
            req = urllib.request.Request(
                url,
                data=body,
                headers={"Content-Type": "application/json"},
                method="POST",
            )

        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                payload = json.loads(r.read())
        except urllib.error.HTTPError as e:
            body = e.read()
            try:
                return json.loads(body)
            except json.JSONDecodeError:
                raise

        if isinstance(payload, dict) and "ok" in payload:
            return payload
        return {"ok": True, "result": payload}

    def ok(self, tool: str, arguments: dict | None = None) -> dict:
        """Call tool, assert ok=True, return result."""
        resp = self.call(tool, arguments)
        assert resp.get("ok"), f"Tool '{tool}' failed: {resp.get('error', resp)}"
        return resp["result"]

    def is_error(self, tool: str, arguments: dict | None = None) -> bool:
        """Return True if the tool call returned ok=False."""
        return not self.call(tool, arguments).get("ok", True)


# ---------------------------------------------------------------------------
# Session fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def ghidra_server() -> Generator[GhidraClient, None, None]:
    """
    Self-contained session fixture.

    Steps:
      1. Compile tests/fixture/test_target.c to a temp directory.
      2. Install the ghidra-mcp-ng extension from dist/*.zip (if not already done).
      3. Import the binary into a Ghidra project via analyzeHeadless.
      4. Start the HTTP server on TEST_PORT.
      5. Wait up to 90 s for the /health endpoint to respond.
      6. Yield a GhidraClient pointed at the running server.

    Everything is cleaned up (server killed, temp dir removed) on session end.
    """
    if not GHIDRA_HOME.is_dir():
        pytest.skip(
            f"GHIDRA_HOME not found at {GHIDRA_HOME} — skipping integration tests"
        )

    tmpdir = Path(tempfile.mkdtemp(prefix="ghidra_mcp_test_"))
    server_proc = None
    try:
        # 1. Compile test binary
        binary = tmpdir / PROG_NAME
        result = subprocess.run(
            ["gcc", "-O0", "-o", str(binary), str(FIXTURE_C)],
            capture_output=True,
        )
        if result.returncode != 0:
            pytest.skip(f"gcc failed:\n{result.stderr.decode()}")

        # 2. Install the freshly built extension for this test run
        _install_extension()

        # 3. Create Ghidra project via analyzeHeadless
        analyze = str(GHIDRA_HOME / "support" / "analyzeHeadless")
        result = subprocess.run(
            [analyze, str(tmpdir), "McpTestProject",
             "-import", str(binary), "-overwrite"],
            capture_output=True,
            timeout=300,
        )
        if result.returncode != 0:
            stderr = result.stderr.decode("utf-8", errors="replace")
            pytest.skip(f"analyzeHeadless failed:\n{stderr[:1000]}")

        # 4. Start HTTP server (no --rules -> naming rules disabled)
        project_path = str(tmpdir / "McpTestProject")
        launch = str(GHIDRA_HOME / "support" / "launch.sh")
        server_proc = subprocess.Popen(
            [launch, "fg", "jdk", "GhidraMcpNg", "2G", "",
             "com.ghidramcpng.GhidraMcpServer",
             "--project", project_path,
             "--port",    str(TEST_PORT)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )

        # 5. Wait up to 90 s for /health to respond
        client = GhidraClient(f"http://127.0.0.1:{TEST_PORT}")
        deadline = time.monotonic() + 90
        healthy = False
        while time.monotonic() < deadline:
            if server_proc.poll() is not None:
                assert server_proc.stderr is not None
                stderr = server_proc.stderr.read().decode("utf-8", errors="replace")
                pytest.skip(f"Server died during startup:\n{stderr[:800]}")
                break
            try:
                if client.health().get("status") == "ok":
                    healthy = True
                    break
            except (urllib.error.URLError, OSError):
                pass
            time.sleep(2)

        if not healthy:
            pytest.skip("Server did not become healthy within 90 s")

        yield client

    finally:
        if server_proc and server_proc.poll() is None:
            try:
                os.killpg(server_proc.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                server_proc.wait(timeout=15)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(server_proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
        shutil.rmtree(tmpdir, ignore_errors=True)


@pytest.fixture(scope="session")
def prog() -> str:
    """Name of the test program in the Ghidra project."""
    return PROG_NAME
