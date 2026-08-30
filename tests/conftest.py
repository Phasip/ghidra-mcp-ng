"""
conftest.py — session fixtures for ghidra-mcp-ng integration tests.

Self-contained: compiles a C test binary, installs the Ghidra extension (if
needed), creates a Ghidra project, and starts the HTTP server — all in a
temporary directory cleaned up at session end.

Optional environment variables
--------------------------------
GHIDRA_HOME      — Ghidra installation directory (required).
                   Tests are skipped if this directory does not exist.
GHIDRA_MCP_PORT  — Base HTTP port for the test server (default: 8199). Under
                   pytest-xdist each worker adds its own index to this.
GHIDRA_MCP_NO_CACHE — Set to 1 to re-run analyzeHeadless instead of reusing the
                   cached analysed project.
"""

from __future__ import annotations

import contextlib
import fcntl
import hashlib
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
BASE_PORT = int(os.environ.get("GHIDRA_MCP_PORT", "8199"))
PROG_NAME = "test_target"
PROJECT_NAME = "McpTestProject"
# Analysed-project cache. Under build/ so `gradle clean` discards it and .gitignore
# already covers it.
CACHE_ROOT = REPO_ROOT / "build" / "test-cache"


def _worker_index() -> int:
    """0 for a serial run, or the gw<N> index when running under pytest-xdist."""
    worker = os.environ.get("PYTEST_XDIST_WORKER", "")
    return int(worker[2:]) if worker.startswith("gw") and worker[2:].isdigit() else 0


def _test_port() -> int:
    """Give every xdist worker its own port so their servers do not collide."""
    return BASE_PORT + _worker_index()


# ---------------------------------------------------------------------------
# Parallel-run safety
# ---------------------------------------------------------------------------

def pytest_configure(config: pytest.Config) -> None:
    """
    Reject the xdist distribution modes that silently mis-run this suite.

    Each worker gets its own Ghidra project and server, so whole classes may be
    spread across workers freely — but tests *within* a class are ordered (one
    defines a prototype the next retypes a parameter of; the script tests share
    one ~/ghidra_scripts directory). '--dist load' splits a class across workers
    and those tests then fail for reasons that look nothing like the cause.
    """
    if not config.pluginmanager.hasplugin("xdist"):
        return
    if config.getoption("numprocesses", None) in (None, 0):
        return
    dist = config.getoption("dist", "load")
    if dist not in ("loadscope", "loadfile", "no"):
        raise pytest.UsageError(
            f"--dist {dist} splits a test class across workers, and the tests in a "
            "class are ordered — run the suite with '--dist loadscope' instead "
            "(that is what `make test` does)."
        )


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


@contextlib.contextmanager
def _shared_lock(name: str):
    """
    Serialise work on a directory shared by every pytest-xdist worker.

    Workers are separate processes with no other coordination, so without this two
    of them can unzip over the same extension directory at once.
    """
    CACHE_ROOT.mkdir(parents=True, exist_ok=True)
    with open(CACHE_ROOT / name, "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(lock, fcntl.LOCK_UN)


def _newest_extension_zip() -> Path:
    zips = sorted((REPO_ROOT / "dist").glob("*.zip"))
    if not zips:
        raise RuntimeError(
            "No dist/*.zip found — run "
            "`GHIDRA_HOME=<path> gradle buildExtension` first"
        )
    return zips[-1]


def _install_extension() -> None:
    """
    Install the newest dist/*.zip, unless that exact zip is already installed.

    The stamp records the zip's content hash, not its name or mtime: rebuilding the
    same day reuses the filename, so anything coarser would leave the tests running
    against the previously installed code.
    """
    zip_path = _newest_extension_zip()
    ext_dir = _ext_install_dir() / "GhidraMcpNg"
    digest = hashlib.sha256(zip_path.read_bytes()).hexdigest()
    stamp = ext_dir / ".installed-from"

    if _extension_installed() and stamp.exists() and stamp.read_text() == digest:
        return

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
    stamp.write_text(digest)


# ---------------------------------------------------------------------------
# Analysed-project cache
# ---------------------------------------------------------------------------

def _fixture_key() -> str:
    """
    Identify everything analyzeHeadless' output depends on.

    Change the fixture source, the compiler or the Ghidra version and this changes,
    so a stale cache can never be reused. The extension is deliberately not part of
    it: analysis runs before the extension is ever loaded.
    """
    digest = hashlib.sha256()
    digest.update(FIXTURE_C.read_bytes())
    digest.update(_ghidra_version().encode())
    gcc = subprocess.run(["gcc", "--version"], capture_output=True)
    digest.update(gcc.stdout)
    return digest.hexdigest()[:16]


def _build_analysed_project(staging: Path) -> None:
    """Compile the fixture and import it into a fresh Ghidra project under `staging`."""
    binary = staging / PROG_NAME
    result = subprocess.run(
        ["gcc", "-O0", "-o", str(binary), str(FIXTURE_C)],
        capture_output=True,
    )
    if result.returncode != 0:
        pytest.skip(f"gcc failed:\n{result.stderr.decode()}")

    analyze = str(GHIDRA_HOME / "support" / "analyzeHeadless")
    result = subprocess.run(
        [analyze, str(staging), PROJECT_NAME, "-import", str(binary), "-overwrite"],
        capture_output=True,
        timeout=300,
    )
    if result.returncode != 0:
        stderr = result.stderr.decode("utf-8", errors="replace")
        pytest.skip(f"analyzeHeadless failed:\n{stderr[:1000]}")


def _analysed_project() -> Path:
    """
    Return a directory holding a pristine, already-analysed project and its binary.

    Analysis is the single most expensive step of the session (~7 s) and its result
    depends only on _fixture_key(), so it is built once and thereafter copied. The
    cache is never handed to the server directly — each session copies it, mutates
    the copy, and throws the copy away.
    """
    cache = CACHE_ROOT / _fixture_key()
    if cache.is_dir() and not os.environ.get("GHIDRA_MCP_NO_CACHE"):
        return cache

    CACHE_ROOT.mkdir(parents=True, exist_ok=True)
    shutil.rmtree(cache, ignore_errors=True)
    staging = Path(tempfile.mkdtemp(prefix="staging_", dir=CACHE_ROOT))
    try:
        _build_analysed_project(staging)
        try:
            # Publish atomically, so a concurrent pytest invocation either sees no
            # cache or sees a complete one — never a half-written project.
            staging.rename(cache)
        except OSError:
            # Losing the race is the expected way this fails: the other invocation
            # published first and its cache is as good as ours. Anything else left
            # no cache to fall back on, so it has to surface here.
            shutil.rmtree(staging, ignore_errors=True)
            if not cache.is_dir():
                raise
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    return cache


def _materialise_project(cache: Path, dest: Path) -> Path:
    """Copy the cached project into `dest` for this session to mutate. Returns the binary."""
    shutil.copytree(cache / f"{PROJECT_NAME}.rep", dest / f"{PROJECT_NAME}.rep")
    shutil.copy2(cache / f"{PROJECT_NAME}.gpr", dest / f"{PROJECT_NAME}.gpr")
    binary = dest / PROG_NAME
    shutil.copy2(cache / PROG_NAME, binary)
    return binary


# ---------------------------------------------------------------------------
# HTTP client
# ---------------------------------------------------------------------------

class GhidraClient:
    """Thin HTTP wrapper for the ghidra-mcp-ng REST API."""

    def __init__(self, base_url: str, binary_path: str | None = None) -> None:
        self.base_url = base_url.rstrip("/")
        # The compiled fixture binary on disk. Tests that exercise import_binary need a real
        # file to import, and this is the one the session already knows how to build.
        self.binary_path = binary_path
        self._schema_cache: dict[str, dict] | None = None

    def health(self) -> dict:
        with urllib.request.urlopen(f"{self.base_url}/health", timeout=5) as r:
            return json.loads(r.read())

    def schema(self) -> dict:
        with urllib.request.urlopen(f"{self.base_url}/schema", timeout=10) as r:
            return json.loads(r.read())

    def tools(self) -> list:
        spec = self.schema()
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

    def raw(self, path: str, method: str = "GET") -> tuple[int, dict]:
        """
        Request an arbitrary path, returning (http_status, parsed_body).

        Bypasses the schema lookup in call(), so it can exercise routes that do not exist —
        which is the point: an unknown tool name must come back as a 404, not a 500.
        """
        req = urllib.request.Request(f"{self.base_url}{path}", method=method)
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                return r.status, json.loads(r.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read())


# ---------------------------------------------------------------------------
# Session fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def ghidra_server() -> Generator[GhidraClient, None, None]:
    """
    Self-contained session fixture.

    Steps:
      1. Build (or reuse) the cached analysed project for tests/fixture/test_target.c.
      2. Install the ghidra-mcp-ng extension from dist/*.zip (if not already done).
      3. Copy the cached project into a temp directory for this session to mutate.
      4. Start the HTTP server on this worker's port.
      5. Wait up to 90 s for the /health endpoint to respond.
      6. Yield a GhidraClient pointed at the running server.

    Everything is cleaned up (server killed, temp dir removed) on session end. The
    cache under build/test-cache survives, which is what makes steps 1-3 near-free
    on every run after the first.
    """
    if not GHIDRA_HOME.is_dir():
        pytest.skip(
            f"GHIDRA_HOME not found at {GHIDRA_HOME} — skipping integration tests"
        )

    tmpdir = Path(tempfile.mkdtemp(prefix="ghidra_mcp_test_"))
    server_proc = None
    port = _test_port()
    try:
        # 1-2. Both touch directories shared by every xdist worker, so one at a time.
        with _shared_lock(".setup.lock"):
            cache = _analysed_project()
            _install_extension()

        # 3. This session's own mutable copy of the analysed project
        binary = _materialise_project(cache, tmpdir)

        # 4. Start HTTP server (no --rules -> naming rules disabled)
        project_path = str(tmpdir / PROJECT_NAME)
        launch = str(GHIDRA_HOME / "support" / "launch.sh")
        server_proc = subprocess.Popen(
            [launch, "fg", "jdk", "GhidraMcpNg", "2G", "",
             "com.ghidramcpng.GhidraMcpServer",
             "--project", project_path,
             "--port",    str(port),
             # Keep the error log inside the temp dir so a test run leaves nothing in $HOME.
             "--log",     str(tmpdir / "server.log")],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )

        # 5. Wait up to 90 s for /health to respond
        client = GhidraClient(f"http://127.0.0.1:{port}", binary_path=str(binary))
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
            time.sleep(0.2)

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
