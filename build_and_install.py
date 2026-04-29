#!/usr/bin/env python3
"""
build_and_install.py — Build the ghidra-mcp-ng extension and install it.

Usage:
    python build_and_install.py <ghidra_path>

    ghidra_path  Path to your Ghidra installation directory
                 (the directory that contains support/launch.sh)

The script:
  1. Validates the Ghidra installation.
  2. Builds the extension with Gradle (GHIDRA_HOME=<ghidra_path>).
  3. Removes any previous installation.
  4. Extracts the built ZIP into the Ghidra user-extensions directory.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _die(msg: str) -> None:
    print(f"ERROR: {msg}", file=sys.stderr)
    sys.exit(1)


def _step(msg: str) -> None:
    print(f">>> {msg}")


def _read_ghidra_version(ghidra_path: Path) -> tuple[str, str]:
    """Return (version, release) read from Ghidra's application.properties."""
    props = ghidra_path / "Ghidra" / "application.properties"
    version = release = ""
    with open(props) as f:
        for line in f:
            if line.startswith("application.version="):
                version = line.split("=", 1)[1].strip()
            elif line.startswith("application.release.name="):
                release = line.split("=", 1)[1].strip()
    if not version:
        _die("Could not read application.version from Ghidra/application.properties")
    return version, release


def _extension_dir(version: str, release: str) -> Path:
    """Return the XDG user-extensions directory for GhidraMcpNg."""
    versioned = f"ghidra_{version}_{release}"
    xdg_base = Path(os.environ.get("XDG_CONFIG_HOME", str(Path.home() / ".config")))
    return xdg_base / "ghidra" / versioned / "Extensions" / "GhidraMcpNg"


# ---------------------------------------------------------------------------
# Steps
# ---------------------------------------------------------------------------

def _build(ghidra_path: Path) -> Path:
    """Run Gradle buildExtension. Return path to the produced ZIP."""
    gradle = shutil.which("gradle")
    if gradle is None:
        _die("gradle not found on PATH — install Gradle and retry")

    _step("Building extension with Gradle …")
    env = {**os.environ, "GHIDRA_HOME": str(ghidra_path)}
    result = subprocess.run(
        [gradle, "buildExtension"],
        cwd=REPO_ROOT,
        env=env,
    )
    if result.returncode != 0:
        _die("Gradle build failed")

    zips = sorted((REPO_ROOT / "dist").glob("ghidra_*.zip"))
    if not zips:
        _die("Build succeeded but no ZIP found in dist/")
    return zips[-1]


def _install(zip_path: Path, install_dir: Path) -> None:
    """Remove any previous install and extract zip_path into install_dir."""
    _step(f"Installing to {install_dir} …")

    if install_dir.exists():
        _step(f"Removing previous installation at {install_dir}")
        shutil.rmtree(install_dir)
    install_dir.mkdir(parents=True)

    with zipfile.ZipFile(zip_path) as zf:
        zf.extractall(install_dir)

    # Ghidra ZIPs contain a single top-level directory; flatten it.
    children = list(install_dir.iterdir())
    if len(children) == 1 and children[0].is_dir():
        tmp = children[0]
        for item in list(tmp.iterdir()):
            item.rename(install_dir / item.name)
        tmp.rmdir()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help"):
        print(__doc__)
        sys.exit(0 if len(sys.argv) >= 2 else 1)

    ghidra_path = Path(sys.argv[1]).expanduser().resolve()

    if not (ghidra_path / "Ghidra" / "application.properties").exists():
        _die(
            f"'{ghidra_path}' does not look like a Ghidra installation\n"
            "  (expected Ghidra/application.properties to exist)"
        )

    version, release = _read_ghidra_version(ghidra_path)
    _step(f"Detected Ghidra {version} ({release})")

    zip_path = _build(ghidra_path)
    _step(f"Built: {zip_path.name}")

    install_dir = _extension_dir(version, release)
    _install(zip_path, install_dir)

    rules_path = install_dir / "rules.yaml"
    print()
    print("=" * 60)
    print("  ghidra-mcp-ng installed successfully!")
    print("=" * 60)
    print()
    print("To start the MCP server:")
    print()
    print(f"  ./start.py --ghidra {ghidra_path} --project /path/to/YourProject --rules {rules_path}")
    print()


if __name__ == "__main__":
    main()
