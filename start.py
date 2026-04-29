#!/usr/bin/env python3
"""
start.py — Start the ghidra-mcp-ng HTTP API server.

Provides a named-flag CLI and zip-slip-safe extension installation.

Examples:

    # Minimal: server with built-in default rules
    ./start.py --ghidra /opt/ghidra --project ~/ghidra-projects/MyProject

    # With naming rules
    ./start.py --ghidra /opt/ghidra --project ~/ghidra-projects/MyProject \\
               --rules ~/rules.yaml

    # Custom port and an extra Ghidra extension to install before launch
    ./start.py --ghidra /opt/ghidra --project ~/ghidra-projects/MyProject \\
               --port 9000 \\
               --install-ext ~/extensions/MyExtension.zip

The server logs to stderr. Send SIGINT/SIGTERM to shut down cleanly.
"""

from __future__ import annotations

import argparse
import os
import shutil
import sys
import zipfile
from pathlib import Path


def _parse_application_properties(props_path: Path) -> dict:
    """Parse a Ghidra application.properties file (key=value lines, # comments)."""
    if not props_path.is_file():
        raise SystemExit(
            f"Cannot find Ghidra application.properties at {props_path}. "
            "Is --ghidra pointing at a Ghidra installation directory?"
        )
    out: dict[str, str] = {}
    for line in props_path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" in line:
            key, value = line.split("=", 1)
            out[key.strip()] = value.strip()
    return out


def _ghidra_settings_dir(ghidra_path: Path) -> Path:
    """
    Replicate ghidra.framework.GhidraApplicationLayout's user-settings location:
        ~/.config/ghidra/<lowercase-name>_<version>[_<release>]
    Honours XDG_CONFIG_HOME when set and non-empty.
    """
    props = _parse_application_properties(ghidra_path / "Ghidra" / "application.properties")
    name = props.get("application.name", "")
    version = props.get("application.version", "")
    release = props.get("application.release.name", "")
    if not name or not version:
        raise SystemExit(
            f"Failed to determine Ghidra version from {ghidra_path}/Ghidra/application.properties."
        )
    vname = f"{name.lower()}_{version}"
    if release:
        vname = f"{vname}_{release}"
    config_home_env = os.environ.get("XDG_CONFIG_HOME", "").strip()
    config_home = Path(config_home_env) if config_home_env else Path.home() / ".config"
    return config_home / "ghidra" / vname


def _safe_extract_zip(zip_path: Path, target_dir: Path) -> str:
    """
    Validate and extract an extension zip into target_dir.

    The archive must contain exactly one top-level directory and no entries with
    absolute paths or '..' components (zip-slip protection). Returns the
    extension's top-level directory name.
    """
    with zipfile.ZipFile(zip_path) as zf:
        names = [n for n in zf.namelist() if n]
        if not names:
            raise SystemExit(f"Extension zip is empty: {zip_path}")

        top_levels = set()
        for name in names:
            # Reject absolute paths, parent traversal and Windows-drive-style names
            if name.startswith("/") or ".." in Path(name).parts or ":" in name:
                raise SystemExit(
                    f"Refusing to install {zip_path}: unsafe entry '{name}'."
                )
            first = name.split("/", 1)[0]
            top_levels.add(first)

        if len(top_levels) != 1:
            raise SystemExit(
                f"Refusing to install {zip_path}: expected exactly one top-level "
                f"directory, found {sorted(top_levels)}."
            )
        ext_name = next(iter(top_levels))

        extension_target = (target_dir / ext_name).resolve()
        # Verify every member resolves under extension_target
        target_dir_resolved = target_dir.resolve()
        for name in names:
            dest = (target_dir / name).resolve()
            try:
                dest.relative_to(target_dir_resolved)
            except ValueError:
                raise SystemExit(
                    f"Refusing to install {zip_path}: '{name}' would escape "
                    f"{target_dir_resolved}."
                )

        if extension_target.exists():
            shutil.rmtree(extension_target)
        zf.extractall(target_dir)
    return ext_name


def _install_extensions(ghidra_path: Path, extensions: list[Path]) -> None:
    settings_dir = _ghidra_settings_dir(ghidra_path)
    ext_dir = settings_dir / "Extensions"
    ext_dir.mkdir(parents=True, exist_ok=True)

    for ext in extensions:
        ext = ext.expanduser()
        if ext.is_file() and ext.suffix.lower() == ".zip":
            ext_name = _safe_extract_zip(ext, ext_dir)
            print(f"Installed extension '{ext_name}' from {ext} -> {ext_dir / ext_name}",
                  file=sys.stderr)
        elif ext.is_dir():
            target = ext_dir / ext.name
            if target.exists():
                shutil.rmtree(target)
            shutil.copytree(ext, target)
            print(f"Installed extension '{ext.name}' from {ext} -> {target}",
                  file=sys.stderr)
        else:
            raise SystemExit(
                f"--install-ext path is not a .zip file or directory: {ext}"
            )


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="start.py",
        description="Start the ghidra-mcp-ng HTTP API server.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--ghidra", required=True, type=Path, metavar="DIR",
                        help="Path to the Ghidra installation directory.")
    parser.add_argument("--project", required=True, type=Path, metavar="DIR",
                        help="Path to the Ghidra project directory (folder containing <name>.rep).")
    parser.add_argument("--rules", type=Path, metavar="FILE", default=None,
                        help="Path to rules.yaml with naming rules and timeouts. "
                             "Omit to disable all naming rules and use built-in defaults.")
    parser.add_argument("--port", type=int, default=8192, metavar="PORT",
                        help="HTTP API port (default: 8192).")
    parser.add_argument("--install-ext", action="append", default=[], type=Path,
                        metavar="ZIP_OR_DIR",
                        help="Install a Ghidra extension ZIP or directory into the user "
                             "extensions directory before starting. Existing copies are "
                             "replaced. May be repeated.")
    args = parser.parse_args()

    ghidra_path: Path = args.ghidra.expanduser().resolve()
    project_path: Path = args.project.expanduser().resolve()
    launch_sh = ghidra_path / "support" / "launch.sh"
    if not launch_sh.is_file():
        raise SystemExit(
            f"Cannot find {launch_sh}. Is --ghidra pointing at a Ghidra install?"
        )
    if not project_path.exists():
        raise SystemExit(f"Project directory does not exist: {project_path}")

    if args.install_ext:
        _install_extensions(ghidra_path, args.install_ext)

    cmd = [
        str(launch_sh), "fg", "jdk", "GhidraMcpNg", "2G", "",
        "com.ghidramcpng.GhidraMcpServer",
        "--project", str(project_path),
        "--port", str(args.port),
    ]
    if args.rules is not None:
        rules_path = args.rules.expanduser().resolve()
        cmd[-2:-2] = ["--rules", str(rules_path)]

    # Replace ourselves with the launcher so signals (Ctrl-C, SIGTERM) reach Ghidra
    # directly and the exit code is propagated.
    os.execv(launch_sh, cmd)


if __name__ == "__main__":
    main()
