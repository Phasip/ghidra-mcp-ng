#!/usr/bin/env python3
"""
Generate TOOLS.md from the Ghidra MCP server's live OpenAPI spec.

Usage:
    python3 scripts/generate_tools_docs.py [--url URL] [--output PATH]

Requires a running Ghidra MCP server (start.py) to fetch /openapi.json.
"""
import argparse
import json
import sys
import urllib.request
from typing import Any

# ---------------------------------------------------------------------------
# A tool's category is the first `tags` entry on its @Operation annotation, so it
# lives next to the tool it describes and cannot drift as tools are added or
# renamed.  bridge.py reads the same tag to group tools for its discovery layer.
# ---------------------------------------------------------------------------
UNCATEGORIZED = "Other"


def _resolve_ref(spec: dict, ref: str) -> dict:
    parts = ref.lstrip("#/").split("/")
    node = spec
    for p in parts:
        node = node[p]
    return node


def _schema_type(spec: dict, schema: dict) -> str:
    if "$ref" in schema:
        schema = _resolve_ref(spec, schema["$ref"])
    t = schema.get("type", "")
    fmt = schema.get("format", "")
    if t == "array":
        items = schema.get("items", {})
        return f"array of {_schema_type(spec, items)}"
    if t == "object":
        # Name an object's keys inline; otherwise a nested shape like a prototype
        # parameter reads as a bare "object" and its field names are undiscoverable here.
        props = schema.get("properties", {})
        if props:
            return "object {" + ", ".join(props) + "}"
        return "object"
    if fmt:
        return f"{t} ({fmt})"
    return t or "any"


def _behaviour(op: dict, method: str) -> str:
    """One line of what the tool does to the program, from the same facts bridge.py publishes
    as MCP tool annotations (McpToolHints.java plus the method-derived defaults). Rendering it
    here is what makes a change to those defaults visible in a diff."""
    hints = op.get("x-mcp") or {}
    if method == "get":
        notes = ["Reads only"]
    else:
        notes = ["Writes, additively" if hints.get("destructive") is False else "Writes, destructively"]
        if hints.get("idempotent"):
            notes.append("repeating it changes nothing further")
    if hints.get("open_world"):
        notes.append("reaches outside the Ghidra project")
    seconds = hints.get("timeout_seconds")
    if seconds:
        notes.append(f"may run for up to {seconds // 60} minutes")
    return "*" + "; ".join(notes) + ".*"


def _categorize(op: dict) -> str:
    tags = op.get("tags") or []
    return tags[0] if tags else UNCATEGORIZED


def _collect_operations(spec: dict) -> list[dict]:
    ops = []
    for path, path_item in spec.get("paths", {}).items():
        for method, op in path_item.items():
            if method not in ("get", "post", "put", "delete", "patch"):
                continue
            op_id = op.get("operationId", path.split("/")[-1])
            summary = op.get("summary", "")

            # Collect parameters (GET query params)
            params = []
            for p in op.get("parameters", []):
                if "$ref" in p:
                    p = _resolve_ref(spec, p["$ref"])
                if p.get("in") != "query":
                    continue
                pschema = p.get("schema", {})
                if "$ref" in pschema:
                    pschema = _resolve_ref(spec, pschema["$ref"])
                default = pschema.get("default", "")
                required = p.get("required", False)
                desc = p.get("description", "")
                params.append({
                    "name": p["name"],
                    "type": _schema_type(spec, pschema),
                    "required": required,
                    "default": str(default) if default != "" else "",
                    "description": desc,
                })

            # Collect request body fields (POST)
            body_fields = []
            rb = op.get("requestBody", {})
            if rb:
                content = rb.get("content", {})
                json_content = content.get("application/json", {})
                body_schema = json_content.get("schema", {})
                if "$ref" in body_schema:
                    body_schema = _resolve_ref(spec, body_schema["$ref"])
                required_fields = body_schema.get("required", [])
                for fname, fschema in body_schema.get("properties", {}).items():
                    if "$ref" in fschema:
                        fschema = _resolve_ref(spec, fschema["$ref"])
                    body_fields.append({
                        "name": fname,
                        "type": _schema_type(spec, fschema),
                        "required": fname in required_fields,
                        "default": "",
                        "description": fschema.get("description", ""),
                    })

            ops.append({
                "op_id": op_id,
                "method": method.upper(),
                "path": path,
                "summary": summary,
                "behaviour": _behaviour(op, method),
                "category": _categorize(op),
                "params": params or body_fields,
            })
    ops.sort(key=lambda o: (o["category"], o["op_id"]))
    return ops


def _param_table(params: list[dict]) -> str:
    if not params:
        return ""
    lines = [
        "| Parameter | Type | Required | Default | Description |",
        "|-----------|------|:--------:|---------|-------------|",
    ]
    for p in params:
        req = "yes" if p["required"] else ""
        default = p["default"] or ""
        desc = p["description"].replace("\n", " ")
        lines.append(f"| `{p['name']}` | {p['type']} | {req} | {default} | {desc} |")
    return "\n".join(lines)


def generate(spec: dict) -> str:
    ops = _collect_operations(spec)

    by_cat: dict[str, list[dict]] = {}
    for op in ops:
        by_cat.setdefault(op["category"], []).append(op)

    # Alphabetical, except that uncategorized tools sort last so a missing tag is
    # visible at the bottom of the page rather than hidden mid-document.
    final_order = sorted(c for c in by_cat if c != UNCATEGORIZED)
    if UNCATEGORIZED in by_cat:
        final_order.append(UNCATEGORIZED)

    lines = [
        "# Tools reference",
        "",
        "> Auto-generated from the Java annotations.  "
        "Run `make tools-docs` to regenerate.",
        "",
    ]

    for cat in final_order:
        lines += [f"## {cat}", ""]
        for op in by_cat[cat]:
            lines += [f"### `{op['op_id']}`", ""]
            if op["summary"]:
                lines += [op["summary"], ""]
            lines += [op["behaviour"], ""]
            table = _param_table(op["params"])
            if table:
                lines += [table, ""]

    return "\n".join(lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default="http://127.0.0.1:8192",
                        help="Base URL of the running Ghidra MCP server")
    parser.add_argument("--output", default="TOOLS.md",
                        help="Output file (default: TOOLS.md)")
    parser.add_argument("--spec", help="Path to a pre-fetched openapi.json (skips HTTP fetch)")
    args = parser.parse_args()

    if args.spec:
        with open(args.spec) as f:
            spec = json.load(f)
    else:
        url = args.url.rstrip("/") + "/openapi.json"
        print(f"Fetching spec from {url} …", file=sys.stderr)
        try:
            with urllib.request.urlopen(url, timeout=10) as r:
                spec = json.loads(r.read())
        except Exception as e:
            print(f"ERROR: {e}", file=sys.stderr)
            print("Is the Ghidra MCP server running?  "
                  "Start it with:  ./start.py --ghidra <ghidra> --project <project>", file=sys.stderr)
            sys.exit(1)

    md = generate(spec)
    with open(args.output, "w") as f:
        f.write(md)
    print(f"Written {len(md)} bytes to {args.output}", file=sys.stderr)


if __name__ == "__main__":
    main()
