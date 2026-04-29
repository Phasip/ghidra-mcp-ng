#!/usr/bin/env python3
"""
Generate TOOLS.md from the Ghidra MCP server's live OpenAPI spec.

Usage:
    python3 scripts/generate_tools_docs.py [--url URL] [--output PATH]

Requires a running Ghidra MCP server (start.py) to fetch /openapi.json.
"""
import argparse
import json
import re
import sys
import urllib.request
from typing import Any

# ---------------------------------------------------------------------------
# Category definitions — operation IDs are matched against these patterns in
# order; first match wins.  Operations with no match go to "Other".
# ---------------------------------------------------------------------------
CATEGORIES: list[tuple[str, re.Pattern]] = [
    ("Infrastructure",    re.compile(r"^(check_connection|list_project_files)$")),
    ("Functions",         re.compile(r"^(search_functions|get_function_info|get_calling_conventions|get_function_variables|get_function_callers|get_function_callees)$")),
    ("Decompilation",     re.compile(r"^decompile_function$")),
    ("Symbols",           re.compile(r"^(list_exports|list_imports)$")),
    ("Cross-references",  re.compile(r"^get_(xrefs|function_xrefs)")),
    ("Data types",        re.compile(r"^(search_data_types|list_data_type_categories|get_struct_layout)$")),
    ("Strings",           re.compile(r"^search_(defined|memory)_strings$")),
    ("Write operations",  re.compile(r"^(import_binary|rename_|set_|create_|add_|remove_|replace_)")),
    ("Scripting",         re.compile(r"^(list|add|run|delete)_script$")),
]


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
        return "object"
    if fmt:
        return f"{t} ({fmt})"
    return t or "any"


def _categorize(op_id: str) -> str:
    for name, pattern in CATEGORIES:
        if pattern.search(op_id):
            return name
    return "Other"


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
                "category": _categorize(op_id),
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

    # Group by category preserving insertion order of CATEGORIES
    ordered_categories: list[str] = []
    by_cat: dict[str, list[dict]] = {}
    for op in ops:
        cat = op["category"]
        if cat not in by_cat:
            ordered_categories.append(cat)
            by_cat[cat] = []
        by_cat[cat].append(op)

    # Reorder so predefined categories come first
    predefined = [c for c, _ in CATEGORIES]
    final_order = [c for c in predefined if c in by_cat]
    final_order += [c for c in ordered_categories if c not in predefined]

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
