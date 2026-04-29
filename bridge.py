#!/usr/bin/env python3
"""
bridge.py — Minimal MCP bridge for ghidra-mcp-ng.

Translates MCP JSON-RPC 2.0 (stdio) to the Ghidra HTTP REST API by fetching
the server's OpenAPI schema at startup and using it to build the MCP tool list
and dispatch every tool call. No tools are hardcoded here.

Usage:
    python bridge.py [--url http://127.0.0.1:8192] [--logfile /tmp/bridge.log]

MCP client config (mcp-config.json):
    {
      "mcpServers": {
        "ghidra": {
          "command": "python",
          "args": ["/path/to/bridge.py", "--url", "http://127.0.0.1:8192"]
        }
      }
    }

Requirements: Python 3.8+, stdlib only.
"""

import sys
import json
import urllib.request
import urllib.error
import urllib.parse
import argparse
import datetime
from typing import Any

PROTOCOL_VERSION = "2024-11-05"
SERVER_NAME = "ghidra-mcp-ng"
SERVER_VERSION = "0.1.0"


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------

def _get(url: str) -> Any:
    with urllib.request.urlopen(url, timeout=30) as r:
        return json.loads(r.read().decode())


def _post(url: str, data: dict) -> Any:
    body = json.dumps(data).encode()
    req = urllib.request.Request(
        url, data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=120) as r:
        return json.loads(r.read().decode())


# ---------------------------------------------------------------------------
# JSON-RPC helpers
# ---------------------------------------------------------------------------

def _send(obj: dict) -> None:
    print(json.dumps(obj, separators=(",", ":")), flush=True)


def _ok(id_: Any, result: dict) -> dict:
    return {"jsonrpc": "2.0", "id": id_, "result": result}


def _err(id_: Any, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": id_, "error": {"code": code, "message": message}}


def _tool_result(id_: Any, text: str, *, is_error: bool = False) -> dict:
    result: dict[str, Any] = {"content": [{"type": "text", "text": text}]}
    if is_error:
        result["isError"] = True
    return _ok(id_, result)


# ---------------------------------------------------------------------------
# OpenAPI → MCP conversion
# ---------------------------------------------------------------------------

def _resolve_ref(spec: dict, ref: str) -> dict:
    """Resolve a JSON $ref like '#/components/schemas/Foo' within the spec."""
    parts = ref.lstrip("#/").split("/")
    node: Any = spec
    for part in parts:
        node = node[part]
    return node


def _resolve(spec: dict, schema: dict) -> dict:
    return _resolve_ref(spec, schema["$ref"]) if "$ref" in schema else schema


def _prop_schema(spec: dict, s: dict) -> dict:
    """Convert a resolved OpenAPI schema node to a JSON Schema property entry."""
    t = s.get("type", "string")
    entry: dict[str, Any] = {"type": t}
    if "description" in s:
        entry["description"] = s["description"]
    if "default" in s:
        entry["default"] = s["default"]
    if "enum" in s:
        entry["enum"] = s["enum"]
    if t == "array":
        raw_items = s.get("items", {})
        entry["items"] = _prop_schema(spec, _resolve(spec, raw_items)) if raw_items else {"type": "string"}
    return entry


def _input_schema(spec: dict, op: dict, method: str) -> dict:
    """Build a JSON Schema inputSchema from an OpenAPI operation."""
    props: dict[str, Any] = {}
    required: list[str] = []

    if method == "get":
        for param in op.get("parameters", []):
            if param.get("in") != "query":
                continue
            name = param["name"]
            s = _resolve(spec, param.get("schema", {}))
            entry = _prop_schema(spec, s)
            if "description" in param and "description" not in entry:
                entry["description"] = param["description"]
            props[name] = entry
            if param.get("required", False):
                required.append(name)
    else:
        body = op.get("requestBody", {})
        content = body.get("content", {}).get("application/json", {})
        schema = _resolve(spec, content.get("schema", {}))
        for name, raw_s in schema.get("properties", {}).items():
            props[name] = _prop_schema(spec, _resolve(spec, raw_s))
        required = schema.get("required", [])

    result: dict[str, Any] = {"type": "object", "properties": props}
    if required:
        result["required"] = required
    return result


def _openapi_to_mcp_tools(spec: dict) -> list[dict]:
    """Convert an OpenAPI spec to an MCP tools list."""
    tools = []
    for path, methods in spec.get("paths", {}).items():
        for method, op in methods.items():
            if method not in ("get", "post") or "operationId" not in op:
                continue
            tools.append({
                "name": op["operationId"],
                "description": op.get("summary", op["operationId"]),
                "inputSchema": _input_schema(spec, op, method),
            })
    tools.sort(key=lambda t: t["name"])
    return tools


def _dispatch(spec: dict, base: str, name: str, arguments: dict) -> Any:
    """Call a tool by looking up its operationId in the OpenAPI spec."""
    for path, methods in spec.get("paths", {}).items():
        for method, op in methods.items():
            if op.get("operationId") != name:
                continue
            url = base + path
            if method == "get":
                if arguments:
                    url = f"{url}?{urllib.parse.urlencode(arguments)}"
                return _get(url)
            else:
                return _post(url, arguments)
    raise ValueError(
        f"Unknown tool: '{name}'. Use tools/list to see all available tools."
    )


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="MCP ↔ Ghidra HTTP bridge")
    parser.add_argument(
        "--url",
        default="http://127.0.0.1:8192",
        help="Base URL of the Ghidra HTTP API (default: http://127.0.0.1:8192)",
    )
    parser.add_argument(
        "--logfile",
        metavar="PATH",
        help="Path to a file for logging all bridge activity (optional)",
    )
    args = parser.parse_args()
    base = args.url.rstrip("/")

    log_fh = open(args.logfile, "a", encoding="utf-8") if args.logfile else None

    def log(tag: str, text: str) -> None:
        if log_fh is None:
            return
        ts = datetime.datetime.now().isoformat(timespec="milliseconds")
        log_fh.write(f"[{ts}] {tag} {text}\n")
        log_fh.flush()

    log("START", f"bridge starting, connecting to {base}")

    try:
        _run_loop(base, log)
    finally:
        if log_fh:
            log("STOP", "bridge exiting")
            log_fh.close()


def _run_loop(base: str, log) -> None:
    # Cached OpenAPI spec — fetched on first tools/list or tools/call, then reused.
    spec_cache: dict | None = None

    def get_spec() -> dict:
        nonlocal spec_cache
        if spec_cache is None:
            spec_cache = _get(f"{base}/openapi.json")
        return spec_cache

    for raw in sys.stdin:
        raw = raw.strip()
        if not raw:
            continue

        log("RECV", raw)

        try:
            req = json.loads(raw)
        except json.JSONDecodeError as e:
            resp = _err(None, -32700, f"Parse error: {e}")
            _send(resp)
            log("SEND", json.dumps(resp))
            continue

        method = req.get("method")
        if not method:
            resp = _err(req.get("id"), -32600, "Missing 'method'")
            _send(resp)
            log("SEND", json.dumps(resp))
            continue

        id_ = req.get("id")

        # Notifications (no id) — no response required
        if id_ is None:
            continue

        params = req.get("params") or {}

        if method == "initialize":
            resp = _ok(id_, {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
            })
            _send(resp)
            log("SEND", json.dumps(resp))

        elif method == "tools/list":
            try:
                resp = _ok(id_, {"tools": _openapi_to_mcp_tools(get_spec())})
                _send(resp)
                log("SEND", f"tools/list → {len(resp['result']['tools'])} tools")
            except urllib.error.HTTPError as e:
                resp = _err(id_, -32603, f"Ghidra API error {e.code}: {e.reason}. Is the server running?")
                _send(resp)
                log("ERROR", json.dumps(resp))
            except (urllib.error.URLError, OSError) as e:
                resp = _err(id_, -32603, f"Cannot reach Ghidra API at {base}: {e}. Is the server running?")
                _send(resp)
                log("ERROR", json.dumps(resp))

        elif method == "tools/call":
            name = params.get("name")
            if not name:
                resp = _err(id_, -32600, "tools/call missing 'name'")
                _send(resp)
                log("SEND", json.dumps(resp))
                continue
            arguments = params.get("arguments") or {}
            try:
                http_resp = _dispatch(get_spec(), base, name, arguments)
                resp = _tool_result(id_, json.dumps(http_resp, indent=2))
                _send(resp)
                log("CALL", f"{name} → ok")
            except ValueError as e:
                resp = _tool_result(id_, str(e), is_error=True)
                _send(resp)
                log("CALL", f"{name} → ValueError: {e}")
            except urllib.error.HTTPError as e:
                body = e.read().decode() if hasattr(e, "read") else ""
                hint = {
                    400: " (bad parameters — check required fields and types)",
                    404: " (endpoint not found — check tool name or server version)",
                    500: " (Ghidra server error — check server logs)",
                }.get(e.code, "")
                msg = f"HTTP {e.code}{hint}: {body or e.reason}"
                resp = _tool_result(id_, msg, is_error=True)
                _send(resp)
                log("CALL", f"{name} → {msg}")
            except (urllib.error.URLError, OSError) as e:
                msg = f"Cannot reach Ghidra API at {base}: {e}. Is the server running?"
                resp = _tool_result(id_, msg, is_error=True)
                _send(resp)
                log("CALL", f"{name} → {msg}")

        elif method == "ping":
            resp = _ok(id_, {})
            _send(resp)
            log("SEND", "ping → pong")

        else:
            resp = _err(id_, -32601, f"Method not found: {method}")
            _send(resp)
            log("SEND", json.dumps(resp))


if __name__ == "__main__":
    main()
