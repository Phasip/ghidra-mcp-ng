#!/usr/bin/env python3
"""
bridge.py — Minimal MCP bridge for ghidra-mcp-ng.

Translates MCP JSON-RPC 2.0 (stdio) to the Ghidra HTTP REST API by fetching
the server's OpenAPI schema and using it to build the MCP tool list and dispatch
every tool call. No tool definitions are hardcoded here; the schema is re-fetched
whenever the server process it came from has been replaced.

Tools are exposed progressively rather than all at once. `tools/list` returns only
the always-useful core (HOT_CORE below) plus three discovery tools; every other
tool is reached through list_tools → describe_tool → call_tool. A full schema dump
costs several thousand tokens of context in every session, most of it for tools a
given session never calls, so the long tail is fetched on demand instead.

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

from __future__ import annotations

import sys
import json
import difflib
import urllib.request
import urllib.error
import urllib.parse
import argparse
import datetime
from typing import Any

# Newest first. The client names the version it wants and gets it back when it is in this list,
# which is what the spec requires; anything else is answered with the newest we speak and the
# client decides whether to continue. 2025-06-18 is the first revision with tool annotations, the
# reason to be on it at all.
SUPPORTED_PROTOCOL_VERSIONS = ("2025-06-18", "2025-03-26", "2024-11-05")
PROTOCOL_VERSION = SUPPORTED_PROTOCOL_VERSIONS[0]
SERVER_NAME = "ghidra-mcp-ng"
SERVER_VERSION = "0.1.0"

# Sent once at initialize. This is the orientation a host gets for free, whatever it is — the
# facts that are true of every tool here and would otherwise have to be rediscovered per session.
INSTRUCTIONS = (
    "Ghidra reverse-engineering tools, driven against an open Ghidra project.\n"
    "Every tool that touches a binary takes 'program' — a name from list_project_files. A "
    "function, symbol or address is always passed as 'name_or_address', accepting an exact "
    "(case-sensitive) name or a 0x-prefixed hex address.\n"
    "Only the most-used tools are listed directly; the rest are reached with list_tools -> "
    "describe_tool -> call_tool.\n"
    "Errors name the offending value and the tool to call next — read one and correct it rather "
    "than retrying the same call."
)

# structuredContent (2025-06-18) is deliberately not used: the spec asks a tool that returns it to
# repeat the same JSON in a text block, which doubles the cost of every response for a surface
# whose whole design is about spending context carefully. Revisit if hosts start suppressing the
# text duplicate.

# Tools listed natively, with full schemas, in every session. These are the ones a
# session reaches for constantly, where a discovery round trip would be pure overhead.
# Everything else is discoverable via list_tools/describe_tool and callable via
# call_tool. Adding an entry here is a deliberate trade: permanent context for one
# saved round trip.
HOT_CORE = (
    "list_project_files",
    "get_program_info",
    "decompile_function",
    "get_function_info",
    "search_functions",
    "get_xrefs_to",
    "get_disassembly",
    "get_function_variables",
    "rename_function",
    "set_variable",
    "set_comment",
    "run_script",
)

UNCATEGORIZED = "Other"


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


def _render_result(payload: Any) -> str:
    """Render a tool's HTTP response as the text the agent reads.

    Two things happen here. The {"ok": true, "result": ...} envelope is dropped: MCP already
    carries success in isError, and repeating it spends tokens on every single call. And any
    multi-line string is lifted out of the JSON and printed as itself — decompiled C and script
    output *are* the answer for the tools that return them, and a JSON-escaped one-liner is both
    bigger and harder to read than the text it encodes.
    """
    if isinstance(payload, dict) and payload.get("ok") is True and "result" in payload:
        payload = payload["result"]
    if not isinstance(payload, dict):
        return json.dumps(payload, separators=(",", ":"))

    text_fields = {k: v for k, v in payload.items() if isinstance(v, str) and "\n" in v}
    if not text_fields:
        return json.dumps(payload, separators=(",", ":"))

    rest = {k: v for k, v in payload.items() if k not in text_fields}
    parts = [json.dumps(rest, separators=(",", ":"))] if rest else []
    parts.extend(f"{key}:\n{value.rstrip()}" for key, value in text_fields.items())
    return "\n\n".join(parts)


def _error_text(status: int, body: str, reason: str) -> str:
    """Surface the server's own message rather than talking over it.

    Every 4xx from this server carries a diagnosis that already names the offending value and
    the tool to call next. Prefixing that with a guess at what might be wrong buries the answer
    under the noise it was written to replace.
    """
    try:
        parsed = json.loads(body)
    except (ValueError, TypeError):
        parsed = None
    if isinstance(parsed, dict) and isinstance(parsed.get("error"), str):
        return parsed["error"]
    return f"HTTP {status}: {body.strip() or reason}"


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
    if t == "object" and s.get("properties"):
        # A record used as a nested field — carry its fields through. Dropping them leaves the
        # agent an untyped 'object' and forces the parent's description to spell the shape out
        # in prose, which is the workaround, not the fix.
        entry["properties"] = {
            name: _prop_schema(spec, _resolve(spec, raw))
            for name, raw in s["properties"].items()
        }
        if s.get("required"):
            entry["required"] = list(s["required"])
    if t == "array":
        raw_items = s.get("items", {})
        if not raw_items:
            entry["items"] = {"type": "string"}
        else:
            item = _prop_schema(spec, _resolve(spec, raw_items))
            # Swagger folds a field's own @Schema(description) into the component it references,
            # so the item would otherwise repeat the array's description word for word.
            if item.get("description") == entry.get("description"):
                item.pop("description", None)
            entry["items"] = item
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

    # The server rejects any parameter or field it does not declare, so say so in the schema and
    # let a strict client catch the typo without spending a round trip on it.
    result: dict[str, Any] = {"type": "object", "properties": props, "additionalProperties": False}
    if required:
        result["required"] = required
    return result


def _index(spec: dict) -> dict[str, dict]:
    """Map every operationId to its path, HTTP method, category and raw operation."""
    ops: dict[str, dict] = {}
    for path, methods in spec.get("paths", {}).items():
        for method, op in methods.items():
            if method not in ("get", "post") or "operationId" not in op:
                continue
            tags = op.get("tags") or []
            ops[op["operationId"]] = {
                "path": path,
                "method": method,
                "category": tags[0] if tags else UNCATEGORIZED,
                "op": op,
            }
    return ops


def _categories(ops: dict[str, dict]) -> dict[str, list[str]]:
    """Group operationIds by category, both the mapping and each list sorted."""
    grouped: dict[str, list[str]] = {}
    for name in sorted(ops):
        grouped.setdefault(ops[name]["category"], []).append(name)
    return dict(sorted(grouped.items()))


def _tool_entry(spec: dict, name: str, entry: dict) -> dict:
    """Build a full MCP tool definition for one indexed operation."""
    return {
        "name": name,
        "description": entry["op"].get("summary", name),
        "inputSchema": _input_schema(spec, entry["op"], entry["method"]),
    }


# ---------------------------------------------------------------------------
# Discovery tools
#
# These three are implemented here in the bridge, not on the Ghidra server: they
# describe the tool surface rather than touching a program, and the server already
# publishes everything they need at /openapi.json.
# ---------------------------------------------------------------------------

def _meta_tools(ops: dict[str, dict]) -> list[dict]:
    category_names = sorted({e["category"] for e in ops.values()})
    hidden = sorted(set(ops) - set(HOT_CORE))
    return [
        {
            "name": "list_tools",
            "description": (
                "List the Ghidra tools not shown here — only the most-used ones are listed "
                "directly. No arguments gives every category and its tool names; a category "
                "adds a one-line summary per tool. Categories: "
                + ", ".join(category_names) + "."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "category": {
                        "type": "string",
                        "description": "Restrict the listing to one category.",
                        "enum": category_names,
                    },
                },
                "additionalProperties": False,
            },
        },
        {
            "name": "describe_tool",
            "description": (
                "Get the full parameter schema for any Ghidra tool, listed here or not. "
                "Use it before call_tool when you do not know a tool's arguments."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "tool_name": {
                        "type": "string",
                        "description": "Tool to describe, e.g. from list_tools.",
                    },
                },
                "required": ["tool_name"],
                "additionalProperties": False,
            },
        },
        {
            "name": "call_tool",
            "description": (
                "Run any Ghidra tool by name, listed here or not (" + ", ".join(hidden[:5])
                + ", … — see list_tools). Pass its arguments as an object."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "tool_name": {
                        "type": "string",
                        "description": "Tool to run, e.g. from list_tools.",
                    },
                    "arguments": {
                        "type": "object",
                        "description": "That tool's arguments; see describe_tool.",
                    },
                },
                "required": ["tool_name"],
                "additionalProperties": False,
            },
        },
    ]


def _openapi_to_mcp_tools(spec: dict) -> list[dict]:
    """Build the MCP tools list: the hot core with full schemas, plus discovery tools."""
    ops = _index(spec)
    tools = [_tool_entry(spec, name, ops[name]) for name in sorted(ops) if name in HOT_CORE]
    tools.extend(_meta_tools(ops))
    return tools


def _unknown_tool(name: str, ops: dict[str, dict]) -> ValueError:
    """Reject an unknown tool name, naming the nearest real one rather than all of them."""
    close = difflib.get_close_matches(name, list(ops), n=1, cutoff=0.6)
    if close:
        hint = f"Did you mean '{close[0]}'?"
    else:
        hint = "Use list_tools to see what exists."
    return ValueError(f"Unknown tool: '{name}'. {hint}")


# What each discovery tool accepts. They are implemented here rather than on the server, so the
# server's unknown-field filter never sees them — this is the same check, in the only place that
# can make it.
_DISCOVERY_ARGS = {
    "list_tools": ("category",),
    "describe_tool": ("tool_name",),
    "call_tool": ("tool_name", "arguments"),
}


def _reject_unknown_arguments(name: str, arguments: dict) -> None:
    """Refuse an argument the discovery tool does not declare, listing the ones it does."""
    allowed = _DISCOVERY_ARGS[name]
    unknown = [key for key in arguments if key not in allowed]
    if not unknown:
        return
    message = (
        "Unknown field" + ("s " if len(unknown) > 1 else " ")
        + ", ".join(f"'{key}'" for key in unknown)
        + f" for tool '{name}'. Valid fields: " + ", ".join(allowed) + "."
    )
    if name == "call_tool":
        # The usual shape of this mistake: the target tool's own arguments, flattened.
        message += " The target tool's own arguments go under 'arguments'."
    raise ValueError(message)


def _do_list_tools(ops: dict[str, dict], arguments: dict) -> Any:
    _reject_unknown_arguments("list_tools", arguments)
    grouped = _categories(ops)
    category = arguments.get("category")
    if category is None:
        return {"categories": grouped}
    if category not in grouped:
        raise ValueError(
            f"Unknown category: '{category}'. Valid categories: " + ", ".join(grouped) + ".")
    return {
        "category": category,
        "tools": [
            {"name": n, "summary": ops[n]["op"].get("summary", n)}
            for n in grouped[category]
        ],
    }


def _missing_tool_name(caller: str, shape: str, arguments: dict) -> ValueError:
    """Reject a discovery call that named no tool, showing the shape it wanted.

    Naming the missing field alone is not enough here: the caller has just guessed a key for
    "the tool I mean", so the fix is the whole expected body next to the keys it actually sent.
    """
    got = ", ".join(f"'{k}'" for k in arguments) or "nothing"
    return ValueError(
        f"Required parameter 'tool_name' is missing for {caller}. "
        f"Expected {shape} — you passed {got}."
    )


def _do_describe_tool(spec: dict, ops: dict[str, dict], arguments: dict) -> Any:
    _reject_unknown_arguments("describe_tool", arguments)
    name = arguments.get("tool_name")
    if not name:
        raise _missing_tool_name(
            "describe_tool", '{"tool_name": "get_struct_layout"}', arguments)
    if name not in ops:
        raise _unknown_tool(name, ops)
    entry = ops[name]
    return {
        "name": name,
        "category": entry["category"],
        "description": entry["op"].get("summary", name),
        "inputSchema": _input_schema(spec, entry["op"], entry["method"]),
    }


def _dispatch(spec: dict, base: str, name: str, arguments: dict) -> Any:
    """Run a tool by name — a discovery tool here, or an operationId over HTTP."""
    ops = _index(spec)

    if name == "list_tools":
        return _do_list_tools(ops, arguments)
    if name == "describe_tool":
        return _do_describe_tool(spec, ops, arguments)
    if name == "call_tool":
        _reject_unknown_arguments("call_tool", arguments)
        target = arguments.get("tool_name")
        if not target:
            raise _missing_tool_name(
                "call_tool",
                '{"tool_name": "get_struct_layout", "arguments": {"program": "..."}}',
                arguments)
        if target in ("list_tools", "describe_tool", "call_tool"):
            raise ValueError(
                f"call_tool cannot run '{target}': it is a discovery tool, call it directly."
            )
        return _dispatch(spec, base, target, arguments.get("arguments") or {})

    if name not in ops:
        raise _unknown_tool(name, ops)

    entry = ops[name]
    url = base + entry["path"]
    if entry["method"] == "get":
        if arguments:
            # doseq spreads a list into repeated params, which is what the server's
            # List<String> query params (ref_types) parse; without it the list arrives
            # as its Python repr and matches no reference type.
            url = f"{url}?{urllib.parse.urlencode(arguments, doseq=True)}"
        return _get(url)
    return _post(url, arguments)


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


def _server_instance(base: str) -> str | None:
    """The running server process's identity, or None when it cannot be asked."""
    try:
        health = _get(f"{base}/health")
        return health.get("started_at") if isinstance(health, dict) else None
    except (urllib.error.URLError, OSError, ValueError):
        return None


def _run_loop(base: str, log) -> None:
    # Cached OpenAPI spec, valid only for the server process it was fetched from. The
    # schema is generated from that process's own annotations, so a rebuild-and-restart
    # under a long-lived bridge leaves the cache describing code that no longer runs —
    # which is how describe_tool ends up advertising a field the live server rejects.
    # /health's started_at changes on every start; a changed one means refetch.
    spec_cache: dict | None = None
    spec_instance: str | None = None

    def get_spec() -> dict:
        nonlocal spec_cache, spec_instance
        instance = _server_instance(base)
        if spec_cache is None or (instance is not None and instance != spec_instance):
            spec_cache = _get(f"{base}/openapi.json")
            spec_instance = instance
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
            # Echo the client's version when we speak it, otherwise answer with the newest we do
            # and let the client decide — the negotiation the spec asks for, rather than
            # announcing one fixed version at everybody.
            requested = params.get("protocolVersion")
            agreed = requested if requested in SUPPORTED_PROTOCOL_VERSIONS else PROTOCOL_VERSION
            resp = _ok(id_, {
                "protocolVersion": agreed,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
                "instructions": INSTRUCTIONS,
            })
            _send(resp)
            log("SEND", f"initialize → protocol {agreed} (client asked for {requested})")

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
                resp = _tool_result(id_, _render_result(http_resp))
                _send(resp)
                log("CALL", f"{name} → ok")
            except ValueError as e:
                resp = _tool_result(id_, str(e), is_error=True)
                _send(resp)
                log("CALL", f"{name} → ValueError: {e}")
            except urllib.error.HTTPError as e:
                body = e.read().decode() if hasattr(e, "read") else ""
                msg = _error_text(e.code, body, e.reason)
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
