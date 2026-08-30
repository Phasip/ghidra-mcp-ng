"""
test_schema_matches_implementation.py — the published schema must be the code's own vocabulary.

A POST tool has two halves that a reader has to keep in step by hand: the request record, which
is what the OpenAPI schema (and therefore describe_tool, TOOLS.md, and the unknown-field filter)
is generated from, and the `required(request, "x")` / `optional(request, "x", …)` calls in the
method body, which are what the tool actually reads. Rename one half and the surface starts
advertising a field the server rejects — the caller is told the truth by the error and a lie by
the schema.

Nothing at runtime can catch that: the field it reads is a string literal. So it is caught here,
by reading the source. Offline and dependency-free, like test_bridge.py.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

_SRC = Path(__file__).resolve().parent.parent / "src/main/java/com/ghidramcpng/tools"
_TOOL_FILES = ("ReadTools.java", "WriteTools.java", "ScriptTool.java")

# Every way a tool reads one field out of the request body: required(request, "x"),
# optional(request, "x", …), and the few tool-specific readers that wrap them.
_BODY_READ = re.compile(r"\b\w+\(\s*request\s*,\s*\"([a-z0-9_]+)\"")
_POST_PATH = re.compile(r"@POST\s+@Path\(\"/([a-z0-9_]+)\"\)")
_SCHEMA = re.compile(r"implementation\s*=\s*(\w+)\.class")


def _read_sources() -> str:
    return "\n".join((_SRC / name).read_text() for name in _TOOL_FILES)


_SIGNATURE_END = re.compile(r"\)\s*(?:throws\s+[\w.,\s]+?)?\s*\{")


def _method_body(text: str, start: int) -> str:
    """The braced body of the method whose signature ends at or after `start`."""
    end = _SIGNATURE_END.search(text, start)
    assert end, "no method body after offset %d" % start
    open_brace = end.end() - 1
    depth = 0
    for i in range(open_brace, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return text[open_brace:i]
    raise AssertionError("unbalanced braces after offset %d" % start)


def _record_components(text: str, record: str) -> set[str]:
    """The component names of `public record Xxx(...)`, which become the JSON field names."""
    match = re.search(r"public record " + re.escape(record) + r"\(", text)
    assert match, f"request record '{record}' is not defined in the tool sources"
    start = match.end()
    depth = 1
    i = start
    while depth:
        if text[i] == "(":
            depth += 1
        elif text[i] == ")":
            depth -= 1
        i += 1
    return {_component_name(part) for part in _split_components(text[start:i - 1])}


def _split_components(params: str) -> list[str]:
    """The record's components, split on the commas that separate them and no others."""
    parts, current, depth, in_string = [], "", 0, False
    previous = ""
    for ch in params:
        if in_string:
            current += ch
            if ch == '"' and previous != "\\":
                in_string = False
            previous = ch
            continue
        if ch == '"':
            in_string = True
        elif ch in "<(":
            depth += 1
        elif ch in ">)":
            depth -= 1
        if ch == "," and depth == 0:
            parts.append(current)
            current = ""
        else:
            current += ch
        previous = ch
    if current.strip():
        parts.append(current)
    return parts


def _component_name(part: str) -> str:
    """A component is `@Schema(…) Type name` — the trailing identifier is the JSON key."""
    match = re.search(r"(\w+)\s*$", part.strip())
    assert match, f"cannot read a component name from '{part.strip()}'"
    return match.group(1)


def _post_tools() -> list[tuple[str, str, str]]:
    """(tool name, request record, method body) for every POST tool that declares a schema."""
    text = _read_sources()
    tools = []
    for match in _POST_PATH.finditer(text):
        # The response schema is declared first, so anchor on the @RequestBody annotation —
        # the request record is the only one this is about.
        body_annotation = text.find("@RequestBody", match.end(), match.end() + 2000)
        if body_annotation < 0:
            continue
        schema = _SCHEMA.search(text, body_annotation)
        assert schema, f"{match.group(1)}'s @RequestBody names no schema"
        tools.append((match.group(1), schema.group(1), _method_body(text, schema.end())))
    assert tools, "no POST tools found — the source layout changed, fix this test"
    return tools


_POST_TOOLS = _post_tools()


@pytest.mark.parametrize("tool,record,body", _POST_TOOLS, ids=[t[0] for t in _POST_TOOLS])
def test_every_field_the_tool_reads_is_in_its_published_schema(tool: str, record: str, body: str):
    declared = _record_components(_read_sources(), record)
    read = set(_BODY_READ.findall(body))
    undeclared = read - declared
    assert not undeclared, (
        f"{tool} reads {sorted(undeclared)} but {record} does not declare "
        f"{'them' if len(undeclared) > 1 else 'it'}: the schema would advertise "
        f"{sorted(declared)} while the server demands something else."
    )


@pytest.mark.parametrize("tool,record,body", _POST_TOOLS, ids=[t[0] for t in _POST_TOOLS])
def test_every_field_the_schema_publishes_is_read_by_the_tool(tool: str, record: str, body: str):
    declared = _record_components(_read_sources(), record)
    read = set(_BODY_READ.findall(body))
    ignored = declared - read
    assert not ignored, (
        f"{record} publishes {sorted(ignored)} but {tool} never reads "
        f"{'them' if len(ignored) > 1 else 'it'}: a caller that fills the field in gets no error "
        "and no effect."
    )
