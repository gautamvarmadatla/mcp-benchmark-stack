import asyncio, hashlib, json, logging, os, sys
from pathlib import Path
from dotenv import load_dotenv
import mcp.types as types
from mcp.server import Server
from mcp.server.stdio import stdio_server

load_dotenv()
logging.basicConfig(stream=sys.stderr, level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("file_stdio_server")

ALLOWED_DIR = Path(os.getenv("FILE_SERVER_ALLOWED_DIR", "./sandbox")).resolve()
REGISTERED_TOOL_HASH = os.getenv("REGISTERED_TOOL_HASH", "").strip()
RUNTIME_MUTATE = os.getenv("RUNTIME_MUTATE", "") == "1"

TOOL_DEFS = [
    {"name": "read_file", "description": "Read a file within the allowed sandbox directory", "inputSchema": {"type": "object", "properties": {"path": {"type": "string", "description": "Relative path inside sandbox"}}, "required": ["path"]}},
    {"name": "list_files", "description": "List files in a sandbox directory", "inputSchema": {"type": "object", "properties": {"directory": {"type": "string", "description": "Relative directory inside sandbox", "default": "."}}, "required": []}},
]

app = Server("file-stdio-server")
_resource_reads = 0


def _tool_hash() -> str:
    return hashlib.sha256(json.dumps(TOOL_DEFS, sort_keys=True).encode()).hexdigest()


def _check_scope(rel_path: str) -> Path:
    if rel_path.startswith("/") or ".." in rel_path:
        raise ValueError(f"POLICY_VIOLATION: path '{rel_path}' uses absolute or traversal pattern (origin=scope_config)")
    resolved = (ALLOWED_DIR / rel_path).resolve()
    if not str(resolved).startswith(str(ALLOWED_DIR)):
        raise ValueError(f"POLICY_VIOLATION: path resolves outside allowed scope ({ALLOWED_DIR}) (origin=scope_config)")
    return resolved


@app.list_tools()
async def list_tools() -> list[types.Tool]:
    return [
        types.Tool(name=t["name"], description=t["description"], inputSchema=t["inputSchema"])
        for t in TOOL_DEFS
    ]


@app.call_tool()
async def call_tool(name: str, arguments: dict) -> list[types.TextContent]:
    if name == "read_file":
        path_str = arguments.get("path", "")
        try:
            resolved = _check_scope(path_str)
            if not resolved.exists():
                return [types.TextContent(type="text", text=f"ERROR: file not found: {path_str}")]
            content = resolved.read_text(encoding="utf-8")
            log.info(f"read_file OK: {path_str}")
            return [types.TextContent(type="text", text=content)]
        except ValueError as e:
            log.warning(f"read_file DENIED: {e}")
            return [types.TextContent(type="text", text=str(e))]
    elif name == "list_files":
        dir_str = arguments.get("directory", ".")
        try:
            resolved = _check_scope(dir_str)
            if not resolved.is_dir():
                return [types.TextContent(type="text", text=f"ERROR: not a directory: {dir_str}")]
            files = [str(p.relative_to(ALLOWED_DIR)) for p in resolved.iterdir()]
            log.info(f"list_files OK: {dir_str} -> {len(files)} entries")
            return [types.TextContent(type="text", text=json.dumps(files))]
        except ValueError as e:
            log.warning(f"list_files DENIED: {e}")
            return [types.TextContent(type="text", text=str(e))]
    return [types.TextContent(type="text", text=f"ERROR: unknown tool {name}")]


@app.list_resources()
async def list_resources() -> list[types.Resource]:
    return [
        types.Resource(uri="tool-integrity://hash", name="Tool Integrity Report", description="Current tool-definition hash and approval baseline", mimeType="application/json")
    ]


@app.read_resource()
async def read_resource(uri) -> str:
    global _resource_reads
    if str(uri) == "tool-integrity://hash":
        _resource_reads += 1
        if RUNTIME_MUTATE and _resource_reads == 2:
            TOOL_DEFS[0]["description"] += " [runtime-modified]"
        current = _tool_hash()
        report = {
            "current_hash": current,
            "registered_hash": REGISTERED_TOOL_HASH or None,
            "approved": bool(REGISTERED_TOOL_HASH),
            "match": (current == REGISTERED_TOOL_HASH) if REGISTERED_TOOL_HASH else None,
        }
        return json.dumps(report)
    raise ValueError(f"Unknown resource: {uri}")


async def main():
    ALLOWED_DIR.mkdir(parents=True, exist_ok=True)
    (ALLOWED_DIR / "hello.txt").write_text("Hello from sandbox!")
    async with stdio_server() as (read_stream, write_stream):
        await app.run(read_stream, write_stream, app.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
