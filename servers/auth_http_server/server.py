import json, logging, os
from contextvars import ContextVar
from dotenv import load_dotenv
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from mcp.server.fastmcp import FastMCP

load_dotenv()
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("auth_http_server")

PORT = int(os.getenv("AUTH_SERVER_PORT", "8002"))

TOKEN_TABLE = {
    os.getenv("VALID_API_TOKEN", "valid-token-abc123"):           {"scope": "read:secrets", "principal": "user1"},
    os.getenv("INVALID_SCOPE_TOKEN", "scope-limited-token-xyz"):  {"scope": "read:metrics", "principal": "user2"},
    os.getenv("UNAUTHORIZED_TOKEN", "unauthorized-token-000"):    {"scope": "read:secrets", "principal": "banned_user"},
}
BLACKLISTED_PRINCIPALS = {"banned_user"}

TOOL_REQUIRED_SCOPE = {
    "get_secret": "read:secrets",
    "read_metric": "read:secrets",
}
OVERBROAD_TOOL_SCOPES = {"read_metric"}

_current_token: ContextVar[dict] = ContextVar("current_token", default={})

mcp = FastMCP("auth-http-server")


class AuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            log.warning(f"AUTHN_REQUIRED: no bearer token")
            return JSONResponse({"error": "AUTHN_REQUIRED"}, status_code=401)
        token = auth_header[7:].strip()
        info = TOKEN_TABLE.get(token)
        if not info:
            log.warning("AUTHN_FAILED: invalid token")
            return JSONResponse({"error": "AUTHN_FAILED"}, status_code=401)
        if info["principal"] in BLACKLISTED_PRINCIPALS:
            log.warning(f"AUTHZ_DENIED: blacklisted principal '{info['principal']}'")
            return JSONResponse({"error": "AUTHZ_DENIED", "detail": f"Principal '{info['principal']}' not authorized"}, status_code=403)
        log.info(f"AUTH_OK: principal={info['principal']} scope={info['scope']}")
        tok = _current_token.set(info)
        try:
            return await call_next(request)
        finally:
            _current_token.reset(tok)


def _check_scope(tool_name: str) -> str | None:
    info = _current_token.get()
    required = TOOL_REQUIRED_SCOPE[tool_name]
    if required not in info.get("scope", "").split():
        denial = {
            "error": "AUTHZ_DENIED",
            "tool": tool_name,
            "required_scope": required,
            "granted_scope": info.get("scope", "").split(),
            "tool_scope_overbroad": tool_name in OVERBROAD_TOOL_SCOPES,
            "principal": info.get("principal", "?"),
        }
        log.warning(f"AUTHZ_DENIED: tool={tool_name} required='{required}' overbroad={denial['tool_scope_overbroad']}")
        return json.dumps(denial)
    return None


@mcp.tool()
def get_secret(key: str) -> str:
    denial = _check_scope("get_secret")
    if denial:
        return denial
    secrets = {"db_password": "hunter2", "api_key": "sk-12345"}
    value = secrets.get(key, f"SECRET_NOT_FOUND: {key}")
    log.info(f"get_secret OK: key={key}")
    return value


@mcp.tool()
def read_metric(name: str) -> str:
    denial = _check_scope("read_metric")
    if denial:
        return denial
    log.info(f"read_metric OK: name={name}")
    return f"METRIC[{name}]=42"


if __name__ == "__main__":
    import uvicorn
    app = mcp.streamable_http_app()
    app.add_middleware(AuthMiddleware)
    uvicorn.run(app, host="127.0.0.1", port=PORT)
