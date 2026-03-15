import httpx, json, logging, os, ssl
from urllib.parse import urlparse
from dotenv import load_dotenv
from mcp.server.fastmcp import FastMCP

load_dotenv()
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("fetch_http_server")

ALLOWED_HOSTS = set(h.strip() for h in os.getenv("FETCH_SERVER_ALLOWED_HOSTS", "example.com,httpbin.org").split(","))
PORT = int(os.getenv("FETCH_SERVER_PORT", "8001"))

mcp = FastMCP("fetch-http-server")

def _check_host(url: str) -> str:
    parsed = urlparse(url)
    host = parsed.hostname or ""
    if host not in ALLOWED_HOSTS:
        raise ValueError(f"POLICY_VIOLATION: host '{host}' not in egress allowlist {ALLOWED_HOSTS}")
    return host

@mcp.tool()
async def fetch_url(url: str) -> str:
    """Fetch a URL. Only allowed hosts are permitted."""
    try:
        host = _check_host(url)
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(url)
            log.info(f"fetch_url OK: {url} -> {resp.status_code}")
            return f"STATUS:{resp.status_code}\n{resp.text[:2000]}"
    except ValueError as e:
        log.warning(f"fetch_url DENIED: {e}")
        return str(e)
    except httpx.ConnectError as e:
        log.error(f"fetch_url TLS/CONNECT ERROR: {e}")
        return f"TLS_ERROR: {e}"
    except Exception as e:
        log.error(f"fetch_url ERROR: {e}")
        return f"ERROR: {e}"

@mcp.tool()
async def check_tls(url: str) -> str:
    """Check TLS certificate for a URL."""
    try:
        _check_host(url)
        parsed = urlparse(url)
        host = parsed.hostname
        port = parsed.port or 443
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(__import__('socket').create_connection((host, port), timeout=5), server_hostname=host) as ssock:
            cert = ssock.getpeercert()
            log.info(f"check_tls OK: {url}")
            return json.dumps({"tls_ok": True, "subject": cert.get("subject"), "notAfter": cert.get("notAfter")})
    except ValueError as e:
        log.warning(f"check_tls DENIED: {e}")
        return str(e)
    except ssl.SSLCertVerificationError as e:
        log.error(f"check_tls TLS_CERT_ERROR: {e}")
        return f"TLS_CERT_ERROR: {e}"
    except Exception as e:
        log.error(f"check_tls ERROR: {e}")
        return f"ERROR: {e}"

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(mcp.streamable_http_app(), host="127.0.0.1", port=PORT)
