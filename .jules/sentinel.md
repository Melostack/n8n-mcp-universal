## 2025-05-12 - Exposing sensitive data in logs

**Vulnerability:** The `/mcp` endpoint logs the raw body using `JSON.stringify(req.body)` which could expose sensitive data like API keys, Bearer tokens, or personal information in JSON-RPC parameters.
**Learning:** Never log raw request bodies or headers on sensitive API endpoints to avoid data leakage. Use flags indicating their presence instead.
**Prevention:** Always log boolean flags or sanitized structures rather than raw `req.body` or complete `req.headers` objects on public or authenticated endpoints.
