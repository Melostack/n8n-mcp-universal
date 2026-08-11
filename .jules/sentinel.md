## 2025-02-21 - [Prevent Information Exposure in Request Logs]
**Vulnerability:** The HTTP server logged raw HTTP request payloads (`req.body`, `bodyContent`) and complete header objects in application logs, specifically in MCP endpoints (`/mcp`, `/mcp/test`). This can expose sensitive user data, Bearer tokens, or API keys within JSON-RPC `params`.
**Learning:** Request bodies and headers often contain sensitive information that should not be persisted in plain text in application logs.
**Prevention:** Use boolean flags (e.g., `hasBody: !!req.body`, `hasHeaders: !!req.headers`) to safely indicate their presence instead of logging the raw content.
