## 2024-05-15 - [Sensitive Data Logging Exposure]
**Vulnerability:** MCP endpoints (`/mcp`, `/mcp/test`) were logging the complete HTTP request `headers` and the raw request `body` in plaintext. This exposed authentication tokens (like Bearer tokens in Authorization headers) and potentially sensitive API keys/payloads contained in the JSON-RPC request bodies.
**Learning:** Raw requests from users often contain sensitive parameters that must never touch the application logs. Simply stringifying request payloads for debugging bypasses standard security boundaries and leads to log poisoning.
**Prevention:** Always use safe abstraction flags like `hasBody: !!req.body` and `hasHeaders: !!req.headers` instead of dumping raw objects directly.
