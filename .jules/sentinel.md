## 2024-05-15 - Logging Raw HTTP Payloads

**Vulnerability:** In `src/http-server-single-session.ts`, the application logs raw HTTP request payloads (`req.body`) using `JSON.stringify(req.body, null, 2)` in `/mcp`, `/mcp/test` and other endpoints.

**Learning:** Logging raw request payloads can inadvertently expose sensitive data such as authentication tokens, passwords, and PII. The MCP specification implies JSON-RPC payloads which can contain tool call parameters having sensitive data. A developer logging to `bodyContent` likely wanted to see what kind of requests were coming in but failed to sanitize the logs or realize the security implications of logging full bodies.

**Prevention:** Never log raw HTTP request bodies. Use boolean flags (e.g. `hasBody: !!req.body`) to indicate the presence of a body without exposing its contents.
