## 2025-08-08 - Fix Information Exposure in HTTP Server

**Vulnerability:** The `/mcp` and `/mcp/test` endpoints logged raw `req.body` (often including the full payload serialized as `bodyContent`) and complete `req.headers`. This risks exposing sensitive information such as Bearer tokens, passwords, and JSON-RPC tool arguments directly in the application logs.
**Learning:** Detailed request logging for debugging must be balanced against data exposure risks. Dumping entire request bodies or headers without sanitization or abstraction easily leads to credential leakage in centralized logging systems.
**Prevention:** Rather than logging the full body or headers, use boolean flags (e.g., `hasBody: !!req.body`, `hasHeaders: !!req.headers`) or explicitly selectively log only safe properties (e.g., `contentLength`, `contentType`) to confirm requests are well-formed without exposing their content.
