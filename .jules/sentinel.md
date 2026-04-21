## 2024-05-15 - [Sensitive Data Exposure in MCP Endpoints]
**Vulnerability:** Raw HTTP request payloads (`req.body`) and complete header objects (`req.headers`) were being logged in the `/mcp` and `/mcp/test` endpoints. This could expose sensitive user data, Bearer tokens, or API keys within JSON-RPC `params`.
**Learning:** Application logs should never contain raw request payloads or headers, especially in authentication or API endpoints, as this is a common vector for credential leakage.
**Prevention:** Use boolean flags (e.g., `hasBody: !!req.body`, `hasHeaders: !!req.headers`) to safely indicate the presence of payloads or headers for debugging purposes without exposing their contents.
