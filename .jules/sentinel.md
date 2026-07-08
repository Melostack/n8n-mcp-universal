## 2024-07-08 - Added Rate Limiting to Deprecated Server
**Vulnerability:** The deprecated HTTP server (`src/http-server.ts`) is missing rate limiting on its authentication endpoint (`/mcp`), making it vulnerable to brute-force attacks and DoS.
**Learning:** The main server (`src/http-server-single-session.ts`) had rate limiting, but the fallback/deprecated server did not. Security measures must be applied symmetrically across all active entry points, even legacy ones.
**Prevention:** Apply the `express-rate-limit` middleware consistently.
