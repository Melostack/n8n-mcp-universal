## 2025-07-05 - SQL Injection in NodeRepository
**Vulnerability:** SQL Injection in `getAllNodes(limit?: number)` via string interpolation. Even though the parameter was typed as `number` in TypeScript, inputs originated from JSON-RPC requests via MCP engine typed as `any` and were passed down, allowing bypass.
**Learning:** TypeScript type annotations don't protect against malicious runtime input from dynamic sources like RPC layers. SQL parameterized bindings must always be used, even for seemingly "safe" types like numbers.
**Prevention:** Always use parameterized queries (`?`) for user-controllable input in all database adapters, and validate boundary types explicitly at the RPC boundary layer.
