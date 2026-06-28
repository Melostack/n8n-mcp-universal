## 2025-05-16 - [SQL Injection via Untyped JSON-RPC Limit Parameter]
**Vulnerability:** The `getAllNodes(limit?: number)` method in `src/database/node-repository.ts` used string interpolation (`LIMIT ${limit}`) for the `limit` parameter. When called via the MCP engine with untyped inputs (e.g., `args.limit` as `any`), a string payload could lead to SQL injection.
**Learning:** Even parameters expected to be numeric (like `limit`) can be exploited if the caller provides an unexpected string type, particularly in systems with weakly typed boundaries like JSON-RPC endpoints.
**Prevention:** Always use parameterized bindings (`?`) for database queries, even for values expected to be numbers, to ensure strong boundaries between SQL code and user input.
