## 2024-06-12 - [SQL Injection Fix in node-repository.ts]
**Vulnerability:** SQL injection vulnerability in `getAllNodes(limit?: number)` via string interpolation of the `limit` parameter.
**Learning:** Found string interpolation instead of parameterized binding for numeric `limit` argument when building the SQL string in `src/database/node-repository.ts`.
**Prevention:** Always use parameterized queries for ALL inputs, including integers like `limit`.
