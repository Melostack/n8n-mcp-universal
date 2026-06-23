## 2026-06-23 - [SQL Injection Fix in getAllNodes]
**Vulnerability:** SQL injection vulnerability in `getAllNodes` method of `src/database/node-repository.ts`.
**Learning:** The `limit` parameter in `getAllNodes` was dynamically concatenated into the SQL string instead of being safely parameterized. This is a common pattern for 'limit' or 'offset' clauses which are sometimes mistaken as safe from SQL injection, especially if type casting isn't enforced strictly at runtime.
**Prevention:** Use parameterized bindings (e.g. `LIMIT ?`) for all variable inputs in better-sqlite3 queries, including integer constraints like `LIMIT`, rather than string concatenation.
