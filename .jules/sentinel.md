## 2026-07-09 - [SQL Injection in NodeRepository]
**Vulnerability:** Found a SQL injection vulnerability in `getAllNodes` where the `limit` parameter was being directly interpolated into the SQL string.
**Learning:** Even though `limit` was typed as a number, data entering via the MCP JSON-RPC interface may bypass these checks, allowing malicious strings to alter the query.
**Prevention:** Always use parameterized queries (`?`) for dynamic parts of a SQL statement, including structural elements like `LIMIT`.
