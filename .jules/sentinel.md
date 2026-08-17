## 2024-05-24 - [SQL Injection Fix in LIMIT clause]
**Vulnerability:** SQL injection vulnerability in `getAllNodes(limit?: number)` method in `src/database/node-repository.ts` due to string interpolation for the `LIMIT` clause (`LIMIT ${limit}`).
**Learning:** Even simple numeric parameters like `limit` that might seem safe can be injected if passed directly into string interpolation rather than parameterized queries (`?`). TypeScript types (like `number`) don't prevent injections if input validation is bypassed or inputs come from untrusted dynamic sources before casting.
**Prevention:** Always use parameterized queries (e.g. `this.db.prepare(sql).all(limit)`) for any parameter in an SQL statement, even those expected to be numeric. Never use string interpolation for SQL queries.
