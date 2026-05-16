## 2026-05-16 - [Fix SQL Injection in limit clause]
**Vulnerability:** String concatenation used to pass `limit` directly into the SQL query in `getAllNodes()` of `src/database/node-repository.ts`. Even though it is expected to be a number, it can lead to SQL injection vulnerabilities if user input is not validated properly.
**Learning:** SQLite supports parameter binding for the `LIMIT` clause, which prevents SQL injection safely and maintains proper parameterized execution flows.
**Prevention:** Always use parameterized query structures (`LIMIT ?`) via the database adapter (`this.db.prepare(sql).all(...params)`) for expected numeric bounds to prevent possible bypass or exploit.
