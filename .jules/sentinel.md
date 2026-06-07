## 2024-06-07 - [Fix SQL injection in getAllNodes]
**Vulnerability:** SQL injection vulnerability in `getAllNodes` method of `src/database/node-repository.ts` due to concatenating user input (`limit`) directly into the SQL query string.
**Learning:** Even simple numerical limit parameters shouldn't be directly concatenated into query strings. Always use parameterized queries for any parameter, even for values like `LIMIT` and `OFFSET`.
**Prevention:** Strictly enforce the use of `?` or named parameters for all dynamic parts of SQL queries constructed with `this.db.prepare`. Avoid string template literals with variable interpolation for any query component.
