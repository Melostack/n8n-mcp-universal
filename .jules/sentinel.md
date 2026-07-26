## 2024-05-18 - SQL Injection in getAllNodes limit parameter
**Vulnerability:** The `getAllNodes` function in `src/database/node-repository.ts` used string interpolation for the `limit` parameter (`sql += \` LIMIT \${limit}\`;`), which is a SQL injection vulnerability if the `limit` is user-controlled.
**Learning:** Even for parameters that are expected to be numbers (like `limit`), always use parameterized queries to prevent SQL injection, especially in repository methods that might be called with untrusted input from API endpoints.
**Prevention:** Always use `?` placeholders for parameters in SQL queries and pass the values in the `.all(...params)` or `.get(...params)` call.
