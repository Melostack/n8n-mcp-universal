## 2025-04-25 - [SQL Injection via String Interpolation in LIMIT Clause]
**Vulnerability:** SQL injection vulnerability found in `getAllNodes` where `LIMIT ${limit}` was using string interpolation instead of a parameterized query binding (`LIMIT ?`).
**Learning:** Even though `limit` may be expected to be a number, using string interpolation within SQL queries creates a vulnerability, especially since numeric values can be manipulated or bypassed. Always use parameterized queries for ALL inputs, even expected numerics like `LIMIT`.
**Prevention:** Always use parameterized query bindings (`?` or named parameters) for dynamic inputs in SQL queries, rather than relying on template literals or string concatenation.
