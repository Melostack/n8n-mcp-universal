## 2026-04-27 - [SQL Injection in NodeRepository]
**Vulnerability:** SQL Injection in getAllNodes
**Learning:** Using template literals directly into SQL queries makes them vulnerable to SQL injection. `getAllNodes(limit?: number)` was interpolating `limit` directly.
**Prevention:** Use parameterized bindings (`?` or named parameters) instead of template strings, even for numbers like limit.
