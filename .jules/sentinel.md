## 2025-05-15 - [CRITICAL] SQL Injection in getAllNodes LIMIT clause
**Vulnerability:** The `limit` parameter in `NodeRepository.getAllNodes` was directly interpolated into the SQL query string using template literals (e.g., `` sql += ` LIMIT ${limit}` ``).
**Learning:** Even though a parameter is typed as `number` in TypeScript, at runtime it could originate from untrusted sources (e.g. HTTP query parameters) and bypass type checks, creating an SQL injection vulnerability.
**Prevention:** Always use parameterized queries (parameter bindings like `?`) when constructing SQL queries, even for numeric or seemingly "safe" variables like `LIMIT`.
