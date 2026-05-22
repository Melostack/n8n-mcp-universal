## 2025-02-24 - [Fix SQL Injection in LIMIT clause]
**Vulnerability:** SQL injection vulnerability in `node-repository.ts`'s `getAllNodes` method due to string interpolation for the `limit` parameter (`sql += \` LIMIT ${limit}\`;`).
**Learning:** Even parameters that are expected to be purely numeric (like `limit`) can be exploited if they aren't properly sanitized or type-checked before string interpolation.
**Prevention:** Always use parameterized bindings (`?` or named parameters) via the database adapter for all SQL query inputs, regardless of expected type.
