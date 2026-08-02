## 2024-08-02 - SQL Injection Vulnerability in getAllNodes
**Vulnerability:** SQL Injection vulnerability in `src/database/node-repository.ts`'s `getAllNodes` method due to string interpolation of the `limit` parameter (`sql += \` LIMIT ${limit}\`;`).
**Learning:** Untyped inputs from external sources like JSON-RPC bypassing TypeScript type checking can easily slip in malicious payload into seemingly numeric fields like `limit`.
**Prevention:** Always use parameterized bindings (`?` or named parameters) instead of template string interpolation, even for numeric parameters like `limit`, to prevent SQL injection vulnerabilities.
