## 2024-06-24 - [SQL Injection Risk in Database Adapter]
**Vulnerability:** SQL injection vulnerability in `getAllNodes` in `src/database/node-repository.ts` due to string interpolation for the `LIMIT` clause.
**Learning:** Even if a parameter like `limit` is typed as a `number` in TypeScript, input from untyped external sources (like JSON-RPC MCP requests) could bypass this type check at runtime and introduce SQL injection vulnerabilities if string interpolation is used instead of parameterized bindings.
**Prevention:** Always use parameterized bindings (`?` or named parameters) when constructing SQL queries using the database adapter (`this.db.prepare()`), even for simple numeric parameters.
