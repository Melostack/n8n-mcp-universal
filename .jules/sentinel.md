## 2024-05-24 - [SQL Injection in Database Adapter]
**Vulnerability:** Found a SQL injection vulnerability in `NodeRepository.getAllNodes` within `src/database/node-repository.ts`. The MCP engine was passing `limit` values (untyped inputs from JSON-RPC) which were being concatenated directly into the SQL string.
**Learning:** Even parameters that appear intuitively numeric, like `limit`, must not be concatenated as string interpolations into SQL queries when interacting directly with better-sqlite3 adapters `db.prepare()`.
**Prevention:** Always use parameterized inputs (`?` syntax with `params` array) for ALL variable components of a SQL query in the SQLite data repository layer.
