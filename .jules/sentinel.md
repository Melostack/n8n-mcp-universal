## 2024-05-18 - [MEDIUM] Replaced insecure Math.random() with crypto.randomBytes()
**Vulnerability:** Usage of Math.random() to generate deterministic identifiers (e.g., node IDs, transaction/mutation IDs).
**Learning:** When Math.random() is used to generate IDs, attackers can predict the identifiers which might lead to vulnerabilities like insecure direct object reference or unauthorized data tampering.
**Prevention:** Always use `crypto.randomBytes(n)` or `crypto.randomUUID()` when generating cryptographic or unique identifiers.
