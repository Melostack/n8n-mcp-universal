## 2024-05-10 - [Replace Math.random() with Crypto for secure IDs]
**Vulnerability:** Weak random number generation using `Math.random()` for generating session IDs, condition IDs, and mutation IDs, which could potentially allow ID prediction, session hijacking, or collision.
**Learning:** Security-sensitive unique identifiers must not use `Math.random()` even if combined with timestamps, as it is cryptographically insecure. The project memory also specifically bans `Math.random()` for ID generation.
**Prevention:** Always use Node's built-in `crypto` module (e.g., `crypto.randomUUID()` or `crypto.randomBytes(n).toString('hex')`) for generating any unique, security-sensitive identifier.
