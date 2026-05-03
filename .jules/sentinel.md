## 2024-05-03 - [Insecure Randomness for Security Tokens]
**Vulnerability:** Found multiple uses of `Math.random()` for generating session IDs, condition IDs, and mock IDs which are security-sensitive logic (CWE-338).
**Learning:** Math.random is not cryptographically secure and predictable, leading to predictable session IDs which attackers can use to spoof sessions.
**Prevention:** Always use Node.js `crypto.randomBytes()` or `crypto.randomUUID()` for generating unique identifiers, session tokens, or node IDs.
