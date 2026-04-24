## 2024-05-24 - [Predictable Identifiers due to Math.random()]
**Vulnerability:** Use of Math.random() to generate session IDs, node IDs, and condition IDs across the codebase.
**Learning:** Math.random() is not a Cryptographically Secure Pseudo-Random Number Generator (CSPRNG). Its outputs are predictable and can be brute-forced or guessed, leading to potential session hijacking, ID collisions, or predictability of internal application state.
**Prevention:** Always use the built-in Node.js crypto module (e.g., crypto.randomBytes() or crypto.randomUUID()) for generating security-sensitive random values, session tokens, or unique identifiers.
