## 2024-05-18 - [Insecure Random Number Generation for Identifiers]
**Vulnerability:** The application used Math.random() to generate IDs for sessions, mutations, and nodes, creating predictable sequences that could allow attackers to guess session/mutation IDs or cause ID collisions.
**Learning:** Using Math.random() for any identifier generation is a security risk as it uses a predictable pseudo-random number generator.
**Prevention:** Always use Node.js crypto module (e.g., crypto.randomBytes()) or standard UUID generators (crypto.randomUUID()) when creating identifiers, tokens, or security-sensitive random values. Choose efficient byte lengths (e.g., n=5 for 10 hex chars) to avoid discarding entropy.
