## YYYY-MM-DD - [Insecure Randomness]
**Vulnerability:** Weak random number generation using `Math.random()` for session IDs, node IDs, and condition IDs.
**Learning:** Using `Math.random()` to generate IDs can lead to collisions or predictability in a multi-session or web context. This poses a risk for IDs that require high entropy like session IDs.
**Prevention:** Always use Node.js built-in `crypto` module (`crypto.randomBytes` or `crypto.randomUUID`) to generate security-sensitive identifiers.
